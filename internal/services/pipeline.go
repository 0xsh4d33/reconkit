package services

import (
	"context"
	"fmt"
	"log"

	"github.com/blackfly/reconkit/internal/config"
	"github.com/blackfly/reconkit/internal/discovery"
	"github.com/blackfly/reconkit/internal/models"
	"github.com/blackfly/reconkit/internal/repository"
	"github.com/blackfly/reconkit/internal/scanners"
	"github.com/blackfly/reconkit/internal/scanners/httpx"
	"github.com/blackfly/reconkit/internal/scanners/nmap"
	"github.com/blackfly/reconkit/internal/workers"
)

// Targets holds the input for a scan run.
type Targets struct {
	Domains    []string
	Subdomains []string // pre-enumerated (skips subfinder)
	CIDRs      []string
	Profile    string
}

// EmitFunc receives phase/log events during pipeline execution.
// event is one of: "phase", "log", "stats", "done", "failed".
// Pass nil to suppress events.
type EmitFunc func(event, data string)

type Pipeline struct {
	cfg      *config.Config
	store    *repository.Store
	scanners []scanners.Scanner
}

// NewPipeline creates a pipeline with the given scanners.
// If no scanners are provided, defaults to [nmap, httpx].
func NewPipeline(cfg *config.Config, store *repository.Store, sc ...scanners.Scanner) *Pipeline {
	if len(sc) == 0 {
		sc = []scanners.Scanner{
			nmap.New(cfg, store),
			httpx.New(cfg, store),
		}
	}
	return &Pipeline{cfg: cfg, store: store, scanners: sc}
}

// Run creates a new scan record and executes the full pipeline.
// Used by the CLI. Returns scanID on success.
func (p *Pipeline) Run(ctx context.Context, targets Targets) (int64, error) {
	scanID, err := p.store.CreateScan(targets.Profile)
	if err != nil {
		return 0, fmt.Errorf("create scan: %w", err)
	}
	return scanID, p.execute(ctx, scanID, targets, nil)
}

// Execute runs the pipeline for a scan record already created by the caller.
// Used by the web layer so scanID is known before the goroutine starts.
// emit receives phase/log events; pass nil to suppress.
func (p *Pipeline) Execute(ctx context.Context, scanID int64, targets Targets, emit EmitFunc) error {
	return p.execute(ctx, scanID, targets, emit)
}

func (p *Pipeline) execute(ctx context.Context, scanID int64, targets Targets, emit EmitFunc) error {
	if emit == nil {
		emit = func(_, _ string) {}
	}

	log.Printf("[pipeline] scan #%d started (profile: %q)", scanID, targets.Profile)
	emit("phase", "discovery")

	status := models.ScanStatusDone
	defer func() {
		if ferr := p.store.FinalizeScan(scanID, status); ferr != nil {
			log.Printf("[pipeline] finalize scan: %v", ferr)
		}
		log.Printf("[pipeline] scan #%d %s", scanID, status)
		if status == models.ScanStatusDone {
			emit("done", "")
		}
	}()

	if err := p.store.LinkScanTargets(scanID, ScanTargetsFromTargets(targets)); err != nil {
		status = models.ScanStatusFailed
		emit("failed", err.Error())
		return fmt.Errorf("link scan targets: %w", err)
	}

	// ── Discovery ─────────────────────────────────────────────────────────────
	assets, err := p.discover(ctx, targets)
	if ctx.Err() != nil {
		status = models.ScanStatusCanceled
		emit("failed", "canceled")
		return ctx.Err()
	}
	if err != nil {
		status = models.ScanStatusFailed
		emit("failed", err.Error())
		return fmt.Errorf("discovery: %w", err)
	}
	log.Printf("[pipeline] discovered %d assets", len(assets))
	emit("log", fmt.Sprintf("discovered %d assets", len(assets)))

	// ── Insert assets ─────────────────────────────────────────────────────────
	for i := range assets {
		assets[i].ScanID = scanID
		if err := p.store.InsertAsset(&assets[i]); err != nil {
			log.Printf("[pipeline] insert asset %q: %v", assets[i].Name, err)
		}
	}

	// ── Scanning phases ───────────────────────────────────────────────────────
	for _, sc := range p.scanners {
		if ctx.Err() != nil {
			status = models.ScanStatusCanceled
			emit("failed", "canceled")
			return ctx.Err()
		}
		log.Printf("[pipeline] running scanner: %s", sc.Name())
		emit("phase", sc.Name())
		if err := sc.Run(ctx, scanID); err != nil {
			if ctx.Err() != nil {
				status = models.ScanStatusCanceled
				emit("failed", "canceled")
				return ctx.Err()
			}
			log.Printf("[pipeline] scanner %s error: %v", sc.Name(), err)
			emit("log", fmt.Sprintf("[%s] error: %v", sc.Name(), err))
		} else {
			emit("log", fmt.Sprintf("[%s] done", sc.Name()))
		}
	}

	emit("phase", "report")
	return nil
}

func (p *Pipeline) discover(ctx context.Context, targets Targets) ([]models.Asset, error) {
	var all []models.Asset

	// Pre-enumerated subdomains → skip subfinder
	for _, sub := range targets.Subdomains {
		all = append(all, models.Asset{
			AssetType: models.AssetTypeSubdomain,
			Name:      sub,
			Hostname:  sub,
		})
	}

	// Domains → subfinder
	if p.cfg.Subfinder.Enabled && len(targets.Domains) > 0 {
		if p.cfg.Debug {
			log.Printf("[debug][discovery] running subfinder on %d domain(s): %v", len(targets.Domains), targets.Domains)
		}
		sf := discovery.NewSubfinderDiscoverer()
		pool := workers.New(p.cfg.Workers.Discovery, func(domain string) error {
			if p.cfg.Debug {
				log.Printf("[debug][discovery] subfinder starting: %s", domain)
			}
			found, err := sf.Discover(ctx, domain)
			if err != nil {
				log.Printf("[discovery] subfinder %q: %v", domain, err)
				return nil
			}
			if p.cfg.Debug {
				log.Printf("[debug][discovery] subfinder %s → %d results", domain, len(found))
			}
			all = append(all, found...)
			return nil
		})
		pool.Start()
		for _, d := range targets.Domains {
			pool.Submit(d)
		}
		pool.Wait()
	} else {
		for _, d := range targets.Domains {
			all = append(all, models.Asset{
				AssetType: models.AssetTypeDomain,
				Name:      d,
				Hostname:  d,
			})
		}
	}

	// DNS resolution for hostname assets
	hostnameAssets := filterByHostname(all)
	if len(hostnameAssets) > 0 {
		if p.cfg.Debug {
			log.Printf("[debug][discovery] dnsx resolving %d hostname assets", len(hostnameAssets))
		}
		dnsx := discovery.NewDNSxResolver()
		resolved, err := dnsx.Resolve(ctx, hostnameAssets)
		if err != nil {
			log.Printf("[discovery] dnsx: %v", err)
		} else {
			if p.cfg.Debug {
				log.Printf("[debug][discovery] dnsx done, got %d resolved", len(resolved))
			}
			all = mergeResolved(all, resolved)
		}
	}

	// CIDRs → IP assets + reverse DNS
	if len(targets.CIDRs) > 0 {
		cidr := discovery.NewCIDRDiscoverer()
		rdns := discovery.NewRDNSResolver(p.cfg.Workers.Discovery, p.cfg.Debug)
		for _, c := range targets.CIDRs {
			if p.cfg.Debug {
				log.Printf("[debug][discovery] expanding CIDR %s", c)
			}
			ipAssets, err := cidr.Discover(ctx, c)
			if err != nil {
				log.Printf("[discovery] cidr %q: %v", c, err)
				continue
			}
			if p.cfg.Debug {
				log.Printf("[debug][discovery] CIDR %s → %d IPs, starting rdns", c, len(ipAssets))
			}
			ipAssets = rdns.Resolve(ctx, ipAssets)
			all = append(all, ipAssets...)
		}
	}

	return dedup(all), nil
}

func filterByHostname(assets []models.Asset) []models.Asset {
	var result []models.Asset
	for _, a := range assets {
		if a.Hostname != "" || a.AssetType == models.AssetTypeSubdomain || a.AssetType == models.AssetTypeDomain {
			result = append(result, a)
		}
	}
	return result
}

func mergeResolved(original, resolved []models.Asset) []models.Asset {
	ipMap := map[string]string{}
	var newIPs []models.Asset
	for _, a := range resolved {
		if a.AssetType == models.AssetTypeIP {
			newIPs = append(newIPs, a)
			continue
		}
		if a.IP != "" {
			ipMap[a.Hostname] = a.IP
		}
	}
	for i, a := range original {
		if ip, ok := ipMap[a.Hostname]; ok {
			original[i].IP = ip
		}
	}
	return append(original, newIPs...)
}

func dedup(assets []models.Asset) []models.Asset {
	seen := map[string]bool{}
	var result []models.Asset
	for _, a := range assets {
		key := string(a.AssetType) + ":" + a.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, a)
	}
	return result
}
