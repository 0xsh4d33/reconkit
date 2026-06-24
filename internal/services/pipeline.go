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
	ew "github.com/blackfly/reconkit/internal/scanners/eyewitness"
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

type Pipeline struct {
	cfg      *config.Config
	store    *repository.Store
	scanners []scanners.Scanner
}

func NewPipeline(cfg *config.Config, store *repository.Store) *Pipeline {
	return &Pipeline{
		cfg:   cfg,
		store: store,
		scanners: []scanners.Scanner{
			nmap.New(cfg, store),
			httpx.New(cfg, store),
			ew.New(cfg, store),
		},
	}
}

func (p *Pipeline) Run(ctx context.Context, targets Targets) (int64, error) {
	scanID, err := p.store.CreateScan(targets.Profile)
	if err != nil {
		return 0, fmt.Errorf("create scan: %w", err)
	}
	log.Printf("[pipeline] scan #%d started (profile: %q)", scanID, targets.Profile)

	status := models.ScanStatusDone
	defer func() {
		if ferr := p.store.FinalizeScan(scanID, status); ferr != nil {
			log.Printf("[pipeline] finalize scan: %v", ferr)
		}
		log.Printf("[pipeline] scan #%d %s", scanID, status)
	}()

	// ── Discovery ─────────────────────────────────────────────────────────────
	assets, err := p.discover(ctx, targets)
	if err != nil {
		status = models.ScanStatusFailed
		return scanID, fmt.Errorf("discovery: %w", err)
	}
	log.Printf("[pipeline] discovered %d assets", len(assets))

	// ── Insert assets ─────────────────────────────────────────────────────────
	for i := range assets {
		assets[i].ScanID = scanID
		if err := p.store.InsertAsset(&assets[i]); err != nil {
			log.Printf("[pipeline] insert asset %q: %v", assets[i].Name, err)
		}
	}

	// ── Scanning phases ───────────────────────────────────────────────────────
	for _, sc := range p.scanners {
		log.Printf("[pipeline] running scanner: %s", sc.Name())
		if err := sc.Run(ctx, scanID); err != nil {
			log.Printf("[pipeline] scanner %s error: %v", sc.Name(), err)
		}
	}

	return scanID, nil
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
		sf := discovery.NewSubfinderDiscoverer()
		pool := workers.New(p.cfg.Workers.Discovery, func(domain string) error {
			found, err := sf.Discover(ctx, domain)
			if err != nil {
				log.Printf("[discovery] subfinder %q: %v", domain, err)
				return nil
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
		// No subfinder: treat domains as bare assets
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
		dnsx := discovery.NewDNSxResolver()
		resolved, err := dnsx.Resolve(ctx, hostnameAssets)
		if err != nil {
			log.Printf("[discovery] dnsx: %v", err)
		} else {
			all = mergeResolved(all, resolved)
		}
	}

	// CIDRs → IP assets + reverse DNS
	if len(targets.CIDRs) > 0 {
		cidr := discovery.NewCIDRDiscoverer()
		rdns := discovery.NewRDNSResolver()
		for _, c := range targets.CIDRs {
			ipAssets, err := cidr.Discover(ctx, c)
			if err != nil {
				log.Printf("[discovery] cidr %q: %v", c, err)
				continue
			}
			ipAssets = rdns.Resolve(ctx, ipAssets)
			all = append(all, ipAssets...)
		}
	}

	return dedup(all), nil
}

// filterByHostname returns only assets that have a hostname to resolve.
func filterByHostname(assets []models.Asset) []models.Asset {
	var result []models.Asset
	for _, a := range assets {
		if a.Hostname != "" || a.AssetType == models.AssetTypeSubdomain || a.AssetType == models.AssetTypeDomain {
			result = append(result, a)
		}
	}
	return result
}

// mergeResolved merges dnsx resolution results back into the original asset list.
func mergeResolved(original, resolved []models.Asset) []models.Asset {
	ipMap := map[string]string{} // hostname → IP
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

// dedup removes duplicate assets by (name, asset_type).
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
