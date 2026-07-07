package web

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/blackfly/reconkit/internal/config"
	"github.com/blackfly/reconkit/internal/reporters"
	"github.com/blackfly/reconkit/internal/repository"
	"github.com/blackfly/reconkit/internal/scanners"
	"github.com/blackfly/reconkit/internal/scanners/httpx"
	"github.com/blackfly/reconkit/internal/scanners/nmap"
	"github.com/blackfly/reconkit/internal/services"
)

// ScanRequest carries targets and per-scan tool overrides from the web form.
type ScanRequest struct {
	Targets      services.Targets
	NmapArgs     string // space-separated, overrides config if non-empty
	NmapWorkers  int    // overrides config if > 0
	HTTPxThreads int    // overrides config if > 0
	HTTPxPorts   string // comma-separated ints, overrides config if non-empty
	EnableNmap   bool
	EnableHTTPx  bool
}

// SSEEvent is a single server-sent event pushed to the browser.
type SSEEvent struct {
	Event string
	Data  string
}

// broadcaster fan-outs events to multiple SSE subscribers.
type broadcaster struct {
	mu   sync.Mutex
	subs []chan SSEEvent
}

func (b *broadcaster) subscribe() (<-chan SSEEvent, func()) {
	ch := make(chan SSEEvent, 64)
	b.mu.Lock()
	b.subs = append(b.subs, ch)
	b.mu.Unlock()

	unsub := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		for i, s := range b.subs {
			if s == ch {
				b.subs = append(b.subs[:i], b.subs[i+1:]...)
				close(ch)
				return
			}
		}
	}
	return ch, unsub
}

func (b *broadcaster) publish(e SSEEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default: // drop if subscriber is slow
		}
	}
}

func (b *broadcaster) closeAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		close(ch)
	}
	b.subs = nil
}

// scanState holds live state for a running scan.
type scanState struct {
	cancel context.CancelFunc
	bc     *broadcaster
}

// ScanManager tracks running scans and coordinates SSE broadcasting.
type ScanManager struct {
	mu      sync.Mutex
	running map[int64]*scanState
	cfg     *config.Config
	store   *repository.Store
}

func newScanManager(cfg *config.Config, store *repository.Store) *ScanManager {
	return &ScanManager{
		running: make(map[int64]*scanState),
		cfg:     cfg,
		store:   store,
	}
}

// Submit starts a new scan asynchronously. Returns the scanID immediately.
// Returns error with HTTP 409 semantics if a scan is already running.
func (sm *ScanManager) Submit(req ScanRequest) (int64, error) {
	sm.mu.Lock()
	if len(sm.running) > 0 {
		sm.mu.Unlock()
		return 0, fmt.Errorf("scan already in progress")
	}
	sm.mu.Unlock()

	// Build per-scan config copy with overrides applied.
	cfg := sm.applyOverrides(req)

	// Build scanner list based on Enable* flags.
	var sc []scanners.Scanner
	if req.EnableNmap {
		sc = append(sc, nmap.New(cfg, sm.store))
	}
	if req.EnableHTTPx {
		sc = append(sc, httpx.New(cfg, sm.store))
	}

	pipeline := services.NewPipeline(cfg, sm.store, sc...)

	// Create scan record synchronously so scanID is known before goroutine starts.
	scanID, err := sm.store.CreateScan(req.Targets.Profile)
	if err != nil {
		return 0, fmt.Errorf("create scan record: %w", err)
	}

	bc := &broadcaster{}
	scanCtx, cancel := context.WithCancel(context.Background())

	sm.mu.Lock()
	sm.running[scanID] = &scanState{cancel: cancel, bc: bc}
	sm.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			bc.closeAll()
			sm.mu.Lock()
			delete(sm.running, scanID)
			sm.mu.Unlock()
		}()

		emit := func(event, data string) {
			bc.publish(SSEEvent{Event: event, Data: data})
		}

		if err := pipeline.Execute(scanCtx, scanID, req.Targets, emit); err != nil {
			log.Printf("[scan #%d] error: %v", scanID, err)
		}

		// Auto-generate reports on completion.
		htmlR := reporters.NewHTMLReporter(sm.store, sm.cfg.Paths.Reports, sm.cfg.Paths.Screenshots)
		jsonR := reporters.NewJSONReporter(sm.store, sm.cfg.Paths.Reports)
		if err := htmlR.Generate(scanID); err != nil {
			log.Printf("[scan #%d] html report: %v", scanID, err)
		}
		if err := jsonR.Generate(scanID); err != nil {
			log.Printf("[scan #%d] json report: %v", scanID, err)
		}
	}()

	return scanID, nil
}

// Subscribe returns a channel that receives SSE events for the given scan.
// The caller must call the returned unsubscribe func when done.
// Returns nil channel if scan is not running (finished or not found).
func (sm *ScanManager) Subscribe(scanID int64) (<-chan SSEEvent, func()) {
	sm.mu.Lock()
	state, ok := sm.running[scanID]
	sm.mu.Unlock()
	if !ok {
		return nil, func() {}
	}
	return state.bc.subscribe()
}

// Cancel cancels a running scan. Returns false if not running.
func (sm *ScanManager) Cancel(scanID int64) bool {
	sm.mu.Lock()
	state, ok := sm.running[scanID]
	sm.mu.Unlock()
	if !ok {
		return false
	}
	state.cancel()
	return true
}

// IsRunning returns true if a scan with the given ID is active.
func (sm *ScanManager) IsRunning(scanID int64) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	_, ok := sm.running[scanID]
	return ok
}

// RunningCount returns the number of currently active scans.
func (sm *ScanManager) RunningCount() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return len(sm.running)
}

// CancelAll cancels all running scans. Called on server shutdown.
func (sm *ScanManager) CancelAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, state := range sm.running {
		state.cancel()
	}
}

// applyOverrides returns a deep copy of sm.cfg with ScanRequest overrides applied.
func (sm *ScanManager) applyOverrides(req ScanRequest) *config.Config {
	c := *sm.cfg // shallow copy — sufficient since we only mutate top-level fields

	if req.NmapArgs != "" {
		c.Nmap = config.NmapConfig{Arguments: strings.Fields(req.NmapArgs)}
	}
	if req.NmapWorkers > 0 {
		c.Workers = sm.cfg.Workers // copy workers struct
		c.Workers.Nmap = req.NmapWorkers
	}
	if req.HTTPxThreads > 0 {
		c.HTTPx.Threads = req.HTTPxThreads
	}
	if req.HTTPxPorts != "" {
		c.HTTPx.Ports = parseIntCSV(req.HTTPxPorts)
	}

	return &c
}

func parseIntCSV(s string) []int {
	var result []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if n, err := strconv.Atoi(part); err == nil && n > 0 && n <= 65535 {
			result = append(result, n)
		}
	}
	return result
}

// parseScanRequest extracts and validates a ScanRequest from HTTP form values.
func parseScanRequest(
	profile, domains, subdomains, cidrs string,
	nmapArgs string, nmapWorkers int,
	httpxThreads int, httpxPorts string,
	enableNmap, enableHTTPx bool,
) ScanRequest {
	targets := services.SanitizeTargets(services.Targets{
		Profile:    profile,
		Domains:    splitCSV(domains),
		Subdomains: splitLines(subdomains),
		CIDRs:      splitAndValidateCIDRs(cidrs),
	})

	return ScanRequest{
		Targets:      targets,
		NmapArgs:     nmapArgs,
		NmapWorkers:  nmapWorkers,
		HTTPxThreads: httpxThreads,
		HTTPxPorts:   httpxPorts,
		EnableNmap:   enableNmap,
		EnableHTTPx:  enableHTTPx,
	}
}

func splitCSV(s string) []string {
	var result []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func splitLines(s string) []string {
	var result []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	return result
}

func splitAndValidateCIDRs(s string) []string {
	var result []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(p); err == nil {
			result = append(result, p)
		} else if net.ParseIP(p) != nil {
			result = append(result, p)
		}
	}
	return result
}
