package discovery

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/blackfly/reconkit/internal/models"
)

type RDNSResolver struct {
	timeout time.Duration
	workers int
	debug   bool
}

func NewRDNSResolver(workers int, debug bool) *RDNSResolver {
	if workers <= 0 {
		workers = 20
	}
	return &RDNSResolver{timeout: time.Second, workers: workers, debug: debug}
}

func (r *RDNSResolver) Name() string { return "rdns" }

func (r *RDNSResolver) Resolve(ctx context.Context, assets []models.Asset) []models.Asset {
	total := len(assets)
	if r.debug {
		log.Printf("[debug][rdns] starting reverse DNS for %d IPs (workers: %d, timeout: %s)", total, r.workers, r.timeout)
	}

	sem := make(chan struct{}, r.workers)
	var wg sync.WaitGroup

	for i := range assets {
		if assets[i].AssetType != models.AssetTypeIP || assets[i].IP == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()

			ip := assets[i].IP
			names, err := lookupAddrWithDig(ctx, ip, r.timeout)

			if r.debug {
				if err != nil {
					log.Printf("[debug][rdns] %s → err: %v", ip, err)
				} else if len(names) > 0 {
					log.Printf("[debug][rdns] %s → %s", ip, names[0])
				}
			}

			if err == nil && len(names) > 0 {
				hostname := names[0]
				if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
					hostname = hostname[:len(hostname)-1]
				}
				assets[i].Hostname = hostname
			}
		}(i)
	}

	wg.Wait()

	if r.debug {
		log.Printf("[debug][rdns] done")
	}
	return assets
}

func lookupAddrWithDig(ctx context.Context, ip string, timeout time.Duration) ([]string, error) {
	digPath, err := exec.LookPath("dig")
	if err != nil {
		digPath = "/usr/bin/dig"
	}

	digCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(digCtx, digPath, "-x", ip, "+short", "+time=1", "+tries=1") // #nosec G204 -- direct exec of dig with IP argument, no shell
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("dig -x %s: %w: %s", ip, err, strings.TrimSpace(stderr.String()))
	}

	var names []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		names = append(names, strings.TrimSuffix(name, "."))
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("dig -x %s returned no PTR records", ip)
	}
	return names, nil
}
