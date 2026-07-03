package discovery

import (
	"context"
	"log"
	"net"
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
			rctx, cancel := context.WithTimeout(ctx, r.timeout)
			names, err := (&net.Resolver{}).LookupAddr(rctx, ip)
			cancel()

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
