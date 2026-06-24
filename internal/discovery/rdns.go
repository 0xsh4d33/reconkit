package discovery

import (
	"context"
	"net"
	"time"

	"github.com/blackfly/reconkit/internal/models"
)

type RDNSResolver struct {
	timeout time.Duration
}

func NewRDNSResolver() *RDNSResolver {
	return &RDNSResolver{timeout: 3 * time.Second}
}

func (r *RDNSResolver) Name() string { return "rdns" }

// Resolve performs reverse DNS on IP assets, attaching hostnames.
func (r *RDNSResolver) Resolve(ctx context.Context, assets []models.Asset) []models.Asset {
	resolver := &net.Resolver{}
	for i, a := range assets {
		if a.AssetType != models.AssetTypeIP || a.IP == "" {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, r.timeout)
		names, err := resolver.LookupAddr(rctx, a.IP)
		cancel()
		if err == nil && len(names) > 0 {
			// Strip trailing dot from PTR record
			hostname := names[0]
			if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
				hostname = hostname[:len(hostname)-1]
			}
			assets[i].Hostname = hostname
		}
	}
	return assets
}
