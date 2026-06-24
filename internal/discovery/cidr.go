package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/blackfly/reconkit/internal/models"
)

type CIDRDiscoverer struct{}

func NewCIDRDiscoverer() *CIDRDiscoverer {
	return &CIDRDiscoverer{}
}

func (c *CIDRDiscoverer) Name() string { return "cidr" }

func (c *CIDRDiscoverer) Discover(_ context.Context, target string) ([]models.Asset, error) {
	_, network, err := net.ParseCIDR(target)
	if err != nil {
		// target might be a bare IP
		if ip := net.ParseIP(target); ip != nil {
			return []models.Asset{{
				AssetType: models.AssetTypeIP,
				Name:      ip.String(),
				IP:        ip.String(),
			}}, nil
		}
		return nil, fmt.Errorf("parse cidr %q: %w", target, err)
	}

	var assets []models.Asset
	for ip := cloneIP(network.IP); network.Contains(ip); incIP(ip) {
		addr := ip.String()
		assets = append(assets, models.Asset{
			AssetType: models.AssetTypeIP,
			Name:      addr,
			IP:        addr,
		})
	}
	return assets, nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incIP(ip net.IP) {
	if len(ip) == 4 {
		n := binary.BigEndian.Uint32(ip)
		binary.BigEndian.PutUint32(ip, n+1)
		return
	}
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
