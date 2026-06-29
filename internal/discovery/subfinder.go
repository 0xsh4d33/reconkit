package discovery

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/blackfly/reconkit/internal/models"
)

type SubfinderDiscoverer struct {
	binary string
}

func NewSubfinderDiscoverer() *SubfinderDiscoverer {
	return &SubfinderDiscoverer{binary: "subfinder"}
}

func (s *SubfinderDiscoverer) Name() string { return "subfinder" }

func (s *SubfinderDiscoverer) Discover(ctx context.Context, target string) ([]models.Asset, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.binary, "-d", target, "-silent") // #nosec G204 -- intentional: subfinder binary from operator config, exec.CommandContext avoids shell injection
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("subfinder %q: %w — %s", target, err, stderr.String())
	}

	var assets []models.Asset
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		sub := strings.TrimSpace(sc.Text())
		if sub == "" {
			continue
		}
		assetType := models.AssetTypeSubdomain
		if sub == target {
			assetType = models.AssetTypeDomain
		}
		assets = append(assets, models.Asset{
			AssetType: assetType,
			Name:      sub,
			Hostname:  sub,
		})
	}
	return assets, sc.Err()
}
