package discovery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/blackfly/reconkit/internal/models"
)

type DNSxResolver struct {
	binary string
}

func NewDNSxResolver() *DNSxResolver {
	return &DNSxResolver{binary: "dnsx"}
}

func (d *DNSxResolver) Name() string { return "dnsx" }

// Resolve takes subdomain assets and attaches resolved IPs.
// Returns the updated assets plus new IP assets for each unique resolved IP.
func (d *DNSxResolver) Resolve(ctx context.Context, assets []models.Asset) ([]models.Asset, error) {
	if len(assets) == 0 {
		return nil, nil
	}

	// Build input list of hostnames
	var input strings.Builder
	for _, a := range assets {
		if a.Hostname != "" {
			input.WriteString(a.Hostname + "\n")
		} else {
			input.WriteString(a.Name + "\n")
		}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, d.binary, "-a", "-json", "-silent")
	cmd.Stdin = strings.NewReader(input.String())
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("dnsx: %w — %s", err, stderr.String())
	}

	type dnsxEntry struct {
		Host string   `json:"host"`
		A    []string `json:"a"`
	}

	// Map hostname → first IP
	resolved := map[string]string{}
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e dnsxEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if len(e.A) > 0 {
			resolved[e.Host] = e.A[0]
		}
	}

	// Attach IPs to existing assets
	seen := map[string]bool{}
	var result []models.Asset
	for _, a := range assets {
		key := a.Hostname
		if key == "" {
			key = a.Name
		}
		if ip, ok := resolved[key]; ok {
			a.IP = ip
		}
		result = append(result, a)
		if a.IP != "" {
			seen[a.IP] = true
		}
	}

	// Create IP assets for each unique resolved IP
	for ip := range seen {
		result = append(result, models.Asset{
			AssetType: models.AssetTypeIP,
			Name:      ip,
			IP:        ip,
		})
	}

	return result, sc.Err()
}
