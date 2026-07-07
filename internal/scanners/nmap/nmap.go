package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blackfly/reconkit/internal/config"
	"github.com/blackfly/reconkit/internal/models"
	"github.com/blackfly/reconkit/internal/repository"
)

type Scanner struct {
	cfg   *config.Config
	store *repository.Store
}

func New(cfg *config.Config, store *repository.Store) *Scanner {
	return &Scanner{cfg: cfg, store: store}
}

func (s *Scanner) Name() string { return "nmap" }

func (s *Scanner) Run(ctx context.Context, scanID int64) error {
	assets, err := s.store.GetIPAssetsByScan(scanID)
	if err != nil {
		return fmt.Errorf("nmap: get IP assets: %w", err)
	}
	if len(assets) == 0 {
		log.Println("[nmap] no IP assets to scan")
		return nil
	}

	// Build IP list and asset map
	ips := make([]string, len(assets))
	assetByIP := make(map[string]models.Asset)
	for i, a := range assets {
		ips[i] = a.IP
		assetByIP[a.IP] = a
	}

	log.Printf("[nmap] scanning %d IPs", len(ips))

	// Build output paths
	ts := time.Now().Format("20060102_150405")
	outDir := filepath.Join(s.cfg.Paths.ScanResults, "nmap")
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return err
	}
	outBase := filepath.Join(outDir, fmt.Sprintf("batch_%s_%d", ts, scanID))
	outXML := outBase + ".xml"
	outNmap := outBase + ".nmap"

	// Build nmap command
	args := append([]string{}, s.cfg.Nmap.Arguments...)
	args = append(args, ips...)
	args = append(args, "-oX", outXML, "-oN", outNmap)

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "nmap", args...) // #nosec G204 -- intentional: nmap is the tool this scanner wraps, exec.CommandContext avoids shell injection
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nmap batch: %w — %s", err, stderr.String())
	}

	// Parse XML batch
	portsByIP, err := parseXMLBatch(outXML)
	if err != nil {
		log.Printf("[nmap] parse batch XML: %v", err)
	}

	// Insert all ports
	totalPorts := 0
	for ip, ports := range portsByIP {
		asset, exists := assetByIP[ip]
		if !exists {
			log.Printf("[nmap] IP %s not in asset map", ip)
			continue
		}
		for _, p := range ports {
			p.AssetID = asset.ID
			if err := s.store.InsertPort(&p); err != nil {
				log.Printf("[nmap] insert port %d/%s for %s: %v", p.Port, p.Protocol, ip, err)
				continue
			}
			totalPorts++
		}
	}

	// Store raw result
	_ = s.store.InsertRawResult(&models.RawResult{
		AssetID:    assets[0].ID,
		Scanner:    "nmap",
		OutputFile: outXML,
	})

	log.Printf("[nmap] inserted %d ports across %d IPs", totalPorts, len(portsByIP))
	return nil
}


// ── XML parsing ───────────────────────────────────────────────────────────────

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func parseXMLBatch(path string) (map[string][]models.Port, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is internally generated from scan output dir
	if err != nil {
		return nil, err
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	portsByIP := make(map[string][]models.Port)
	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}

		ip := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}

		var ports []models.Port
		for _, p := range host.Ports.Ports {
			if !strings.EqualFold(p.State.State, "open") {
				continue
			}
			ports = append(ports, models.Port{
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
			})
		}
		if len(ports) > 0 {
			portsByIP[ip] = ports
		}
	}
	return portsByIP, nil
}
