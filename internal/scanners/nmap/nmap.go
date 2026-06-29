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
	"github.com/blackfly/reconkit/internal/workers"
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

	log.Printf("[nmap] scanning %d IPs (workers: %d)", len(assets), s.cfg.Workers.Nmap)

	pool := workers.New(s.cfg.Workers.Nmap, func(a models.Asset) error {
		return s.scanAsset(ctx, scanID, a)
	})
	pool.Start()
	for _, a := range assets {
		pool.Submit(a)
	}
	errs := pool.Wait()
	if len(errs) > 0 {
		for _, e := range errs {
			log.Printf("[nmap] error: %v", e)
		}
	}
	return nil
}

func (s *Scanner) scanAsset(ctx context.Context, scanID int64, asset models.Asset) error {
	ts := time.Now().Format("20060102_150405")
	outDir := filepath.Join(s.cfg.Paths.ScanResults, "nmap")
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return err
	}
	outBase := filepath.Join(outDir, fmt.Sprintf("%s_%s_%d", asset.IP, ts, asset.ID))

	args := append([]string{}, s.cfg.Nmap.Arguments...)
	args = append(args, asset.IP, "-oX", outBase+".xml", "-oN", outBase+".nmap")

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "nmap", args...)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nmap %s: %w — %s", asset.IP, err, stderr.String())
	}

	ports, err := parseXML(outBase + ".xml")
	if err != nil {
		return fmt.Errorf("nmap parse %s: %w", asset.IP, err)
	}

	for _, p := range ports {
		p.AssetID = asset.ID
		if err := s.store.InsertPort(&p); err != nil {
			log.Printf("[nmap] insert port %d for asset %d: %v", p.Port, asset.ID, err)
		}
	}

	_ = s.store.InsertRawResult(&models.RawResult{
		AssetID:    asset.ID,
		Scanner:    "nmap",
		OutputFile: outBase + ".xml",
	})

	log.Printf("[nmap] %s: %d open ports", asset.IP, len(ports))
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

func parseXML(path string) ([]models.Port, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	var ports []models.Port
	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}
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
	}
	return ports, nil
}
