package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

func (s *Scanner) Name() string { return "httpx" }

func (s *Scanner) Run(ctx context.Context, scanID int64) error {
	assets, err := s.store.GetHTTPxTargetsByScan(scanID)
	if err != nil {
		return fmt.Errorf("httpx: get assets: %w", err)
	}
	if len(assets) == 0 {
		log.Println("[httpx] no assets to probe")
		return nil
	}

	// Build dynamic target list: use nmap open ports if available, else fallback to default ports
	defaultPorts := make([]string, len(s.cfg.HTTPx.Ports))
	for i, p := range s.cfg.HTTPx.Ports {
		defaultPorts[i] = strconv.Itoa(p)
	}

	// Collect and deduplicate targets
	seen := map[string]bool{}
	var targets []string

	for _, a := range assets {
		target := a.IP
		if target == "" {
			target = a.Hostname
		}
		if target == "" {
			continue
		}

		// For IP assets, query nmap results for open ports
		if a.IP != "" && a.AssetType == "ip" {
			ports, err := s.store.GetPortsByAsset(a.ID)
			if err != nil {
				log.Printf("[httpx] get ports for %s: %v", a.IP, err)
				continue
			}

			// Collect targets for each open port
			portsFound := 0
			for _, p := range ports {
				if p.State != "open" {
					continue
				}
				t := fmt.Sprintf("%s:%d", a.IP, p.Port)
				if !seen[t] {
					seen[t] = true
					targets = append(targets, t)
					portsFound++
				}
			}
			if portsFound > 0 {
				log.Printf("[httpx] %s: found %d open ports from nmap", a.IP, portsFound)
			}
			continue
		}

		// For non-IP assets (domains/subdomains), use default port list
		for _, port := range defaultPorts {
			t := fmt.Sprintf("%s:%s", target, port)
			if !seen[t] {
				seen[t] = true
				targets = append(targets, t)
			}
		}
	}

	// Write deduplicated targets to temp file
	tmp, err := os.CreateTemp("", "reconkit-httpx-*.txt")
	if err != nil {
		return fmt.Errorf("httpx: tmp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	for _, t := range targets {
		fmt.Fprintln(tmp, t)
	}
	_ = tmp.Close()

	targetCount := len(targets)

	if targetCount == 0 {
		log.Println("[httpx] no targets to probe (no open ports from nmap, no domains)")
		return nil
	}

	// Build output paths
	ts := time.Now().Format("20060102_150405")
	outDir := filepath.Join(s.cfg.Paths.ScanResults, "httpx")
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return err
	}
	jsonOut := filepath.Join(outDir, fmt.Sprintf("httpx_%s_%d.json", ts, scanID))

	args := []string{
		"-l", tmp.Name(),
		"-ss",
		"-esb",
		"-ehb",
		"-status-code",
		"-title",
		"-tech-detect",
		"-server",
		"-ip",
		"-follow-redirects",
		"-threads", strconv.Itoa(s.cfg.HTTPx.Threads),
		"-timeout", "10",
		"-mc", "200,201,204,301,302,303,307,308,401,403,405",
		"-json",
		"-silent",
	}

	log.Printf("[httpx] probing %d targets (from nmap + default ports)", targetCount)

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "httpx", args...) // #nosec G204 -- intentional: httpx is the tool this scanner wraps, exec.CommandContext avoids shell injection
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// httpx exits non-zero when no results found — not always an error
		log.Printf("[httpx] exit: %v", err)
	}

	// Write JSON output file
	if err := os.WriteFile(jsonOut, stdout.Bytes(), 0o600); err != nil {
		log.Printf("[httpx] write output: %v", err)
	}

	// Parse and store results
	assetByHost := buildHostMap(assets)
	count := 0
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		ws, assetHost, screenshotPath, err := parseLine(line)
		if err != nil {
			continue
		}

		asset := assetByHost[assetHost]
		if asset == nil {
			// Try IP
			asset = assetByHost[assetHost]
		}
		if asset == nil {
			continue
		}

		ws.AssetID = asset.ID
		if err := s.store.InsertWebService(ws); err != nil {
			log.Printf("[httpx] insert web service: %v", err)
			continue
		}
		count++

		// Handle screenshot if present
		if screenshotPath != "" {
			destPath := filepath.Join(s.cfg.Paths.Screenshots, fmt.Sprintf("%s_%d.png", assetHost, asset.ID))
			if err := copyFile(screenshotPath, destPath); err != nil {
				log.Printf("[httpx] copy screenshot: %v", err)
				continue
			}
			if err := s.store.InsertScreenshot(&models.Screenshot{
				AssetID:  asset.ID,
				FilePath: filepath.Base(destPath),
			}); err != nil {
				log.Printf("[httpx] insert screenshot: %v", err)
			}
		}
	}

	// Store raw result against first asset as a marker
	if len(assets) > 0 {
		_ = s.store.InsertRawResult(&models.RawResult{
			AssetID:    assets[0].ID,
			Scanner:    "httpx",
			OutputFile: jsonOut,
		})
	}

	log.Printf("[httpx] found %d web services", count)
	return sc.Err()
}

// buildHostMap maps hostname and IP to asset for quick lookup.
func buildHostMap(assets []models.Asset) map[string]*models.Asset {
	m := map[string]*models.Asset{}
	for i := range assets {
		a := &assets[i]
		if a.Hostname != "" {
			m[a.Hostname] = a
		}
		if a.IP != "" {
			if _, exists := m[a.IP]; !exists {
				m[a.IP] = a
			}
		}
		m[a.Name] = a
	}
	return m
}

// httpxEntry covers both old and new httpx JSON field names.
type httpxEntry struct {
	URL              string   `json:"url"`
	Input            string   `json:"input"`
	Host             string   `json:"host"`
	Port             string   `json:"port"`
	Title            string   `json:"title"`
	StatusCode       int      `json:"status_code"`
	StatusCodeV2     int      `json:"status-code"`
	WebServer        string   `json:"webserver"`
	HostIP           string   `json:"host_ip"`
	A                []string `json:"a"`
	Scheme           string   `json:"scheme"`
	FaviconHash      string   `json:"favicon_hash"`
	FaviconHashV2    string   `json:"favicon-hash"`
	Tech             []string `json:"tech"`
	Technologies     []string `json:"technologies"`
	Failed           bool     `json:"failed"`
	ScreenshotPath   string   `json:"screenshot_path"`
	ScreenshotPathRel string  `json:"screenshot_path_rel"`
}

func parseLine(line string) (*models.WebService, string, string, error) {
	var e httpxEntry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return nil, "", "", err
	}
	if e.Failed || e.URL == "" {
		return nil, "", "", fmt.Errorf("skipped")
	}

	// Normalise fields that have two possible names
	status := e.StatusCode
	if status == 0 {
		status = e.StatusCodeV2
	}
	faviconHash := e.FaviconHash
	if faviconHash == "" {
		faviconHash = e.FaviconHashV2
	}
	techs := e.Technologies
	if len(techs) == 0 {
		techs = e.Tech
	}

	techJSON, _ := json.Marshal(techs)

	// Determine asset host: prefer Input (bare hostname), then parsed Host
	assetHost := strings.TrimSpace(e.Input)
	if assetHost == "" {
		assetHost = e.Host
	}
	// Strip port from host
	if idx := strings.LastIndex(assetHost, ":"); idx > 0 {
		if !strings.Contains(assetHost[idx:], ".") {
			assetHost = assetHost[:idx]
		}
	}

	ws := &models.WebService{
		URL:          e.URL,
		Title:        e.Title,
		StatusCode:   status,
		Scheme:       e.Scheme,
		Technologies: string(techJSON),
		FaviconHash:  faviconHash,
	}
	return ws, assetHost, e.ScreenshotPath, nil
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	data, err := os.ReadFile(src) // #nosec G304 -- src is internally generated from httpx output
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600) // #nosec G306 G703 -- dst is assembled from controlled base path
}
