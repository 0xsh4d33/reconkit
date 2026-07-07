package eyewitness

import (
	"bytes"
	"context"
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

func (s *Scanner) Name() string { return "eyewitness" }

func (s *Scanner) Run(ctx context.Context, scanID int64) error {
	if !s.cfg.EyeWitness.Enabled {
		log.Println("[eyewitness] disabled in config")
		return nil
	}
	if s.cfg.EyeWitness.Path == "" {
		log.Println("[eyewitness] no path configured, skipping")
		return nil
	}

	pythonBin := s.cfg.EyeWitness.Python
	entrypoint := filepath.Join(s.cfg.EyeWitness.Path, "Python", "EyeWitness.py")

	if _, err := os.Stat(entrypoint); err != nil {
		return fmt.Errorf("eyewitness: entrypoint not found: %s", entrypoint)
	}
	if _, err := os.Stat(pythonBin); err != nil {
		return fmt.Errorf("eyewitness: python not found: %s", pythonBin)
	}

	services, err := s.store.GetWebServicesByScan(scanID)
	if err != nil {
		return fmt.Errorf("eyewitness: get web services: %w", err)
	}
	if len(services) == 0 {
		log.Println("[eyewitness] no web services to screenshot")
		return nil
	}

	// Write URL list
	tmp, err := os.CreateTemp("", "reconkit-ew-*.txt")
	if err != nil {
		return fmt.Errorf("eyewitness: tmp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	urlToService := map[string]*models.WebService{}
	for i, ws := range services {
		fmt.Fprintln(tmp, ws.URL)
		urlToService[ws.URL] = &services[i]
	}
	_ = tmp.Close()

	ts := time.Now().Format("20060102_150405")
	outDir, err := filepath.Abs(filepath.Join(s.cfg.Paths.ScanResults, "eyewitness", fmt.Sprintf("ew_%s_%d", ts, scanID)))
	if err != nil {
		return fmt.Errorf("eyewitness: abs path: %w", err)
	}
	// Only create parent — EyeWitness requires outDir to not exist yet (it creates it itself)
	if err := os.MkdirAll(filepath.Dir(outDir), 0o750); err != nil {
		return err
	}

	log.Printf("[eyewitness] screenshotting %d URLs", len(services))
	log.Printf("[eyewitness] outDir: %s", outDir)
	log.Printf("[eyewitness] cmd: %s %s --web -f %s -d %s --no-prompt", pythonBin, entrypoint, tmp.Name(), outDir)

	var stderr, stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, pythonBin, entrypoint, // #nosec G204 -- intentional: eyewitness binary/entrypoint from operator config, exec.CommandContext avoids shell injection
		"--web",
		"-f", tmp.Name(),
		"-d", outDir,
		"--no-prompt",
	)
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	cmd.Dir = s.cfg.EyeWitness.Path

	if err := cmd.Run(); err != nil {
		log.Printf("[eyewitness] exit: %v", err)
	}
	if stderr.Len() > 0 {
		log.Printf("[eyewitness] stderr: %s", stderr.String())
	}
	if stdout.Len() > 0 {
		log.Printf("[eyewitness] stdout: %s", stdout.String())
	}

	// Log what EyeWitness actually created
	if entries, err2 := os.ReadDir(outDir); err2 == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		log.Printf("[eyewitness] output dir contents: %v", names)
	}

	// Match screenshots to web service assets
	screensDir := filepath.Join(outDir, "screens")
	entries, err := os.ReadDir(screensDir)
	if err != nil {
		log.Printf("[eyewitness] no screenshots dir: %v", err)
		return nil
	}

	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".png") {
			continue
		}
		screenshotPath := filepath.Join(screensDir, e.Name())
		// Match screenshot filename to a web service asset
		// EyeWitness names files after the URL's hostname
		hostname := strings.TrimSuffix(e.Name(), ".png")

		// Find the asset that owns this hostname
		assetID := s.findAssetIDForHostname(hostname, services)
		if assetID == 0 {
			continue
		}

		// Copy to permanent screenshots dir
		dest := filepath.Join(s.cfg.Paths.Screenshots, fmt.Sprintf("%s_%d.png", hostname, scanID))
		if err := copyFile(screenshotPath, dest); err != nil {
			log.Printf("[eyewitness] copy screenshot: %v", err)
			dest = screenshotPath
		}

		if err := s.store.InsertScreenshot(&models.Screenshot{
			AssetID:  assetID,
			FilePath: filepath.Base(dest),
		}); err != nil {
			log.Printf("[eyewitness] insert screenshot: %v", err)
			continue
		}
		count++
	}

	log.Printf("[eyewitness] stored %d screenshots", count)
	return nil
}

func (s *Scanner) findAssetIDForHostname(hostname string, services []models.WebService) int64 {
	// hostname from EyeWitness filename may contain port: "host.com_8080"
	host := strings.SplitN(hostname, "_", 2)[0]
	for _, ws := range services {
		if strings.Contains(ws.URL, host) {
			return ws.AssetID
		}
	}
	return 0
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	data, err := os.ReadFile(src) // #nosec G304 -- src is internally generated from scan output dir
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600) // #nosec G306 G703 -- dst is assembled from controlled base path
}
