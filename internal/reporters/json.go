package reporters

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blackfly/reconkit/internal/models"
	"github.com/blackfly/reconkit/internal/repository"
)

type JSONReporter struct {
	store     *repository.Store
	outputDir string
}

func NewJSONReporter(store *repository.Store, outputDir string) *JSONReporter {
	return &JSONReporter{store: store, outputDir: outputDir}
}

type jsonScanReport struct {
	Scan     *models.Scan          `json:"scan"`
	Stats    *repository.ScanStats `json:"stats"`
	Assets   []jsonAsset           `json:"assets"`
}

type jsonAsset struct {
	models.Asset
	Ports       []models.Port       `json:"ports"`
	WebServices []models.WebService `json:"web_services"`
	Screenshots []models.Screenshot `json:"screenshots"`
	Findings    []models.Finding    `json:"findings"`
}

func (r *JSONReporter) Generate(scanID int64) error {
	scan, err := r.store.GetScan(scanID)
	if err != nil {
		return fmt.Errorf("json report: get scan: %w", err)
	}

	stats, err := r.store.GetScanStats(scanID)
	if err != nil {
		return fmt.Errorf("json report: stats: %w", err)
	}

	dbAssets, err := r.store.GetAssetsByScan(scanID)
	if err != nil {
		return fmt.Errorf("json report: assets: %w", err)
	}

	var assets []jsonAsset
	for _, a := range dbAssets {
		ports, _ := r.store.GetPortsByAsset(a.ID)
		services, _ := r.store.GetWebServicesByAsset(a.ID)
		screenshots, _ := r.store.GetScreenshotsByAsset(a.ID)
		findings, _ := r.store.GetFindingsByAsset(a.ID)

		assets = append(assets, jsonAsset{
			Asset:       a,
			Ports:       ports,
			WebServices: services,
			Screenshots: screenshots,
			Findings:    findings,
		})
	}

	report := jsonScanReport{
		Scan:   scan,
		Stats:  stats,
		Assets: assets,
	}

	outDir := filepath.Join(r.outputDir, "json")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	outPath := filepath.Join(outDir, fmt.Sprintf("scan_%d.json", scanID))

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return err
	}

	fmt.Printf("[json] report written: %s\n", outPath)
	return nil
}
