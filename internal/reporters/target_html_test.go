package reporters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blackfly/reconkit/internal/database"
	"github.com/blackfly/reconkit/internal/models"
	"github.com/blackfly/reconkit/internal/repository"
)

func TestTargetHTMLReporterGenerate(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := repository.New(db)
	targetID := createTargetHTMLFixture(t, store)
	outputDir := t.TempDir()

	relPath, err := NewTargetHTMLReporter(store, outputDir).Generate(targetID)
	if err != nil {
		t.Fatalf("generate target html report: %v", err)
	}
	if relPath == "" {
		t.Fatalf("relative path was empty")
	}

	data, err := os.ReadFile(filepath.Join(outputDir, relPath))
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}
	html := string(data)
	for _, want := range []string{"192.168.1.0/24", "server1", "192.168.1.1", "Apache", "2.4.66"} {
		if !strings.Contains(html, want) {
			t.Fatalf("generated report missing %q", want)
		}
	}
}

func createTargetHTMLFixture(t *testing.T, store *repository.Store) int64 {
	t.Helper()

	scanID, err := store.CreateScan("report")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.LinkScanTargets(scanID, []models.ScanTarget{
		{TargetType: models.TargetTypeCIDR, Value: "192.168.1.0/24"},
	}); err != nil {
		t.Fatalf("link scan target: %v", err)
	}

	asset := models.Asset{
		ScanID:    scanID,
		AssetType: models.AssetTypeIP,
		Name:      "192.168.1.1",
		IP:        "192.168.1.1",
		Hostname:  "server1",
	}
	if err := store.InsertAsset(&asset); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	if err := store.InsertPort(&models.Port{
		AssetID:  asset.ID,
		Port:     80,
		Protocol: "tcp",
		State:    "open",
		Service:  "http",
		Product:  "Apache",
		Version:  "2.4.66",
	}); err != nil {
		t.Fatalf("insert port: %v", err)
	}
	if err := store.InsertWebService(&models.WebService{
		AssetID:      asset.ID,
		URL:          "http://192.168.1.1:80",
		StatusCode:   200,
		Scheme:       "http",
		Technologies: `["Apache:2.4.66"]`,
	}); err != nil {
		t.Fatalf("insert web service: %v", err)
	}
	if err := store.FinalizeScan(scanID, models.ScanStatusDone); err != nil {
		t.Fatalf("finalize scan: %v", err)
	}

	targets, err := store.GetScanTargets()
	if err != nil {
		t.Fatalf("get scan targets: %v", err)
	}
	for _, target := range targets {
		if target.Value == "192.168.1.0/24" {
			return target.ID
		}
	}
	t.Fatalf("target not found")
	return 0
}
