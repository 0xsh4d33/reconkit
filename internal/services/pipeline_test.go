package services

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/blackfly/reconkit/internal/config"
	"github.com/blackfly/reconkit/internal/database"
	"github.com/blackfly/reconkit/internal/models"
	"github.com/blackfly/reconkit/internal/repository"
)

type noopScanner struct{}

func (noopScanner) Name() string { return "noop" }
func (noopScanner) Run(context.Context, int64) error {
	return nil
}

func TestPipelineTracksBareIPInputAsIPTargetAndAsset(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := repository.New(db)
	cfg := &config.Config{}
	pipeline := NewPipeline(cfg, store, noopScanner{})

	scanID, err := pipeline.Run(context.Background(), SanitizeTargets(Targets{
		Profile:    "test",
		Subdomains: []string{"192.168.1.1"},
	}))
	if err != nil {
		t.Fatalf("run pipeline: %v", err)
	}

	assets, err := store.GetAssetsByScan(scanID)
	if err != nil {
		t.Fatalf("get assets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("asset count = %d, want 1: %v", len(assets), assets)
	}
	if assets[0].AssetType != models.AssetTypeIP || assets[0].Name != "192.168.1.1" || assets[0].IP != "192.168.1.1" {
		t.Fatalf("asset = %+v, want IP asset for 192.168.1.1", assets[0])
	}

	targets, err := store.GetScanTargets()
	if err != nil {
		t.Fatalf("get scan targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("target count = %d, want 1: %v", len(targets), targets)
	}
	if targets[0].TargetType != models.TargetTypeIP || targets[0].Value != "192.168.1.1" {
		t.Fatalf("target = %+v, want IP target for 192.168.1.1", targets[0])
	}
	if targets[0].LastScanID != scanID || targets[0].LastScanStatus != models.ScanStatusDone || targets[0].LastScannedAt == nil {
		t.Fatalf("target scan metadata = %+v, want finalized scan metadata", targets[0])
	}
}
