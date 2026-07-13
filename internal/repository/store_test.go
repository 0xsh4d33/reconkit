package repository

import (
	"path/filepath"
	"testing"

	"github.com/blackfly/reconkit/internal/database"
	"github.com/blackfly/reconkit/internal/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	db, err := database.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return New(db)
}

func TestLinkScanTargetsDeduplicatesAndFinalizeUpdatesLastScan(t *testing.T) {
	store := newTestStore(t)

	scanID1, err := store.CreateScan("first")
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	scanID2, err := store.CreateScan("second")
	if err != nil {
		t.Fatalf("create second scan: %v", err)
	}

	targets := []models.ScanTarget{
		{TargetType: models.TargetTypeDomain, Value: "example.com"},
		{TargetType: models.TargetTypeDomain, Value: "example.com"},
	}
	if err := store.LinkScanTargets(scanID1, targets); err != nil {
		t.Fatalf("link first scan targets: %v", err)
	}
	if err := store.LinkScanTargets(scanID2, targets[:1]); err != nil {
		t.Fatalf("link second scan targets: %v", err)
	}
	if err := store.FinalizeScan(scanID1, models.ScanStatusDone); err != nil {
		t.Fatalf("finalize first scan: %v", err)
	}
	if err := store.FinalizeScan(scanID2, models.ScanStatusFailed); err != nil {
		t.Fatalf("finalize second scan: %v", err)
	}

	scanTargets, err := store.GetScanTargets()
	if err != nil {
		t.Fatalf("get scan targets: %v", err)
	}
	if len(scanTargets) != 1 {
		t.Fatalf("scan target count = %d, want 1: %v", len(scanTargets), scanTargets)
	}
	if scanTargets[0].LastScanID != scanID2 {
		t.Fatalf("last scan id = %d, want %d", scanTargets[0].LastScanID, scanID2)
	}
	if scanTargets[0].LastScanStatus != models.ScanStatusFailed {
		t.Fatalf("last scan status = %q, want %q", scanTargets[0].LastScanStatus, models.ScanStatusFailed)
	}
	if scanTargets[0].LastScannedAt == nil {
		t.Fatalf("last scanned at was not set")
	}
}

func TestInsertAssetDeduplicatesWithinScanOnly(t *testing.T) {
	store := newTestStore(t)

	scanID1, err := store.CreateScan("first")
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	scanID2, err := store.CreateScan("second")
	if err != nil {
		t.Fatalf("create second scan: %v", err)
	}

	first := models.Asset{ScanID: scanID1, AssetType: models.AssetTypeIP, Name: "192.168.1.1", IP: "192.168.1.1"}
	if err := store.InsertAsset(&first); err != nil {
		t.Fatalf("insert first asset: %v", err)
	}

	duplicate := models.Asset{ScanID: scanID1, AssetType: models.AssetTypeIP, Name: "192.168.1.1", IP: "192.168.1.1"}
	if err := store.InsertAsset(&duplicate); err != nil {
		t.Fatalf("insert duplicate asset: %v", err)
	}
	if duplicate.ID != first.ID {
		t.Fatalf("duplicate id = %d, want existing id %d", duplicate.ID, first.ID)
	}
	if !duplicate.FirstSeen.Equal(first.FirstSeen) || !duplicate.LastSeen.Equal(first.LastSeen) {
		t.Fatalf("duplicate timestamps changed: got %s/%s want %s/%s", duplicate.FirstSeen, duplicate.LastSeen, first.FirstSeen, first.LastSeen)
	}

	secondScanAsset := models.Asset{ScanID: scanID2, AssetType: models.AssetTypeIP, Name: "192.168.1.1", IP: "192.168.1.1"}
	if err := store.InsertAsset(&secondScanAsset); err != nil {
		t.Fatalf("insert second scan asset: %v", err)
	}
	if secondScanAsset.ID == first.ID {
		t.Fatalf("second scan asset reused first scan id %d", first.ID)
	}
}

func TestInsertWebServiceDeduplicatesByAssetAndURL(t *testing.T) {
	store := newTestStore(t)

	scanID, err := store.CreateScan("web")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	asset := models.Asset{ScanID: scanID, AssetType: models.AssetTypeIP, Name: "192.168.1.1", IP: "192.168.1.1"}
	if err := store.InsertAsset(&asset); err != nil {
		t.Fatalf("insert asset: %v", err)
	}

	first := models.WebService{AssetID: asset.ID, URL: "http://192.168.1.1:80", Title: "KeeneticOS Web Panel", StatusCode: 200}
	if err := store.InsertWebService(&first); err != nil {
		t.Fatalf("insert first web service: %v", err)
	}
	duplicate := models.WebService{AssetID: asset.ID, URL: "http://192.168.1.1:80", Title: "KeeneticOS Web Panel", StatusCode: 200}
	if err := store.InsertWebService(&duplicate); err != nil {
		t.Fatalf("insert duplicate web service: %v", err)
	}
	if duplicate.ID != first.ID {
		t.Fatalf("duplicate id = %d, want existing id %d", duplicate.ID, first.ID)
	}

	services, err := store.GetWebServicesByAsset(asset.ID)
	if err != nil {
		t.Fatalf("get web services: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("web service count = %d, want 1: %+v", len(services), services)
	}
}

func TestTargetSummariesAndDetailOnlyIncludeMatchingAssets(t *testing.T) {
	store := newTestStore(t)

	scanID, err := store.CreateScan("mixed")
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.LinkScanTargets(scanID, []models.ScanTarget{
		{TargetType: models.TargetTypeDomain, Value: "example.com"},
		{TargetType: models.TargetTypeCIDR, Value: "10.0.0.0/30"},
	}); err != nil {
		t.Fatalf("link scan targets: %v", err)
	}

	domainAsset := models.Asset{
		ScanID:    scanID,
		AssetType: models.AssetTypeSubdomain,
		Name:      "api.example.com",
		Hostname:  "api.example.com",
		IP:        "203.0.113.10",
	}
	cidrAsset := models.Asset{
		ScanID:    scanID,
		AssetType: models.AssetTypeIP,
		Name:      "10.0.0.1",
		IP:        "10.0.0.1",
		Hostname:  "host-1.local",
	}
	otherAsset := models.Asset{
		ScanID:    scanID,
		AssetType: models.AssetTypeIP,
		Name:      "192.168.1.1",
		IP:        "192.168.1.1",
	}
	for _, asset := range []*models.Asset{&domainAsset, &cidrAsset, &otherAsset} {
		if err := store.InsertAsset(asset); err != nil {
			t.Fatalf("insert asset %s: %v", asset.Name, err)
		}
	}
	if err := store.InsertPort(&models.Port{AssetID: cidrAsset.ID, Port: 443, Protocol: "tcp", State: "open", Service: "https"}); err != nil {
		t.Fatalf("insert cidr port: %v", err)
	}
	if err := store.InsertWebService(&models.WebService{AssetID: domainAsset.ID, URL: "https://api.example.com", StatusCode: 200}); err != nil {
		t.Fatalf("insert domain web service: %v", err)
	}
	if err := store.FinalizeScan(scanID, models.ScanStatusDone); err != nil {
		t.Fatalf("finalize scan: %v", err)
	}

	summaries, err := store.ListTargetSummaries()
	if err != nil {
		t.Fatalf("list target summaries: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("summary count = %d, want 2: %+v", len(summaries), summaries)
	}

	byValue := map[string]TargetSummary{}
	for _, summary := range summaries {
		byValue[summary.Target.Value] = summary
	}
	if got := byValue["example.com"]; got.AssetCount != 1 || got.WebServiceCount != 1 || got.OpenPortCount != 0 {
		t.Fatalf("domain summary = %+v, want one domain asset with one web service", got)
	}
	if got := byValue["10.0.0.0/30"]; got.AssetCount != 1 || got.IPCount != 1 || got.OpenPortCount != 1 {
		t.Fatalf("cidr summary = %+v, want one matching IP asset with one open port", got)
	}

	cidrDetail, err := store.GetTargetDetail(byValue["10.0.0.0/30"].Target.ID)
	if err != nil {
		t.Fatalf("get cidr detail: %v", err)
	}
	if len(cidrDetail.Assets) != 1 || cidrDetail.Assets[0].Asset.IP != "10.0.0.1" {
		t.Fatalf("cidr detail assets = %+v, want only 10.0.0.1", cidrDetail.Assets)
	}
}
