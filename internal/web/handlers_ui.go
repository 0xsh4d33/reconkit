package web

import (
	"log"
	"net/http"
	"strconv"

	"github.com/blackfly/reconkit/internal/models"
	"github.com/blackfly/reconkit/internal/repository"
)

func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/scans", http.StatusMovedPermanently)
}

// ── Scan list ─────────────────────────────────────────────────────────────────

type scansPageData struct {
	pageBase
	Scans      []models.Scan
	Running    map[int64]bool
	TotalScans int
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans()
	if err != nil {
		log.Printf("[web] list scans: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	running := make(map[int64]bool, len(scans))
	for _, sc := range scans {
		running[sc.ID] = s.scanManager.IsRunning(sc.ID)
	}

	s.renderTemplate(w, "scans", scansPageData{
		pageBase:   s.baseFor("scans"),
		Scans:      scans,
		Running:    running,
		TotalScans: len(scans),
	})
}

// ── New scan form submit ───────────────────────────────────────────────────────

func (s *Server) handleSubmitScan(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if s.scanManager.RunningCount() > 0 {
		http.Error(w, "a scan is already in progress", http.StatusConflict)
		return
	}

	nmapWorkers, _ := strconv.Atoi(r.FormValue("nmap_workers"))
	httpxThreads, _ := strconv.Atoi(r.FormValue("httpx_threads"))

	req := parseScanRequest(
		r.FormValue("profile"),
		r.FormValue("domains"),
		r.FormValue("subdomains"),
		r.FormValue("cidrs"),
		r.FormValue("nmap_args"),
		nmapWorkers,
		httpxThreads,
		r.FormValue("httpx_ports"),
		r.FormValue("enable_nmap") == "on",
		r.FormValue("enable_httpx") == "on",
		r.FormValue("enable_ew") == "on",
	)

	if len(req.Targets.Domains)+len(req.Targets.Subdomains)+len(req.Targets.CIDRs) == 0 {
		http.Error(w, "no valid targets specified", http.StatusBadRequest)
		return
	}

	scanID, err := s.scanManager.Submit(req)
	if err != nil {
		log.Printf("[web] submit scan: %v", err)
		http.Error(w, "failed to start scan", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/scans/"+strconv.FormatInt(scanID, 10), http.StatusSeeOther)
}

// ── Scan detail ───────────────────────────────────────────────────────────────

type scanDetailData struct {
	pageBase
	Scan       *models.Scan
	Stats      *repository.ScanStats
	Assets     []models.Asset
	PortCounts map[string]int
	IsRunning  bool
	Config     scanConfigDefaults
}

type scanConfigDefaults struct {
	NmapArgs     string
	NmapWorkers  int
	HTTPxThreads int
	HTTPxPorts   string
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseScanID(r)
	if err != nil {
		http.Error(w, "invalid scan ID", http.StatusBadRequest)
		return
	}

	scan, err := s.store.GetScan(scanID)
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	stats, err := s.store.GetScanStats(scanID)
	if err != nil {
		log.Printf("[web] get stats: %v", err)
		stats = &repository.ScanStats{}
	}

	assets, err := s.store.GetAssetsByScan(scanID)
	if err != nil {
		log.Printf("[web] get assets: %v", err)
		assets = []models.Asset{}
	}

	portCounts, err := s.store.GetPortCountsByScan(scanID)
	if err != nil {
		log.Printf("[web] get port counts: %v", err)
		portCounts = map[string]int{}
	}

	s.renderTemplate(w, "scan_detail", scanDetailData{
		pageBase:   s.baseFor("scans"),
		Scan:       scan,
		Stats:      stats,
		Assets:     assets,
		PortCounts: portCounts,
		IsRunning:  s.scanManager.IsRunning(scanID),
		Config: scanConfigDefaults{
			NmapArgs:     joinStrings(s.cfg.Nmap.Arguments),
			NmapWorkers:  s.cfg.Workers.Nmap,
			HTTPxThreads: s.cfg.HTTPx.Threads,
			HTTPxPorts:   joinInts(s.cfg.HTTPx.Ports),
		},
	})
}

// ── Asset detail ──────────────────────────────────────────────────────────────

type assetDetailData struct {
	pageBase
	ScanID      int64
	Asset       *models.Asset
	Ports       []models.Port
	WebServices []models.WebService
	Screenshots []models.Screenshot
	Findings    []models.Finding
}

func (s *Server) handleAssetDetail(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseScanID(r)
	if err != nil {
		http.Error(w, "invalid scan ID", http.StatusBadRequest)
		return
	}

	assetID, err := strconv.ParseInt(r.PathValue("assetID"), 10, 64)
	if err != nil {
		http.Error(w, "invalid asset ID", http.StatusBadRequest)
		return
	}

	assets, err := s.store.GetAssetsByScan(scanID)
	if err != nil {
		http.Error(w, "failed to fetch assets", http.StatusInternalServerError)
		return
	}

	var asset *models.Asset
	for i := range assets {
		if assets[i].ID == assetID {
			asset = &assets[i]
			break
		}
	}
	if asset == nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}

	ports, err := s.store.GetPortsByAsset(assetID)
	if err != nil {
		log.Printf("[web] get ports: %v", err)
	}
	webSvcs, err := s.store.GetWebServicesByAsset(assetID)
	if err != nil {
		log.Printf("[web] get web services: %v", err)
	}
	screenshots, err := s.store.GetScreenshotsByAsset(assetID)
	if err != nil {
		log.Printf("[web] get screenshots: %v", err)
	}
	findings, err := s.store.GetFindingsByAsset(assetID)
	if err != nil {
		log.Printf("[web] get findings: %v", err)
	}

	s.renderTemplate(w, "asset_detail", assetDetailData{
		pageBase:    s.baseFor("scans"),
		ScanID:      scanID,
		Asset:       asset,
		Ports:       ports,
		WebServices: webSvcs,
		Screenshots: screenshots,
		Findings:    findings,
	})
}

// ── Diff ──────────────────────────────────────────────────────────────────────

type diffPageData struct {
	pageBase
	Scans  []models.Scan
	BaseID int64
	CmpID  int64
	Diff   *repository.DiffResult
	Err    string
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := diffPageData{pageBase: s.baseFor("diff"), Scans: scans}

	baseIDStr := r.URL.Query().Get("base")
	cmpIDStr := r.URL.Query().Get("cmp")

	if baseIDStr != "" && cmpIDStr != "" {
		baseID, err1 := strconv.ParseInt(baseIDStr, 10, 64)
		cmpID, err2 := strconv.ParseInt(cmpIDStr, 10, 64)
		if err1 != nil || err2 != nil {
			data.Err = "invalid scan IDs"
		} else if baseID == cmpID {
			data.Err = "select two different scans"
		} else {
			data.BaseID = baseID
			data.CmpID = cmpID
			diff, err := s.store.Diff(baseID, cmpID)
			if err != nil {
				log.Printf("[web] diff: %v", err)
				data.Err = "diff failed: " + err.Error()
			} else {
				data.Diff = diff
			}
		}
	}

	s.renderTemplate(w, "diff", data)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseScanID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}

func joinInts(ints []int) string {
	result := ""
	for i, n := range ints {
		if i > 0 {
			result += ", "
		}
		result += strconv.Itoa(n)
	}
	return result
}
