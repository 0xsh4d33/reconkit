package web

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/blackfly/reconkit/internal/models"
	"github.com/blackfly/reconkit/internal/reporters"
	"github.com/blackfly/reconkit/internal/repository"
)

func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/scans", http.StatusMovedPermanently)
}

// ── Target list ───────────────────────────────────────────────────────────────

type targetsPageData struct {
	pageBase
	Targets      []repository.TargetSummary
	TotalTargets int
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.store.ListTargetSummaries()
	if err != nil {
		log.Printf("[web] list targets: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.renderTemplate(w, "targets", targetsPageData{
		pageBase:     s.baseFor("targets"),
		Targets:      targets,
		TotalTargets: len(targets),
	})
}

// ── Target detail ─────────────────────────────────────────────────────────────

type targetDetailData struct {
	pageBase
	Detail     *repository.TargetDetail
	TechCounts []techCount
}

type techCount struct {
	Name  string
	Count int
}

func (s *Server) handleTargetDetail(w http.ResponseWriter, r *http.Request) {
	targetID, err := parseTargetID(r)
	if err != nil {
		http.Error(w, "invalid target ID", http.StatusBadRequest)
		return
	}

	detail, err := s.store.GetTargetDetail(targetID)
	if err != nil {
		log.Printf("[web] get target detail: %v", err)
		http.Error(w, "target not found", http.StatusNotFound)
		return
	}

	s.renderTemplate(w, "target_detail", targetDetailData{
		pageBase:   s.baseFor("targets"),
		Detail:     detail,
		TechCounts: buildTargetTechCounts(detail),
	})
}

func (s *Server) handleGenerateTargetReport(w http.ResponseWriter, r *http.Request) {
	targetID, err := parseTargetID(r)
	if err != nil {
		http.Error(w, "invalid target ID", http.StatusBadRequest)
		return
	}

	detail, err := s.store.GetTargetDetail(targetID)
	if err != nil {
		log.Printf("[web] get target detail for report: %v", err)
		http.Error(w, "target not found", http.StatusNotFound)
		return
	}
	if detail.Scan == nil {
		http.Error(w, "target has no scan to report", http.StatusBadRequest)
		return
	}

	reporter := reporters.NewTargetHTMLReporter(s.store, s.cfg.Paths.Reports)
	filePath, err := reporter.Generate(targetID)
	if err != nil {
		log.Printf("[web] generate target report: %v", err)
		http.Error(w, "failed to generate report", http.StatusInternalServerError)
		return
	}

	if _, err := s.store.CreateReportRecord("target", targetID, detail.Scan.ID, detail.Target.Value, filePath); err != nil {
		log.Printf("[web] store report record: %v", err)
		http.Error(w, "failed to store report record", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/reports", http.StatusSeeOther)
}

// ── Reports ──────────────────────────────────────────────────────────────────

type reportsPageData struct {
	pageBase
	Reports []repository.ReportRecord
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	reports, err := s.store.ListReportRecords()
	if err != nil {
		log.Printf("[web] list reports: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.renderTemplate(w, "reports", reportsPageData{
		pageBase: s.baseFor("reports"),
		Reports:  reports,
	})
}

func (s *Server) handleDeleteReport(w http.ResponseWriter, r *http.Request) {
	reportID, err := parseReportID(r)
	if err != nil {
		http.Error(w, "invalid report ID", http.StatusBadRequest)
		return
	}

	report, err := s.store.GetReportRecord(reportID)
	if err != nil {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}

	if err := deleteReportFile(s.cfg.Paths.Reports, report.FilePath); err != nil {
		log.Printf("[web] delete report file: %v", err)
		http.Error(w, "failed to delete report file", http.StatusInternalServerError)
		return
	}
	if err := s.store.DeleteReportRecord(reportID); err != nil {
		log.Printf("[web] delete report record: %v", err)
		http.Error(w, "failed to delete report record", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/reports", http.StatusSeeOther)
}

func deleteReportFile(baseDir, relPath string) error {
	if relPath == "" {
		return nil
	}
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(filepath.Join(baseDir, relPath))
	if err != nil {
		return err
	}
	if pathAbs != baseAbs && !strings.HasPrefix(pathAbs, baseAbs+string(os.PathSeparator)) {
		return os.ErrPermission
	}

	if filepath.Base(pathAbs) == "index.html" {
		return os.RemoveAll(filepath.Dir(pathAbs))
	}
	err = os.Remove(pathAbs)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func buildTargetTechCounts(detail *repository.TargetDetail) []techCount {
	counts := map[string]int{}
	for _, asset := range detail.Assets {
		for _, service := range asset.WebServices {
			for _, tech := range parseTechnologies(service.Technologies) {
				counts[tech]++
			}
		}
	}

	result := make([]techCount, 0, len(counts))
	for name, count := range counts {
		result = append(result, techCount{Name: name, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count == result[j].Count {
			return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
		}
		return result[i].Count > result[j].Count
	})
	return result
}

func parseTechnologies(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var jsonTechs []string
	if err := json.Unmarshal([]byte(raw), &jsonTechs); err == nil {
		return cleanTechnologies(jsonTechs)
	}

	return cleanTechnologies(strings.Split(raw, ","))
}

func cleanTechnologies(values []string) []string {
	var result []string
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
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

	httpxThreads, _ := strconv.Atoi(r.FormValue("httpx_threads"))

	req := parseScanRequest(
		r.FormValue("profile"),
		r.FormValue("domains"),
		r.FormValue("subdomains"),
		r.FormValue("cidrs"),
		r.FormValue("nmap_args"),
		httpxThreads,
		r.FormValue("httpx_ports"),
		r.FormValue("enable_nmap") == "on",
		r.FormValue("enable_httpx") == "on",
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

func parseTargetID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func parseReportID(r *http.Request) (int64, error) {
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
