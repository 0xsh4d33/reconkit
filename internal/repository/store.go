package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blackfly/reconkit/internal/database"
	"github.com/blackfly/reconkit/internal/models"
)

type Store struct {
	db *database.DB
}

func New(db *database.DB) *Store {
	return &Store{db: db}
}

// ── Scans ─────────────────────────────────────────────────────────────────────

func (s *Store) CreateScan(profile string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO scans (started_at, profile, status) VALUES (?, ?, ?)`,
		time.Now().UTC(), profile, models.ScanStatusRunning,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) FinalizeScan(id int64, status models.ScanStatus) error {
	finishedAt := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`UPDATE scans SET finished_at=?, status=? WHERE id=?`,
		finishedAt, status, id,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		`UPDATE scan_targets
		 SET last_scan_id=?, last_scanned_at=?, last_scan_status=?
		 WHERE id IN (SELECT target_id FROM scan_target_links WHERE scan_id=?)`,
		id, finishedAt, status, id,
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) GetScan(id int64) (*models.Scan, error) {
	row := s.db.QueryRow(`SELECT id, started_at, finished_at, profile, status FROM scans WHERE id=?`, id)
	return scanRow(row)
}

func (s *Store) GetLatestScan() (*models.Scan, error) {
	row := s.db.QueryRow(`SELECT id, started_at, finished_at, profile, status FROM scans ORDER BY id DESC LIMIT 1`)
	return scanRow(row)
}

func (s *Store) ListScans() ([]models.Scan, error) {
	rows, err := s.db.Query(`SELECT id, started_at, finished_at, profile, status FROM scans ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scans []models.Scan
	for rows.Next() {
		sc, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		scans = append(scans, *sc)
	}
	return scans, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRow(r scanner) (*models.Scan, error) {
	var sc models.Scan
	var finishedAt sql.NullTime
	if err := r.Scan(&sc.ID, &sc.StartedAt, &finishedAt, &sc.Profile, &sc.Status); err != nil {
		return nil, err
	}
	if finishedAt.Valid {
		sc.FinishedAt = &finishedAt.Time
	}
	return &sc, nil
}

// ── Generated Reports ───────────────────────────────────────────────────────

type ReportRecord struct {
	ID         int64
	ReportType string
	TargetID   int64
	ScanID     int64
	Title      string
	FilePath   string
	CreatedAt  time.Time
}

func (s *Store) CreateReportRecord(reportType string, targetID, scanID int64, title, filePath string) (*ReportRecord, error) {
	now := time.Now().UTC()
	var targetValue any
	if targetID != 0 {
		targetValue = targetID
	}
	var scanValue any
	if scanID != 0 {
		scanValue = scanID
	}
	res, err := s.db.Exec(
		`INSERT INTO reports (report_type, target_id, scan_id, title, file_path, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		reportType, targetValue, scanValue, title, filePath, now,
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &ReportRecord{
		ID:         id,
		ReportType: reportType,
		TargetID:   targetID,
		ScanID:     scanID,
		Title:      title,
		FilePath:   filePath,
		CreatedAt:  now,
	}, nil
}

func (s *Store) ListReportRecords() ([]ReportRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, report_type, COALESCE(target_id, 0), COALESCE(scan_id, 0), title, file_path, created_at
		 FROM reports ORDER BY created_at DESC, id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []ReportRecord
	for rows.Next() {
		var report ReportRecord
		if err := rows.Scan(
			&report.ID,
			&report.ReportType,
			&report.TargetID,
			&report.ScanID,
			&report.Title,
			&report.FilePath,
			&report.CreatedAt,
		); err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (s *Store) GetReportRecord(id int64) (*ReportRecord, error) {
	row := s.db.QueryRow(
		`SELECT id, report_type, COALESCE(target_id, 0), COALESCE(scan_id, 0), title, file_path, created_at
		 FROM reports WHERE id=?`,
		id,
	)
	var report ReportRecord
	if err := row.Scan(
		&report.ID,
		&report.ReportType,
		&report.TargetID,
		&report.ScanID,
		&report.Title,
		&report.FilePath,
		&report.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &report, nil
}

func (s *Store) DeleteReportRecord(id int64) error {
	_, err := s.db.Exec(`DELETE FROM reports WHERE id=?`, id)
	return err
}

// ── Scan Targets ─────────────────────────────────────────────────────────────

func (s *Store) LinkScanTargets(scanID int64, targets []models.ScanTarget) error {
	for _, target := range targets {
		if target.TargetType == "" || target.Value == "" {
			continue
		}
		targetID, err := s.upsertScanTarget(target)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(
			`INSERT OR IGNORE INTO scan_target_links (scan_id, target_id) VALUES (?, ?)`,
			scanID, targetID,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) upsertScanTarget(target models.ScanTarget) (int64, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO scan_targets (target_type, value, first_seen)
		 VALUES (?, ?, ?)`,
		target.TargetType, target.Value, now,
	)
	if err != nil {
		return 0, err
	}
	if rows, err := res.RowsAffected(); err == nil && rows > 0 {
		return res.LastInsertId()
	}

	var id int64
	err = s.db.QueryRow(
		`SELECT id FROM scan_targets WHERE target_type=? AND value=?`,
		target.TargetType, target.Value,
	).Scan(&id)
	return id, err
}

func (s *Store) GetScanTargets() ([]models.ScanTarget, error) {
	rows, err := s.db.Query(
		`SELECT id, target_type, value, first_seen, COALESCE(last_scan_id, 0), last_scanned_at, last_scan_status
		 FROM scan_targets ORDER BY target_type, value`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTargets(rows)
}

func scanTargets(rows *sql.Rows) ([]models.ScanTarget, error) {
	var targets []models.ScanTarget
	for rows.Next() {
		var target models.ScanTarget
		var lastScannedAt sql.NullTime
		if err := rows.Scan(
			&target.ID,
			&target.TargetType,
			&target.Value,
			&target.FirstSeen,
			&target.LastScanID,
			&lastScannedAt,
			&target.LastScanStatus,
		); err != nil {
			return nil, err
		}
		if lastScannedAt.Valid {
			target.LastScannedAt = &lastScannedAt.Time
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

type TargetSummary struct {
	Target          models.ScanTarget
	LastScanProfile string
	LastScanStarted *time.Time
	LastScanEnded   *time.Time
	AssetCount      int
	IPCount         int
	OpenPortCount   int
	WebServiceCount int
}

type TargetAssetDetail struct {
	Asset       models.Asset
	Ports       []models.Port
	WebServices []models.WebService
}

type TargetDetail struct {
	Target models.ScanTarget
	Scan   *models.Scan
	Assets []TargetAssetDetail
}

type TargetServiceReport struct {
	Target           models.ScanTarget
	Scan             *models.Scan
	AssetCount       int
	ResolvedDNSCount int
	OpenPortCount    int
	WebServiceCount  int
	Rows             []TargetServiceReportRow
}

type TargetServiceReportRow struct {
	DNS              string
	IP               string
	Port             int
	ServerTechnology string
	Version          string
	LastScan         time.Time
}

func (s *Store) ListTargetSummaries() ([]TargetSummary, error) {
	rows, err := s.db.Query(
		`SELECT
		    st.id, st.target_type, st.value, st.first_seen, COALESCE(st.last_scan_id, 0), st.last_scanned_at, st.last_scan_status,
		    COALESCE(sc.profile, ''),
		    sc.started_at,
		    sc.finished_at
		 FROM scan_targets st
		 LEFT JOIN scans sc ON sc.id = st.last_scan_id
		 ORDER BY st.last_scanned_at DESC, st.target_type, st.value`,
	)
	if err != nil {
		return nil, err
	}

	var summaries []TargetSummary
	for rows.Next() {
		var summary TargetSummary
		var lastScannedAt, startedAt, finishedAt sql.NullTime
		if err := rows.Scan(
			&summary.Target.ID,
			&summary.Target.TargetType,
			&summary.Target.Value,
			&summary.Target.FirstSeen,
			&summary.Target.LastScanID,
			&lastScannedAt,
			&summary.Target.LastScanStatus,
			&summary.LastScanProfile,
			&startedAt,
			&finishedAt,
		); err != nil {
			return nil, err
		}
		if lastScannedAt.Valid {
			summary.Target.LastScannedAt = &lastScannedAt.Time
		}
		if startedAt.Valid {
			summary.LastScanStarted = &startedAt.Time
		}
		if finishedAt.Valid {
			summary.LastScanEnded = &finishedAt.Time
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	for i := range summaries {
		if summaries[i].Target.LastScanID == 0 {
			continue
		}
		if err := s.populateTargetSummaryCounts(&summaries[i]); err != nil {
			return nil, err
		}
	}
	return summaries, nil
}

func (s *Store) populateTargetSummaryCounts(summary *TargetSummary) error {
	assets, err := s.GetAssetsByScan(summary.Target.LastScanID)
	if err != nil {
		return err
	}
	for _, asset := range assets {
		if !assetMatchesTarget(asset, summary.Target) {
			continue
		}
		summary.AssetCount++
		if asset.AssetType == models.AssetTypeIP {
			summary.IPCount++
		}
		ports, err := s.GetPortsByAsset(asset.ID)
		if err != nil {
			return err
		}
		webServices, err := s.GetWebServicesByAsset(asset.ID)
		if err != nil {
			return err
		}
		summary.OpenPortCount += len(ports)
		summary.WebServiceCount += len(webServices)
	}
	return nil
}

func (s *Store) GetTargetDetail(targetID int64) (*TargetDetail, error) {
	target, err := s.getScanTarget(targetID)
	if err != nil {
		return nil, err
	}

	detail := &TargetDetail{Target: *target}
	if target.LastScanID == 0 {
		return detail, nil
	}

	scan, err := s.GetScan(target.LastScanID)
	if err != nil {
		return nil, err
	}
	detail.Scan = scan

	assets, err := s.GetAssetsByScan(target.LastScanID)
	if err != nil {
		return nil, err
	}

	for _, asset := range assets {
		if !assetMatchesTarget(asset, *target) {
			continue
		}
		ports, err := s.GetPortsByAsset(asset.ID)
		if err != nil {
			return nil, err
		}
		webServices, err := s.GetWebServicesByAsset(asset.ID)
		if err != nil {
			return nil, err
		}
		detail.Assets = append(detail.Assets, TargetAssetDetail{
			Asset:       asset,
			Ports:       ports,
			WebServices: webServices,
		})
	}

	return detail, nil
}

func (s *Store) GetTargetServiceReport(targetID int64) (*TargetServiceReport, error) {
	detail, err := s.GetTargetDetail(targetID)
	if err != nil {
		return nil, err
	}

	report := &TargetServiceReport{
		Target: detail.Target,
		Scan:   detail.Scan,
	}
	if detail.Scan == nil {
		return report, nil
	}

	lastScan := detail.Scan.StartedAt
	if detail.Scan.FinishedAt != nil {
		lastScan = *detail.Scan.FinishedAt
	}

	for _, assetDetail := range detail.Assets {
		asset := assetDetail.Asset
		report.AssetCount++
		if asset.Hostname != "" {
			report.ResolvedDNSCount++
		}
		report.OpenPortCount += len(assetDetail.Ports)
		report.WebServiceCount += len(assetDetail.WebServices)

		portsByNumber := map[int]models.Port{}
		for _, port := range assetDetail.Ports {
			portsByNumber[port.Port] = port
		}

		for _, service := range assetDetail.WebServices {
			portNumber := webServicePort(service)
			port := portsByNumber[portNumber]
			report.Rows = append(report.Rows, targetServiceRows(asset, service, port, portNumber, lastScan)...)
		}
	}

	sort.Slice(report.Rows, func(i, j int) bool {
		if report.Rows[i].IP != report.Rows[j].IP {
			return ipLess(report.Rows[i].IP, report.Rows[j].IP)
		}
		if report.Rows[i].Port != report.Rows[j].Port {
			return report.Rows[i].Port < report.Rows[j].Port
		}
		return report.Rows[i].ServerTechnology < report.Rows[j].ServerTechnology
	})

	return report, nil
}

func assetIP(asset models.Asset) string {
	if asset.IP != "" {
		return asset.IP
	}
	return asset.Name
}

func displayValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func webServicePort(service models.WebService) int {
	if parsed, err := url.Parse(service.URL); err == nil {
		if parsed.Port() != "" {
			if port, err := strconv.Atoi(parsed.Port()); err == nil {
				return port
			}
		}
		switch parsed.Scheme {
		case "https":
			return 443
		case "http":
			return 80
		}
	}
	return 0
}

func targetServiceRows(asset models.Asset, service models.WebService, port models.Port, portNumber int, lastScan time.Time) []TargetServiceReportRow {
	techs := parseStoredTechnologies(service.Technologies)
	var rows []TargetServiceReportRow
	for _, tech := range techs {
		name, techVersion := splitTechnologyVersion(tech)
		if name == "" {
			continue
		}
		rows = append(rows, TargetServiceReportRow{
			DNS:              displayValue(asset.Hostname),
			IP:               assetIP(asset),
			Port:             portNumber,
			ServerTechnology: name,
			Version:          displayValue(techVersion),
			LastScan:         lastScan,
		})
	}
	if len(rows) > 0 {
		return dedupTargetServiceRows(rows)
	}

	name := "-"
	version := "-"
	switch {
	case port.Product != "":
		name = port.Product
		version = displayValue(port.Version)
	case port.Service != "":
		name = port.Service
		version = displayValue(port.Version)
	case service.Title != "":
		name = service.Title
	}
	return []TargetServiceReportRow{{
		DNS:              displayValue(asset.Hostname),
		IP:               assetIP(asset),
		Port:             portNumber,
		ServerTechnology: name,
		Version:          version,
		LastScan:         lastScan,
	}}
}

func parseStoredTechnologies(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var jsonTechs []string
	if err := json.Unmarshal([]byte(raw), &jsonTechs); err == nil {
		return jsonTechs
	}
	return strings.Split(raw, ",")
}

func dedupTargetServiceRows(rows []TargetServiceReportRow) []TargetServiceReportRow {
	var result []TargetServiceReportRow
	seen := map[string]bool{}
	for _, row := range rows {
		key := row.DNS + "|" + row.IP + "|" + strconv.Itoa(row.Port) + "|" + row.ServerTechnology + "|" + row.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, row)
	}
	return result
}

func splitTechnologyVersion(tech string) (string, string) {
	tech = strings.TrimSpace(tech)
	if tech == "" {
		return "", ""
	}
	for _, sep := range []string{":", "/"} {
		if idx := strings.LastIndex(tech, sep); idx > 0 && idx < len(tech)-1 {
			return strings.TrimSpace(tech[:idx]), strings.TrimSpace(tech[idx+1:])
		}
	}
	return tech, ""
}

func dedupNonEmpty(values []string) []string {
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

func ipLess(a, b string) bool {
	ipa := net.ParseIP(a)
	ipb := net.ParseIP(b)
	if ipa == nil || ipb == nil {
		return a < b
	}
	return bytesCompare(ipa.To16(), ipb.To16()) < 0
}

func bytesCompare(a, b []byte) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func (s *Store) getScanTarget(targetID int64) (*models.ScanTarget, error) {
	row := s.db.QueryRow(
		`SELECT id, target_type, value, first_seen, COALESCE(last_scan_id, 0), last_scanned_at, last_scan_status
		 FROM scan_targets WHERE id=?`,
		targetID,
	)
	var target models.ScanTarget
	var lastScannedAt sql.NullTime
	if err := row.Scan(
		&target.ID,
		&target.TargetType,
		&target.Value,
		&target.FirstSeen,
		&target.LastScanID,
		&lastScannedAt,
		&target.LastScanStatus,
	); err != nil {
		return nil, err
	}
	if lastScannedAt.Valid {
		target.LastScannedAt = &lastScannedAt.Time
	}
	return &target, nil
}

func assetMatchesTarget(asset models.Asset, target models.ScanTarget) bool {
	switch target.TargetType {
	case models.TargetTypeDomain:
		return asset.AssetType == models.AssetTypeDomain ||
			asset.AssetType == models.AssetTypeSubdomain ||
			asset.Hostname == target.Value ||
			hasDomainSuffix(asset.Name, target.Value) ||
			hasDomainSuffix(asset.Hostname, target.Value)
	case models.TargetTypeIP:
		return asset.IP == target.Value || asset.Name == target.Value
	case models.TargetTypeCIDR:
		return assetInCIDR(asset, target.Value)
	default:
		return false
	}
}

func hasDomainSuffix(value, domain string) bool {
	return value == domain || len(value) > len(domain) && value[len(value)-len(domain)-1:] == "."+domain
}

func assetInCIDR(asset models.Asset, cidr string) bool {
	ipValue := asset.IP
	if ipValue == "" {
		ipValue = asset.Name
	}
	ip := net.ParseIP(ipValue)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

// ── Assets ────────────────────────────────────────────────────────────────────

func (s *Store) InsertAsset(a *models.Asset) error {
	now := time.Now().UTC()
	a.FirstSeen = now
	a.LastSeen = now
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO assets (scan_id, asset_type, name, hostname, ip, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ScanID, a.AssetType, a.Name, a.Hostname, a.IP, a.FirstSeen, a.LastSeen,
	)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err == nil && rows == 0 {
		return s.getExistingAssetID(a)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	a.ID = id
	return nil
}

func (s *Store) getExistingAssetID(a *models.Asset) error {
	row := s.db.QueryRow(
		`SELECT id, first_seen, last_seen FROM assets WHERE scan_id=? AND asset_type=? AND name=?`,
		a.ScanID, a.AssetType, a.Name,
	)
	return row.Scan(&a.ID, &a.FirstSeen, &a.LastSeen)
}

func (s *Store) GetAssetsByScan(scanID int64) ([]models.Asset, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, asset_type, name, hostname, ip, first_seen, last_seen
		 FROM assets WHERE scan_id=? ORDER BY name`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssets(rows)
}

func (s *Store) GetIPAssetsByScan(scanID int64) ([]models.Asset, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, asset_type, name, hostname, ip, first_seen, last_seen
		 FROM assets WHERE scan_id=? AND asset_type=? ORDER BY ip`,
		scanID, models.AssetTypeIP,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssets(rows)
}

// GetHTTPxTargetsByScan returns all non-IP assets plus IP assets that have at
// least one open port from nmap. IP assets with zero ports are skipped — they
// are dead hosts and httpx will find nothing on them.
func (s *Store) GetHTTPxTargetsByScan(scanID int64) ([]models.Asset, error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT a.id, a.scan_id, a.asset_type, a.name, a.hostname, a.ip, a.first_seen, a.last_seen
		 FROM assets a
		 WHERE a.scan_id = ?
		   AND (
		     a.asset_type != 'ip'
		     OR EXISTS (SELECT 1 FROM ports p WHERE p.asset_id = a.id)
		   )
		 ORDER BY a.name`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssets(rows)
}

func scanAssets(rows *sql.Rows) ([]models.Asset, error) {
	var assets []models.Asset
	for rows.Next() {
		var a models.Asset
		if err := rows.Scan(&a.ID, &a.ScanID, &a.AssetType, &a.Name, &a.Hostname, &a.IP, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

// ── Ports ─────────────────────────────────────────────────────────────────────

func (s *Store) InsertPort(p *models.Port) error {
	res, err := s.db.Exec(
		`INSERT INTO ports (asset_id, port, protocol, state, service, product, version)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.AssetID, p.Port, p.Protocol, p.State, p.Service, p.Product, p.Version,
	)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	p.ID = id
	return nil
}

func (s *Store) GetPortsByAsset(assetID int64) ([]models.Port, error) {
	rows, err := s.db.Query(
		`SELECT id, asset_id, port, protocol, state, service, product, version
		 FROM ports WHERE asset_id=? ORDER BY port`,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ports []models.Port
	for rows.Next() {
		var p models.Port
		if err := rows.Scan(&p.ID, &p.AssetID, &p.Port, &p.Protocol, &p.State, &p.Service, &p.Product, &p.Version); err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}
	return ports, rows.Err()
}

// GetPortCountsByScan returns a map of IP → open port count for all assets in a scan.
// Keyed by IP so both IP assets and subdomain assets (which carry .IP from dnsx) share the same lookup.
func (s *Store) GetPortCountsByScan(scanID int64) (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT a.ip, COUNT(*) FROM ports p
		 JOIN assets a ON a.id = p.asset_id
		 WHERE a.scan_id = ? AND a.ip != '' GROUP BY a.ip`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err != nil {
			return nil, err
		}
		counts[ip] = count
	}
	return counts, rows.Err()
}

// ── Web Services ──────────────────────────────────────────────────────────────

func (s *Store) InsertWebService(ws *models.WebService) error {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO web_services (asset_id, url, title, status_code, scheme, technologies, favicon_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ws.AssetID, ws.URL, ws.Title, ws.StatusCode, ws.Scheme, ws.Technologies, ws.FaviconHash,
	)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err == nil && rows == 0 {
		return s.getExistingWebServiceID(ws)
	}
	id, _ := res.LastInsertId()
	ws.ID = id
	return nil
}

func (s *Store) getExistingWebServiceID(ws *models.WebService) error {
	return s.db.QueryRow(
		`SELECT id FROM web_services WHERE asset_id=? AND url=?`,
		ws.AssetID, ws.URL,
	).Scan(&ws.ID)
}

func (s *Store) GetWebServicesByAsset(assetID int64) ([]models.WebService, error) {
	rows, err := s.db.Query(
		`SELECT MIN(id), asset_id, url, title, status_code, scheme, technologies, favicon_hash
		 FROM web_services
		 WHERE asset_id=?
		 GROUP BY asset_id, url
		 ORDER BY url`,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanWebServices(rows)
}

func scanWebServices(rows *sql.Rows) ([]models.WebService, error) {
	var services []models.WebService
	for rows.Next() {
		var ws models.WebService
		if err := rows.Scan(&ws.ID, &ws.AssetID, &ws.URL, &ws.Title, &ws.StatusCode, &ws.Scheme, &ws.Technologies, &ws.FaviconHash); err != nil {
			return nil, err
		}
		services = append(services, ws)
	}
	return services, rows.Err()
}

// ── Screenshots ───────────────────────────────────────────────────────────────

func (s *Store) InsertScreenshot(ss *models.Screenshot) error {
	ss.CreatedAt = time.Now().UTC()
	res, err := s.db.Exec(
		`INSERT INTO screenshots (asset_id, file_path, created_at) VALUES (?, ?, ?)`,
		ss.AssetID, ss.FilePath, ss.CreatedAt,
	)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	ss.ID = id
	return nil
}

func (s *Store) GetScreenshotsByAsset(assetID int64) ([]models.Screenshot, error) {
	rows, err := s.db.Query(
		`SELECT id, asset_id, file_path, created_at FROM screenshots WHERE asset_id=?`,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var shots []models.Screenshot
	for rows.Next() {
		var ss models.Screenshot
		if err := rows.Scan(&ss.ID, &ss.AssetID, &ss.FilePath, &ss.CreatedAt); err != nil {
			return nil, err
		}
		shots = append(shots, ss)
	}
	return shots, rows.Err()
}

// ── Findings ──────────────────────────────────────────────────────────────────

func (s *Store) InsertFinding(f *models.Finding) error {
	res, err := s.db.Exec(
		`INSERT INTO findings (asset_id, severity, category, name, description, evidence)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		f.AssetID, f.Severity, f.Category, f.Name, f.Description, f.Evidence,
	)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	f.ID = id
	return nil
}

func (s *Store) GetFindingsByAsset(assetID int64) ([]models.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, asset_id, severity, category, name, description, evidence
		 FROM findings WHERE asset_id=? ORDER BY severity`,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		if err := rows.Scan(&f.ID, &f.AssetID, &f.Severity, &f.Category, &f.Name, &f.Description, &f.Evidence); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// ── Raw Results ───────────────────────────────────────────────────────────────

func (s *Store) InsertRawResult(r *models.RawResult) error {
	res, err := s.db.Exec(
		`INSERT INTO raw_results (asset_id, scanner, output_file) VALUES (?, ?, ?)`,
		r.AssetID, r.Scanner, r.OutputFile,
	)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	r.ID = id
	return nil
}

// ── Reporting Queries ─────────────────────────────────────────────────────────

type ScanStats struct {
	TotalAssets   int
	TotalPorts    int
	TotalServices int
	TotalFindings int
}

func (s *Store) GetScanStats(scanID int64) (*ScanStats, error) {
	var stats ScanStats
	row := s.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE scan_id=?`, scanID)
	if err := row.Scan(&stats.TotalAssets); err != nil {
		return nil, err
	}
	row = s.db.QueryRow(
		`SELECT COUNT(*) FROM ports p JOIN assets a ON a.id=p.asset_id WHERE a.scan_id=?`, scanID,
	)
	if err := row.Scan(&stats.TotalPorts); err != nil {
		return nil, err
	}
	row = s.db.QueryRow(
		`SELECT COUNT(*) FROM web_services ws JOIN assets a ON a.id=ws.asset_id WHERE a.scan_id=?`, scanID,
	)
	if err := row.Scan(&stats.TotalServices); err != nil {
		return nil, err
	}
	row = s.db.QueryRow(
		`SELECT COUNT(*) FROM findings f JOIN assets a ON a.id=f.asset_id WHERE a.scan_id=?`, scanID,
	)
	if err := row.Scan(&stats.TotalFindings); err != nil {
		return nil, err
	}
	return &stats, nil
}

// ── Diff ──────────────────────────────────────────────────────────────────────

type DiffResult struct {
	NewAssets         []models.Asset
	DisappearedAssets []models.Asset
	NewPorts          []PortDiff
	NewServices       []models.WebService
}

type PortDiff struct {
	Asset models.Asset
	Port  models.Port
}

func (s *Store) Diff(scanID1, scanID2 int64) (*DiffResult, error) {
	diff := &DiffResult{}

	// Assets in scan2 not in scan1 (by name+type)
	rows, err := s.db.Query(
		`SELECT id, scan_id, asset_type, name, hostname, ip, first_seen, last_seen
		 FROM assets WHERE scan_id=?
		   AND name NOT IN (SELECT name FROM assets WHERE scan_id=?)
		 ORDER BY name`,
		scanID2, scanID1,
	)
	if err != nil {
		return nil, fmt.Errorf("new assets: %w", err)
	}
	diff.NewAssets, err = scanAssets(rows)
	_ = rows.Close()
	if err != nil {
		return nil, err
	}

	// Assets in scan1 not in scan2
	rows, err = s.db.Query(
		`SELECT id, scan_id, asset_type, name, hostname, ip, first_seen, last_seen
		 FROM assets WHERE scan_id=?
		   AND name NOT IN (SELECT name FROM assets WHERE scan_id=?)
		 ORDER BY name`,
		scanID1, scanID2,
	)
	if err != nil {
		return nil, fmt.Errorf("disappeared assets: %w", err)
	}
	diff.DisappearedAssets, err = scanAssets(rows)
	_ = rows.Close()
	if err != nil {
		return nil, err
	}

	rows, err = s.db.Query(
		`SELECT a.id, a.scan_id, a.asset_type, a.name, a.hostname, a.ip, a.first_seen, a.last_seen,
		        p.id, p.asset_id, p.port, p.protocol, p.state, p.service, p.product, p.version
		 FROM ports p
		 JOIN assets a ON a.id = p.asset_id
		 WHERE a.scan_id = ?
		   AND NOT EXISTS (
		     SELECT 1
		     FROM ports p1
		     JOIN assets a1 ON a1.id = p1.asset_id
		     WHERE a1.scan_id = ?
		       AND a1.name = a.name
		       AND p1.port = p.port
		       AND p1.protocol = p.protocol
		   )
		 ORDER BY a.name, p.port, p.protocol`,
		scanID2, scanID1,
	)
	if err != nil {
		return nil, fmt.Errorf("new ports: %w", err)
	}
	diff.NewPorts, err = scanPortDiffs(rows)
	_ = rows.Close()
	if err != nil {
		return nil, err
	}

	rows, err = s.db.Query(
		`SELECT MIN(ws.id), ws.asset_id, ws.url, ws.title, ws.status_code, ws.scheme, ws.technologies, ws.favicon_hash
		 FROM web_services ws
		 JOIN assets a ON a.id = ws.asset_id
		 WHERE a.scan_id = ?
		   AND NOT EXISTS (
		     SELECT 1
		     FROM web_services ws1
		     JOIN assets a1 ON a1.id = ws1.asset_id
		     WHERE a1.scan_id = ?
		       AND ws1.url = ws.url
		   )
		 GROUP BY ws.asset_id, ws.url
		 ORDER BY ws.url`,
		scanID2, scanID1,
	)
	if err != nil {
		return nil, fmt.Errorf("new web services: %w", err)
	}
	diff.NewServices, err = scanWebServices(rows)
	_ = rows.Close()
	if err != nil {
		return nil, err
	}

	return diff, nil
}

func scanPortDiffs(rows *sql.Rows) ([]PortDiff, error) {
	var ports []PortDiff
	for rows.Next() {
		var diff PortDiff
		if err := rows.Scan(
			&diff.Asset.ID,
			&diff.Asset.ScanID,
			&diff.Asset.AssetType,
			&diff.Asset.Name,
			&diff.Asset.Hostname,
			&diff.Asset.IP,
			&diff.Asset.FirstSeen,
			&diff.Asset.LastSeen,
			&diff.Port.ID,
			&diff.Port.AssetID,
			&diff.Port.Port,
			&diff.Port.Protocol,
			&diff.Port.State,
			&diff.Port.Service,
			&diff.Port.Product,
			&diff.Port.Version,
		); err != nil {
			return nil, err
		}
		ports = append(ports, diff)
	}
	return ports, rows.Err()
}
