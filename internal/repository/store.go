package repository

import (
	"database/sql"
	"fmt"
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
	_, err := s.db.Exec(
		`UPDATE scans SET finished_at=?, status=? WHERE id=?`,
		time.Now().UTC(), status, id,
	)
	return err
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

// ── Assets ────────────────────────────────────────────────────────────────────

func (s *Store) InsertAsset(a *models.Asset) error {
	now := time.Now().UTC()
	a.FirstSeen = now
	a.LastSeen = now
	res, err := s.db.Exec(
		`INSERT INTO assets (scan_id, asset_type, name, hostname, ip, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ScanID, a.AssetType, a.Name, a.Hostname, a.IP, a.FirstSeen, a.LastSeen,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	a.ID = id
	return nil
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

func (s *Store) GetHostAssetsByScan(scanID int64) ([]models.Asset, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, asset_type, name, hostname, ip, first_seen, last_seen
		 FROM assets WHERE scan_id=? AND asset_type != ? ORDER BY name`,
		scanID, models.AssetTypeIP,
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

// ── Web Services ──────────────────────────────────────────────────────────────

func (s *Store) InsertWebService(ws *models.WebService) error {
	res, err := s.db.Exec(
		`INSERT INTO web_services (asset_id, url, title, status_code, scheme, technologies, favicon_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ws.AssetID, ws.URL, ws.Title, ws.StatusCode, ws.Scheme, ws.Technologies, ws.FaviconHash,
	)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	ws.ID = id
	return nil
}

func (s *Store) GetWebServicesByAsset(assetID int64) ([]models.WebService, error) {
	rows, err := s.db.Query(
		`SELECT id, asset_id, url, title, status_code, scheme, technologies, favicon_hash
		 FROM web_services WHERE asset_id=? ORDER BY url`,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanWebServices(rows)
}

func (s *Store) GetWebServicesByScan(scanID int64) ([]models.WebService, error) {
	rows, err := s.db.Query(
		`SELECT ws.id, ws.asset_id, ws.url, ws.title, ws.status_code, ws.scheme, ws.technologies, ws.favicon_hash
		 FROM web_services ws
		 JOIN assets a ON a.id = ws.asset_id
		 WHERE a.scan_id=? ORDER BY ws.url`,
		scanID,
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
	rows.Close()
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
	rows.Close()
	if err != nil {
		return nil, err
	}

	return diff, nil
}
