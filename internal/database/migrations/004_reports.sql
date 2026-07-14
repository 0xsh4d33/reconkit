CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_type TEXT    NOT NULL,
    target_id   INTEGER,
    scan_id     INTEGER,
    title       TEXT    NOT NULL,
    file_path   TEXT    NOT NULL,
    created_at  DATETIME NOT NULL,
    FOREIGN KEY(target_id) REFERENCES scan_targets(id),
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
CREATE INDEX IF NOT EXISTS idx_reports_target_id ON reports(target_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
