CREATE TABLE IF NOT EXISTS scan_targets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type      TEXT    NOT NULL,
    value            TEXT    NOT NULL,
    first_seen       DATETIME NOT NULL,
    last_scan_id     INTEGER,
    last_scanned_at  DATETIME,
    last_scan_status TEXT    NOT NULL DEFAULT '',
    UNIQUE(target_type, value),
    FOREIGN KEY(last_scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_scan_targets_type_value ON scan_targets(target_type, value);
CREATE INDEX IF NOT EXISTS idx_scan_targets_last_scan_id ON scan_targets(last_scan_id);

CREATE TABLE IF NOT EXISTS scan_target_links (
    scan_id   INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    PRIMARY KEY(scan_id, target_id),
    FOREIGN KEY(scan_id) REFERENCES scans(id),
    FOREIGN KEY(target_id) REFERENCES scan_targets(id)
);

CREATE INDEX IF NOT EXISTS idx_scan_target_links_target_id ON scan_target_links(target_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_scan_type_name
    ON assets(scan_id, asset_type, name);
