PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  DATETIME NOT NULL,
    finished_at DATETIME,
    profile     TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL,
    asset_type TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    hostname   TEXT    NOT NULL DEFAULT '',
    ip         TEXT    NOT NULL DEFAULT '',
    first_seen DATETIME NOT NULL,
    last_seen  DATETIME NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_assets_name    ON assets(name);
CREATE INDEX IF NOT EXISTS idx_assets_ip      ON assets(ip);

CREATE TABLE IF NOT EXISTS ports (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id  INTEGER NOT NULL,
    port      INTEGER NOT NULL,
    protocol  TEXT    NOT NULL DEFAULT 'tcp',
    state     TEXT    NOT NULL DEFAULT 'open',
    service   TEXT    NOT NULL DEFAULT '',
    product   TEXT    NOT NULL DEFAULT '',
    version   TEXT    NOT NULL DEFAULT '',
    FOREIGN KEY(asset_id) REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_ports_asset_id ON ports(asset_id);
CREATE INDEX IF NOT EXISTS idx_ports_port     ON ports(port);

CREATE TABLE IF NOT EXISTS web_services (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     INTEGER NOT NULL,
    url          TEXT    NOT NULL,
    title        TEXT    NOT NULL DEFAULT '',
    status_code  INTEGER NOT NULL DEFAULT 0,
    scheme       TEXT    NOT NULL DEFAULT '',
    technologies TEXT    NOT NULL DEFAULT '[]',
    favicon_hash TEXT    NOT NULL DEFAULT '',
    FOREIGN KEY(asset_id) REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_web_services_asset_id ON web_services(asset_id);

CREATE TABLE IF NOT EXISTS screenshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL,
    file_path  TEXT    NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_screenshots_asset_id ON screenshots(asset_id);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'info',
    category    TEXT    NOT NULL DEFAULT '',
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    evidence    TEXT    NOT NULL DEFAULT '',
    FOREIGN KEY(asset_id) REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS raw_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL,
    scanner     TEXT    NOT NULL,
    output_file TEXT    NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_raw_results_asset_id ON raw_results(asset_id);
