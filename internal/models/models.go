package models

import "time"

type AssetType string

const (
	AssetTypeDomain    AssetType = "domain"
	AssetTypeSubdomain AssetType = "subdomain"
	AssetTypeHost      AssetType = "host"
	AssetTypeIP        AssetType = "ip"
)

type ScanStatus string

const (
	ScanStatusRunning  ScanStatus = "running"
	ScanStatusDone     ScanStatus = "done"
	ScanStatusFailed   ScanStatus = "failed"
	ScanStatusCanceled ScanStatus = "canceled"
)

type Scan struct {
	ID         int64
	StartedAt  time.Time
	FinishedAt *time.Time
	Profile    string
	Status     ScanStatus
}

type Asset struct {
	ID        int64
	ScanID    int64
	AssetType AssetType
	Name      string
	Hostname  string
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
}

type Port struct {
	ID       int64
	AssetID  int64
	Port     int
	Protocol string
	State    string
	Service  string
	Product  string
	Version  string
}

type WebService struct {
	ID           int64
	AssetID      int64
	URL          string
	Title        string
	StatusCode   int
	Scheme       string
	Technologies string
	FaviconHash  string
}

type Screenshot struct {
	ID        int64
	AssetID   int64
	FilePath  string
	CreatedAt time.Time
}

type Finding struct {
	ID          int64
	AssetID     int64
	Severity    string
	Category    string
	Name        string
	Description string
	Evidence    string
}

type RawResult struct {
	ID         int64
	AssetID    int64
	Scanner    string
	OutputFile string
}
