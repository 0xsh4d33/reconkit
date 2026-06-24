# ReconKit

Modular Go recon pipeline for bug bounty and pentest. Single binary, SQLite persistence, HTML/JSON reports generated from DB.

## Quick Start

```bash
# Build
go build -o recon ./cmd/recon/

# Config (set eyewitness.path if using EyeWitness)
cp config.example.yaml config.yaml

# Run full scan
./recon scan -config config.yaml -targets targets.yaml

# Or inline
./recon scan -config config.yaml -domains example.com
./recon scan -config config.yaml -subdomains subdomains.txt -profile recheck
./recon scan -config config.yaml -cidrs 10.0.0.0/24
```

Reports written to `reports/html/scan_N/index.html` and `reports/json/scan_N.json`.

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Run full pipeline against targets |
| `report` | Re-generate reports from DB |
| `diff` | Compare two scans |
| `scans` | List all recorded scans |

```bash
./recon scan   -config config.yaml -targets targets.yaml -profile full
./recon report -config config.yaml -scan-id 3
./recon diff   -config config.yaml -scan-id1 1 -scan-id2 2
./recon scans  -config config.yaml
```

## Targets File

`targets.yaml` (copy from `targets.example.yaml`):

```yaml
targets:
  domains:
    - example.com          # subfinder enumerates subdomains
  subdomains:
    - api.example.com      # pre-enumerated, skips subfinder
  cidrs:
    - 10.0.0.0/24          # expands to IPs + reverse DNS
```

## Config

`config.yaml` (copy from `config.example.yaml`):

```yaml
database:
  path: ./data/recon.db

workers:
  nmap: 10
  httpx: 50
  eyewitness: 5

nmap:
  arguments: [-sV, --open, -T4]

eyewitness:
  enabled: true
  path: /path/to/EyeWitness
  python: eyewitness-venv/bin/python
```

## Tool Requirements

| Tool | Location |
|------|----------|
| `subfinder` | `/usr/bin/subfinder` |
| `dnsx` | `~/go/bin/dnsx` |
| `nmap` | `/usr/bin/nmap` |
| `httpx` | `~/go/bin/httpx` |
| EyeWitness | config-driven (Python subprocess) |

## Pipeline

```
Domains → subfinder → subdomains
Subdomains → dnsx → IP resolution
CIDRs → expand → reverse DNS
           ↓
     INSERT assets (SQLite)
           ↓
   nmap (per-IP, worker pool)
           ↓
   httpx (batch, all assets)
           ↓
   eyewitness (batch, web services)
           ↓
   HTML + JSON reports from DB
```

## Project Structure

```
cmd/recon/                  CLI entrypoint
internal/
  config/                   YAML config + defaults
  models/                   Asset, Port, WebService, Screenshot, Finding, Scan
  database/                 SQLite open + embedded WAL migrations
  repository/               DB CRUD (Store)
  discovery/                subfinder, dnsx, rdns, cidr
  scanners/nmap|httpx|ew    Scanner implementations
  workers/                  Generic Pool[T]
  services/                 Pipeline orchestrator
  reporters/                HTML + JSON reporters
data/                       recon.db (gitignored)
scan_results/               Raw nmap XML, httpx JSONL, eyewitness dirs
reports/                    Generated HTML + JSON reports
screenshots/                Permanent screenshot copies
```

## Adding a Scanner

1. Create `internal/scanners/yourscanner/yourscanner.go`
2. Implement `Name() string` and `Run(ctx context.Context, scanID int64) error`
3. Inject `*config.Config` and `*repository.Store` via constructor
4. Append to scanner slice in `internal/services/pipeline.go`
