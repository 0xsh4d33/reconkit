# ReconKit

Modular Go recon pipeline for bug bounty and pentest. Single binary, SQLite persistence, HTML/JSON reports generated from DB.

## Quick Start (Docker — recommended)

Docker bundles every tool (nmap, httpx, subfinder, dnsx, EyeWitness + Chromium) so there is nothing to install manually.

```bash
# Build the image (~1.5 GB, takes a few minutes first time)
docker compose build

# Run a scan
docker compose run --rm reconkit scan -domains example.com
docker compose run --rm reconkit scan -targets targets.yaml -profile full

# Re-generate reports
docker compose run --rm reconkit report

# Compare two scans
docker compose run --rm reconkit diff -scan-id1 1 -scan-id2 2

# List recorded scans
docker compose run --rm reconkit scans
```

Scan data, results and reports are stored in named Docker volumes and persist across runs.

### Custom config

The image ships with `config.docker.yaml` pre-baked at `/etc/reconkit/config.yaml`.
To use your own config mount it over that path:

```yaml
# docker-compose.yml — uncomment the bind-mount line
volumes:
  - ./config.yaml:/etc/reconkit/config.yaml:ro
```

## Quick Start (native build)

Requires nmap, httpx, subfinder, dnsx, and optionally EyeWitness installed on the host.

```bash
# Build
go build -o recon ./cmd/recon/

# Config
cp config.example.yaml config.yaml

# Run
./recon scan -config config.yaml -targets targets.yaml
./recon scan -config config.yaml -domains example.com
./recon scan -config config.yaml -subdomains subdomains.txt -profile recheck
./recon scan -config config.yaml -cidrs 10.0.0.0/24
```

Reports are written to `reports/html/scan_N/index.html` and `reports/json/scan_N.json`.

## Commands

| Command | Description |
|---------|-------------|
| `scan`   | Run full pipeline against targets |
| `report` | Re-generate reports from DB |
| `diff`   | Compare two scans |
| `scans`  | List all recorded scans |

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
  python: /path/to/EyeWitness/eyewitness-venv/bin/python
```

## Tool Requirements (native only)

When running natively the following tools must be on `PATH` (or configured with full paths in `config.yaml`):

| Tool | Install |
|------|---------|
| `nmap` | `apt install nmap` |
| `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `dnsx` | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| EyeWitness | [RedSiege/EyeWitness](https://github.com/RedSiege/EyeWitness) — config-driven |

Docker handles all of the above automatically.

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
   httpx (batch, non-IP assets + IPs with open ports)
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
Dockerfile                  Multi-stage image (builder + tools + final)
docker-compose.yml          Volume mounts + nmap capabilities
config.docker.yaml          Default config baked into the Docker image
```

## Adding a Scanner

1. Create `internal/scanners/yourscanner/yourscanner.go`
2. Implement `Name() string` and `Run(ctx context.Context, scanID int64) error`
3. Inject `*config.Config` and `*repository.Store` via constructor
4. Append to the scanner slice in `internal/services/pipeline.go`
