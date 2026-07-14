# ReconKit

Modular external recon pipeline for bug bounty and penetration testing.
Discovers subdomains, resolves IPs, port-scans, probes HTTP, screenshots web services,
tracks target history, and generates reports — all stored in SQLite so every scan is auditable.

Single binary, two modes:

| Mode | Use case |
|------|---------|
| **CLI** | Scripted scans, CI pipelines, headless Docker, automation |
| **Web** | Interactive use, live progress, target history, asset browser, diff viewer |

---

## Quick Start — Docker (web UI)

Docker is designed for the **web interface only**. It bundles all tools (nmap, httpx, subfinder, dnsx, dig/dnsutils, Chromium) so you don't install anything on the host.

```bash
# Build the image (~1.5 GB, first time takes a few minutes)
docker compose build

# Start the web UI
docker compose up -d

# Open http://127.0.0.1:8080
# Submit scans, watch live progress, browse assets, compare scans.

# Stop
docker compose down
```

Scan data, results, and screenshots persist in named Docker volumes across restarts.

For CLI usage — build the native binary instead (see below). Running `docker compose run` for every scan is unnecessary overhead.

---

## Quick Start — CLI (native binary)

Requires nmap, httpx, subfinder, dnsx, and dig on PATH.

```bash
go build -o recon ./cmd/recon/
cp config.example.yaml config.yaml

# CLI
./recon scan -targets targets.yaml -profile full
./recon scan -domains example.com
./recon scan -subdomains subdomains.txt
./recon scan -cidrs 10.0.0.0/24

# Web
./recon web                      # http://127.0.0.1:8080
./recon web -addr 0.0.0.0:9090   # custom bind address
./recon web -debug               # verbose pipeline logging
```

---

## Commands

| Command | Description |
|---------|-------------|
| `scan`   | Run full recon pipeline against targets |
| `report` | Regenerate HTML+JSON reports from DB |
| `diff`   | Compare two scans, show new/disappeared assets |
| `scans`  | List all recorded scans |
| `web`    | Start web interface (default: http://127.0.0.1:8080) |

```bash
./recon scan   -targets targets.yaml -profile full
./recon report -scan-id 3
./recon diff   -scan-id1 2 -scan-id2 3
./recon scans
./recon web    -addr 127.0.0.1:8080
./recon web    -debug
```

---

## Web Interface

Start with `./recon web` then open `http://127.0.0.1:8080`.

**Pages:**
- `/targets` — tracked submitted targets with first/last scan metadata, duration, profile, asset counts, ports, and web service counts
- `/targets/{id}` — target detail with matching assets, resolved DNS names, open ports, web services, and technology counts
- `/scans` — scan list + new scan form with per-scan tool config
- `/scans/{id}` — scan detail with live SSE progress, phase stepper, asset table
- `/scans/{id}/assets/{aid}` — asset detail: ports, web services, screenshots, findings
- `/diff` — compare two scans, see new/disappeared assets, new ports and services

**JSON API:**
```
GET  /api/scans              list all scans
GET  /api/scans/{id}         scan status + stats
GET  /api/scans/{id}/events  SSE stream (live scan events)
POST /api/scans/{id}/cancel  cancel running scan
```

Per-scan overrides available in the form: nmap arguments, httpx threads/ports,
and enable/disable controls for nmap and httpx.

---

## Targets File

```yaml
# targets.yaml
targets:
  domains:
    - example.com        # subfinder enumerates subdomains
  subdomains:
    - api.example.com    # pre-enumerated, skips subfinder
    - admin.example.com
  cidrs:
    - 10.0.0.0/24        # expands to IPs + reverse DNS
```

---

## Config Reference

```yaml
database:
  path: ./data/recon.db

workers:
  discovery: 20

nmap:
  arguments: ["-sV", "--open", "-T4"]

httpx:
  threads: 50
  ports: [80, 443, 8080, 8443, 8000, 8888]

subfinder:
  enabled: true

paths:
  scan_results: ./scan_results
  screenshots:  ./screenshots
  reports:      ./reports

web:
  host: "127.0.0.1"   # bind address for web mode
  port: 8080
```

---

## Tool Requirements (native)

| Tool | Install |
|------|---------|
| `nmap` | `apt install nmap` / `brew install nmap` |
| `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `dnsx` | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `dig` | `apt install dnsutils` / `brew install bind` |

Docker handles all of the above automatically.

---

## Pipeline

```
Domains    → subfinder → subdomains
Subdomains → dnsx      → IP resolution
CIDRs/IPs  → expand    → reverse DNS via dig
                ↓
       link submitted targets + insert assets (SQLite)
                ↓
       nmap  (batch scan over IP assets)
                ↓
       httpx (batch HTTP probe, screenshots, tech detect)
                ↓
       HTML + JSON reports from DB
```

For domain and subdomain assets, httpx probes the configured `httpx.ports`. For IP assets, httpx probes open ports found by nmap.

---

## Project Structure

```
cmd/recon/               — CLI entrypoint (scan, report, diff, scans, web)
internal/
  config/                — YAML config loader + defaults
  models/                — Asset, Port, WebService, Screenshot, Finding, Scan, ScanTarget
  database/              — SQLite + WAL mode + embedded migrations
  repository/            — DB CRUD, target history, stats, diff queries
  discovery/             — subfinder, dnsx, rdns, CIDR expander
  scanners/              — nmap, httpx (Scanner interface)
  services/              — Pipeline orchestrator + input validation
  workers/               — Generic concurrency pool
  reporters/             — HTML + JSON report generators
  web/                   — HTTP server, SSE broadcaster, scan manager, templates
data/                    — recon.db (gitignored)
scan_results/            — raw nmap XML, httpx JSONL
reports/                 — generated HTML + JSON reports
screenshots/             — httpx screenshots
Dockerfile               — multi-stage image (all tools bundled)
docker-compose.yml       — web service with persistent volumes
config.docker.yaml       — config baked into Docker image
```

---

## Adding a Scanner

1. Create `internal/scanners/myscanner/myscanner.go`
2. Implement `Name() string` and `Run(ctx context.Context, scanID int64) error`
3. Inject `*config.Config` and `*repository.Store` via constructor
4. Pass to `services.NewPipeline(cfg, store, ..., myscanner.New(cfg, store))`
