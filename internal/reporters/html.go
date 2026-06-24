package reporters

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blackfly/reconkit/internal/models"
	"github.com/blackfly/reconkit/internal/repository"
)

type HTMLReporter struct {
	store     *repository.Store
	outputDir string
}

func NewHTMLReporter(store *repository.Store, outputDir string) *HTMLReporter {
	return &HTMLReporter{store: store, outputDir: outputDir}
}

// ── View models ───────────────────────────────────────────────────────────────

type dashboardView struct {
	ScanID      int64
	Profile     string
	StartedAt   string
	FinishedAt  string
	Stats       *repository.ScanStats
	Assets      []assetRow
	GeneratedAt string
}

type assetRow struct {
	Asset    models.Asset
	PortCnt  int
	SvcCnt   int
	FindCnt  int
	TopPorts string
}

type assetDetailView struct {
	Asset       models.Asset
	Ports       []models.Port
	WebServices []wsView
	Screenshots []models.Screenshot
	Findings    []models.Finding
	ScanID      int64
	GeneratedAt string
}

type wsView struct {
	models.WebService
	TechList []string
}

// ── Generate ──────────────────────────────────────────────────────────────────

func (r *HTMLReporter) Generate(scanID int64) error {
	scan, err := r.store.GetScan(scanID)
	if err != nil {
		return fmt.Errorf("html report: get scan: %w", err)
	}

	dir := filepath.Join(r.outputDir, "html", fmt.Sprintf("scan_%d", scanID))
	assetsDir := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		return err
	}

	stats, err := r.store.GetScanStats(scanID)
	if err != nil {
		return fmt.Errorf("html report: stats: %w", err)
	}

	dbAssets, err := r.store.GetAssetsByScan(scanID)
	if err != nil {
		return fmt.Errorf("html report: assets: %w", err)
	}

	// Build asset rows and detail pages
	var rows []assetRow
	for _, a := range dbAssets {
		ports, _ := r.store.GetPortsByAsset(a.ID)
		services, _ := r.store.GetWebServicesByAsset(a.ID)
		findings, _ := r.store.GetFindingsByAsset(a.ID)
		screenshots, _ := r.store.GetScreenshotsByAsset(a.ID)

		topPorts := make([]string, 0, 5)
		for i, p := range ports {
			if i >= 5 {
				break
			}
			topPorts = append(topPorts, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
		}

		rows = append(rows, assetRow{
			Asset:    a,
			PortCnt:  len(ports),
			SvcCnt:   len(services),
			FindCnt:  len(findings),
			TopPorts: strings.Join(topPorts, ", "),
		})

		// Copy screenshots into report dir, rewrite paths to relative
		ssDir := filepath.Join(assetsDir, "screenshots")
		localScreenshots := make([]models.Screenshot, 0, len(screenshots))
		for _, ss := range screenshots {
			if ss.FilePath == "" {
				continue
			}
			fname := filepath.Base(ss.FilePath)
			dest := filepath.Join(ssDir, fname)
			if err := copyFileReport(ss.FilePath, dest); err != nil {
				log.Printf("[html] copy screenshot %s: %v", ss.FilePath, err)
				continue
			}
			ss.FilePath = "screenshots/" + fname
			localScreenshots = append(localScreenshots, ss)
		}

		// Generate detail page
		wsViews := make([]wsView, len(services))
		for i, ws := range services {
			var techs []string
			_ = json.Unmarshal([]byte(ws.Technologies), &techs)
			wsViews[i] = wsView{WebService: ws, TechList: techs}
		}

		detail := assetDetailView{
			Asset:       a,
			Ports:       ports,
			WebServices: wsViews,
			Screenshots: localScreenshots,
			Findings:    findings,
			ScanID:      scanID,
			GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		}
		if err := renderTemplate(
			detailTpl,
			filepath.Join(assetsDir, fmt.Sprintf("%d.html", a.ID)),
			detail,
		); err != nil {
			log.Printf("[html] detail page asset %d: %v", a.ID, err)
		}
	}

	// Generate dashboard
	startedAt := scan.StartedAt.Format("2006-01-02 15:04:05")
	finishedAt := ""
	if scan.FinishedAt != nil {
		finishedAt = scan.FinishedAt.Format("2006-01-02 15:04:05")
	}

	dash := dashboardView{
		ScanID:      scanID,
		Profile:     scan.Profile,
		StartedAt:   startedAt,
		FinishedAt:  finishedAt,
		Stats:       stats,
		Assets:      rows,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	if err := renderTemplate(dashboardTpl, filepath.Join(dir, "index.html"), dash); err != nil {
		return fmt.Errorf("html dashboard: %w", err)
	}

	log.Printf("[html] report written: %s", filepath.Join(dir, "index.html"))
	return nil
}

func copyFileReport(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func renderTemplate(tplStr, path string, data any) error {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}).Parse(tplStr)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tpl.Execute(f, data)
}

// ── Templates ─────────────────────────────────────────────────────────────────

const sharedCSS = `
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:ui-sans-serif,system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}
h1{font-size:1.6rem;font-weight:700;margin-bottom:4px}
h2{font-size:1.1rem;font-weight:600;margin:20px 0 8px;color:#94a3b8}
h3{font-size:.95rem;font-weight:600;margin:16px 0 6px;color:#cbd5e1}
.meta{color:#64748b;font-size:.85rem;margin-bottom:20px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.stat{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px 20px;min-width:120px}
.stat-n{font-size:1.8rem;font-weight:700;color:#38bdf8}
.stat-l{font-size:.8rem;color:#64748b;margin-top:2px}
.search{margin-bottom:16px}
.search input{width:100%;max-width:480px;padding:9px 12px;border-radius:8px;border:1px solid #334155;background:#020617;color:#e2e8f0;font-size:.9rem}
table{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:16px}
th{background:#1e293b;padding:8px 10px;text-align:left;color:#94a3b8;font-weight:500;border-bottom:1px solid #334155;cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:#e2e8f0}
th.sort-asc::after{content:" ↑"}
th.sort-desc::after{content:" ↓"}
td{padding:8px 10px;border-bottom:1px solid #1e293b;vertical-align:top;word-break:break-word}
tr:hover td{background:#1e293b}
a{color:#38bdf8;text-decoration:none}
a:hover{text-decoration:underline}
.badge{display:inline-block;border-radius:999px;padding:2px 8px;font-size:.75rem;font-weight:500;margin:1px}
.badge-domain{background:#1e3a5f;color:#7dd3fc}
.badge-subdomain{background:#1a2e4a;color:#93c5fd}
.badge-ip{background:#1c2a1c;color:#86efac}
.badge-host{background:#2d1f3a;color:#c4b5fd}
.sev-critical{color:#f87171;font-weight:600}
.sev-high{color:#fb923c;font-weight:600}
.sev-medium{color:#fbbf24}
.sev-low{color:#a3e635}
.sev-info{color:#94a3b8}
.back{display:inline-block;margin-bottom:16px;padding:6px 14px;background:#1e293b;border-radius:8px;border:1px solid #334155;font-size:.85rem}
img.screenshot{max-width:100%;border-radius:8px;border:1px solid #334155;margin-top:8px}
</style>`

const dashboardTpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconKit — Scan #{{.ScanID}}</title>
` + sharedCSS + `
<script>
function filter(){
  const q=document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(r=>{
    r.style.display=r.innerText.toLowerCase().includes(q)?'':'none';
  });
}

let sortCol=-1,sortAsc=true;
function sortBy(col){
  const tb=document.querySelector('tbody');
  const rows=[...tb.querySelectorAll('tr')];
  const ths=[...document.querySelectorAll('thead th')];
  if(sortCol===col){sortAsc=!sortAsc;}else{sortCol=col;sortAsc=true;}
  ths.forEach((t,i)=>{t.classList.remove('sort-asc','sort-desc');if(i===col)t.classList.add(sortAsc?'sort-asc':'sort-desc');});
  rows.sort((a,b)=>{
    const av=a.children[col]?.innerText.trim()??'';
    const bv=b.children[col]?.innerText.trim()??'';
    const an=parseFloat(av),bn=parseFloat(bv);
    const cmp=(!isNaN(an)&&!isNaN(bn))?(an-bn):av.localeCompare(bv);
    return sortAsc?cmp:-cmp;
  });
  rows.forEach(r=>tb.appendChild(r));
}
</script>
</head>
<body>
<h1>ReconKit — Scan #{{.ScanID}}</h1>
<div class="meta">
  Profile: {{.Profile}} &nbsp;|&nbsp;
  Started: {{.StartedAt}}{{if .FinishedAt}} &nbsp;|&nbsp; Finished: {{.FinishedAt}}{{end}} &nbsp;|&nbsp;
  Generated: {{.GeneratedAt}}
</div>

<div class="stats">
  <div class="stat"><div class="stat-n">{{.Stats.TotalAssets}}</div><div class="stat-l">Assets</div></div>
  <div class="stat"><div class="stat-n">{{.Stats.TotalPorts}}</div><div class="stat-l">Open Ports</div></div>
  <div class="stat"><div class="stat-n">{{.Stats.TotalServices}}</div><div class="stat-l">Web Services</div></div>
  <div class="stat"><div class="stat-n">{{.Stats.TotalFindings}}</div><div class="stat-l">Findings</div></div>
</div>

<div class="search"><input id="q" onkeyup="filter()" placeholder="Search assets, IPs, ports…"></div>

<table>
<thead><tr>
  <th onclick="sortBy(0)">Asset</th>
  <th onclick="sortBy(1)">Type</th>
  <th onclick="sortBy(2)">IP</th>
  <th onclick="sortBy(3)">Top Ports</th>
  <th onclick="sortBy(4)">Web Services</th>
  <th onclick="sortBy(5)">Findings</th>
  <th onclick="sortBy(6)">Last Seen</th>
</tr></thead>
<tbody>
{{range .Assets}}
<tr>
  <td><a href="assets/{{.Asset.ID}}.html">{{.Asset.Name}}</a></td>
  <td><span class="badge badge-{{.Asset.AssetType}}">{{.Asset.AssetType}}</span></td>
  <td>{{.Asset.IP}}</td>
  <td>{{.TopPorts}}</td>
  <td>{{.SvcCnt}}</td>
  <td>{{.FindCnt}}</td>
  <td>{{.Asset.LastSeen.Format "2006-01-02 15:04"}}</td>
</tr>
{{end}}
</tbody>
</table>
</body>
</html>`

const detailTpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Asset.Name}} — ReconKit</title>
` + sharedCSS + `
</head>
<body>
<a class="back" href="../index.html">← Back to dashboard</a>
<h1>{{.Asset.Name}}</h1>
<div class="meta">
  <span class="badge badge-{{.Asset.AssetType}}">{{.Asset.AssetType}}</span>
  {{if .Asset.IP}} &nbsp; IP: {{.Asset.IP}}{{end}}
  {{if .Asset.Hostname}} &nbsp; Hostname: {{.Asset.Hostname}}{{end}}
  &nbsp;|&nbsp; First seen: {{.Asset.FirstSeen.Format "2006-01-02 15:04"}}
  &nbsp;|&nbsp; Last seen: {{.Asset.LastSeen.Format "2006-01-02 15:04"}}
</div>

{{if .Ports}}
<h2>Open Ports ({{len .Ports}})</h2>
<table>
<thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
<tbody>
{{range .Ports}}
<tr>
  <td>{{.Port}}</td>
  <td>{{.Protocol}}</td>
  <td>{{.Service}}</td>
  <td>{{.Product}}</td>
  <td>{{.Version}}</td>
</tr>
{{end}}
</tbody>
</table>
{{end}}

{{if .WebServices}}
<h2>Web Services ({{len .WebServices}})</h2>
<table>
<thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Technologies</th></tr></thead>
<tbody>
{{range .WebServices}}
<tr>
  <td><a href="{{.URL}}" target="_blank" rel="noopener">{{.URL}}</a></td>
  <td>{{.StatusCode}}</td>
  <td>{{.Title}}</td>
  <td>{{range .TechList}}<span class="badge" style="background:#1e293b;color:#cbd5e1">{{.}}</span> {{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{end}}

{{if .Screenshots}}
<h2>Screenshots</h2>
{{range .Screenshots}}
<div>
  <a href="{{.FilePath}}" target="_blank"><img class="screenshot" src="{{.FilePath}}" alt="screenshot" loading="lazy"></a>
</div>
{{end}}
{{end}}

{{if .Findings}}
<h2>Findings ({{len .Findings}})</h2>
{{range .Findings}}
<div style="margin-bottom:12px;padding:12px;background:#1e293b;border-radius:8px;border:1px solid #334155">
  <div class="sev-{{.Severity}}">{{.Severity}} — {{.Name}}</div>
  {{if .Category}}<div style="color:#64748b;font-size:.8rem">{{.Category}}</div>{{end}}
  {{if .Description}}<div style="margin-top:6px">{{.Description}}</div>{{end}}
  {{if .Evidence}}<pre style="margin-top:8px;padding:8px;background:#0f172a;border-radius:6px;font-size:.8rem;overflow-x:auto">{{.Evidence}}</pre>{{end}}
</div>
{{end}}
{{end}}

<div class="meta" style="margin-top:24px">Generated: {{.GeneratedAt}}</div>
</body>
</html>`
