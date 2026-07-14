package reporters

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/blackfly/reconkit/internal/repository"
)

type TargetHTMLReporter struct {
	store     *repository.Store
	outputDir string
}

func NewTargetHTMLReporter(store *repository.Store, outputDir string) *TargetHTMLReporter {
	return &TargetHTMLReporter{store: store, outputDir: outputDir}
}

type targetReportView struct {
	Title       string
	GeneratedAt string
	Report      *repository.TargetServiceReport
	OutputPath  string
}

func (r *TargetHTMLReporter) Generate(targetID int64) (string, error) {
	report, err := r.store.GetTargetServiceReport(targetID)
	if err != nil {
		return "", fmt.Errorf("target html report: get target report: %w", err)
	}

	ts := time.Now().UTC().Format("20060102_150405")
	relPath := filepath.Join("html", "targets", fmt.Sprintf("target_%d_%s", targetID, ts), "index.html")
	outPath := filepath.Join(r.outputDir, relPath)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		return "", err
	}

	view := targetReportView{
		Title:       report.Target.Value,
		GeneratedAt: time.Now().Format("02.01.2006 15:04"),
		Report:      report,
		OutputPath:  relPath,
	}

	tpl, err := template.New("target-report").Funcs(template.FuncMap{
		"date": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("02.01.2006")
		},
	}).Parse(targetReportTpl)
	if err != nil {
		return "", err
	}

	f, err := os.Create(outPath) // #nosec G304 -- path is assembled from configured reports output dir
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := tpl.Execute(f, view); err != nil {
		return "", err
	}

	return relPath, nil
}

const targetReportTpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconKit Target Report - {{.Title}}</title>
<style>
:root{--bg:#0a0a0a;--panel:#111;--line:#2a2a2a;--line2:#353535;--text:#b8b8b8;--muted:#666;--hi:#e6e6e6;--green:#00c853;--amber:#ffab00;--mono:"JetBrains Mono","Fira Code","Cascadia Code",monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:13px/1.55 var(--mono)}
.topbar{height:48px;border-bottom:1px solid var(--line);background:var(--panel);display:flex;align-items:center;padding:0 24px;gap:22px;position:sticky;top:0;z-index:2}
.brand{color:var(--green);font-weight:700;letter-spacing:2px}.brand span{color:var(--muted)}.topbar .meta{margin-left:auto;color:var(--muted);font-size:11px}
.shell{max-width:1180px;margin:0 auto;padding:28px 24px 42px}
.head{display:grid;grid-template-columns:1fr;gap:20px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:20px}
.kicker{color:var(--green);font-size:10px;letter-spacing:2px;text-transform:uppercase}
h1{margin:4px 0 0;color:var(--hi);font-size:24px;letter-spacing:.2px}.sub{color:var(--muted);font-size:12px;margin-top:4px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);margin-bottom:18px}
.stat{background:var(--panel);padding:15px 16px;min-width:0}.stat .n{font-size:26px;line-height:1;color:var(--green);font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.stat .l{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1.4px;margin-top:5px}
.card{border:1px solid var(--line);background:var(--panel)}.card-h{border-bottom:1px solid var(--line);padding:9px 13px;display:flex;gap:8px;align-items:center;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:1.5px}.card-h strong{color:var(--hi);font-weight:600}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse}th{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:1.3px;text-align:left;font-weight:400;border-bottom:1px solid var(--line2);padding:9px 12px;white-space:nowrap}td{border-bottom:1px solid var(--line);padding:10px 12px;vertical-align:middle}tr:last-child td{border-bottom:0}
td:nth-child(1),td:nth-child(2),td:nth-child(4){color:var(--hi)}td:nth-child(3),td:nth-child(5),td:nth-child(6){font-variant-numeric:tabular-nums}
.empty{text-align:center;padding:34px;color:var(--muted)}
@media(max-width:780px){.stats-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:520px){.stats-grid{grid-template-columns:1fr}.topbar{padding:0 14px}.shell{padding:20px 14px}}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">RECON<span>/</span>KIT</div>
  <div class="meta">target report generated {{.GeneratedAt}}</div>
</div>
<main class="shell">
  <section class="head">
    <div>
      <div class="kicker">target scan report</div>
      <h1>{{.Report.Target.Value}}</h1>
      <div class="sub">target type: {{.Report.Target.TargetType}}{{if .Report.Scan}} · scan #{{.Report.Scan.ID}} · profile {{.Report.Scan.Profile}} · status {{.Report.Scan.Status}}{{end}}</div>
    </div>
  </section>
  <section class="stats-grid" aria-label="target summary">
    <div class="stat"><div class="n">{{.Report.AssetCount}}</div><div class="l">assets scanned</div></div>
    <div class="stat"><div class="n">{{.Report.ResolvedDNSCount}}</div><div class="l">resolved dns names</div></div>
    <div class="stat"><div class="n">{{.Report.OpenPortCount}}</div><div class="l">open ports</div></div>
    <div class="stat"><div class="n">{{.Report.WebServiceCount}}</div><div class="l">web services</div></div>
  </section>
  <section class="card">
    <div class="card-h"><strong>services</strong><span>one row per detected service</span></div>
    <div class="table-wrap">
      {{if .Report.Rows}}
      <table>
        <thead>
          <tr><th>DNS</th><th>IP</th><th>Port</th><th>Server / Technology</th><th>Version</th><th>Last Scan</th></tr>
        </thead>
        <tbody>
          {{range .Report.Rows}}
          <tr><td>{{.DNS}}</td><td>{{.IP}}</td><td>{{.Port}}</td><td>{{.ServerTechnology}}</td><td>{{.Version}}</td><td>{{date .LastScan}}</td></tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <div class="empty">no web services found for this target</div>
      {{end}}
    </div>
  </section>
</main>
</body>
</html>`
