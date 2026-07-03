package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/blackfly/reconkit/internal/config"
	"github.com/blackfly/reconkit/internal/repository"
)

//go:embed templates/*.html
var templateFS embed.FS

// Server is the ReconKit web interface.
type Server struct {
	cfg         *config.Config
	store       *repository.Store
	scanManager *ScanManager
	tpl         *template.Template
	httpSrv     *http.Server
}

// New creates and initialises a new Server.
func New(cfg *config.Config, store *repository.Store) (*Server, error) {
	// Parse only base.html into the base template set.
	// Page templates are cloned from this base on each render so their
	// {{define "content"}} blocks don't overwrite each other.
	tpl, err := template.New("").Funcs(templateFuncs()).ParseFS(templateFS, "templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("parse base template: %w", err)
	}
	return &Server{
		cfg:         cfg,
		store:       store,
		scanManager: newScanManager(cfg, store),
		tpl:         tpl,
	}, nil
}

// Start registers routes, begins listening, and blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// UI
	mux.HandleFunc("GET /{$}", s.handleRedirect)
	mux.HandleFunc("GET /scans", s.handleListScans)
	mux.HandleFunc("POST /scans", s.handleSubmitScan)
	mux.HandleFunc("GET /scans/{id}", s.handleScanDetail)
	mux.HandleFunc("GET /scans/{id}/assets/{assetID}", s.handleAssetDetail)
	mux.HandleFunc("GET /diff", s.handleDiff)

	// API
	mux.HandleFunc("GET /api/scans", s.handleAPIListScans)
	mux.HandleFunc("GET /api/scans/{id}", s.handleAPIScanStatus)
	mux.HandleFunc("GET /api/scans/{id}/events", s.handleSSEStream)
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.handleCancelScan)

	// Static
	mux.Handle("GET /reports/", http.StripPrefix("/reports/",
		http.FileServer(http.Dir(s.cfg.Paths.Reports))))
	mux.Handle("GET /screenshots/", http.StripPrefix("/screenshots/",
		http.FileServer(http.Dir(s.cfg.Paths.Screenshots))))

	addr := fmt.Sprintf("%s:%d", s.cfg.Web.Host, s.cfg.Web.Port)
	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[web] listen error: %v", err)
		}
	}()

	<-ctx.Done()

	s.scanManager.CancelAll()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(shutdownCtx)
}

// ── Page base data ────────────────────────────────────────────────────────────

// pageBase holds fields required by base.html for every page.
type pageBase struct {
	Nav      string // active nav item: "scans" | "diff"
	NavBadge string // optional right-side badge text (e.g. "2 running")
}

func (s *Server) baseFor(nav string) pageBase {
	n := s.scanManager.RunningCount()
	badge := ""
	if n > 0 {
		if n == 1 {
			badge = "1 scan running"
		} else {
			badge = fmt.Sprintf("%d scans running", n)
		}
	}
	return pageBase{Nav: nav, NavBadge: badge}
}

// ── SSE helper ────────────────────────────────────────────────────────────────

func writeSSE(w http.ResponseWriter, event, data string) {
	// Escape newlines in data — SSE data field must be single-line per field.
	data = strings.ReplaceAll(data, "\n", " ")
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// ── Response helpers ──────────────────────────────────────────────────────────

type apiError struct {
	Error string `json:"error"`
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) renderTemplate(w http.ResponseWriter, page string, data any) {
	// Clone base so each page gets its own {{define "content"}} scope.
	t, err := s.tpl.Clone()
	if err != nil {
		log.Printf("[web] clone template: %v", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	// ParseFS names the template by the last path element (e.g. "scans.html").
	t, err = t.ParseFS(templateFS, "templates/"+page+".html")
	if err != nil {
		log.Printf("[web] parse template %q: %v", page, err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Execute the top-level content of the page file (named by its basename).
	if err := t.ExecuteTemplate(w, page+".html", data); err != nil {
		log.Printf("[web] execute template %q: %v", page, err)
	}
}

// ── Template functions ────────────────────────────────────────────────────────

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"add": func(a, b int) int { return a + b },

		"formatDuration": func(start, end *time.Time) string {
			if start == nil || end == nil {
				return "—"
			}
			d := end.Sub(*start).Round(time.Second)
			if d < time.Minute {
				return fmt.Sprintf("%ds", int(d.Seconds()))
			}
			if d < time.Hour {
				return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
			}
			return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
		},

		"statusClass": func(status any) string {
			switch fmt.Sprintf("%v", status) {
			case "running":
				return "badge-running"
			case "done":
				return "badge-done"
			case "failed":
				return "badge-failed"
			case "canceled":
				return "badge-unknown"
			default:
				return "badge-unknown"
			}
		},

		"statusIcon": func(status any) string {
			switch fmt.Sprintf("%v", status) {
			case "running":
				return "⬤"
			case "done":
				return "✓"
			case "failed":
				return "✗"
			case "canceled":
				return "⊘"
			default:
				return "?"
			}
		},

		"joinInts": func(ints []int) string {
			parts := make([]string, len(ints))
			for i, n := range ints {
				parts[i] = fmt.Sprintf("%d", n)
			}
			return strings.Join(parts, ", ")
		},

		"joinStrings": func(ss []string) string {
			return strings.Join(ss, " ")
		},

		"splitTech": func(s string) []string {
			if s == "" {
				return nil
			}
			var parts []string
			for _, p := range strings.Split(s, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					parts = append(parts, p)
				}
			}
			return parts
		},

		"lower": strings.ToLower,

		"safeHTML": func(s string) template.HTML {
			return template.HTML(s) // #nosec G203 — only used for trusted internal strings
		},
	}
}
