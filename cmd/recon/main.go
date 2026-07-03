package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/blackfly/reconkit/internal/config"
	"github.com/blackfly/reconkit/internal/database"
	"github.com/blackfly/reconkit/internal/reporters"
	"github.com/blackfly/reconkit/internal/repository"
	"github.com/blackfly/reconkit/internal/services"
	"github.com/blackfly/reconkit/internal/web"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath    = "config.yaml"
	defaultConfigPathMsg = "path to config.yaml"
)

const usage = `Usage: recon <command> [flags]

Modes:
  CLI  — run scans from the terminal, generate reports, compare scans
  Web  — HTTP server with UI, live scan progress, asset browser, diff viewer

Commands:
  scan    Run a full recon pipeline against targets
  report  Generate HTML/JSON reports from the database
  diff    Compare two scans and show changes
  scans   List all recorded scans
  web     Start the web interface (default: http://127.0.0.1:8080)

Flags common to all commands:
  -config string   Path to config.yaml (default: config.yaml)

Run 'recon <command> -h' for command-specific flags.
`

func main() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)

	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "diff":
		cmdDiff(os.Args[2:])
	case "scans":
		cmdScans(os.Args[2:])
	case "web":
		cmdWeb(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

// ── scan ──────────────────────────────────────────────────────────────────────

type targetsFile struct {
	Targets struct {
		Domains    []string `yaml:"domains"`
		Subdomains []string `yaml:"subdomains"`
		CIDRs      []string `yaml:"cidrs"`
	} `yaml:"targets"`
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath, defaultConfigPathMsg)
	targetsPath := fs.String("targets", "", "path to targets.yaml")
	domainsFlag := fs.String("domains", "", "comma-separated domains (or @file.txt)")
	subdomainsFlag := fs.String("subdomains", "", "pre-enumerated subdomains file")
	cidrsFlag := fs.String("cidrs", "", "comma-separated CIDR ranges (or @file.txt)")
	profileFlag := fs.String("profile", "default", "scan profile label")
	reportFlag := fs.Bool("report", true, "generate HTML+JSON report after scan")
	debugFlag := fs.Bool("debug", false, "enable verbose pipeline logging")
	_ = fs.Parse(args)

	cfg := mustLoadConfig(*cfgPath)
	cfg.Debug = *debugFlag

	var targets services.Targets
	targets.Profile = *profileFlag

	// Load from targets file
	if *targetsPath != "" {
		tf := mustLoadTargets(*targetsPath)
		targets.Domains = append(targets.Domains, tf.Targets.Domains...)
		targets.Subdomains = append(targets.Subdomains, tf.Targets.Subdomains...)
		targets.CIDRs = append(targets.CIDRs, tf.Targets.CIDRs...)
	}

	// CLI overrides / additions
	if *domainsFlag != "" {
		targets.Domains = append(targets.Domains, parseListFlag(*domainsFlag)...)
	}
	if *subdomainsFlag != "" {
		targets.Subdomains = append(targets.Subdomains, mustReadLines(*subdomainsFlag)...)
	}
	if *cidrsFlag != "" {
		targets.CIDRs = append(targets.CIDRs, parseListFlag(*cidrsFlag)...)
	}

	targets = services.SanitizeTargets(targets)

	if len(targets.Domains)+len(targets.Subdomains)+len(targets.CIDRs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no targets specified (use -targets, -domains, or -cidrs)")
		os.Exit(1)
	}

	db := mustOpenDB(cfg.Database.Path)
	defer db.Close()
	store := repository.New(db)
	pipeline := services.NewPipeline(cfg, store)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	scanID, err := pipeline.Run(ctx, targets)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	if *reportFlag {
		htmlR := reporters.NewHTMLReporter(store, cfg.Paths.Reports)
		jsonR := reporters.NewJSONReporter(store, cfg.Paths.Reports)
		if err := htmlR.Generate(scanID); err != nil {
			log.Printf("html report: %v", err)
		}
		if err := jsonR.Generate(scanID); err != nil {
			log.Printf("json report: %v", err)
		}
	}
}

// ── report ────────────────────────────────────────────────────────────────────

func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath, defaultConfigPathMsg)
	scanIDFlag := fs.Int64("scan-id", 0, "scan ID to report (0 = latest)")
	_ = fs.Parse(args)

	cfg := mustLoadConfig(*cfgPath)
	db := mustOpenDB(cfg.Database.Path)
	defer db.Close()
	store := repository.New(db)

	scanID := *scanIDFlag
	if scanID == 0 {
		scan, err := store.GetLatestScan()
		if err != nil {
			log.Fatalf("get latest scan: %v", err)
		}
		scanID = scan.ID
		log.Printf("using latest scan: #%d", scanID)
	}

	htmlR := reporters.NewHTMLReporter(store, cfg.Paths.Reports)
	jsonR := reporters.NewJSONReporter(store, cfg.Paths.Reports)

	if err := htmlR.Generate(scanID); err != nil {
		log.Printf("html report: %v", err)
	}
	if err := jsonR.Generate(scanID); err != nil {
		log.Printf("json report: %v", err)
	}
}

// ── diff ──────────────────────────────────────────────────────────────────────

func cmdDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath, defaultConfigPathMsg)
	id1 := fs.Int64("scan-id1", 0, "baseline scan ID")
	id2 := fs.Int64("scan-id2", 0, "comparison scan ID")
	_ = fs.Parse(args)

	if *id1 == 0 || *id2 == 0 {
		fmt.Fprintln(os.Stderr, "error: both -scan-id1 and -scan-id2 required")
		os.Exit(1)
	}

	cfg := mustLoadConfig(*cfgPath)
	db := mustOpenDB(cfg.Database.Path)
	defer db.Close()
	store := repository.New(db)

	diff, err := store.Diff(*id1, *id2)
	if err != nil {
		log.Fatalf("diff: %v", err)
	}

	fmt.Printf("\nScan diff: #%d → #%d\n\n", *id1, *id2)

	fmt.Printf("New assets (%d):\n", len(diff.NewAssets))
	for _, a := range diff.NewAssets {
		fmt.Printf("  + [%s] %s  %s\n", a.AssetType, a.Name, a.IP)
	}

	fmt.Printf("\nDisappeared assets (%d):\n", len(diff.DisappearedAssets))
	for _, a := range diff.DisappearedAssets {
		fmt.Printf("  - [%s] %s  %s\n", a.AssetType, a.Name, a.IP)
	}
}

// ── scans ─────────────────────────────────────────────────────────────────────

func cmdScans(args []string) {
	fs := flag.NewFlagSet("scans", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath, defaultConfigPathMsg)
	_ = fs.Parse(args)

	cfg := mustLoadConfig(*cfgPath)
	db := mustOpenDB(cfg.Database.Path)
	defer db.Close()
	store := repository.New(db)

	scans, err := store.ListScans()
	if err != nil {
		log.Fatalf("list scans: %v", err)
	}

	fmt.Printf("%-6s  %-20s  %-20s  %-10s  %s\n", "ID", "Started", "Finished", "Status", "Profile")
	fmt.Println(strings.Repeat("-", 72))
	for _, s := range scans {
		finished := ""
		if s.FinishedAt != nil {
			finished = s.FinishedAt.Format("2006-01-02 15:04:05")
		}
		fmt.Printf("%-6d  %-20s  %-20s  %-10s  %s\n",
			s.ID,
			s.StartedAt.Format("2006-01-02 15:04:05"),
			finished,
			s.Status,
			s.Profile,
		)
	}
}

// ── web ───────────────────────────────────────────────────────────────────────

func cmdWeb(args []string) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath, defaultConfigPathMsg)
	addrFlag := fs.String("addr", "", "override listen address (e.g. 0.0.0.0:9090)")
	_ = fs.Parse(args)

	cfg := mustLoadConfig(*cfgPath)
	if *addrFlag != "" {
		// parse host:port override
		parts := strings.SplitN(*addrFlag, ":", 2)
		if len(parts) == 2 {
			cfg.Web.Host = parts[0]
			fmt.Sscanf(parts[1], "%d", &cfg.Web.Port)
		}
	}

	db := mustOpenDB(cfg.Database.Path)
	defer db.Close()
	store := repository.New(db)

	srv, err := web.New(cfg, store)
	if err != nil {
		log.Fatalf("web: init server: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("[web] listening on http://%s:%d", cfg.Web.Host, cfg.Web.Port)
	if err := srv.Start(ctx); err != nil {
		log.Fatalf("web: %v", err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mustLoadConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("load config %q: %v", path, err)
	}
	return cfg
}

func mustOpenDB(path string) *database.DB {
	db, err := database.Open(path)
	if err != nil {
		log.Fatalf("open database %q: %v", path, err)
	}
	return db
}

func mustLoadTargets(path string) *targetsFile {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a CLI argument, expected for a CLI tool
	if err != nil {
		log.Fatalf("read targets %q: %v", path, err)
	}
	var tf targetsFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		log.Fatalf("parse targets %q: %v", path, err)
	}
	return &tf
}

// parseListFlag handles "a,b,c" or "@file.txt" (one entry per line).
func parseListFlag(s string) []string {
	if strings.HasPrefix(s, "@") {
		return mustReadLines(s[1:])
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func mustReadLines(path string) []string {
	f, err := os.Open(path) // #nosec G304 -- path is a CLI argument, expected for a CLI tool
	if err != nil {
		log.Fatalf("open file %q: %v", path, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

