package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database  DatabaseConfig  `yaml:"database"`
	Workers   WorkersConfig   `yaml:"workers"`
	Nmap      NmapConfig      `yaml:"nmap"`
	HTTPx     HTTPxConfig     `yaml:"httpx"`
	Subfinder SubfinderConfig `yaml:"subfinder"`
	Paths     PathsConfig     `yaml:"paths"`
	Web       WebConfig       `yaml:"web"`
	Debug     bool            `yaml:"-"` // set via CLI flag only, not config file
}

type WebConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type WorkersConfig struct {
	Discovery int `yaml:"discovery"`
}

type NmapConfig struct {
	Arguments []string `yaml:"arguments"`
}

type HTTPxConfig struct {
	Threads int   `yaml:"threads"`
	Ports   []int `yaml:"ports"`
}

type SubfinderConfig struct {
	Enabled bool `yaml:"enabled"`
}

type PathsConfig struct {
	ScanResults string `yaml:"scan_results"`
	Screenshots string `yaml:"screenshots"`
	Reports     string `yaml:"reports"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 -- path is a CLI argument, expected for a CLI tool
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil { //nolint:typecheck
		return nil, err
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Database.Path == "" {
		c.Database.Path = "./data/recon.db"
	}
	if c.Workers.Discovery == 0 {
		c.Workers.Discovery = 20
	}
	if c.Paths.ScanResults == "" {
		c.Paths.ScanResults = "./scan_results"
	}
	if c.Paths.Screenshots == "" {
		c.Paths.Screenshots = "./screenshots"
	}
	if c.Paths.Reports == "" {
		c.Paths.Reports = "./reports"
	}
	if len(c.Nmap.Arguments) == 0 {
		c.Nmap.Arguments = []string{"-sV", "--open"}
	}
	if len(c.HTTPx.Ports) == 0 {
		c.HTTPx.Ports = []int{80, 443, 8080, 8443, 8000, 8888}
	}
	if c.HTTPx.Threads == 0 {
		c.HTTPx.Threads = 50
	}
	if c.Web.Host == "" {
		c.Web.Host = "127.0.0.1"
	}
	if c.Web.Port == 0 {
		c.Web.Port = 8080
	}
}
