package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database   DatabaseConfig   `yaml:"database"`
	Workers    WorkersConfig    `yaml:"workers"`
	Nmap       NmapConfig       `yaml:"nmap"`
	HTTPx      HTTPxConfig      `yaml:"httpx"`
	EyeWitness EyeWitnessConfig `yaml:"eyewitness"`
	Subfinder  SubfinderConfig  `yaml:"subfinder"`
	Paths      PathsConfig      `yaml:"paths"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type WorkersConfig struct {
	Discovery  int `yaml:"discovery"`
	Nmap       int `yaml:"nmap"`
	HTTPx      int `yaml:"httpx"`
	EyeWitness int `yaml:"eyewitness"`
}

type NmapConfig struct {
	Arguments []string `yaml:"arguments"`
}

type HTTPxConfig struct {
	Threads int   `yaml:"threads"`
	Ports   []int `yaml:"ports"`
}

type EyeWitnessConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Python  string `yaml:"python"`
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
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
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
	if c.Workers.Nmap == 0 {
		c.Workers.Nmap = 10
	}
	if c.Workers.HTTPx == 0 {
		c.Workers.HTTPx = 50
	}
	if c.Workers.EyeWitness == 0 {
		c.Workers.EyeWitness = 5
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
	if c.EyeWitness.Python == "" {
		c.EyeWitness.Python = "eyewitness-venv/bin/python"
	}
}
