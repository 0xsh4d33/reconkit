package nmap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blackfly/reconkit/internal/models"
)

func TestParseXMLBatch(t *testing.T) {
	// Use existing XML file from old per-IP scan
	xmlPath := filepath.Join("../../../scan_results/nmap", "192.168.1.94_20260707_120449_15657.xml")
	if _, err := os.Stat(xmlPath); os.IsNotExist(err) {
		t.Skip("test XML file not found")
	}

	portsByIP, err := parseXMLBatch(xmlPath)
	if err != nil {
		t.Fatalf("parseXMLBatch failed: %v", err)
	}

	// Should find 192.168.1.94 with port 80 open
	ports, exists := portsByIP["192.168.1.94"]
	if !exists {
		t.Fatalf("expected IP 192.168.1.94 not found in results. Got keys: %v", mapKeys(portsByIP))
	}

	if len(ports) != 1 {
		t.Fatalf("expected 1 open port, got %d: %v", len(ports), ports)
	}

	p := ports[0]
	if p.Port != 80 {
		t.Errorf("expected port 80, got %d", p.Port)
	}
	if p.Service != "http" {
		t.Errorf("expected service 'http', got %q", p.Service)
	}
	if p.State != "open" {
		t.Errorf("expected state 'open', got %q", p.State)
	}
}

func mapKeys(m map[string][]models.Port) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
