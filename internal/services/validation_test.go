package services

import (
	"testing"

	"github.com/blackfly/reconkit/internal/models"
)

func TestSanitizeTargetsMovesBareIPsToCIDRs(t *testing.T) {
	targets := SanitizeTargets(Targets{
		Domains:    []string{"Example.COM.", "192.168.1.1"},
		Subdomains: []string{"API.Example.COM.", "10.0.0.5"},
		CIDRs:      []string{"172.16.1.12/24", "bad cidr"},
	})

	if got, want := targets.Domains, []string{"example.com"}; !sameStrings(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
	if got, want := targets.Subdomains, []string{"api.example.com"}; !sameStrings(got, want) {
		t.Fatalf("subdomains = %v, want %v", got, want)
	}
	if got, want := targets.CIDRs, []string{"192.168.1.1", "10.0.0.5", "172.16.1.0/24"}; !sameStrings(got, want) {
		t.Fatalf("cidrs = %v, want %v", got, want)
	}
}

func TestScanTargetsFromTargetsTracksDomainsCIDRsAndIPs(t *testing.T) {
	targets := ScanTargetsFromTargets(SanitizeTargets(Targets{
		Domains:    []string{"Example.COM", "192.168.1.1"},
		Subdomains: []string{"api.example.com"},
		CIDRs:      []string{"10.0.0.1", "172.16.1.12/24"},
	}))

	want := []models.ScanTarget{
		{TargetType: models.TargetTypeDomain, Value: "example.com"},
		{TargetType: models.TargetTypeIP, Value: "192.168.1.1"},
		{TargetType: models.TargetTypeIP, Value: "10.0.0.1"},
		{TargetType: models.TargetTypeCIDR, Value: "172.16.1.0/24"},
	}

	if len(targets) != len(want) {
		t.Fatalf("target count = %d, want %d: %v", len(targets), len(want), targets)
	}
	for i := range want {
		if targets[i].TargetType != want[i].TargetType || targets[i].Value != want[i].Value {
			t.Fatalf("target[%d] = %s/%s, want %s/%s", i, targets[i].TargetType, targets[i].Value, want[i].TargetType, want[i].Value)
		}
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
