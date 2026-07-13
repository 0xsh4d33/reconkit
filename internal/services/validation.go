package services

import (
	"log"
	"net"
	"regexp"
	"strings"

	"github.com/blackfly/reconkit/internal/models"
)

var validHostname = regexp.MustCompile(
	`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`,
)

func IsValidHostname(s string) bool {
	return len(s) <= 253 && validHostname.MatchString(s)
}

func SanitizeTargets(t Targets) Targets {
	out := Targets{Profile: t.Profile}

	for _, d := range t.Domains {
		d = normalizeHostname(d)
		if ip := net.ParseIP(d); ip != nil {
			out.CIDRs = append(out.CIDRs, ip.String())
		} else if IsValidHostname(d) {
			out.Domains = append(out.Domains, d)
		} else {
			log.Printf("[input] rejected invalid domain: %q", d)
		}
	}

	for _, s := range t.Subdomains {
		s = normalizeHostname(s)
		if ip := net.ParseIP(s); ip != nil {
			out.CIDRs = append(out.CIDRs, ip.String())
		} else if IsValidHostname(s) {
			out.Subdomains = append(out.Subdomains, s)
		} else {
			log.Printf("[input] rejected invalid subdomain: %q", s)
		}
	}

	for _, c := range t.CIDRs {
		if normalized, ok := normalizeCIDROrIP(c); ok {
			out.CIDRs = append(out.CIDRs, normalized)
		} else {
			log.Printf("[input] rejected invalid CIDR/IP: %q", c)
		}
	}

	out.Domains = dedupStrings(out.Domains)
	out.Subdomains = dedupStrings(out.Subdomains)
	out.CIDRs = dedupStrings(out.CIDRs)

	return out
}

func ScanTargetsFromTargets(t Targets) []models.ScanTarget {
	var targets []models.ScanTarget
	seen := map[string]bool{}

	for _, domain := range t.Domains {
		domain = normalizeHostname(domain)
		if domain == "" || net.ParseIP(domain) != nil || !IsValidHostname(domain) {
			continue
		}
		appendScanTarget(&targets, seen, models.TargetTypeDomain, domain)
	}

	for _, cidr := range t.CIDRs {
		normalized, ok := normalizeCIDROrIP(cidr)
		if !ok {
			continue
		}
		targetType := models.TargetTypeCIDR
		if net.ParseIP(normalized) != nil {
			targetType = models.TargetTypeIP
		}
		appendScanTarget(&targets, seen, targetType, normalized)
	}

	return targets
}

func appendScanTarget(targets *[]models.ScanTarget, seen map[string]bool, targetType models.TargetType, value string) {
	key := string(targetType) + ":" + value
	if seen[key] {
		return
	}
	seen[key] = true
	*targets = append(*targets, models.ScanTarget{
		TargetType: targetType,
		Value:      value,
	})
}

func normalizeHostname(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func normalizeCIDROrIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true
	}
	if ip, network, err := net.ParseCIDR(s); err == nil {
		network.IP = ip.Mask(network.Mask)
		return network.String(), true
	}
	return "", false
}

func dedupStrings(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
