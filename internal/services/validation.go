package services

import (
	"log"
	"net"
	"regexp"
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
		if IsValidHostname(d) {
			out.Domains = append(out.Domains, d)
		} else {
			log.Printf("[input] rejected invalid domain: %q", d)
		}
	}

	for _, s := range t.Subdomains {
		if IsValidHostname(s) {
			out.Subdomains = append(out.Subdomains, s)
		} else {
			log.Printf("[input] rejected invalid subdomain: %q", s)
		}
	}

	for _, c := range t.CIDRs {
		if _, _, err := net.ParseCIDR(c); err == nil {
			out.CIDRs = append(out.CIDRs, c)
		} else if net.ParseIP(c) != nil {
			out.CIDRs = append(out.CIDRs, c)
		} else {
			log.Printf("[input] rejected invalid CIDR/IP: %q", c)
		}
	}

	return out
}
