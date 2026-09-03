package openvpnprofile

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ChallengeURLAllowed reports whether an authentication URL pushed by the
// OpenVPN server belongs to the configured enterprise.
func ChallengeURLAllowed(rawURL string, remotes []Remote, domains ...string) bool {
	_, allowed := ChallengeURLScope(rawURL, remotes, domains...)
	return allowed
}

// ChallengeURLScope returns the narrowest trusted domain suffix, or an exact
// remote IP, that a browser needs while completing an OAuth challenge. The
// scope is derived only from the managed profile; it is never learned by
// fetching the one-time URL outside the browser.
func ChallengeURLScope(rawURL string, remotes []Remote, domains ...string) (string, bool) {
	host, hostIP, ok := parseChallengeURL(rawURL)
	if !ok {
		return "", false
	}
	if hostIP != nil {
		for _, remote := range remotes {
			remoteIP := net.ParseIP(strings.Trim(strings.TrimSpace(remote.Server), "[]"))
			if remoteIP != nil && remoteIP.Equal(hostIP) {
				return hostIP.String(), true
			}
		}
		return "", false
	}

	bestDomain := ""
	for _, rawDomain := range domains {
		domain := normalizeDomain(rawDomain)
		if domain == "" {
			continue
		}
		if suffix, icann := publicsuffix.PublicSuffix(domain); icann && suffix == domain {
			continue
		}
		if (host == domain || strings.HasSuffix(host, "."+domain)) && len(domain) > len(bestDomain) {
			bestDomain = domain
		}
	}
	if bestDomain != "" {
		return bestDomain, true
	}

	for _, remote := range remotes {
		server := normalizeDomain(strings.Trim(strings.TrimSpace(remote.Server), "[]"))
		if server == "" || net.ParseIP(server) != nil {
			continue
		}
		if host != server && !strings.HasSuffix(host, "."+server) && !sameRegistrableDomain(host, server) {
			continue
		}
		if scope, registrable := registrableDomain(server); registrable {
			return scope, true
		}
		return server, true
	}
	return "", false
}

func parseChallengeURL(rawURL string) (string, net.IP, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.User != nil {
		return "", nil, false
	}
	host := strings.Trim(parsed.Hostname(), "[]")
	if host == "" {
		return "", nil, false
	}
	if hostIP := net.ParseIP(host); hostIP != nil {
		return hostIP.String(), hostIP, true
	}
	host = normalizeDomain(host)
	return host, nil, host != ""
}

func sameRegistrableDomain(a, b string) bool {
	domainA, okA := registrableDomain(a)
	domainB, okB := registrableDomain(b)
	return okA && okB && domainA == domainB
}

// registrableDomain returns the eTLD+1 of an ASCII host, reporting false for
// hosts that are themselves a public suffix or are not ICANN-managed.
func registrableDomain(host string) (string, bool) {
	suffix, icann := publicsuffix.PublicSuffix(host)
	if !icann {
		return "", false
	}
	labels := strings.Split(host, ".")
	suffixLabels := strings.Split(suffix, ".")
	if len(labels) <= len(suffixLabels) {
		return "", false
	}
	return strings.Join(labels[len(labels)-len(suffixLabels)-1:], "."), true
}
