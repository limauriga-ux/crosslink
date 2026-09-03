package openvpnprofile

import "testing"

func TestChallengeURLAllowedMatchesConfiguredServerOwnership(t *testing.T) {
	remotes := []Remote{
		{Server: "vpn.example.com", Port: 1194, Network: "udp"},
		{Server: "192.0.2.20", Port: 1194, Network: "udp"},
		{Server: "2001:db8::20", Port: 1194, Network: "udp"},
		{Server: "gateway.example.co.uk", Port: 443, Network: "tcp"},
	}
	for _, test := range []struct {
		name string
		url  string
		want bool
	}{
		{name: "exact host", url: "https://vpn.example.com/auth", want: true},
		{name: "subdomain of remote", url: "https://sso.vpn.example.com/auth", want: true},
		{name: "same registrable domain", url: "https://login.example.com/sso?token=x", want: true},
		{name: "port kept", url: "https://sso.example.com:8443/auth", want: true},
		{name: "co.uk registrable domain", url: "https://portal.example.co.uk/auth", want: true},
		{name: "different registrable domain", url: "https://evil.example.net/auth", want: false},
		{name: "public suffix itself", url: "https://co.uk/auth", want: false},
		{name: "unrelated ip host", url: "https://198.51.100.9/auth", want: false},
		{name: "exact ipv4 remote", url: "https://192.0.2.20:8443/auth", want: true},
		{name: "different ipv4 remote", url: "https://192.0.2.21/auth", want: false},
		{name: "equivalent ipv6 remote", url: "https://[2001:0db8:0:0:0:0:0:20]/auth", want: true},
		{name: "different ipv6 remote", url: "https://[2001:db8::21]/auth", want: false},
		{name: "plaintext scheme", url: "http://vpn.example.com/auth", want: false},
		{name: "credentials in url", url: "https://user:pass@vpn.example.com/auth", want: false},
		{name: "not a url", url: "vpn.example.com auth", want: false},
		{name: "empty", url: "", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ChallengeURLAllowed(test.url, remotes); got != test.want {
				t.Fatalf("ChallengeURLAllowed(%q) = %v, want %v", test.url, got, test.want)
			}
		})
	}
}

func TestChallengeURLAllowedWithoutRemotesRejectsEverything(t *testing.T) {
	if ChallengeURLAllowed("https://vpn.example.com/auth", nil) {
		t.Fatal("challenge URL allowed without configured remotes")
	}
}

func TestChallengeURLAllowedAcceptsExplicitSplitDomainForIPRemote(t *testing.T) {
	remotes := []Remote{{Server: "192.0.2.20", Port: 12294, Network: "tcp"}}
	if !ChallengeURLAllowed("https://vpn.corp.example/oauth2/start?state=x", remotes, "corp.example") {
		t.Fatal("SSO URL under explicit OpenVPN split domain was rejected")
	}
	for _, rawURL := range []string{
		"https://corp.example.evil.example/auth",
		"https://evil.example/auth",
		"http://vpn.corp.example/auth",
	} {
		if ChallengeURLAllowed(rawURL, remotes, "corp.example") {
			t.Fatalf("untrusted challenge URL was allowed: %s", rawURL)
		}
	}
}

func TestChallengeURLAllowedRejectsPublicSuffixOwnership(t *testing.T) {
	remotes := []Remote{{Server: "192.0.2.20", Port: 12294, Network: "tcp"}}
	if ChallengeURLAllowed("https://attacker.com/auth", remotes, "com") {
		t.Fatal("public suffix widened challenge ownership to arbitrary host")
	}
}

func TestChallengeURLScopeDerivesNarrowestTrustedSuffix(t *testing.T) {
	remotes := []Remote{{Server: "192.0.2.20", Port: 12294, Network: "tcp"}}
	if scope, ok := ChallengeURLScope(" HTTPS://VPN.CORP.EXAMPLE./oauth2/start?state=x ", remotes, "corp.example"); !ok || scope != "corp.example" {
		t.Fatalf("challenge URL scope = %q, %v", scope, ok)
	}
	if scope, ok := ChallengeURLScope("https://192.0.2.20/auth", remotes, "corp.example"); !ok || scope != "192.0.2.20" {
		t.Fatalf("IP challenge URL scope = %q, %v", scope, ok)
	}
	domainRemotes := []Remote{{Server: "vpn.example.com", Port: 443, Network: "tcp"}}
	if scope, ok := ChallengeURLScope("https://sso.example.com/auth", domainRemotes); !ok || scope != "example.com" {
		t.Fatalf("domain remote challenge scope = %q, %v", scope, ok)
	}
	for _, rawURL := range []string{
		"http://vpn.corp.example/auth",
		"https://user:pass@vpn.corp.example/auth",
		"https://co.uk/auth",
		"not-a-url",
		"https://attacker.com/auth",
	} {
		if scope, ok := ChallengeURLScope(rawURL, remotes, "corp.example"); ok {
			t.Fatalf("untrusted challenge URL %q returned scope %q", rawURL, scope)
		}
	}
	if _, ok := ChallengeURLScope("https://192.0.2.21/auth", remotes, "corp.example"); ok {
		t.Fatal("unknown IP challenge URL derived a scope")
	}
}

func TestRegistrableDomainRejectsPublicSuffixes(t *testing.T) {
	if domain, ok := registrableDomain("vpn.example.com"); !ok || domain != "example.com" {
		t.Fatalf("registrableDomain(vpn.example.com) = %q, %v", domain, ok)
	}
	if domain, ok := registrableDomain("portal.example.co.uk"); !ok || domain != "example.co.uk" {
		t.Fatalf("registrableDomain(portal.example.co.uk) = %q, %v", domain, ok)
	}
	if _, ok := registrableDomain("com"); ok {
		t.Fatal("public-suffix host must not be registrable")
	}
	if _, ok := registrableDomain("unknown-suffix-invalid"); ok {
		t.Fatal("non-ICANN suffix host must not be registrable")
	}
}
