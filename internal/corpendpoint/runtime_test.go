package corpendpoint

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestRuntimeRoutesRemainFailClosedWhileDisconnected(t *testing.T) {
	runtime := NewRuntime()
	runtime.UpdateRoutes(
		[]string{"10.42.0.0/16"},
		[]string{".corp.example"},
		[]netip.Addr{netip.MustParseAddr("10.42.0.53")},
		false,
	)

	if !runtime.MatchDomain("api.corp.example") {
		t.Fatal("corporate suffix did not select corporate endpoint")
	}
	if !runtime.MatchAddress(netip.MustParseAddr("10.42.8.9")) {
		t.Fatal("corporate CIDR did not select corporate endpoint")
	}
	if !runtime.MatchAddress(netip.MustParseAddr("10.42.0.53")) {
		t.Fatal("corporate DNS host route was not forced through endpoint")
	}
	if runtime.MatchDomain("example.com") {
		t.Fatal("public domain incorrectly selected corporate endpoint")
	}

	runtime.Deactivate()
	if !runtime.MatchDomain("api.corp.example") {
		t.Fatal("disconnect erased route snapshot and would leak corporate domain")
	}
	if _, err := runtime.Acquire(); err == nil {
		t.Fatal("disconnected runtime unexpectedly returned a live generation")
	}
}

func TestRuntimeFullTunnelKeepsSplitDNS(t *testing.T) {
	runtime := NewRuntime()
	runtime.UpdateRoutes(nil, []string{"corp.example"}, nil, true)

	if !runtime.MatchDomain("public.example") {
		t.Fatal("full tunnel did not prefer corporate endpoint")
	}
	if !runtime.MatchAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("full tunnel did not prefer corporate endpoint for public IP")
	}
	if runtime.MatchCorporateDomain("public.example") {
		t.Fatal("full tunnel incorrectly sent public DNS name to corporate resolver")
	}
	if !runtime.MatchCorporateDomain("git.corp.example") {
		t.Fatal("split DNS lost corporate suffix in full-tunnel mode")
	}
}

func TestRuntimeSplitModeIgnoresPublicCDNRoutesAndPublicSuffixes(t *testing.T) {
	runtime := NewRuntime()
	runtime.UpdateRoutes(
		[]string{
			"10.42.0.0/16",
			"104.21.79.4/32",   // shared Cloudflare address
			"172.67.139.58/32", // shared Cloudflare address
			"0.0.0.0/0",
		},
		[]string{"*.corp.example.com", "com"},
		nil,
		false,
	)

	if runtime.MatchAddress(netip.MustParseAddr("104.21.79.4")) || runtime.MatchAddress(netip.MustParseAddr("172.67.139.58")) {
		t.Fatal("public CDN address from corporate split routes captured unrelated tenants")
	}
	if !runtime.MatchAddress(netip.MustParseAddr("10.42.8.9")) {
		t.Fatal("private corporate route was filtered")
	}
	if runtime.MatchDomain("ippure.com") {
		t.Fatal("ICANN public suffix captured every .com domain")
	}
	if !runtime.MatchDomain("git.corp.example.com") {
		t.Fatal("corporate wildcard suffix was not normalized")
	}
	stats := runtime.PolicyStats()
	if stats.EffectiveRoutes != 1 || stats.EffectiveDomains != 1 || stats.IgnoredPublicRoutes != 3 || stats.IgnoredPublicSuffixes != 1 {
		t.Fatalf("policy stats = %+v", stats)
	}
}

func TestRuntimePublicAuthScopeIsSuffixBoundedAndAdvancesEnvironment(t *testing.T) {
	runtime := NewRuntime()
	runtime.UpdateRoutes(nil, []string{"corp.example"}, nil, false)
	before := runtime.DNSEnvironment()
	if !runtime.SetPublicAuthScope(" VPN.CORP.EXAMPLE. ", 0) {
		t.Fatal("setting a new public auth scope reported no change")
	}
	afterSet := runtime.DNSEnvironment()
	if reflect.DeepEqual(before, afterSet) {
		t.Fatalf("DNS environment did not change: %v", afterSet)
	}
	if !runtime.MatchPublicAuthDomain("vpn.corp.example.") || !runtime.MatchPublicAuthDomain("idp.vpn.corp.example") {
		t.Fatal("authentication scope did not cover itself and its IdP subdomains")
	}
	if runtime.MatchPublicAuthDomain("api.corp.example") || runtime.MatchPublicAuthDomain("evil-vpn.corp.example") || runtime.MatchPublicAuthDomain("com") {
		t.Fatal("authentication scope widened beyond the managed suffix")
	}
	if runtime.SetPublicAuthScope("vpn.corp.example", 0) {
		t.Fatal("identical auth scope advanced policy")
	}
	if !reflect.DeepEqual(afterSet, runtime.DNSEnvironment()) {
		t.Fatal("identical auth scope changed cache environment")
	}
	if !runtime.SetPublicAuthScope("", 0) || runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("clearing public auth scope failed")
	}
	if reflect.DeepEqual(afterSet, runtime.DNSEnvironment()) {
		t.Fatal("clearing auth scope did not invalidate cache environment")
	}
}

func TestRuntimePublicAuthAddressScopeIsExact(t *testing.T) {
	runtime := NewRuntime()
	if !runtime.SetPublicAuthScope("192.0.2.20", 0) {
		t.Fatal("setting an address auth scope reported no change")
	}
	if !runtime.MatchPublicAuthAddress(netip.MustParseAddr("192.0.2.20")) {
		t.Fatal("exact authentication address did not match")
	}
	if runtime.MatchPublicAuthAddress(netip.MustParseAddr("192.0.2.21")) || runtime.MatchPublicAuthDomain("192.0.2.20") {
		t.Fatal("address authentication scope widened")
	}
	if runtime.MatchPublicAuthAddress(netip.Addr{}) {
		t.Fatal("invalid address matched authentication scope")
	}
}

func TestRuntimePublicAuthScopeExpiresWithoutStatusPoll(t *testing.T) {
	runtime := NewRuntime()
	runtime.UpdateRoutes(nil, []string{"corp.example"}, nil, false)
	deadline := time.Now().Unix() + 1
	if !runtime.SetPublicAuthScope("vpn.corp.example", deadline) {
		t.Fatal("setting expiring public auth scope reported no change")
	}
	activeEnvironment := runtime.DNSEnvironment()
	if !runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("unexpired public auth scope did not match")
	}

	time.Sleep(time.Until(time.Unix(deadline, 0)) + 20*time.Millisecond)
	if runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("expired public auth scope still matched without a status poll")
	}
	expiredEnvironment := runtime.DNSEnvironment()
	if reflect.DeepEqual(activeEnvironment, expiredEnvironment) {
		t.Fatalf("DNS environment did not change at expiry: %v", expiredEnvironment)
	}
}

func TestRuntimePublicAuthDeadlineExtensionIsBounded(t *testing.T) {
	runtime := NewRuntime()
	runtime.UpdateRoutes(nil, []string{"corp.example"}, nil, false)
	if !runtime.SetPublicAuthScope("corp.example", time.Now().Add(-time.Second).Unix()) {
		t.Fatal("setting expired public auth scope reported no change")
	}
	expiredEnvironment := runtime.DNSEnvironment()
	deadline := time.Now().Add(time.Minute).Unix()
	if !runtime.ExtendPublicAuthDeadline(deadline) {
		t.Fatal("extending expired public auth scope reported no change")
	}
	if !runtime.MatchPublicAuthDomain("sso.corp.example") || runtime.MatchPublicAuthDomain("corp.example.evil.example") {
		t.Fatal("extended public auth scope was inactive or broadened")
	}
	if reflect.DeepEqual(expiredEnvironment, runtime.DNSEnvironment()) {
		t.Fatal("revived public auth scope did not change the DNS environment")
	}
	if runtime.ExtendPublicAuthDeadline(deadline - 1) {
		t.Fatal("shorter auth scope deadline replaced the active grace window")
	}
	runtime.SetPublicAuthScope("", 0)
	if runtime.ExtendPublicAuthDeadline(time.Now().Add(time.Hour).Unix()) {
		t.Fatal("cleared public auth scope was revived")
	}
}

func TestRuntimeYieldsOpenVPNClaims(t *testing.T) {
	runtime := NewRuntime()
	runtime.UpdateRoutes([]string{"10.42.0.0/16", "10.99.0.0/16"}, []string{"corp.example", "internal.example"}, nil, false)
	if !runtime.MatchDomain("git.corp.example") || !runtime.MatchAddress(netip.MustParseAddr("10.42.8.9")) {
		t.Fatal("baseline CorpLink claim missing")
	}

	runtime.SetOpenVPNClaims([]string{"10.42.0.0/16"}, []string{"corp.example"})
	if runtime.MatchDomain("git.corp.example") || runtime.MatchAddress(netip.MustParseAddr("10.42.8.9")) {
		t.Fatal("CorpLink retained an OpenVPN-claimed segment")
	}
	if !runtime.MatchDomain("git.internal.example") || !runtime.MatchAddress(netip.MustParseAddr("10.99.8.9")) {
		t.Fatal("OpenVPN claims shadowed an unrelated CorpLink segment")
	}
	if !runtime.MatchCorporateDomain("git.corp.example") {
		t.Fatal("OpenVPN claims leaked into split-DNS selection")
	}

	runtime.SetOpenVPNClaims(nil, nil)
	if !runtime.MatchDomain("git.corp.example") || !runtime.MatchAddress(netip.MustParseAddr("10.42.8.9")) {
		t.Fatal("clearing OpenVPN claims did not restore CorpLink ownership")
	}
}
