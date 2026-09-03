package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/corpendpoint"
	"github.com/limauriga-ux/crosslink/internal/openvpnprofile"
	"github.com/limauriga-ux/crosslink/internal/profile"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func TestCompileOpenVPNEndpointAndPriority(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	profilePath := filepath.Join(dir, "proxy.json")
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(profilePath, []byte(`{
		"outbounds":[
			{"type":"direct","tag":"edge"},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{
			"rules":[{"domain_suffix":[".profile.corp.example"],"action":"route","outbound":"Proxy"}],
			"final":"Proxy"
		}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveRulePlanAtomic(rulesPath, profile.RulePlan{
		Prepend: []string{"DOMAIN-SUFFIX,explicit.corp.example,Proxy"},
		Append:  []string{"IP-CIDR,10.20.1.0/24,DIRECT"},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = profilePath
	cfg.Core.Rules = rulesPath
	cfg.Core.RuleSetDir = filepath.Join(dir, ".crosslink", "rulesets")
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	openVPN := &openVPNRuntimeConfig{profile: openVPNCompileProfile(t)}
	compiled, err := compileConfigWithOpenVPN(cfg, openVPN)
	if err != nil {
		t.Fatal(err)
	}

	runtime := corpendpoint.NewRuntime()
	registries := newRegistries(runtime)
	ctx := registries.context(context.Background())
	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, compiled.content)
	if err != nil {
		t.Fatalf("generated config did not parse: %v\n%s", err, compiled.content)
	}
	if len(options.Endpoints) != 2 || options.Endpoints[1].Tag != openvpnprofile.EndpointTag || options.Endpoints[1].Type != "openvpn-client" {
		t.Fatalf("endpoints = %#v", options.Endpoints)
	}
	for _, outbound := range options.Outbounds {
		if outbound.Tag == openvpnprofile.EndpointTag {
			t.Fatalf("active endpoint collided with offline block outbound: %#v", options.Outbounds)
		}
	}
	root, err := singjson.UnmarshalExtended[map[string]any](compiled.content)
	if err != nil {
		t.Fatal(err)
	}
	rules := root["route"].(map[string]any)["rules"].([]any)
	authBypass := rules[4].(map[string]any)
	if authBypass["outbound"] != corpendpoint.PublicAuthOutboundTag || authBypass["preferred_by"].([]any)[0] != corpendpoint.PublicAuthOutboundTag {
		t.Fatalf("public authentication bypass rule = %#v", authBypass)
	}
	staticDomain := rules[5].(map[string]any)
	if staticDomain["outbound"] != openvpnprofile.EndpointTag || staticDomain["domain_suffix"].([]any)[0] != "corp.example" {
		t.Fatalf("static OpenVPN domain rule = %#v", staticDomain)
	}
	staticIP := rules[6].(map[string]any)
	if staticIP["outbound"] != openvpnprofile.EndpointTag || staticIP["ip_cidr"].([]any)[0] != "10.20.0.0/16" {
		t.Fatalf("static OpenVPN IP rule = %#v", staticIP)
	}
	if rules[7].(map[string]any)["preferred_by"].([]any)[0] != openvpnprofile.EndpointTag {
		t.Fatalf("dynamic OpenVPN preference = %#v", rules[7])
	}
	if rules[10].(map[string]any)["rule_set"].([]any)[0] != domesticDomainRuleSetTag {
		t.Fatalf("domestic fallback moved before OpenVPN = %#v", rules[10])
	}

	dns := root["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	serverTags := map[string]bool{}
	for _, raw := range servers {
		serverTags[raw.(map[string]any)["tag"].(string)] = true
	}
	if !serverTags[openvpnprofile.PushedDNSTag] || !serverTags[openvpnprofile.StaticDNSTag] {
		t.Fatalf("OpenVPN DNS servers = %#v", serverTags)
	}
	dnsRules := dns["rules"].([]any)
	if len(dnsRules) != 3 || dnsRules[0].(map[string]any)["server"] != dnsTransportTag || dnsRules[1].(map[string]any)["server"] != openvpnprofile.StaticDNSTag || dnsRules[2].(map[string]any)["server"] != openvpnprofile.PushedDNSTag {
		t.Fatalf("DNS rule order = %#v", dnsRules)
	}
}

func TestCompileOpenVPNStaticDNSWithoutDomainsUsesVPNResolverAsDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = ""
	cfg.Core.Rules = ""
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	cfg.DirectOutbound.Interface = "lo0"
	profile := openVPNCompileProfile(t)
	profile.Domains = nil
	compiled, err := compileConfigWithOpenVPN(cfg, &openVPNRuntimeConfig{profile: profile})
	if err != nil {
		t.Fatal(err)
	}
	root, err := singjson.UnmarshalExtended[map[string]any](compiled.content)
	if err != nil {
		t.Fatal(err)
	}
	dns := root["dns"].(map[string]any)
	rules := dns["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("DNS rules = %#v", rules)
	}
	staticRule := rules[2].(map[string]any)
	if staticRule["server"] != openvpnprofile.StaticDNSTag || len(staticRule) != 2 {
		t.Fatalf("default OpenVPN static DNS rule = %#v", staticRule)
	}
	if rules[1].(map[string]any)["server"] != openvpnprofile.PushedDNSTag {
		t.Fatalf("pushed split DNS must precede static default: %#v", rules)
	}
	servers := dns["servers"].([]any)
	found := false
	for _, raw := range servers {
		server := raw.(map[string]any)
		if server["tag"] != openvpnprofile.StaticDNSTag {
			continue
		}
		found = true
		if domains, ok := server["domains"].([]any); ok && len(domains) != 0 {
			t.Fatalf("static DNS domains = %#v", domains)
		}
	}
	if !found {
		t.Fatalf("OpenVPN static DNS server missing: %#v", servers)
	}
}

func TestOfflineOpenVPNRuleRoutesToBlockOutbound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	rulesPath := filepath.Join(dir, "rules.json")
	if err := profile.SaveRulePlanAtomic(rulesPath, profile.RulePlan{Prepend: []string{"DOMAIN-SUFFIX,corp.example,OPENVPN"}}); err != nil {
		t.Fatal(err)
	}
	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = ""
	cfg.Core.Rules = rulesPath
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	manager := New(cfg)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	decision := selectAdversarialRoute(manager.instance.Router(), domainMetadata("private.corp.example"), directTag)
	if decision.index != 3 || decision.action != "route(openvpn-enterprise)" {
		t.Fatalf("offline OpenVPN route = %+v", decision)
	}
	outbound, found := manager.instance.Outbound().Outbound(openvpnprofile.EndpointTag)
	if !found || outbound.Type() != "block" {
		t.Fatalf("offline OpenVPN outbound = %T found=%v", outbound, found)
	}
}

func TestDisconnectOpenVPNKeepsStoppedCoreStopped(t *testing.T) {
	manager := New(appconfig.DefaultConfig())
	manager.openVPN = &openVPNRuntimeConfig{profile: openVPNCompileProfile(t)}
	manager.runtime.SetPublicAuthScope("vpn.corp.example", 0)

	if err := manager.DisconnectOpenVPN(); err != nil {
		t.Fatal(err)
	}
	if manager.openVPN != nil || manager.instance != nil || manager.coreRunning.Load() {
		t.Fatalf("disconnect started or retained core state: openvpn=%v instance=%v running=%v", manager.openVPN != nil, manager.instance != nil, manager.coreRunning.Load())
	}
	if manager.runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("disconnect retained OpenVPN authentication scope")
	}
}

func TestStopCoreClearsOpenVPNChallengeAuthScope(t *testing.T) {
	manager := New(appconfig.DefaultConfig())
	manager.openVPN = &openVPNRuntimeConfig{profile: openvpnprofile.Profile{
		Remotes: []openvpnprofile.Remote{{Server: "192.0.2.20", Port: 12294, Network: "tcp"}},
		Domains: []string{"corp.example"},
	}}
	if err := manager.armOpenVPNChallengeLocked("challenge", "https://vpn.corp.example/oauth2/start", 0); err != nil {
		t.Fatal(err)
	}
	if !manager.runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("armed challenge did not publish the authentication scope")
	}
	if err := manager.stopCoreLocked(); err != nil {
		t.Fatal(err)
	}
	if manager.openVPNChallengeID != "" || manager.runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("stopped core retained authentication scope")
	}
}

func TestArmOpenVPNChallengePublishesNarrowestTrustedScope(t *testing.T) {
	manager := New(appconfig.DefaultConfig())
	manager.openVPN = &openVPNRuntimeConfig{profile: openvpnprofile.Profile{
		Remotes: []openvpnprofile.Remote{{Server: "192.0.2.20", Port: 12294, Network: "tcp"}},
		Domains: []string{"corp.example"},
	}}
	if err := manager.armOpenVPNChallengeLocked("challenge", "https://vpn.corp.example/oauth2/start", 0); err != nil {
		t.Fatal(err)
	}
	if !manager.runtime.MatchPublicAuthDomain("vpn.corp.example") || !manager.runtime.MatchPublicAuthDomain("login.corp.example") {
		t.Fatal("authentication scope did not cover the managed enterprise suffix")
	}
	if manager.runtime.MatchPublicAuthDomain("corp.example.evil.example") || manager.runtime.MatchPublicAuthDomain("login.microsoftonline.com") {
		t.Fatal("authentication scope widened beyond the managed enterprise")
	}
	if err := manager.armOpenVPNChallengeLocked("challenge", "https://evil.example/oauth2/start", 0); err == nil {
		t.Fatal("untrusted authentication URL armed a public scope")
	}
}

func TestMergeOpenVPNStatusCopiesChallengeAndTunnelInfo(t *testing.T) {
	deadline := time.Now().Add(time.Minute).Truncate(time.Second)
	connected := time.Now().Add(-time.Minute).Truncate(time.Second)
	result := mergeOpenVPNStatus(OpenVPNStatus{Configured: true, Active: true}, adapter.OpenVPNStatus{
		State:     adapter.OpenVPNStateAuthPending,
		Challenge: &adapter.OpenVPNChallenge{ID: "challenge", Kind: "secret", Message: "OTP", Deadline: deadline},
		TunnelInfo: &adapter.OpenVPNTunnelInfo{
			Server: "vpn.example.com:443", Network: "tcp", Cipher: "AES-256-GCM",
			IPv4: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
			DNS:  []netip.Addr{netip.MustParseAddr("10.20.0.53")}, MTU: 1400, ConnectedSince: connected,
		},
	})
	if result.State != adapter.OpenVPNStateAuthPending || result.Challenge == nil || result.Challenge.ID != "challenge" || result.Challenge.Deadline != deadline.Unix() {
		t.Fatalf("challenge status = %+v", result)
	}
	if result.Server != "vpn.example.com:443" || len(result.IPv4) != 1 || result.IPv4[0] != "10.8.0.2/24" || len(result.DNS) != 1 || result.DNS[0] != "10.20.0.53" || result.ConnectedAt != connected.Unix() {
		t.Fatalf("tunnel status = %+v", result)
	}
}

func TestFinalizeOpenVPNStatusDoesNotArmScopeWithoutExplicitPrepare(t *testing.T) {
	manager := New(appconfig.DefaultConfig())
	manager.openVPN = &openVPNRuntimeConfig{profile: openvpnprofile.Profile{
		Remotes: []openvpnprofile.Remote{{Server: "192.0.2.20", Port: 12294, Network: "tcp"}},
		Domains: []string{"corp.example"},
	}}
	before := manager.runtime.DNSEnvironment()
	challengeStatus := OpenVPNStatus{
		State: adapter.OpenVPNStateAuthPending,
		Challenge: &OpenVPNChallenge{
			ID: "challenge", Kind: "open-url",
			URL: "https://vpn.corp.example/oauth2/start?state=x",
		},
	}
	status := manager.finalizeOpenVPNStatus(challengeStatus)
	if !status.Challenge.URLAllowed {
		t.Fatalf("finalized challenge = %+v", status.Challenge)
	}
	if manager.runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("status poll armed the authentication scope without an explicit prepare")
	}
	if after := manager.runtime.DNSEnvironment(); !reflect.DeepEqual(before, after) {
		t.Fatalf("status poll changed DNS environment: before=%v after=%v", before, after)
	}

	if err := manager.armOpenVPNChallengeLocked("challenge", challengeStatus.Challenge.URL, 0); err != nil {
		t.Fatal(err)
	}
	armed := manager.runtime.DNSEnvironment()
	manager.finalizeOpenVPNStatus(challengeStatus)
	if !manager.runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("status poll discarded an armed authentication scope")
	}
	if after := manager.runtime.DNSEnvironment(); !reflect.DeepEqual(armed, after) {
		t.Fatalf("identical status poll advanced DNS environment: before=%v after=%v", armed, after)
	}

	manager.finalizeOpenVPNStatus(OpenVPNStatus{State: adapter.OpenVPNStateConnected})
	if manager.runtime.MatchPublicAuthDomain("vpn.corp.example") {
		t.Fatal("completed challenge retained the authentication scope")
	}
	if after := manager.runtime.DNSEnvironment(); reflect.DeepEqual(armed, after) {
		t.Fatalf("clearing challenge did not advance DNS environment: %v", after)
	}
}

func TestFinalizeOpenVPNStatusKeepsGraceScopeWhenChallengeChanges(t *testing.T) {
	manager := New(appconfig.DefaultConfig())
	manager.openVPN = &openVPNRuntimeConfig{profile: openvpnprofile.Profile{
		Remotes: []openvpnprofile.Remote{{Server: "192.0.2.20", Port: 12294, Network: "tcp"}},
		Domains: []string{"corp.example"},
	}}
	if err := manager.armOpenVPNChallengeLocked("old", "https://vpn.corp.example/oauth2/start", time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	status := manager.finalizeOpenVPNStatus(OpenVPNStatus{
		State: adapter.OpenVPNStateAuthPending,
		Challenge: &OpenVPNChallenge{
			ID: "new", Kind: "open-url",
			URL: "https://vpn.corp.example/oauth2/start?state=y",
		},
	})
	if !status.Challenge.URLAllowed {
		t.Fatal("trusted replacement challenge lost ownership result")
	}
	if manager.openVPNChallengeID != "" || manager.openVPNChallengeGraceID != "new" || !manager.runtime.MatchPublicAuthDomain("sso.corp.example") {
		t.Fatal("replacement challenge did not retain one trusted grace scope")
	}
	manager.finalizeOpenVPNStatus(OpenVPNStatus{State: adapter.OpenVPNStateConnected})
	if manager.openVPNChallengeGraceID != "" || manager.runtime.MatchPublicAuthDomain("sso.corp.example") {
		t.Fatal("connected endpoint retained replacement challenge grace scope")
	}
}

func TestFinalizeOpenVPNStatusKeepsBoundedScopeForExpiredChallenge(t *testing.T) {
	manager := New(appconfig.DefaultConfig())
	manager.openVPN = &openVPNRuntimeConfig{profile: openvpnprofile.Profile{
		Remotes: []openvpnprofile.Remote{{Server: "192.0.2.20", Port: 12294, Network: "tcp"}},
		Domains: []string{"corp.example"},
	}}
	expiredAt := time.Now().Add(-time.Second).Unix()
	if err := manager.armOpenVPNChallengeLocked("expired", "https://vpn.corp.example/oauth2/start", expiredAt); err != nil {
		t.Fatal(err)
	}
	status := manager.finalizeOpenVPNStatus(OpenVPNStatus{
		State: adapter.OpenVPNStateAuthPending,
		Challenge: &OpenVPNChallenge{
			ID: "expired", Kind: "open-url", Deadline: expiredAt,
			URL: "https://vpn.corp.example/oauth2/start?state=x",
		},
	})
	if !status.Challenge.URLAllowed {
		t.Fatal("trusted but expired challenge lost ownership result")
	}
	if manager.openVPNChallengeID != "" || manager.openVPNChallengeGraceID != "expired" || !manager.runtime.MatchPublicAuthDomain("sso.corp.example") {
		t.Fatal("expired challenge did not retain one trusted grace scope")
	}
	manager.finalizeOpenVPNStatus(status)
	if manager.openVPNChallengeGraceID != "expired" {
		t.Fatal("repeated expired status changed the grace generation")
	}
	manager.finalizeOpenVPNStatus(OpenVPNStatus{State: adapter.OpenVPNStateConnected})
	if manager.openVPNChallengeGraceID != "" || manager.runtime.MatchPublicAuthDomain("sso.corp.example") {
		t.Fatal("connected endpoint retained expired challenge grace scope")
	}
}

func openVPNCompileProfile(t *testing.T) openvpnprofile.Profile {
	t.Helper()
	profile := openVPNProfileWithGeneratedIdentity(t)
	profile.Name = "Enterprise"
	profile.Remotes = []openvpnprofile.Remote{{Server: "127.0.0.1", Port: freeOpenVPNTestPort(t), Network: "tcp"}}
	profile.RouteNoPull = true
	profile.Routes = []string{"10.20.0.0/16"}
	profile.DNSServers = []string{"10.20.0.53"}
	profile.Domains = []string{"corp.example"}
	return profile
}

func openVPNProfileWithGeneratedIdentity(t *testing.T) openvpnprofile.Profile {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Core Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Core Test Client"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	return openvpnprofile.Profile{
		Version:              openvpnprofile.Version,
		Name:                 "test",
		Remotes:              []openvpnprofile.Remote{{Server: "127.0.0.1", Port: 1194, Network: "tcp"}},
		CertificateAuthority: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		ClientCertificate:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})),
		ClientKey:            string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		RemoteCertificateTLS: "server",
	}
}
func freeOpenVPNTestPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return uint16(port)
}
func TestOpenVPNAuthScopeBypassesFailClosedEndpoint(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = ""
	cfg.Core.Rules = ""
	cfg.Core.DomesticDirect = false
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = int(freeOpenVPNTestPort(t))

	profile := openVPNCompileProfile(t)
	// A loopback static route is artificial but exercises the exact precedence:
	// the fail-closed endpoint owns it until a user-opened auth challenge arms
	// the narrow public scope, and owns it again once the challenge clears.
	profile.Routes = []string{"127.0.0.1/32"}

	manager := New(cfg)
	if err := manager.ConnectOpenVPN(profile, "", ""); err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()

	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(cfg.Core.MixedPort))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}

	if _, err := client.Get(target.URL); err == nil {
		t.Fatal("unarmed authentication scope leaked the static route to the public final")
	}

	manager.lifecycleMu.Lock()
	armErr := manager.armOpenVPNChallengeLocked("challenge", "https://127.0.0.1/auth", 0)
	manager.lifecycleMu.Unlock()
	if armErr != nil {
		t.Fatal(armErr)
	}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("armed authentication scope did not reach the public final: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	manager.lifecycleMu.Lock()
	manager.clearOpenVPNChallengeLocked()
	manager.lifecycleMu.Unlock()
	if _, err := client.Get(target.URL); err == nil {
		t.Fatal("cleared authentication scope still bypassed the fail-closed endpoint")
	}
}

func TestCorpLinkYieldsOverlappingClaimsToOpenVPN(t *testing.T) {
	dir := t.TempDir()
	cfg := adversarialCoreConfig(dir, "", "")
	cfg.Core.DomesticDirect = false
	manager := New(cfg)
	profile := openVPNCompileProfile(t)
	if err := manager.ConnectOpenVPN(profile, "", ""); err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()

	// CorpLink pushes overlapping claims after the OpenVPN profile is active.
	manager.runtime.UpdateRoutes([]string{"10.20.0.0/16", "10.99.0.0/16"}, []string{"corp.example", "internal.example"}, nil, false)

	router := manager.instance.Router()
	if decision := selectAdversarialRoute(router, ipMetadata("10.20.8.9"), directTag); decision.action != "route(openvpn-enterprise)" {
		t.Fatalf("overlapping address decision = %+v", decision)
	}
	if decision := selectAdversarialRoute(router, domainMetadata("git.corp.example"), directTag); decision.action != "route(openvpn-enterprise)" {
		t.Fatalf("overlapping domain decision = %+v", decision)
	}
	if decision := selectAdversarialRoute(router, ipMetadata("10.99.8.9"), directTag); decision.action != "route(corp)" {
		t.Fatalf("CorpLink-only address decision = %+v", decision)
	}
	if decision := selectAdversarialRoute(router, domainMetadata("git.internal.example"), directTag); decision.action != "route(corp)" {
		t.Fatalf("CorpLink-only domain decision = %+v", decision)
	}
}

func TestOpenVPNStaticRoutesOutrankSubscriptionBoilerplate(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "proxy.json")
	// A typical Clash subscription carries blanket private-range DIRECT rules
	// that must not shadow the explicitly imported OpenVPN profile.
	if err := os.WriteFile(profilePath, []byte(`{
		"outbounds":[
			{"type":"socks","tag":"edge","server":"127.0.0.1","server_port":1},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{"rules":[
			{"ip_cidr":["10.0.0.0/8"],"action":"route","outbound":"direct"},
			{"ip_cidr":["192.168.0.0/16"],"action":"route","outbound":"direct"}
		],"final":"Proxy"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := adversarialCoreConfig(dir, profilePath, "")
	cfg.Core.DomesticDirect = false
	manager := New(cfg)
	if err := manager.ConnectOpenVPN(openVPNCompileProfile(t), "", ""); err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()

	router := manager.instance.Router()
	if decision := selectAdversarialRoute(router, ipMetadata("10.20.8.9"), directTag); decision.action != "route(openvpn-enterprise)" {
		t.Fatalf("OpenVPN-claimed address decision = %+v", decision)
	}
	if decision := selectAdversarialRoute(router, ipMetadata("192.168.1.9"), directTag); decision.action != "route(direct)" {
		t.Fatalf("unclaimed private address decision = %+v", decision)
	}
	if decision := selectAdversarialRoute(router, domainMetadata("git.corp.example"), directTag); decision.action != "route(openvpn-enterprise)" {
		t.Fatalf("OpenVPN-claimed domain decision = %+v", decision)
	}
}
