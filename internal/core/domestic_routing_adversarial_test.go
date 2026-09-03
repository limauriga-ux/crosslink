package core

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/profile"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
)

type adversarialRouteDecision struct {
	index      int
	actionType string
	action     string
}

func TestDomesticRoutingAdversarialPriorityMatrix(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "test")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "proxy.json")
	rulesPath := filepath.Join(dir, "rules.json")
	profileContent := []byte(`{
		"outbounds":[
			{"type":"socks","tag":"edge","server":"127.0.0.1","server_port":1},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{
			"rules":[{"domain":["www.baidu.com"],"action":"reject"}],
			"final":"Proxy"
		}
	}`)
	if err := os.WriteFile(profilePath, profileContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveRulePlanAtomic(rulesPath, profile.RulePlan{
		Prepend: []string{"DOMAIN-SUFFIX,xiaohongshu.com,Proxy"},
		Append: []string{
			"DOMAIN-SUFFIX,qq.com,Proxy",
			"IP-CIDR,114.114.114.114/32,Proxy,no-resolve",
		},
	}); err != nil {
		t.Fatal(err)
	}

	cfg := adversarialCoreConfig(dir, profilePath, rulesPath)
	manager := startAdversarialCore(t, cfg)

	tests := []struct {
		name       string
		metadata   adapter.InboundContext
		wantIndex  int
		wantType   string
		wantAction string
	}{
		{
			name:       "prepend proxy beats domestic domain",
			metadata:   domainMetadata("www.xiaohongshu.com"),
			wantIndex:  3,
			wantType:   C.RuleActionTypeRoute,
			wantAction: "route(Proxy)",
		},
		{
			name:       "profile reject beats domestic domain",
			metadata:   domainMetadata("www.baidu.com"),
			wantIndex:  4,
			wantType:   C.RuleActionTypeReject,
			wantAction: "reject",
		},
		{
			name:       "append proxy beats domestic domain",
			metadata:   domainMetadata("im.qq.com"),
			wantIndex:  5,
			wantType:   C.RuleActionTypeRoute,
			wantAction: "route(Proxy)",
		},
		{
			name:       "append proxy beats domestic IP",
			metadata:   ipMetadata("114.114.114.114"),
			wantIndex:  6,
			wantType:   C.RuleActionTypeRoute,
			wantAction: "route(Proxy)",
		},
		{
			name:       "uncovered domestic domain uses geosite",
			metadata:   domainMetadata("www.taobao.com"),
			wantIndex:  7,
			wantType:   C.RuleActionTypeRoute,
			wantAction: "route(direct)",
		},
		{
			name:       "uncovered domestic IP uses geoip",
			metadata:   ipMetadata("223.5.5.5"),
			wantIndex:  8,
			wantType:   C.RuleActionTypeRoute,
			wantAction: "route(direct)",
		},
		{
			name: "resolved domestic IP uses geoip",
			metadata: adapter.InboundContext{
				Domain:               "unlisted.example",
				DestinationAddresses: []netip.Addr{netip.MustParseAddr("223.5.5.5")},
			},
			wantIndex:  8,
			wantType:   C.RuleActionTypeRoute,
			wantAction: "route(direct)",
		},
		{
			name:       "overseas IPv6 remains on profile final",
			metadata:   ipMetadata("2606:4700:4700::1111"),
			wantIndex:  -1,
			wantType:   "final",
			wantAction: "route(Proxy)",
		},
		{
			name:       "overseas IP remains on profile final",
			metadata:   ipMetadata("1.1.1.1"),
			wantIndex:  -1,
			wantType:   "final",
			wantAction: "route(Proxy)",
		},
		{
			name:       "suffix lookalike remains on profile final",
			metadata:   domainMetadata("xiaohongshu.com.evil.example"),
			wantIndex:  -1,
			wantType:   "final",
			wantAction: "route(Proxy)",
		},
		{
			name: "DNS hijack remains ahead of domestic domain",
			metadata: adapter.InboundContext{
				Protocol: "dns",
				Domain:   "www.taobao.com",
			},
			wantIndex:  1,
			wantType:   C.RuleActionTypeHijackDNS,
			wantAction: "hijack-dns",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := selectAdversarialRoute(manager.instance.Router(), test.metadata, "Proxy")
			if decision.index != test.wantIndex || decision.actionType != test.wantType || decision.action != test.wantAction {
				t.Fatalf("decision = %+v, want index=%d type=%q action=%q", decision, test.wantIndex, test.wantType, test.wantAction)
			}
		})
	}
}

func TestDomesticRoutingAdversarialSystemProtectionWins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "test")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "proxy.json")
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(profilePath, []byte(`{
		"outbounds":[
			{"type":"socks","tag":"edge","server":"127.0.0.1","server_port":1},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{"final":"Proxy"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveRulePlanAtomic(rulesPath, profile.RulePlan{
		Prepend: []string{"DOMAIN-SUFFIX,xiaohongshu.com,Proxy"},
	}); err != nil {
		t.Fatal(err)
	}

	cfg := adversarialCoreConfig(dir, profilePath, rulesPath)
	manager := New(cfg)
	manager.runtime.UpdateRoutes(nil, []string{"xiaohongshu.com"}, nil, false)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Disconnect() })

	decision := selectAdversarialRoute(manager.instance.Router(), domainMetadata("www.xiaohongshu.com"), "Proxy")
	if decision.index != 2 || decision.actionType != C.RuleActionTypeRoute || decision.action != "route(corp)" {
		t.Fatalf("system protection decision = %+v", decision)
	}
}

func TestDomesticRoutingDisabledLeavesNoRuleSetFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "test")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "proxy.json")
	if err := os.WriteFile(profilePath, []byte(`{
		"outbounds":[
			{"type":"socks","tag":"edge","server":"127.0.0.1","server_port":1},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{"final":"Proxy"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := adversarialCoreConfig(dir, profilePath, "")
	cfg.Core.DomesticDirect = false
	manager := startAdversarialCore(t, cfg)
	decision := selectAdversarialRoute(manager.instance.Router(), domainMetadata("www.taobao.com"), "Proxy")
	if decision.index != -1 || decision.actionType != "final" || decision.action != "route(Proxy)" {
		t.Fatalf("disabled domestic decision = %+v", decision)
	}
	if _, err := os.Stat(cfg.Core.RuleSetDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disabled domestic routing touched cache directory: %v", err)
	}
	status := manager.PublicProxyStatus()
	if status.DomesticDirect || len(status.DomesticRuleSets) != 0 {
		t.Fatalf("disabled domestic status = %+v", status)
	}
}

func TestDomesticRoutingReloadValidationKeepsLiveCore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "test")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "proxy.json")
	if err := os.WriteFile(profilePath, []byte(`{
		"outbounds":[
			{"type":"socks","tag":"edge","server":"127.0.0.1","server_port":1},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{"final":"Proxy"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := adversarialCoreConfig(dir, profilePath, "")
	manager := startAdversarialCore(t, cfg)
	previousInstance := manager.instance
	previousConfig := manager.cfg

	invalid := *cfg
	invalid.Core.RuleSetDir = filepath.Join(home, "outside-crosslink")
	err := manager.Reload(&invalid)
	if err == nil || !strings.Contains(err.Error(), "validate core reload") {
		t.Fatalf("invalid reload error = %v", err)
	}
	if manager.instance != previousInstance || !manager.coreRunning.Load() {
		t.Fatalf("invalid reload replaced live core: same=%v running=%v", manager.instance == previousInstance, manager.coreRunning.Load())
	}
	if manager.cfg != previousConfig {
		t.Fatal("invalid reload replaced active configuration")
	}
	decision := selectAdversarialRoute(manager.instance.Router(), domainMetadata("www.taobao.com"), "Proxy")
	if decision.index < 0 || decision.action != "route(direct)" {
		t.Fatalf("live core stopped routing after failed reload: %+v", decision)
	}
}

func TestDomesticRoutingReloadStartFailureRestoresPreviousCore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "test")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "proxy.json")
	if err := os.WriteFile(profilePath, []byte(`{
		"outbounds":[
			{"type":"socks","tag":"edge","server":"127.0.0.1","server_port":1},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{"final":"Proxy"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := adversarialCoreConfig(dir, profilePath, "")
	manager := startAdversarialCore(t, cfg)
	previousConfig := manager.cfg

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	conflictingPort := listener.Addr().(*net.TCPAddr).Port

	invalid := *cfg
	invalid.Core.MixedPort = conflictingPort
	err = manager.Reload(&invalid)
	if err == nil || !strings.Contains(err.Error(), "previous core restored") {
		t.Fatalf("port-conflict reload error = %v", err)
	}
	if manager.instance == nil || !manager.coreRunning.Load() || manager.cfg != previousConfig {
		t.Fatalf("previous core not restored: instance=%v running=%v cfgRestored=%v", manager.instance != nil, manager.coreRunning.Load(), manager.cfg == previousConfig)
	}
	decision := selectAdversarialRoute(manager.instance.Router(), domainMetadata("www.taobao.com"), "Proxy")
	if decision.index < 0 || decision.action != "route(direct)" {
		t.Fatalf("restored core routing = %+v", decision)
	}
}

func TestDomesticRoutingInvalidCacheFailsBeforeCoreStarts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".crosslink", "test")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "proxy.json")
	if err := os.WriteFile(profilePath, []byte(`{
		"outbounds":[{"type":"direct","tag":"Proxy"}],
		"route":{"final":"Proxy"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	blockingFile := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blockingFile, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := adversarialCoreConfig(dir, profilePath, "")
	cfg.Core.RuleSetDir = filepath.Join(blockingFile, "rulesets")
	manager := New(cfg)
	err := manager.Start()
	if err == nil || !strings.Contains(err.Error(), "prepare domestic rule-sets") {
		t.Fatalf("invalid cache start error = %v", err)
	}
	if manager.instance != nil || manager.coreRunning.Load() {
		t.Fatalf("core survived invalid rule-set cache: instance=%v running=%v", manager.instance != nil, manager.coreRunning.Load())
	}
}

func adversarialCoreConfig(dir, profilePath, rulesPath string) *appconfig.Config {
	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = profilePath
	cfg.Core.Rules = rulesPath
	cfg.Core.RuleSetDir = filepath.Join(dir, "rulesets")
	cfg.Core.StateFile = filepath.Join(dir, "proxy-state.json")
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	cfg.Core.LogLevel = "error"
	cfg.DirectOutbound.Interface = "crosslink-test-interface"
	return cfg
}

func startAdversarialCore(t *testing.T, cfg *appconfig.Config) *Manager {
	t.Helper()
	manager := New(cfg)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Disconnect() })
	return manager
}

func domainMetadata(domain string) adapter.InboundContext {
	return adapter.InboundContext{Domain: domain}
}

func ipMetadata(address string) adapter.InboundContext {
	return adapter.InboundContext{Destination: M.SocksaddrFrom(netip.MustParseAddr(address), 443)}
}

func selectAdversarialRoute(router adapter.Router, metadata adapter.InboundContext, final string) adversarialRouteDecision {
	for index, candidate := range router.Rules() {
		metadata.ResetRuleCache()
		if !candidate.Match(&metadata) {
			continue
		}
		action := candidate.Action()
		switch action.Type() {
		case C.RuleActionTypeRoute, C.RuleActionTypeReject, C.RuleActionTypeHijackDNS:
			return adversarialRouteDecision{index: index, actionType: action.Type(), action: action.String()}
		}
	}
	return adversarialRouteDecision{index: -1, actionType: "final", action: "route(" + final + ")"}
}
