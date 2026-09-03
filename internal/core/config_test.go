package core

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/corpendpoint"
	"github.com/limauriga-ux/crosslink/internal/profile"

	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	singjson "github.com/sagernet/sing/common/json"
)

func TestCompileConfigOwnsSystemLayers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = ""
	cfg.Core.Rules = ""
	cfg.Core.RuleSetDir = filepath.Join(home, ".crosslink", "rulesets")
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0

	compiled, err := compileConfig(cfg)
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
	if len(options.Endpoints) != 1 || options.Endpoints[0].Tag != corpEndpointTag {
		t.Fatalf("endpoints = %#v", options.Endpoints)
	}
	if len(options.Outbounds) != 3|| options.Outbounds[0].Tag != directTag || options.Outbounds[1].Tag != profile.OpenVPNTargetTag || options.Outbounds[1].Type != "block" || options.Outbounds[2].Tag != corpendpoint.PublicAuthOutboundTag {
		t.Fatalf("outbounds = %#v", options.Outbounds)
	}
	if options.DNS == nil || len(options.DNS.Servers) != 4 {
		t.Fatalf("dns = %#v", options.DNS)
	}
	tags := make(map[string]bool, len(options.DNS.Servers))
	for _, server := range options.DNS.Servers {
		tags[server.Tag] = true
	}
	if !tags[dnsTransportTag] || !tags[bootstrapDNSTag] || !tags[publicDNSTagPrefix+"1"] || !tags[publicDNSTagPrefix+"2"] {
		t.Fatalf("DNS tags = %#v", tags)
	}
}

func TestCompileConfigLetsSingTunAllocateDarwinInterface(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific TUN naming")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = ""
	cfg.Core.Rules = ""
	cfg.Core.RuleSetDir = filepath.Join(home, ".crosslink", "rulesets")
	cfg.Core.MixedPort = 0

	compiled, err := compileConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runtimeState := corpendpoint.NewRuntime()
	registries := newRegistries(runtimeState)
	ctx := registries.context(context.Background())
	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, compiled.content)
	if err != nil {
		t.Fatalf("generated config did not parse: %v\n%s", err, compiled.content)
	}
	if len(options.Inbounds) != 1 {
		t.Fatalf("inbounds = %#v", options.Inbounds)
	}
	tunOptions, ok := options.Inbounds[0].Options.(*option.TunInboundOptions)
	if !ok {
		t.Fatalf("TUN options type = %T", options.Inbounds[0].Options)
	}
	if tunOptions.InterfaceName != "" {
		t.Fatalf("compiled interface name = %q, want automatic allocation", tunOptions.InterfaceName)
	}
	allocated := tun.CalculateInterfaceName(tunOptions.InterfaceName)
	if !strings.HasPrefix(allocated, "utun") {
		t.Fatalf("sing-tun allocated name = %q", allocated)
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(allocated, "utun")); err != nil {
		t.Fatalf("sing-tun allocated invalid macOS name %q: %v", allocated, err)
	}
	existingInterfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, networkInterface := range existingInterfaces {
		if networkInterface.Name == allocated {
			t.Fatalf("sing-tun automatic allocation selected occupied interface %s", allocated)
		}
	}
}

func TestCompileConfigPreservesExplicitDarwinInterface(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific TUN naming")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = ""
	cfg.Core.Rules = ""
	cfg.Core.RuleSetDir = filepath.Join(home, ".crosslink", "rulesets")
	cfg.Core.MixedPort = 0
	cfg.TUN.Name = "utun1234"

	compiled, err := compileConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	root, err := singjson.UnmarshalExtended[map[string]any](compiled.content)
	if err != nil {
		t.Fatal(err)
	}
	inbounds := root["inbounds"].([]any)
	tunInbound := inbounds[0].(map[string]any)
	if tunInbound["interface_name"] != "utun1234" {
		t.Fatalf("compiled interface name = %#v", tunInbound["interface_name"])
	}
}

func TestCompileConfigOrdersInjectedRulesAroundProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	profilePath := filepath.Join(dir, "proxy.json")
	rulesPath := filepath.Join(dir, "rules.json")
	profileContent := []byte(`{
		"outbounds":[
			{"type":"direct","tag":"edge"},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		],
		"route":{
			"rules":[{"domain":["subscription.example"],"action":"route","outbound":"Proxy"}],
			"final":"Proxy"
		}
	}`)
	if err := os.WriteFile(profilePath, profileContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveRulePlanAtomic(rulesPath, profile.RulePlan{
		Prepend: []string{"DOMAIN,prepend.example,DIRECT"},
		Append:  []string{"DOMAIN,append.example,Proxy"},
	}); err != nil {
		t.Fatal(err)
	}

	cfg := appconfig.DefaultConfig()
	cfg.Core.Profile = profilePath
	cfg.Core.Rules = rulesPath
	cfg.Core.RuleSetDir = filepath.Join(dir, ".crosslink", "rulesets")
	cfg.Core.TUNEnabled = false
	cfg.Core.MixedPort = 0
	compiled, err := compileConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	root, err := singjson.UnmarshalExtended[map[string]any](compiled.content)
	if err != nil {
		t.Fatal(err)
	}
	route := root["route"].(map[string]any)
	rules := route["rules"].([]any)
	if len(rules) != 9 {
		t.Fatalf("compiled rules = %#v", rules)
	}
	wantDomains := []string{"prepend.example", "subscription.example", "append.example"}
	for offset, want := range wantDomains {
		rule := rules[3+offset].(map[string]any)
		domains := rule["domain"].([]any)
		if len(domains) != 1 || domains[0] != want {
			t.Fatalf("rule %d = %#v, want domain %s", 3+offset, rule, want)
		}
	}
	if rules[6].(map[string]any)["rule_set"].([]any)[0] != domesticDomainRuleSetTag ||
		rules[7].(map[string]any)["rule_set"].([]any)[0] != domesticIPRuleSetTag {
		t.Fatalf("domestic rules = %#v", rules[6:8])
	}
	if private, _ := rules[8].(map[string]any)["ip_is_private"].(bool); !private {
		t.Fatalf("final safety rule = %#v", rules[8])
	}
}
