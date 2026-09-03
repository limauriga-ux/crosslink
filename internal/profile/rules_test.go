package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileRulePlanUsesStrictClashSyntax(t *testing.T) {
	plan := RulePlan{
		Prepend: []string{
			"DOMAIN-SUFFIX,example.com,Proxy",
			"DOMAIN-KEYWORD,advert,REJECT",
		},
		Append: []string{"IP-CIDR,10.20.0.0/16,CORP,no-resolve"},
	}
	prepend, appendRules, err := CompileRulePlan(plan, []string{"Proxy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepend) != 2 || len(appendRules) != 1 {
		t.Fatalf("compiled counts = %d/%d", len(prepend), len(appendRules))
	}
	first := prepend[0].(map[string]any)
	if first["outbound"] != "Proxy" || first["domain_suffix"].([]string)[0] != ".example.com" {
		t.Fatalf("first rule = %#v", first)
	}
	second := prepend[1].(map[string]any)
	if second["action"] != "reject" {
		t.Fatalf("reject rule = %#v", second)
	}
	last := appendRules[0].(map[string]any)
	if last["outbound"] != "corp" || last["ip_cidr"].([]string)[0] != "10.20.0.0/16" {
		t.Fatalf("corporate rule = %#v", last)
	}
}

func TestCompileRulePlanAlwaysAcceptsOpenVPNAsFailClosedTarget(t *testing.T) {
	prepend, _, err := CompileRulePlan(RulePlan{Prepend: []string{
		"DOMAIN-SUFFIX,corp.example,OPENVPN",
		"IP-CIDR,10.20.0.0/16,openvpn-enterprise",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index, raw := range prepend {
		rule := raw.(map[string]any)
		if rule["outbound"] != OpenVPNTargetTag {
			t.Fatalf("rule %d = %#v", index, rule)
		}
	}
}

func TestCompileRulePlanRejectsUnavailableTargetsAndMatch(t *testing.T) {
	_, _, err := CompileRulePlan(RulePlan{Prepend: []string{"DOMAIN,example.com,Missing"}}, []string{"Proxy"})
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing-target error = %v", err)
	}
	_, _, err = CompileRulePlan(RulePlan{Append: []string{"MATCH,DIRECT"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "MATCH is not injectable") {
		t.Fatalf("MATCH error = %v", err)
	}
}

func TestRulePlanPersistsSeparatelyWithSecurePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	plan := RulePlan{
		Prepend: []string{"  DOMAIN,one.example,DIRECT  ", ""},
		Append:  []string{"# discarded comment", "NETWORK,tcp,REJECT"},
	}
	if err := SaveRulePlanAtomic(path, plan); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRulePlan(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != RulePlanVersion || len(loaded.Prepend) != 1 || len(loaded.Append) != 1 {
		t.Fatalf("loaded plan = %+v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("rule plan permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestInspectRuleContextPreservesProfileOrder(t *testing.T) {
	context, err := InspectRuleContext([]byte(`{
		"outbounds":[
			{"type":"direct","tag":"edge"},
			{"type":"selector","tag":"Proxy","outbounds":["edge"]},
			{"type":"direct","tag":"DIRECT"}
		],
		"route":{"rules":[{"domain":["profile.example"],"action":"route","outbound":"Proxy"}],"final":"Proxy"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(context.Targets) != 2 || context.Targets[0] != "edge" || context.Targets[1] != "Proxy" {
		t.Fatalf("targets = %#v", context.Targets)
	}
	if context.ProfileRuleCount != 1 || context.Final != "Proxy" {
		t.Fatalf("context = %+v", context)
	}
}
