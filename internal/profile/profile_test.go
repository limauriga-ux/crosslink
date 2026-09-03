package profile

import (
	"strings"
	"testing"

	singjson "github.com/sagernet/sing/common/json"
)

func TestNormalizeClashCreatesLocalSelector(t *testing.T) {
	content := []byte(`
proxies:
  - name: edge
    type: ss
    server: 203.0.113.10
    port: 443
    cipher: aes-128-gcm
    password: secret
tun:
  enable: true
dns:
  enable: true
`)

	normalized, report, err := Normalize(content)
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != "clash" || report.Nodes != 1 {
		t.Fatalf("report = %+v", report)
	}
	root, err := singjson.UnmarshalExtended[map[string]any](normalized)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := root["tun"]; exists {
		t.Fatal("remote Clash TUN settings escaped normalization")
	}
	if _, exists := root["dns"]; exists {
		t.Fatal("remote Clash DNS settings escaped normalization")
	}
	route, ok := root["route"].(map[string]any)
	if !ok || route["final"] != "Proxy" {
		t.Fatalf("route = %#v", root["route"])
	}
}

func TestNormalizeClashPreservesGroupsAndRules(t *testing.T) {
	content := []byte(`
proxies:
  - { name: ECorpLink, type: socks5, server: 127.0.0.1, port: 7890 }
  - { name: edge, type: ss, server: 203.0.113.10, port: 443, cipher: aes-128-gcm, password: secret }
proxy-groups:
  - { name: Company, type: select, proxies: [ECorpLink, DIRECT] }
  - { name: 节点选择, type: select, proxies: [ECorpLink, edge, DIRECT] }
rules:
  - DOMAIN-SUFFIX,corp.example,Company
  - DOMAIN-SUFFIX,example.com,节点选择
  - DOMAIN-KEYWORD,advert,REJECT
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
`)

	normalized, report, err := Normalize(content)
	if err != nil {
		t.Fatal(err)
	}
	root, err := singjson.UnmarshalExtended[map[string]any](normalized)
	if err != nil {
		t.Fatal(err)
	}
	outbounds := root["outbounds"].([]any)
	for _, raw := range outbounds {
		outbound := raw.(map[string]any)
		if outbound["tag"] == "ECorpLink" || outbound["tag"] == "Company" {
			t.Fatalf("legacy corporate proxy/group survived: %#v", outbound)
		}
	}
	route := root["route"].(map[string]any)
	if route["final"] != "节点选择" {
		t.Fatalf("route final = %#v", route["final"])
	}
	rules := route["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("converted rules = %#v", rules)
	}
	if rules[0].(map[string]any)["outbound"] != "corp" {
		t.Fatalf("corporate rule = %#v", rules[0])
	}
	if rules[2].(map[string]any)["outbound"] != "block" {
		t.Fatalf("reject rule = %#v", rules[2])
	}
	if len(report.Warnings) == 0 || !strings.Contains(strings.Join(report.Warnings, "\n"), "GEOIP") {
		t.Fatalf("warnings = %#v, want GEOIP compatibility warning", report.Warnings)
	}
}

func TestNormalizeSingBoxRejectsReservedEntriesAndActions(t *testing.T) {
	content := []byte(`{
  "outbounds": [
    {"type":"direct","tag":"unsafe-direct"},
    {"type":"socks","tag":"safe","server":"127.0.0.1","server_port":1080}
  ],
  "endpoints": [{"type":"corplink","tag":"foreign-corp"}],
  "route": {
    "rules": [
      {"action":"hijack-dns"},
      {"domain_suffix":"example.com","action":"route","outbound":"safe"}
    ],
    "final":"safe"
  },
  "services": [{"type":"api","listen":"0.0.0.0"}]
}`)

	normalized, _, err := Normalize(content)
	if err != nil {
		t.Fatal(err)
	}
	root, err := singjson.UnmarshalExtended[map[string]any](normalized)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := root["services"]; exists {
		t.Fatal("remote service settings escaped normalization")
	}
	endpoints, _ := root["endpoints"].([]any)
	if len(endpoints) != 0 {
		t.Fatalf("reserved endpoint survived: %#v", endpoints)
	}
	route := root["route"].(map[string]any)
	rules := route["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("unsafe route action survived: %#v", rules)
	}
}

func TestPreviewGroupsReadsSanitizedProfile(t *testing.T) {
	content := []byte(`{
		"outbounds":[
			{"type":"direct","tag":"edge"},
			{"type":"selector","tag":"Proxy","outbounds":["edge"],"default":"edge"}
		]
	}`)
	groups, err := PreviewGroups(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Tag != "Proxy" || groups[0].Selected != "edge" || len(groups[0].Items) != 1 {
		t.Fatalf("groups = %+v", groups)
	}
}
