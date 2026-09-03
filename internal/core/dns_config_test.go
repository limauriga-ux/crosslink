package core

import (
	"reflect"
	"testing"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
)

func TestBuildDNSServersDetoursPublicDoHThroughSelectedProxy(t *testing.T) {
	servers, err := buildDNSServers(appconfig.ProxyDoHDefaults(), "Proxy", "en0")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 4 {
		t.Fatalf("DNS servers = %#v", servers)
	}
	mux := servers[0].(map[string]any)
	if mux["type"] != "corplink" || mux["tag"] != dnsTransportTag {
		t.Fatalf("DNS mux = %#v", mux)
	}
	wantPublicTags := []string{publicDNSTagPrefix + "1", publicDNSTagPrefix + "2"}
	if !reflect.DeepEqual(mux["public_transports"], wantPublicTags) {
		t.Fatalf("public transports = %#v", mux["public_transports"])
	}
	bootstrap := servers[1].(map[string]any)
	if bootstrap["type"] != "udp" || bootstrap["tag"] != bootstrapDNSTag || bootstrap["bind_interface"] != "en0" || bootstrap["server"] != "114.114.114.114" {
		t.Fatalf("bootstrap DNS = %#v", bootstrap)
	}
	wantHosts := []string{"1.1.1.1", "8.8.8.8"}
	wantSNI := []string{"cloudflare-dns.com", "dns.google"}
	for index, raw := range servers[2:] {
		server := raw.(map[string]any)
		if server["type"] != "https" || server["detour"] != "Proxy" || server["server"] != wantHosts[index] {
			t.Fatalf("public DoH %d = %#v", index+1, server)
		}
		if server["domain_resolver"] != nil {
			t.Fatalf("fixed-IP public DoH unexpectedly needs bootstrap: %#v", server)
		}
		tlsOptions := server["tls"].(map[string]any)
		if tlsOptions["server_name"] != wantSNI[index] {
			t.Fatalf("public DoH SNI %d = %#v", index+1, tlsOptions)
		}
	}
}

func TestBuildDNSServersAutoBindsBootstrapToPhysicalInterface(t *testing.T) {
	previous := detectPhysicalInterface
	detectPhysicalInterface = func() (string, error) { return "en-test", nil }
	defer func() { detectPhysicalInterface = previous }()

	servers, err := buildDNSServers(appconfig.ProxyDoHDefaults(), "Proxy", "")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := servers[1].(map[string]any)
	if bootstrap["bind_interface"] != "en-test" {
		t.Fatalf("bootstrap DNS did not bind physical interface: %#v", bootstrap)
	}
}

func TestProxyServerDomainsUseBootstrapDoH(t *testing.T) {
	original := map[string]any{"type": "anytls", "tag": "edge", "server": "edge.example"}
	compiled := withBootstrapDomainResolver(original)
	if compiled["domain_resolver"] != bootstrapDNSTag {
		t.Fatalf("compiled outbound = %#v", compiled)
	}
	if _, exists := original["domain_resolver"]; exists {
		t.Fatal("profile outbound was mutated in place")
	}
	ipOutbound := map[string]any{"type": "anytls", "tag": "ip-edge", "server": "203.0.113.8"}
	if got := withBootstrapDomainResolver(ipOutbound); got["domain_resolver"] != nil {
		t.Fatalf("IP outbound unexpectedly needs DNS: %#v", got)
	}
}
