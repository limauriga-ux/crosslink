package corpendpoint

import (
	"net/netip"
	"testing"
)

func TestEndpointPreferredRoutesYieldToArmedAuthScope(t *testing.T) {
	runtime := NewRuntime()
	runtime.UpdateRoutes([]string{"10.42.0.0/16"}, []string{"corp.example"}, nil, false)
	endpoint := &Endpoint{runtime: runtime}

	if !endpoint.PreferredDomain(nil, "api.corp.example") {
		t.Fatal("corporate suffix did not select the corporate endpoint")
	}
	if !endpoint.PreferredAddress(nil, netip.MustParseAddr("10.42.1.5")) {
		t.Fatal("corporate route did not select the corporate endpoint")
	}

	runtime.SetPublicAuthScope("vpn.corp.example", 0)
	if endpoint.PreferredDomain(nil, "vpn.corp.example") || endpoint.PreferredDomain(nil, "idp.vpn.corp.example") {
		t.Fatal("armed authentication domain still claimed by the corporate endpoint")
	}
	if !endpoint.PreferredDomain(nil, "api.corp.example") {
		t.Fatal("authentication scope shadowed an unrelated corporate suffix")
	}

	runtime.SetPublicAuthScope("10.42.1.5", 0)
	if endpoint.PreferredAddress(nil, netip.MustParseAddr("10.42.1.5")) {
		t.Fatal("armed authentication address still claimed by the corporate endpoint")
	}
	if !endpoint.PreferredAddress(nil, netip.MustParseAddr("10.42.1.6")) {
		t.Fatal("authentication scope shadowed an unrelated corporate address")
	}

	runtime.SetPublicAuthScope("", 0)
	if !endpoint.PreferredDomain(nil, "vpn.corp.example") || !endpoint.PreferredAddress(nil, netip.MustParseAddr("10.42.1.5")) {
		t.Fatal("cleared authentication scope did not restore corporate preference")
	}
}
