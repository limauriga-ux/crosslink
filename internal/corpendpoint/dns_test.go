package corpendpoint

import (
	"context"
	"errors"
	"testing"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
)

type fakeDNSTransport struct {
	tag      string
	response *mdns.Msg
	err      error
	calls    int
}

func (f *fakeDNSTransport) Type() string                   { return "fake" }
func (f *fakeDNSTransport) Tag() string                    { return f.tag }
func (f *fakeDNSTransport) Dependencies() []string         { return nil }
func (f *fakeDNSTransport) Start(adapter.StartStage) error { return nil }
func (f *fakeDNSTransport) Close() error                   { return nil }
func (f *fakeDNSTransport) Reset()                         {}
func (f *fakeDNSTransport) Exchange(context.Context, *mdns.Msg) (*mdns.Msg, error) {
	f.calls++
	return f.response, f.err
}
func (f *fakeDNSTransport) ExchangeAsync(ctx context.Context, message *mdns.Msg, callback func(*mdns.Msg, error)) {
	response, err := f.Exchange(ctx, message)
	callback(response, err)
}

func TestPublicDNSDelegatesToProxyDoHTransport(t *testing.T) {
	query := new(mdns.Msg)
	query.SetQuestion("leak-test.example.", mdns.TypeA)
	response := new(mdns.Msg)
	response.SetReply(query)
	first := &fakeDNSTransport{tag: "first", err: errors.New("temporary failure")}
	second := &fakeDNSTransport{tag: "second", response: response}
	transport := &DNSTransport{
		runtime:          NewRuntime(),
		publicTransports: []adapter.DNSTransport{first, second},
	}

	got, err := transport.Exchange(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if got != response || first.calls != 1 || second.calls != 1 {
		t.Fatalf("response=%p calls=%d/%d", got, first.calls, second.calls)
	}
}

func TestAuthenticationScopeOverridesCorporateSuffix(t *testing.T) {
	query := new(mdns.Msg)
	query.SetQuestion("vpn.corp.example.", mdns.TypeA)
	response := new(mdns.Msg)
	response.SetReply(query)
	public := &fakeDNSTransport{tag: "public-doh", response: response}
	runtime := NewRuntime()
	runtime.UpdateRoutes(nil, []string{"corp.example"}, nil, false)
	runtime.SetPublicAuthScope("vpn.corp.example", 0)
	transport := &DNSTransport{runtime: runtime, publicTransports: []adapter.DNSTransport{public}}

	if !transport.PreferredDomain("vpn.corp.example") {
		t.Fatal("authentication hostname did not arm the DNS mux rule")
	}
	got, err := transport.Exchange(context.Background(), query)
	if err != nil || got != response || public.calls != 1 {
		t.Fatalf("authentication DNS response=%p calls=%d err=%v", got, public.calls, err)
	}

	idp := new(mdns.Msg)
	idp.SetQuestion("idp.vpn.corp.example.", mdns.TypeA)
	if _, err := transport.Exchange(context.Background(), idp); err != nil || public.calls != 2 {
		t.Fatalf("authentication IdP sibling calls=%d err=%v, want public DNS", public.calls, err)
	}

	sibling := new(mdns.Msg)
	sibling.SetQuestion("api.corp.example.", mdns.TypeA)
	if _, err := transport.Exchange(context.Background(), sibling); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-excepted corporate sibling error=%v, want unavailable corporate tunnel", err)
	}
	if public.calls != 2 {
		t.Fatalf("corporate sibling leaked to public DNS: calls=%d", public.calls)
	}
}

func TestCorporateDNSMuxDeclaresProxyDoHDependencies(t *testing.T) {
	transport := &DNSTransport{publicTags: []string{"doh-a", "doh-b"}}
	dependencies := transport.Dependencies()
	if len(dependencies) != 2 || dependencies[0] != "doh-a" || dependencies[1] != "doh-b" {
		t.Fatalf("dependencies = %#v", dependencies)
	}
	dependencies[0] = "mutated"
	if transport.publicTags[0] != "doh-a" {
		t.Fatal("Dependencies exposed internal slice")
	}
}
