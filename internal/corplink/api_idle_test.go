package corplink

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limauriga-ux/crosslink/internal/config"
)

type idleTrackingRoundTripper struct {
	closed atomic.Int32
}

func (r *idleTrackingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.EOF
}

func (r *idleTrackingRoundTripper) CloseIdleConnections() {
	r.closed.Add(1)
}

func TestClientCloseIdleConnectionsDelegatesWithoutHoldingClientLock(t *testing.T) {
	cl := NewClientWithConfig(LoadSession(t.TempDir()+"/session.json"), config.CorplinkConfig{})
	rt := &idleTrackingRoundTripper{}
	cl.mu.Lock()
	cl.httpClient = &http.Client{Transport: rt}
	cl.mu.Unlock()

	cl.CloseIdleConnections()
	if got := rt.closed.Load(); got != 1 {
		t.Fatalf("CloseIdleConnections called %d times, want 1", got)
	}
}

func TestClientCloseIdleConnectionsWithNilHTTPClient(t *testing.T) {
	cl := NewClient(LoadSession(t.TempDir() + "/session.json"))
	cl.mu.Lock()
	cl.httpClient = nil
	cl.mu.Unlock()

	cl.CloseIdleConnections()
}

type closeBeforeListRoundTripper struct {
	closed atomic.Int32
	rounds atomic.Int32
}

func (r *closeBeforeListRoundTripper) CloseIdleConnections() {
	r.closed.Add(1)
}

func (r *closeBeforeListRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.rounds.Add(1)
	if r.closed.Load() == 0 {
		return nil, fmt.Errorf("stale transport was used")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"code":0,"message":"","data":[]}`)),
		Header:     make(http.Header),
	}, nil
}

func TestListNodesClosesIdleConnectionBeforeRequest(t *testing.T) {
	session := LoadSession(t.TempDir() + "/session.json")
	session.Server = "https://feilian.example:10443"
	client := NewClientWithConfig(session, config.CorplinkConfig{})
	transport := &closeBeforeListRoundTripper{}
	client.mu.Lock()
	client.httpClient = &http.Client{Transport: transport, Jar: session.Jar(), Timeout: time.Second}
	client.mu.Unlock()

	nodes, err := client.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 || transport.closed.Load() != 1 || transport.rounds.Load() != 1 {
		t.Fatalf("nodes=%v closes=%d rounds=%d", nodes, transport.closed.Load(), transport.rounds.Load())
	}
}

func TestResolveServerIPv4UsesPhysicalLookupAndReturnsAllUniqueAddresses(t *testing.T) {
	session := LoadSession(t.TempDir() + "/session.json")
	session.Server = "https://control.corp.example:10443"
	client := NewClientWithConfig(session, config.CorplinkConfig{})
	var lookedUp string
	var hadDeadline bool
	client.mu.Lock()
	client.lookupHost = func(ctx context.Context, host string) ([]string, error) {
		lookedUp = host
		_, hadDeadline = ctx.Deadline()
		return []string{"192.0.2.10", "10.20.0.4", "192.0.2.10", "2001:db8::1", "198.51.100.20"}, nil
	}
	client.mu.Unlock()

	addresses, err := client.ResolveServerIPv4(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lookedUp != "control.corp.example" || !hadDeadline {
		t.Fatalf("lookup host=%q deadline=%v", lookedUp, hadDeadline)
	}
	want := []string{"192.0.2.10", "10.20.0.4", "198.51.100.20"}
	if strings.Join(addresses, ",") != strings.Join(want, ",") {
		t.Fatalf("resolved addresses=%v want=%v", addresses, want)
	}
}
