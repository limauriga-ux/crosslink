package gui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunConnectivityTestsTreatsHTTPAuthAsReachable(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	svc := NewService(Options{Runner: &fakeRunner{}})
	report := svc.RunConnectivityTests(TestRequest{
		TimeoutMillis: 1000,
		HTTPClient:    server.Client(),
		Items: []TestTarget{{
			Name:           "api",
			URL:            server.URL,
			ExpectedPolicy: "DEFAULT",
		}},
	})
	if len(report.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(report.Results))
	}
	got := report.Results[0]
	if !got.Reachable || got.HTTPStatus != 403 || got.DurationMillis <= 0 {
		t.Fatalf("result = %+v", got)
	}
}

func TestRunConnectivityTestsStopsAtFirstRedirect(t *testing.T) {
	// Server perpetually redirects to itself with a growing query string,
	// the way bing.com does with `?cc=cn` when cookies are dropped between
	// hops. Without CheckRedirect override we'd hit the 10-redirect ceiling
	// and report unreachable; with the override we should see HTTPStatus=302
	// and Reachable=true after a single hop.
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, r.URL.Path+"?cc=cn"+r.URL.RawQuery, http.StatusFound)
	}))
	defer server.Close()

	svc := NewService(Options{Runner: &fakeRunner{}})
	report := svc.RunConnectivityTests(TestRequest{
		TimeoutMillis: 1000,
		HTTPClient:    server.Client(),
		Items:         []TestTarget{{Name: "bing-like", URL: server.URL}},
	})
	got := report.Results[0]
	if !got.Reachable || got.HTTPStatus != http.StatusFound {
		t.Fatalf("redirect handling broken: %+v", got)
	}
	if hits != 1 {
		t.Fatalf("expected exactly 1 server hit (no follow), got %d", hits)
	}
}

func TestRunConnectivityTestsTreats5xxAsReachable(t *testing.T) {
	// qq.com under default Go UA can return 501. After the UA fix it
	// typically returns 200, but the contract for connectivity tests is
	// "any HTTP response = network reachable" — so 5xx still counts.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}))
	defer server.Close()

	svc := NewService(Options{Runner: &fakeRunner{}})
	report := svc.RunConnectivityTests(TestRequest{
		TimeoutMillis: 1000,
		HTTPClient:    server.Client(),
		Items:         []TestTarget{{Name: "qq-like", URL: server.URL}},
	})
	got := report.Results[0]
	if !got.Reachable || got.HTTPStatus != http.StatusNotImplemented {
		t.Fatalf("5xx must count as reachable: %+v", got)
	}
}

func TestRunConnectivityTestsSendsBrowserUA(t *testing.T) {
	var gotUA string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewService(Options{Runner: &fakeRunner{}})
	svc.RunConnectivityTests(TestRequest{
		TimeoutMillis: 1000,
		HTTPClient:    server.Client(),
		Items:         []TestTarget{{Name: "ua-probe", URL: server.URL}},
	})
	if gotUA == "" || gotUA == "Go-http-client/1.1" {
		t.Fatalf("expected browser-style UA, got %q", gotUA)
	}
}

func TestRunConnectivityTestsMarksTimeoutUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewService(Options{Runner: &fakeRunner{}})
	report := svc.RunConnectivityTests(TestRequest{
		TimeoutMillis: 20,
		Items: []TestTarget{{
			Name: "slow",
			URL:  server.URL,
		}},
	})
	if len(report.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(report.Results))
	}
	if report.Results[0].Reachable || report.Results[0].Error == "" {
		t.Fatalf("result = %+v", report.Results[0])
	}
}

func TestRunSingleTestDirectBypassesEnvProxy(t *testing.T) {
	// A poisoned env proxy must not affect the direct path — the whole point
	// of the explicit transport is that "direct" is not negotiable.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")

	svc := NewService(Options{Runner: &fakeRunner{}})
	got := svc.RunSingleTest(TestTarget{Name: "direct", URL: server.URL}, "", 1)
	if !got.Reachable || got.HTTPStatus != http.StatusOK {
		t.Fatalf("direct result = %+v", got)
	}
}

func TestRunSingleTestViaProxyUsesAbsoluteURI(t *testing.T) {
	// A minimal forward proxy: it must receive the absolute-form request URI
	// (http://host/path), proving the probe actually went through the proxy
	// instead of dialing the origin directly.
	var sawAbsoluteURI bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() && r.URL.Host == "example.com" {
			sawAbsoluteURI = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	proxyAddr := proxy.Listener.Addr().String()

	svc := NewService(Options{Runner: &fakeRunner{}})
	got := svc.RunSingleTest(TestTarget{Name: "via", URL: "http://example.com/"}, proxyAddr, 1)
	if !got.Reachable {
		t.Fatalf("via-proxy result = %+v", got)
	}
	if !sawAbsoluteURI {
		t.Fatalf("proxy never saw an absolute URI for example.com; probe did not go through the proxy")
	}
}

func TestRunSingleTestAggregatesSamples(t *testing.T) {
	// Two out of three probes succeed; the result must be reachable, report
	// 2/3, and average the duration over the successful probes only.
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 2 {
			time.Sleep(50 * time.Millisecond) // still within timeout, but slow
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewService(Options{Runner: &fakeRunner{}})
	got := svc.RunSingleTest(TestTarget{Name: "flaky", URL: server.URL}, "", 3)
	if !got.Reachable || got.Samples != 3 || got.Successes != 3 || hits != 3 {
		t.Fatalf("aggregate = %+v (hits=%d), want reachable 3/3", got, hits)
	}
	if got.DurationMillis <= 0 {
		t.Fatalf("mean duration not computed: %+v", got)
	}
}

func TestRunSingleTestReportsFailureCount(t *testing.T) {
	// A dead target must report 0/N with an error, not a lone timeout.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := server.Listener.Addr().String()
	server.Close() // nothing is listening now

	svc := NewService(Options{Runner: &fakeRunner{}})
	got := svc.RunSingleTest(TestTarget{Name: "dead", URL: "http://" + addr}, "", 3)
	if got.Reachable || got.Successes != 0 || got.Samples != 3 || got.Error == "" {
		t.Fatalf("dead target = %+v, want unreachable 0/3 with error", got)
	}
}
