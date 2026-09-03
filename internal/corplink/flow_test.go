package corplink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// newMockCorplinkServer creates a mock corplink server matching the real API structure.
func newMockCorplinkServer(t *testing.T, domainFn func() string, loginOrders, loginAccount []string, scanEnabled bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/match", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		t.Logf("  POST /api/match  code=%q", req.Code)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"code": 0, "data": map[string]string{"domain": domainFn()},
		})
	})

	mux.HandleFunc("/api/login/setting", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("  GET /api/login/setting  query=%q", r.URL.RawQuery)
		if !strings.Contains(r.URL.RawQuery, "os=Android") {
			t.Errorf("missing os=Android in query: %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"code": 0,
			"data": map[string]any{
				"login_orders":           loginOrders,
				"login_account":          loginAccount,
				"scan_code_login_enable": scanEnabled,
				"scan_code_tps":          []string{"feisian", "lark"},
			},
		})
	})

	return httptest.NewServer(mux)
}

// TestDiscoverAndLoginMethods uses the real response structure returned by CorpLink.
func TestDiscoverAndLoginMethods(t *testing.T) {
	var serverURL string
	ts := newMockCorplinkServer(t,
		func() string { return serverURL },
		[]string{"feilian", "lark"},
		[]string{"email", "mobile"},
		true,
	)
	defer ts.Close()
	serverURL = ts.URL

	sess := LoadSession(t.TempDir() + "/session.json")
	cl := NewClient(sess)
	cl.matchURLOverride = ts.URL + "/api/match"

	ctx := context.Background()

	t.Log("Step 1: DiscoverCompany")
	if err := cl.DiscoverCompany(ctx, "test"); err != nil {
		t.Fatalf("DiscoverCompany failed: %v", err)
	}
	if sess.Server == "" {
		t.Fatal("Server not set after DiscoverCompany")
	}
	t.Logf("  Server: %s", sess.Server)

	t.Log("Step 2: LoginMethods")
	info, err := cl.LoginMethods(ctx)
	if err != nil {
		t.Fatalf("LoginMethods failed: %v", err)
	}
	if len(info.Methods) == 0 {
		t.Fatal("LoginMethods returned empty list")
	}
	t.Logf("  Methods: %v", info.Methods)

	want := map[string]bool{"email": true, "mobile": true, "lark": true}
	for _, m := range info.Methods {
		if !want[m] {
			t.Errorf("unexpected method %q", m)
		}
		delete(want, m)
	}
	for m := range want {
		t.Errorf("missing expected method %q", m)
	}
}

func TestLoginMethodsOnlyEmail(t *testing.T) {
	var serverURL string
	ts := newMockCorplinkServer(t,
		func() string { return serverURL },
		[]string{"feilian"},
		[]string{"email"},
		false,
	)
	defer ts.Close()
	serverURL = ts.URL

	sess := LoadSession(t.TempDir() + "/session.json")
	cl := NewClient(sess)
	cl.matchURLOverride = ts.URL + "/api/match"

	cl.DiscoverCompany(context.Background(), "test") //nolint:errcheck

	info, err := cl.LoginMethods(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Methods) != 1 || info.Methods[0] != "email" {
		t.Fatalf("want [email], got %v", info.Methods)
	}
	t.Logf("Methods: %v", info.Methods)
}

func TestDiscoverEmptyDomain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"code": 0, "data": map[string]string{"domain": ""},
		})
	}))
	defer ts.Close()

	sess := LoadSession(t.TempDir() + "/session.json")
	cl := NewClient(sess)
	cl.matchURLOverride = ts.URL + "/api/match"

	err := cl.DiscoverCompany(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for empty domain, got nil")
	}
	t.Logf("Got expected error: %v", err)
}

func TestDiscoverAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"code": 404, "message": "company not found",
		})
	}))
	defer ts.Close()

	sess := LoadSession(t.TempDir() + "/session.json")
	cl := NewClient(sess)
	cl.matchURLOverride = ts.URL + "/api/match"

	err := cl.DiscoverCompany(context.Background(), "invalid")
	if err == nil || !strings.Contains(err.Error(), "company not found") {
		t.Fatalf("expected 'company not found' error, got: %v", err)
	}
	t.Logf("Got expected error: %v", err)
}

// TestDiscoverBytedanceRealAPI hits the real corplink match endpoint with
// company_name="bytedance" and verifies that DiscoverCompany resolves a
// valid server URL and that LoginMethods can be fetched from it.
//
// Network-dependent: hits an external CN endpoint. GitHub-hosted runners
// (especially macOS-15) can't reach it reliably and time out at 20s,
// failing the whole release build. Skip in CI (`CI`/`GITHUB_ACTIONS` env)
// and when -short is passed.
func TestDiscoverBytedanceRealAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent real-API test in -short mode")
	}
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("skipping network-dependent real-API test in CI (endpoint unreachable from GitHub runners)")
	}
	ctx := context.Background()
	sess := LoadSession(t.TempDir() + "/session.json")
	cl := NewClient(sess)

	t.Log("Step 1: DiscoverCompany with real API (company=bytedance)")
	if err := cl.DiscoverCompany(ctx, "bytedance"); err != nil {
		t.Fatalf("DiscoverCompany failed: %v", err)
	}
	if sess.Server == "" {
		t.Fatal("Server not set after DiscoverCompany")
	}
	t.Logf("  Resolved Server: %s", sess.Server)
	t.Logf("  CompanyName: %s", sess.CompanyName)

	// Verify the resolved URL is well-formed.
	if !strings.HasPrefix(sess.Server, "http://") && !strings.HasPrefix(sess.Server, "https://") {
		t.Fatalf("resolved Server %q missing scheme", sess.Server)
	}

	t.Log("Step 2: LoginMethods from resolved server")
	info, err := cl.LoginMethods(ctx)
	if err != nil {
		t.Fatalf("LoginMethods failed: %v", err)
	}
	if len(info.Methods) == 0 {
		t.Fatal("LoginMethods returned empty list")
	}
	t.Logf("  Available methods: %v", info.Methods)
	t.Logf("  Verify types: %v", info.VerifyTypes)
}

// TestCookieInjectionToNodeHost verifies that cookies set by the main server
// are correctly sent to VPN node requests on a different host.
func TestCookieInjectionToNodeHost(t *testing.T) {
	var mainServerURL string
	var nodeReceivedCookies string

	// Main server: sets auth cookies on login verify
	mainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/match":
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"code": 0, "data": map[string]string{"domain": mainServerURL},
			})
		case "/api/login/code/verify":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-session-token", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "device_id", Value: "test-device-id", Path: "/"})
			json.NewEncoder(w).Encode(map[string]any{"code": 0}) //nolint:errcheck
		}
	}))
	defer mainServer.Close()
	mainServerURL = mainServer.URL

	// Node server: record what cookies it receives
	nodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nodeReceivedCookies = r.Header.Get("Cookie")
		t.Logf("  Node received Cookie header: %q", nodeReceivedCookies)
		json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "pong"}) //nolint:errcheck
	}))
	defer nodeServer.Close()

	sess := LoadSession(t.TempDir() + "/session.json")
	cl := NewClient(sess)
	cl.matchURLOverride = mainServer.URL + "/api/match"

	ctx := context.Background()

	// Step 1: discover + login (sets cookies)
	if err := cl.DiscoverCompany(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if err := cl.VerifyCode(ctx, "mobile", "1234567890", "123456"); err != nil {
		t.Fatal(err)
	}

	// Step 2: make request to a different host (simulating VPN node)
	var resp any
	if err := cl.get(ctx, nodeServer.URL+"/vpn/ping?os=Android&os_version=2", &resp); err != nil {
		t.Fatalf("node request failed: %v", err)
	}

	// Verify cookies were injected
	if !strings.Contains(nodeReceivedCookies, "session=test-session-token") {
		t.Errorf("session cookie NOT injected to node host. got: %q", nodeReceivedCookies)
	}
	if !strings.Contains(nodeReceivedCookies, "device_id=test-device-id") {
		t.Errorf("device_id cookie NOT injected to node host. got: %q", nodeReceivedCookies)
	}
	t.Logf("✓ Cookies correctly injected to different host")
}

// TestSessionExpiredErrorDetection verifies code 10220002 is reported as auth error.
func TestSessionExpiredErrorDetection(t *testing.T) {
	var mainServerURL string

	mainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/match" {
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"code": 0, "data": map[string]string{"domain": mainServerURL},
			})
			return
		}
		// All other requests: session expired
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"code": 10220002, "message": "The session is expired",
		})
	}))
	defer mainServer.Close()
	mainServerURL = mainServer.URL

	sess := LoadSession(t.TempDir() + "/session.json")
	cl := NewClient(sess)
	cl.matchURLOverride = mainServer.URL + "/api/match"
	cl.DiscoverCompany(context.Background(), "test") //nolint:errcheck

	_, err := cl.LoginMethods(context.Background())
	if err == nil {
		t.Fatal("expected error for session expired, got nil")
	}
	if !IsSessionExpired(err) {
		t.Errorf("expected IsSessionExpired=true, got false. err=%v", err)
	}
	t.Logf("✓ Session expired correctly detected: %v", err)
}
