package corplink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestLogoutClearsCredentialsAndRebindsClientJar(t *testing.T) {
	var mainServerURL string
	var logoutCalls atomic.Int32
	mainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/match":
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"code": 0, "data": map[string]string{"domain": mainServerURL},
			})
		case "/api/login/code/verify":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "auth-token", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "device_id", Value: "device", Path: "/"})
			json.NewEncoder(w).Encode(map[string]any{"code": 0}) //nolint:errcheck
		case "/api/logout":
			logoutCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"code": 0}) //nolint:errcheck
		default:
			t.Errorf("unexpected request path %s", r.URL.Path)
			json.NewEncoder(w).Encode(map[string]any{"code": 0}) //nolint:errcheck
		}
	}))
	defer mainServer.Close()
	mainServerURL = mainServer.URL

	sess := LoadSession(t.TempDir() + "/session.json")
	cl := NewClient(sess)
	cl.matchURLOverride = mainServer.URL + "/api/match"

	ctx := context.Background()
	if err := cl.DiscoverCompany(ctx, "test"); err != nil {
		t.Fatalf("DiscoverCompany failed: %v", err)
	}
	if err := cl.VerifyCode(ctx, "mobile", "user@example.com", "123456"); err != nil {
		t.Fatalf("VerifyCode failed: %v", err)
	}
	if !sess.IsAuthenticated() {
		t.Fatal("session was not authenticated before logout")
	}
	sess.mu.Lock()
	sess.TOTPSecret = "totp-secret"
	sess.mu.Unlock()

	oldServer, err := url.Parse(mainServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	cl.Logout(ctx)

	if got := logoutCalls.Load(); got != 1 {
		t.Fatalf("logout endpoint called %d time(s), want 1", got)
	}
	sess.mu.Lock()
	company := sess.CompanyName
	server := sess.Server
	totp := sess.TOTPSecret
	cookies := sess.Cookies
	sess.mu.Unlock()
	if company != "" || server != "" || totp != "" || len(cookies) != 0 {
		t.Fatalf("credentials survived logout: company=%q server=%q totp=%q cookies=%d", company, server, totp, len(cookies))
	}
	if sess.IsAuthenticated() {
		t.Fatal("session still authenticated after logout")
	}
	// The rebuilt client must never resend cookies from the pre-logout jar.
	cl.mu.RLock()
	httpClient := cl.httpClient
	cl.mu.RUnlock()
	if httpClient == nil {
		t.Fatal("HTTP client missing after logout")
	}
	if jarCookies := httpClient.Jar.Cookies(oldServer); len(jarCookies) != 0 {
		t.Fatalf("client jar still serves %d cookie(s) after logout", len(jarCookies))
	}
}

func TestLogoutClearsCredentialsWhenServerUnreachable(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closed.URL
	closed.Close()

	sess := LoadSession(t.TempDir() + "/session.json")
	sess.mu.Lock()
	sess.Server = closedURL
	sess.CompanyName = "test"
	sess.Cookies = []*SerialCookie{{Name: "session", Value: "token", Path: "/"}}
	sess.TOTPSecret = "totp-secret"
	sess.rebuildJar()
	sess.mu.Unlock()
	cl := NewClient(sess)

	cl.Logout(context.Background())

	if sess.IsAuthenticated() {
		t.Fatal("session still authenticated after unreachable-server logout")
	}
	sess.mu.Lock()
	company, server, totp, cookies := sess.CompanyName, sess.Server, sess.TOTPSecret, sess.Cookies
	sess.mu.Unlock()
	if company != "" || server != "" || totp != "" || len(cookies) != 0 {
		t.Fatalf("credentials survived unreachable-server logout: company=%q server=%q totp=%q cookies=%d", company, server, totp, len(cookies))
	}
}
