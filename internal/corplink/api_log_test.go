package corplink

import (
	"net/http"
	"strings"
	"testing"

	"github.com/limauriga-ux/crosslink/internal/config"
)

func TestRedactHTTPLogBodyMasksSensitiveFields(t *testing.T) {
	body := []byte(`{"user_name":"alice@example.com","code":"123456","token":"qr-token","totp_secret":"totp","nested":{"cookie":"secret-cookie"},"safe":"ok"}`)
	got := redactHTTPLogBody(body, 2048)
	text := string(got)
	for _, secret := range []string{"alice@example.com", "123456", "qr-token", "totp", "secret-cookie"} {
		if strings.Contains(text, secret) {
			t.Fatalf("redacted body still contains %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, `"safe":"ok"`) {
		t.Fatalf("redacted body lost non-sensitive field: %s", text)
	}
}

func TestClientTLSAndBodyLoggingDefaults(t *testing.T) {
	cl := NewClient(LoadSession(t.TempDir() + "/session.json"))
	tr, ok := cl.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", cl.httpClient.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default client must verify TLS certificates")
	}
	if cl.httpBodyLoggingEnabled() {
		t.Fatal("HTTP body logging should be disabled by default")
	}
}

func TestClientTLSAndBodyLoggingFollowConfig(t *testing.T) {
	cl := NewClientWithConfig(LoadSession(t.TempDir()+"/session.json"), config.CorplinkConfig{
		InsecureSkipVerify: false,
		DebugHTTPBody:      true,
	})
	tr, ok := cl.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", cl.httpClient.Transport)
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure_skip_verify=false should enable TLS verification")
	}
	if !cl.httpBodyLoggingEnabled() {
		t.Fatal("debug_http_body=true should enable HTTP body logging")
	}
}
