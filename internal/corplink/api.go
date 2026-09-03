package corplink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/outbound"
)

const (
	matchURL  = "https://corplink.volcengine.cn/api/match"
	osQuery   = "os=Android&os_version=2"
	userAgent = "CorpLink/201000 (GooglePixel; Android 10; en)"
)

type apiResp[T any] struct {
	Code    int    `json:"code"`
	Action  string `json:"action,omitempty"`
	Message string `json:"message"`
	Data    T      `json:"data"`
}

type hostLookupFunc func(context.Context, string) ([]string, error)

// Client is an HTTP client for the corplink API.
type Client struct {
	session          *Session
	mu               sync.RWMutex
	httpClient       *http.Client
	lookupHost       hostLookupFunc
	debugBody        bool
	matchURLOverride string // non-empty overrides the default matchURL (used in tests)
}

// NewClient creates a Client using the session's cookie jar.
func NewClient(session *Session) *Client {
	return NewClientWithConfig(session, config.DefaultConfig().Corplink)
}

// NewClientWithConfig creates a Client using the session's cookie jar and
// Corplink-specific transport/logging settings.
func NewClientWithConfig(session *Session, cfg config.CorplinkConfig) *Client {
	httpClient, lookupHost := newHTTPClient(session, cfg)
	return &Client{
		session:    session,
		httpClient: httpClient,
		lookupHost: lookupHost,
		debugBody:  cfg.DebugHTTPBody,
	}
}

func (c *Client) Configure(cfg config.CorplinkConfig) {
	httpClient, lookupHost := newHTTPClient(c.session, cfg)
	c.mu.Lock()
	previous := c.httpClient
	c.httpClient = httpClient
	c.lookupHost = lookupHost
	c.debugBody = cfg.DebugHTTPBody
	c.mu.Unlock()
	if previous != nil {
		previous.CloseIdleConnections()
	}
}

// rebindJar replaces the HTTP client with one that shares the current
// transport but stores response cookies in the session's latest jar.
// Session.rebuildJar swaps the jar object (cookiejar has no clear API), so
// the client must be rebuilt for Set-Cookie responses to land in the right
// jar; mutating Client.Jar in place would race requests that already
// snapshotted the client in do.
func (c *Client) rebindJar() {
	jar := c.session.Jar()
	c.mu.Lock()
	previous := c.httpClient
	if previous != nil {
		c.httpClient = &http.Client{Transport: previous.Transport, Jar: jar, Timeout: previous.Timeout}
	}
	c.mu.Unlock()
	if previous != nil {
		// Idle keep-alive sockets may still be authorized by the old jar.
		previous.CloseIdleConnections()
	}
}

func newHTTPClient(session *Session, cfg config.CorplinkConfig) (*http.Client, hostLookupFunc) {
	tlsTemplate := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // explicit compatibility option for private PKI
	plainDialer := &net.Dialer{}
	dialContext := plainDialer.DialContext
	lookupHost := func(context.Context, string) ([]string, error) {
		return nil, fmt.Errorf("physical bootstrap DNS resolver is unavailable")
	}
	direct := outbound.NewDirect(cfg.DirectInterface, cfg.PublicDNS)
	if err := direct.Init(); err != nil {
		log.Printf("[corplink] physical interface binding unavailable: %v", err)
	} else {
		boundDialer := direct.DialerWithDNS()
		if boundDialer.Resolver != nil {
			lookupHost = boundDialer.Resolver.LookupHost
		}
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(address)
			ip := net.ParseIP(strings.Trim(host, "[]"))
			if strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()) {
				return plainDialer.DialContext(ctx, network, address)
			}
			return boundDialer.DialContext(ctx, network, address)
		}
	}
	transport := newHTTPTransport(session, tlsTemplate, dialContext)
	return &http.Client{
		Jar:       session.Jar(),
		Transport: transport,
		Timeout:   20 * time.Second,
	}, lookupHost
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func newHTTPTransport(session *Session, tlsTemplate *tls.Config, dialContext dialContextFunc) *http.Transport {
	transport := &http.Transport{
		TLSClientConfig:   tlsTemplate.Clone(),
		DialContext:       dialContext,
		ForceAttemptHTTP2: true,
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		rawConn, err := dialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		tlsConfig := tlsTemplate.Clone()
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = tlsServerNameForAddress(session, address)
		}
		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return transport
}

func tlsServerNameForAddress(session *Session, address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return strings.Trim(address, "[]")
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) == nil {
		return host
	}
	session.mu.Lock()
	serverURL := session.Server
	session.mu.Unlock()
	parsed, err := url.Parse(serverURL)
	if err == nil {
		serverName := parsed.Hostname()
		if serverName != "" && net.ParseIP(serverName) == nil {
			return serverName
		}
	}
	return host
}

// CloseIdleConnections drops keep-alive connections retained by the current
// HTTP transport. A network hand-off can leave those sockets bound to an old
// physical interface; the next request must establish a fresh connection
// instead of waiting for the old path to time out.
func (c *Client) CloseIdleConnections() {
	c.mu.RLock()
	httpClient := c.httpClient
	c.mu.RUnlock()
	if httpClient != nil {
		httpClient.CloseIdleConnections()
	}
}

// ResolveServerIPv4 resolves the authenticated control server through the
// same physical-interface bootstrap resolver used by HTTP dialing. It never
// consults a VPN-overridden system resolver, which may return an internal
// split-horizon address that is unreachable on the physical interface.
func (c *Client) ResolveServerIPv4(ctx context.Context) ([]string, error) {
	c.session.mu.Lock()
	server := c.session.Server
	c.session.mu.Unlock()
	if strings.TrimSpace(server) == "" {
		return nil, nil
	}
	parsed, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("parse CorpLink server: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("CorpLink server has no hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return []string{ip4.String()}, nil
		}
		return nil, fmt.Errorf("CorpLink server has no IPv4 address")
	}
	c.mu.RLock()
	lookupHost := c.lookupHost
	c.mu.RUnlock()
	if lookupHost == nil {
		return nil, fmt.Errorf("CorpLink physical resolver is unavailable")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := lookupHost(lookupCtx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve CorpLink server %q: %w", host, err)
	}
	seen := make(map[string]struct{}, len(addresses))
	result := make([]string, 0, len(addresses))
	for _, raw := range addresses {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To4() == nil {
			continue
		}
		value := ip.To4().String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("resolve CorpLink server %q: no IPv4 addresses", host)
	}
	return result, nil
}

func (c *Client) post(ctx context.Context, rawURL string, body, out any) error {
	return c.do(ctx, http.MethodPost, rawURL, body, out)
}

func (c *Client) get(ctx context.Context, rawURL string, out any) error {
	return c.do(ctx, http.MethodGet, rawURL, nil, out)
}

func (c *Client) do(ctx context.Context, method, rawURL string, body, out any) error {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	c.mu.RLock()
	httpClient := c.httpClient
	debugBody := c.debugBody
	c.mu.RUnlock()
	log.Printf("[corplink] → %s %s", method, rawURL)
	if debugBody && len(bodyBytes) > 0 {
		log.Printf("[corplink] → body=%s", redactHTTPLogBody(bodyBytes, 512))
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	c.session.mu.Lock()
	serverStr := c.session.Server
	c.session.mu.Unlock()

	if serverStr != "" {
		if serverURL, err2 := url.Parse(serverStr); err2 == nil {
			reqURL, _ := url.Parse(rawURL)

			// Always inject all session cookies manually as a Cookie header.
			// This bypasses Go's cookiejar domain-matching so VPN node requests
			// (different host/IP) get the same cookies as the main server.
			cookies := c.session.Jar().Cookies(serverURL)
			if len(cookies) > 0 {
				var parts []string
				for _, ck := range cookies {
					parts = append(parts, ck.Name+"="+ck.Value)
					if ck.Name == "csrf-token" {
						req.Header.Set("X-Csrf-Token", ck.Value)
					}
				}
				req.Header.Set("Cookie", strings.Join(parts, "; "))
				if reqURL != nil && reqURL.Host != serverURL.Host {
					log.Printf("[corplink] injected %d cookies for cross-host %s", len(parts), reqURL.Host)
				}
			}
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[corplink] ← ERROR %s: %v", rawURL, err)
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	log.Printf("[corplink] ← %d %s", resp.StatusCode, rawURL)
	if debugBody && len(respBody) > 0 {
		log.Printf("[corplink] ← body=%s", redactHTTPLogBody(respBody, 1024))
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(bytes.NewReader(respBody)).Decode(out); err != nil {
		return err
	}
	// Detect session expiry from API response envelope before the caller checks.
	var envelope struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if json.NewDecoder(bytes.NewReader(respBody)).Decode(&envelope) == nil {
		if envelope.Code == 101 || envelope.Code == 10220002 {
			return fmt.Errorf("%w: %s", ErrSessionExpired, envelope.Message)
		}
	}
	return nil
}

func truncate(b []byte, max int) string {
	s := string(b)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func (c *Client) httpBodyLoggingEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.debugBody
}

func redactHTTPLogBody(body []byte, max int) []byte {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return []byte("<redacted non-json body>")
	}
	redactJSONValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return []byte("<redacted body>")
	}
	if len(out) > max {
		return []byte(truncate(out, max))
	}
	return out
}

func redactJSONValue(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if sensitiveHTTPLogKey(k) {
				delete(x, k)
				x["redacted"] = "[masked]"
				continue
			}
			redactJSONValue(child)
		}
	case []any:
		for _, child := range x {
			redactJSONValue(child)
		}
	}
}

func sensitiveHTTPLogKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "_", "-")
	switch key {
	case "authorization", "code", "cookie", "cookies", "csrf-token", "jwt", "login-url", "password", "private-key", "public-key", "qr-token", "server-public-key", "set-cookie", "token", "totp-secret", "user-name", "vpn-ip":
		return true
	default:
		return strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "cookie")
	}
}

// ErrSessionExpired is returned when the server reports a session expiry (code 101 or 10220002).
var ErrSessionExpired = fmt.Errorf("session expired")

// IsSessionExpired reports whether err is (or wraps) a session-expiry error.
func IsSessionExpired(err error) bool {
	return err != nil && strings.Contains(err.Error(), ErrSessionExpired.Error())
}

// CopySessionCookiesToURL copies authentication cookies from the main server
// to the given VPN node URL so that node API calls (ping, conn) are authorized.
// Cookies are stripped of their Domain attribute before copying so that
// Go's cookiejar accepts them for a different host (VPN node IP).
func (c *Client) CopySessionCookiesToURL(nodeBaseURL string) {
	c.session.mu.Lock()
	serverStr := c.session.Server
	c.session.mu.Unlock()
	if serverStr == "" {
		return
	}
	serverURL, err := url.Parse(serverStr)
	if err != nil {
		return
	}
	nodeURL, err := url.Parse(nodeBaseURL)
	if err != nil {
		return
	}
	jar := c.session.Jar()
	cookies := jar.Cookies(serverURL)
	if len(cookies) == 0 {
		return
	}
	// Strip Domain so cookiejar accepts them for the node's IP host.
	stripped := make([]*http.Cookie, len(cookies))
	for i, ck := range cookies {
		stripped[i] = &http.Cookie{
			Name:  ck.Name,
			Value: ck.Value,
			Path:  "/",
		}
	}
	jar.SetCookies(nodeURL, stripped)
	log.Printf("[corplink] copied %d cookies from %s → %s", len(stripped), serverURL.Host, nodeURL.Host)
}

func (c *Client) apiURL(path string) string {
	c.session.mu.Lock()
	server := c.session.Server
	c.session.mu.Unlock()
	return server + path + "?" + osQuery
}

// DiscoverCompany resolves a company code to a server URL.
func (c *Client) DiscoverCompany(ctx context.Context, code string) error {
	type matchReq struct {
		Code string `json:"code"`
	}
	type companyData struct {
		Domain string `json:"domain"`
	}
	target := matchURL
	if c.matchURLOverride != "" {
		target = c.matchURLOverride
	}
	var resp apiResp[companyData]
	if err := c.post(ctx, target, matchReq{Code: code}, &resp); err != nil {
		return err
	}
	if resp.Code != 0 {
		return fmt.Errorf("discover company: %s", resp.Message)
	}
	if resp.Data.Domain == "" {
		return fmt.Errorf("discover company: empty domain in response")
	}

	c.session.mu.Lock()
	c.session.Server = resp.Data.Domain
	c.session.CompanyName = code
	c.session.rebuildJar()
	c.session.mu.Unlock()
	c.rebindJar()
	return nil
}

// LoginMethodInfo holds available login methods and their verify types.
type LoginMethodInfo struct {
	Methods     []string `json:"methods"`
	VerifyTypes []string `json:"verify_types"`
}

// LoginMethods returns available login method identifiers and verify types.
// Returns: "email", "mobile", "lark" depending on server config.
func (c *Client) LoginMethods(ctx context.Context) (*LoginMethodInfo, error) {
	type loginSetting struct {
		LoginOrders         []string `json:"login_orders"`
		LoginAccount        []string `json:"login_account"`
		ScanCodeLoginEnable bool     `json:"scan_code_login_enable"`
		ScanCodeTps         []string `json:"scan_code_tps"`
		LoginVerifyType     []string `json:"login_verify_type"`
	}
	var resp apiResp[loginSetting]
	if err := c.get(ctx, c.apiURL("/api/login/setting"), &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("login setting: %s", resp.Message)
	}

	d := resp.Data
	var methods []string
	seen := map[string]bool{}

	add := func(m string) {
		if !seen[m] {
			seen[m] = true
			methods = append(methods, m)
		}
	}

	for _, order := range d.LoginOrders {
		switch order {
		case "feilian", "feilian_v1", "mobile_auth":
			for _, acc := range d.LoginAccount {
				switch acc {
				case "email":
					add("email")
				case "mobile":
					add("mobile")
				}
			}
		case "lark":
			add("lark")
		}
	}

	// Fallback: scan_code_tps (for servers that don't list lark in login_orders)
	if d.ScanCodeLoginEnable {
		for _, tps := range d.ScanCodeTps {
			if tps == "lark" {
				add("lark")
			}
		}
	}

	return &LoginMethodInfo{
		Methods:     methods,
		VerifyTypes: d.LoginVerifyType,
	}, nil
}

// LoginWithPassword performs password-based login (used by bytedance and
// other deployments where login_verify_type is "password").
// Password is SHA256-hashed before sending if it is not already a 64-char hex string.
func (c *Client) LoginWithPassword(ctx context.Context, account, password string) error {
	// Hash password if not already a 64-char hex string (SHA256 length)
	if len(password) != 64 {
		h := sha256.New()
		h.Write([]byte(password))
		password = fmt.Sprintf("%x", h.Sum(nil))
	}

	type loginReq struct {
		Password string `json:"password"`
		UserName string `json:"user_name"`
	}
	var loginResp apiResp[any]
	if err := c.post(ctx, c.apiURL("/api/login"), loginReq{Password: password, UserName: account}, &loginResp); err != nil {
		return err
	}
	if loginResp.Code != 0 {
		return fmt.Errorf("login: %s", loginResp.Message)
	}
	return nil
}
