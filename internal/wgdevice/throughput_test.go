package wgdevice_test

// Integration throughput test: connects to a real Corplink TCP VPN node using
// the locally stored session and measures download speed through the WireGuard
// tunnel's in-memory gVisor netstack.
//
// "In-memory TUN" here refers to the fact that the WireGuard userspace device
// (wgdevice.Device) uses an internal gVisor netstack (tnet) rather than an OS
// TUN interface. All packet handling happens in-process with no kernel calls and
// no root privileges required.
//
// Run: go test -v -run TestTCPNodeThroughput -timeout 60s ./internal/wgdevice/
// Requires: valid session at ~/.crosslink/corplink_session.json

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limauriga-ux/crosslink/internal/corplink"
	"github.com/limauriga-ux/crosslink/internal/wgdevice"
)

var sessionPath = filepath.Join(os.Getenv("HOME"), ".crosslink", "corplink_session.json")

// TestTCPNodeThroughput connects to a real TCP VPN node (Protocol=1) via the
// WireGuard userspace device and downloads a test payload. It asserts that
// throughput after the Nagle fix is above a meaningful threshold.
func TestTCPNodeThroughput(t *testing.T) {
	t.Helper()
	runThroughputTest(t, 1 /* TCP */, "新加坡", "TCP node throughput (Nagle fix)")
}

// TestUDPNodeThroughput is a baseline: UDP nodes should have always been fast.
func TestUDPNodeThroughput(t *testing.T) {
	t.Helper()
	runThroughputTest(t, 2 /* UDP */, "", "UDP node throughput (baseline)")
}

func runThroughputTest(t *testing.T, wantProtocol int, nameHint, label string) {
	t.Helper()
	// Only run when INTEGRATION_TEST=1 is set explicitly.
	if os.Getenv("INTEGRATION_TEST") != "1" {
		t.Skip("set INTEGRATION_TEST=1 to run real-network VPN tests")
	}

	// ── 1. Load existing session ──────────────────────────────────────────────
	sess := corplink.LoadSession(sessionPath)
	if !sess.IsAuthenticated() {
		t.Skipf("no valid session at %s — run the app and log in first", sessionPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cl := corplink.NewClient(sess)

	// ── 2. Pick a node with the requested protocol ────────────────────────────
	nodes, err := cl.ListNodes(ctx)
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	var node corplink.VPNNode
	for _, n := range nodes {
		if n.ProtocolMode != wantProtocol {
			continue
		}
		// If nameHint is set, prefer a node whose name contains it.
		if nameHint != "" && !containsStr(n.Name, nameHint) {
			continue
		}
		node = n
		break
	}
	// If no name-matched node found, fall back to first matching protocol.
	if node.ID == 0 && nameHint != "" {
		for _, n := range nodes {
			if n.ProtocolMode == wantProtocol {
				node = n
				break
			}
		}
	}
	if node.ID == 0 {
		t.Skipf("no node with ProtocolMode=%d found", wantProtocol)
	}
	t.Logf("using node: %s (%s), protocol=%d", node.Name, node.IP, node.ProtocolMode)

	// ── 3. Get WireGuard config ───────────────────────────────────────────────
	privB64, pubB64, err := corplink.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	wgInfo, err := cl.GetWGConfig(ctx, node, pubB64, sess.TOTPSecret)
	if err != nil {
		t.Fatalf("get wg config: %v", err)
	}
	t.Logf("vpn_ip=%s mtu=%d dns=%v", wgInfo.VpnIP, wgInfo.MTU, wgInfo.DNSServers)

	// ── 4. Create WireGuard device (in-memory gVisor, no OS TUN) ─────────────
	dev, err := wgdevice.New(wgdevice.Config{
		PrivateKeyB64:      privB64,
		ServerPublicKeyB64: wgInfo.ServerPublicKey,
		ServerEndpoint:     wgInfo.ServerEndpoint,
		ProtocolMode:       wgInfo.ProtocolMode,
		VpnIP:              wgInfo.VpnIP,
		DNSServers:         wgInfo.DNSServers,
		MTU:                wgInfo.MTU,
	})
	if err != nil {
		t.Fatalf("create wg device: %v", err)
	}
	defer dev.Close()

	// Wait for WireGuard handshake to complete (initial handshake takes 100-500ms).
	time.Sleep(2 * time.Second)

	// ── 5. Download through the in-memory tunnel via http.Client ─────────────
	// We inject the WG tnet as the dialer so all HTTP(S) traffic goes through
	// the WireGuard tunnel without needing a real OS TUN device.
	const (
		testURL      = "https://speed.cloudflare.com/__down?bytes=104857600"
		testDuration = 15 * time.Second
		minSpeedKBs  = 20 // KB/s — lower bound; TcpBind Nagle fix should provide >> 19 KB/s
	)

	tnet := dev.Net()

	// Build a custom http.Transport whose DialContext routes through the WG tunnel.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if net.ParseIP(host) == nil {
				// Query a public resolver directly so the integration probe observes
				// the real target address instead of the system TUN DNS path.
				realResolver := &net.Resolver{
					PreferGo: true,
					Dial: func(rCtx context.Context, rNet, rAddr string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(rCtx, "udp", "223.5.5.5:53")
					},
				}
				ips, lookupErr := realResolver.LookupHost(ctx, host)
				if lookupErr != nil || len(ips) == 0 {
					return nil, fmt.Errorf("resolve %s: %w", host, lookupErr)
				}
				host = ips[0]
			}
			t.Logf("dialing %s (resolved from %s)", net.JoinHostPort(host, port), strings.Split(addr, ":")[0])
			dialStart := time.Now()
			conn, dialErr := tnet.DialContext(ctx, network, net.JoinHostPort(host, port))
			t.Logf("dial done in %v err=%v", time.Since(dialStart).Round(time.Millisecond), dialErr)
			return conn, dialErr
		},
		TLSClientConfig:     &tls.Config{},
		DisableKeepAlives:   true,
		MaxIdleConns:        1,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 20 * time.Second,
		ForceAttemptHTTP2:   false, // stay with HTTP/1.1 for simpler framing
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	t.Logf("starting download: %s", testURL)
	reqCtx, reqCancel := context.WithTimeout(ctx, 60*time.Second)
	defer reqCancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, testURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	httpReq.Header.Set("User-Agent", "crosslink-throughput-test/1.0")

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("http GET: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("HTTP %d %s (headers in %v)", resp.StatusCode, resp.Status, time.Since(start).Round(time.Millisecond))

	// Drain body for up to testDuration via io.LimitedReader + io.Copy.
	limitedBody := io.LimitReader(resp.Body, 100*1024*1024) // up to 100 MB
	countW := &byteCounter{}
	deadlineCh := time.After(testDuration)
	done := make(chan struct{})
	var copyErr error
	go func() {
		_, copyErr = io.Copy(countW, limitedBody)
		close(done)
	}()
	select {
	case <-done:
		if copyErr != nil && copyErr != io.EOF {
			t.Logf("copy stopped: %v", copyErr)
		}
	case <-deadlineCh:
	}
	totalBytes := countW.n
	elapsed := time.Since(start)

	speedKBs := float64(totalBytes) / elapsed.Seconds() / 1024
	t.Logf("%s: %.1f KB/s  (%d KB in %v)", label, speedKBs, totalBytes/1024, elapsed.Round(time.Millisecond))

	// Report WireGuard stats.
	stats, _ := dev.GetStats()
	t.Logf("wg stats: tx=%d KB rx=%d KB last_handshake_age=%ds",
		stats.TxBytes/1024, stats.RxBytes/1024,
		time.Now().Unix()-stats.LastHandshakeSec)

	if speedKBs < minSpeedKBs {
		t.Errorf("throughput %.1f KB/s < minimum %d KB/s — Nagle fix may not be working",
			speedKBs, minSpeedKBs)
	}
}

// BenchmarkTCPNodeThroughput runs the throughput test as a Go benchmark so the
// result appears in benchmark output for easier comparison across commits.
func BenchmarkTCPNodeThroughput(b *testing.B) {
	if os.Getenv("INTEGRATION_TEST") != "1" {
		b.Skip("set INTEGRATION_TEST=1 to run real-network VPN benchmarks")
	}

	sess := corplink.LoadSession(sessionPath)
	if !sess.IsAuthenticated() {
		b.Skipf("no valid session at %s", sessionPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cl := corplink.NewClient(sess)
	nodes, err := cl.ListNodes(ctx)
	if err != nil {
		b.Fatalf("list nodes: %v", err)
	}
	var node corplink.VPNNode
	for _, n := range nodes {
		if n.ProtocolMode == 1 {
			node = n
			break
		}
	}
	if node.ID == 0 {
		b.Skip("no TCP node found")
	}

	privB64, pubB64, _ := corplink.GenerateKeyPair()
	wgInfo, err := cl.GetWGConfig(ctx, node, pubB64, sess.TOTPSecret)
	if err != nil {
		b.Fatalf("get wg config: %v", err)
	}

	dev, err := wgdevice.New(wgdevice.Config{
		PrivateKeyB64:      privB64,
		ServerPublicKeyB64: wgInfo.ServerPublicKey,
		ServerEndpoint:     wgInfo.ServerEndpoint,
		ProtocolMode:       wgInfo.ProtocolMode,
		VpnIP:              wgInfo.VpnIP,
		DNSServers:         wgInfo.DNSServers,
		MTU:                wgInfo.MTU,
	})
	if err != nil {
		b.Fatalf("wg device: %v", err)
	}
	defer dev.Close()
	time.Sleep(500 * time.Millisecond)

	tnet := dev.Net()
	addrs, _ := net.DefaultResolver.LookupHost(ctx, "codeload.github.com")
	if len(addrs) == 0 {
		b.Fatal("resolve failed")
	}

	b.ResetTimer()
	var totalBytes int64
	for i := 0; i < b.N; i++ {
		conn, err := tnet.DialContext(ctx, "tcp", net.JoinHostPort(addrs[0], "443"))
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		req := "GET /WireGuard/wireguard-go/zip/refs/heads/master HTTP/1.1\r\nHost: codeload.github.com\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(req))                           //nolint:errcheck
		conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		n, _ := io.Copy(io.Discard, conn)
		totalBytes += n
		conn.Close()
	}
	b.SetBytes(totalBytes / int64(b.N))
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}

// byteCounter counts bytes written to it (implements io.Writer).
type byteCounter struct{ n int64 }

func (b *byteCounter) Write(p []byte) (int, error) { b.n += int64(len(p)); return len(p), nil }

// ensure netip is used (import guard)
var _ = netip.MustParseAddr
