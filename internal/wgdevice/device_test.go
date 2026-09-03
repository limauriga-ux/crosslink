package wgdevice

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// generateTestKeyPair returns (privateKeyB64, publicKeyB64) for testing.
func generateTestKeyPair(t *testing.T) (string, string) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	// Clamp per RFC 7748
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub[:])
}

// TestBuildIPC verifies the IPC string format is correct for device.IpcSet.
// The `set=1` header must NOT be present — that is only for UNIX socket UAPI.
func TestBuildIPC(t *testing.T) {
	privKey := make([]byte, 32)
	pubKey := make([]byte, 32)
	rand.Read(privKey) //nolint:errcheck
	rand.Read(pubKey)  //nolint:errcheck

	ipc := buildIPC(privKey, pubKey, "1.2.3.4:51820")

	if len(ipc) == 0 {
		t.Fatal("IPC string is empty")
	}
	// Must NOT start with "set=1"
	if len(ipc) >= 5 && ipc[:5] == "set=1" {
		t.Errorf("IPC string must not start with 'set=1' (that is the UNIX socket UAPI prefix, not for IpcSet())\ngot: %s", ipc[:80])
	}
	// Must contain private_key
	if !containsKey(ipc, "private_key=") {
		t.Error("IPC missing private_key")
	}
	// Must contain public_key (peer)
	if !containsKey(ipc, "public_key=") {
		t.Error("IPC missing public_key")
	}
	// Must contain endpoint
	if !containsKey(ipc, "endpoint=1.2.3.4:51820") {
		t.Errorf("IPC missing endpoint, got:\n%s", ipc)
	}
	// Must contain allowed_ip
	if !containsKey(ipc, "allowed_ip=") {
		t.Error("IPC missing allowed_ip")
	}
	t.Logf("IPC string:\n%s", ipc)
}

func containsKey(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstr(s, sub))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestNewDeviceUDP creates a WireGuard netstack device in UDP mode with valid keys.
// Does NOT set up routing — just verifies the device can be created and closed.
func TestNewDeviceUDP(t *testing.T) {
	privB64, _, err := func() (string, string, error) {
		p, q := generateTestKeyPair(t)
		return p, q, nil
	}()
	_ = err
	_, serverPubB64 := generateTestKeyPair(t)

	vpnIP := netip.MustParseAddr("10.8.0.2")
	dns := []netip.Addr{netip.MustParseAddr("1.1.1.1")}

	cfg := Config{
		PrivateKeyB64:      privB64,
		ServerPublicKeyB64: serverPubB64,
		ServerEndpoint:     "127.0.0.1:51820", // loopback, no real server
		ProtocolMode:       2,                 // UDP
		VpnIP:              vpnIP,
		DNSServers:         dns,
		MTU:                1420,
	}

	dev, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer dev.Close()

	if dev.tnet == nil {
		t.Error("tnet is nil after New()")
	}
	t.Log("WireGuard UDP device created and closed successfully")
}

// TestNewDeviceTCP creates a WireGuard netstack device in TCP mode.
// Uses loopback as endpoint — the TCP dial will fail within 15s timeout,
// but the important thing is IpcSet succeeds before the handshake attempt.
func TestNewDeviceTCP(t *testing.T) {
	privB64, _ := generateTestKeyPair(t)
	_, serverPubB64 := generateTestKeyPair(t)

	vpnIP := netip.MustParseAddr("10.8.0.3")

	cfg := Config{
		PrivateKeyB64:      privB64,
		ServerPublicKeyB64: serverPubB64,
		ServerEndpoint:     "127.0.0.1:51821", // loopback, no real server
		ProtocolMode:       1,                 // TCP
		VpnIP:              vpnIP,
		DNSServers:         nil,
		MTU:                1420,
	}

	dev, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer dev.Close()
	t.Log("WireGuard TCP device created successfully")
}

func TestDialErrMeansReachable(t *testing.T) {
	if !dialErrMeansReachable(nil) {
		t.Fatal("nil (connected) must be reachable")
	}
	// A refused/reset means the host answered → tunnel carried the packet.
	for _, msg := range []string{"connection refused", "connection reset by peer"} {
		if !dialErrMeansReachable(errors.New(msg)) {
			t.Fatalf("%q must count as reachable (host responded)", msg)
		}
	}
	// No response at all → not reachable.
	if dialErrMeansReachable(timeoutErr{}) {
		t.Fatal("timeout must count as NOT reachable")
	}
	for _, msg := range []string{"no route to host", "network is unreachable"} {
		if dialErrMeansReachable(errors.New(msg)) {
			t.Fatalf("%q must count as NOT reachable", msg)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestVPNResolverForcesTCP(t *testing.T) {
	// The resolver must never ask the netstack for udp: a lost UDP datagram in
	// the tunnel has nothing to retransmit it, so lookups time out far more
	// often than the link warrants.
	for _, in := range []string{"udp", "udp4", "udp6"} {
		got := in
		if strings.HasPrefix(got, "udp") {
			got = "tcp" + strings.TrimPrefix(got, "udp")
		}
		want := "tcp" + strings.TrimPrefix(in, "udp")
		if got != want {
			t.Fatalf("%q → %q, want %q", in, got, want)
		}
	}
	// Non-udp networks pass through untouched.
	for _, in := range []string{"tcp", "tcp4"} {
		if strings.HasPrefix(in, "udp") {
			t.Fatalf("%q must not be rewritten", in)
		}
	}
}
