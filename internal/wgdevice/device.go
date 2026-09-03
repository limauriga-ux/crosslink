// internal/wgdevice/device.go
package wgdevice

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Config holds parameters for a WireGuard netstack device.
type Config struct {
	PrivateKeyB64      string // base64-encoded X25519 private key
	ServerPublicKeyB64 string // base64-encoded server public key
	ServerEndpoint     string // "ip:port"
	ProtocolMode       int    // CorpLink server encoding: 1=UDP, 2=TCP
	VpnIP              netip.Addr
	DNSServers         []netip.Addr
	FallbackDNS        netip.Addr // used when DNSServers is empty
	MTU                int
}

// Device wraps a wireguard-go netstack device.
type Device struct {
	dev          *device.Device
	tnet         *netstack.Net
	dnsAddrPorts []string
	dnsCursor    atomic.Uint64
}

// New creates and starts a WireGuard device in netstack (userspace) mode.
func New(cfg Config) (*Device, error) {
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1420
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.ServerPublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode server public key: %w", err)
	}

	dnsServers := cfg.DNSServers
	if len(dnsServers) == 0 && cfg.FallbackDNS.IsValid() {
		dnsServers = []netip.Addr{cfg.FallbackDNS}
		log.Printf("[wg] VPN provided no DNS servers, using fallback %s", cfg.FallbackDNS)
	}
	dnsAddrPorts := make([]string, 0, len(dnsServers))
	for _, dns := range dnsServers {
		if dns.IsValid() {
			dnsAddrPorts = append(dnsAddrPorts, net.JoinHostPort(dns.String(), "53"))
		}
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.VpnIP}, dnsServers, mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	// CorpLink encodes the WireGuard transport in `protocol_mode` on each
	// node: 1 = plain UDP, 2 = TCP-encapsulated. Verified against the
	// official client connecting to the JY-BJ-电信 node, which advertises
	// protocol_mode=2 and connects over TCP.
	var bind conn.Bind
	if cfg.ProtocolMode == 2 {
		bind = conn.NewTCPBind()
	} else {
		bind = conn.NewDefaultBind()
	}

	logger := device.NewLogger(device.LogLevelSilent, "wg: ")
	dev := device.NewDevice(tdev, bind, logger)

	ipc := buildIPC(privKeyBytes, pubKeyBytes, cfg.ServerEndpoint)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg up: %w", err)
	}

	configureWGNetstack(tnet)
	return &Device{dev: dev, tnet: tnet, dnsAddrPorts: dnsAddrPorts}, nil
}

func buildIPC(privKey, serverPubKey []byte, endpoint string) string {
	var b strings.Builder
	// Note: do NOT include "set=1" here — that prefix is for the UNIX socket
	// UAPI protocol. device.IpcSet() expects the body directly.
	b.WriteString("private_key=" + hex.EncodeToString(privKey) + "\n")
	b.WriteString("replace_peers=true\n")
	b.WriteString("public_key=" + hex.EncodeToString(serverPubKey) + "\n")
	b.WriteString("endpoint=" + endpoint + "\n")
	b.WriteString("persistent_keepalive_interval=25\n")
	b.WriteString("replace_allowed_ips=true\n")
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString("allowed_ip=::/0\n")
	b.WriteString("\n") // UAPI requires a blank line to terminate
	return b.String()
}

// Close shuts down the WireGuard device.
func (d *Device) Close() {
	d.dev.Close()
}

// Net returns the netstack.Net for dialing through the tunnel.
func (d *Device) Net() *netstack.Net {
	return d.tnet
}

// VPNResolver returns a net.Resolver that resolves hostnames through the
// WireGuard tunnel (via the VPN's own DNS servers). Use it with a short
// deadline — the VPN DNS only services its own corporate domains; external
// hostnames may produce NXDOMAIN or time out.
//
// Queries are forced over TCP. Go's PreferGo resolver asks for "udp", but a
// UDP datagram lost inside the tunnel has nothing to retransmit it, so lookups
// time out far more often than the link warrants (measured against this corp
// DNS: ~7.7% of UDP lookups timed out vs ~1.2% over TCP). Returning a stream
// conn is safe: the resolver picks its framing from the connection type — a
// non-PacketConn gets the length-prefixed DNS-over-TCP encoding — not from the
// network string it asked for.
func (d *Device) VPNResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			target := address
			if len(d.dnsAddrPorts) > 0 {
				i := d.dnsCursor.Add(1) - 1
				target = d.dnsAddrPorts[int(i%uint64(len(d.dnsAddrPorts)))]
			}
			if strings.HasPrefix(network, "udp") {
				network = "tcp" + strings.TrimPrefix(network, "udp")
			}
			return d.tnet.DialContext(ctx, network, target)
		},
	}
}

// TunnelReachable reports whether the tunnel data path can reach the VPN's
// DNS server(s) at the transport level. It TCP-dials each DNS server through
// the netstack: a successful connect — or an actively refused one (RST) —
// proves packets traverse the tunnel and the peer responds, so the data path
// is alive. Only a timeout / unreachable error (no response at all) means the
// tunnel is dead.
//
// This is deliberately independent of whether any particular name resolves:
// a flaky corp DNS record can time out on VPNResolver while the tunnel itself
// is perfectly alive, so this is used to confirm death before a costly
// reconnect and thereby suppress false positives. With no DNS server known it
// returns true (cannot judge death on this basis).
func (d *Device) TunnelReachable(ctx context.Context) bool {
	if len(d.dnsAddrPorts) == 0 {
		return true
	}
	for _, addr := range d.dnsAddrPorts {
		conn, err := d.tnet.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close() //nolint:errcheck
			return true
		}
		if dialErrMeansReachable(err) {
			return true
		}
	}
	return false
}

// dialErrMeansReachable classifies a netstack TCP dial error: a connection
// refused (RST) means the host answered, so the tunnel carried the packet —
// reachable. A timeout or unreachable error means no response — not reachable.
func dialErrMeansReachable(err error) bool {
	if err == nil {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "refused") || strings.Contains(msg, "reset") {
		return true // host responded (RST) → tunnel carried the packet
	}
	// "no route", "unreachable", "timeout", etc. → treat as not reachable.
	return false
}

// configureWGNetstack switches the WireGuard userspace TCP stack from the
// default Reno congestion control to CUBIC and tunes RTO for lossy paths.
func configureWGNetstack(tnet *netstack.Net) {
	tnet.ConfigureCubic()
	log.Printf("[wg] netstack configured: CUBIC, minRTO=20ms, moderateRecvBuf")
}

// Stats holds cumulative byte counters for the WireGuard tunnel.
type Stats struct {
	TxBytes          int64
	RxBytes          int64
	LastHandshakeSec int64 // unix timestamp of last successful handshake, 0 if none
}

// GetStats reads cumulative tx/rx bytes from the WireGuard device via IPC.
func (d *Device) GetStats() (Stats, error) {
	out, err := d.dev.IpcGet()
	if err != nil {
		return Stats{}, fmt.Errorf("ipc get: %w", err)
	}
	var s Stats
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "tx_bytes":
			s.TxBytes += n
		case "rx_bytes":
			s.RxBytes += n
		case "last_handshake_time_sec":
			if n > s.LastHandshakeSec {
				s.LastHandshakeSec = n
			}
		}
	}
	return s, nil
}
