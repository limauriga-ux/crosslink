package outbound

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/limauriga-ux/crosslink/internal/boundedexec"
)

// Direct dials TCP/UDP connections bound to a specific network interface,
// bypassing VPN default routes.
type Direct struct {
	IfaceName string         // "" = auto-detect on Init()
	iface     *net.Interface // resolved interface
	upstream  []string       // DNS upstream servers ("ip:port" or "SYSTEM")
}

// NewDirect creates a new Direct dialer with the given interface name and upstream DNS servers.
func NewDirect(ifaceName string, upstream []string) *Direct {
	return &Direct{
		IfaceName: ifaceName,
		upstream:  upstream,
	}
}

// vpnPrefixes lists interface name prefixes that are VPN/virtual/loopback.
var vpnPrefixes = []string{"utun", "tun", "tap", "lo", "veth", "docker", "br-", "virbr"}

func isPhysical(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	name := iface.Name
	for _, prefix := range vpnPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		// Require a routable IPv4 address. Reject 169.254.0.0/16 link-local
		// (APIPA self-assigned): such an interface is "up" with an address but
		// has no DHCP lease and no gateway, so binding direct traffic to it
		// makes every DIRECT dial fail ("no gateway for physical iface").
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// ResolvedIfaceName returns the actual interface name used (after auto-detect).
func (d *Direct) ResolvedIfaceName() string {
	if d.iface != nil {
		return d.iface.Name
	}
	return d.IfaceName
}

// Init resolves and locks the interface. Must be called before Dialer()/Resolver().
// If IfaceName is "", auto-detects the physical interface:
//   - Prefers the interface owning the IPv4 default route
//   - Otherwise the first interface that has a routable (non-loopback,
//     non-169.254 link-local) IPv4 address
//   - Name does not start with: utun, tun, tap, lo, veth, docker, br-, virbr
//   - Flag net.FlagUp is set
func (d *Direct) Init() error {
	if d.IfaceName != "" {
		iface, err := net.InterfaceByName(d.IfaceName)
		if err != nil {
			return fmt.Errorf("outbound: interface %q not found: %w", d.IfaceName, err)
		}
		d.iface = iface
		return nil
	}

	// Auto-detect the physical interface. Prefer the interface that owns the
	// IPv4 default route — that is the NIC actually carrying internet traffic.
	// Fall back to the first physical interface only when the default-route
	// interface can't be determined or isn't usable. This avoids picking a
	// stale/secondary adapter (e.g. an unplugged dock or a 169.254 link-local
	// NIC) that happens to enumerate before the real one.
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("outbound: failed to list interfaces: %w", err)
	}

	if def := defaultRouteIfaceName(); def != "" {
		for _, iface := range ifaces {
			iface := iface
			if iface.Name == def && isPhysical(iface) {
				d.iface = &iface
				return nil
			}
		}
	}

	for _, iface := range ifaces {
		iface := iface
		if isPhysical(iface) {
			d.iface = &iface
			return nil
		}
	}
	return fmt.Errorf("outbound: no suitable physical interface found")
}

// defaultRouteIfaceName returns the name of the interface that owns the IPv4
// default route, skipping TUN/utun interfaces (those are VPN tunnels we
// manage). Returns "" when it can't be determined (e.g. non-darwin, no
// default route, or netstat unavailable), in which case the caller falls
// back to first-physical-interface detection.
func defaultRouteIfaceName() string {
	out, err := boundedexec.Output("netstat", "-rn", "-f", "inet")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		iface := fields[len(fields)-1]
		if strings.HasPrefix(iface, "utun") || strings.HasPrefix(iface, "tun") {
			continue
		}
		return iface
	}
	return ""
}

// Dialer returns a *net.Dialer whose connections are bound to d's interface.
// If Init() was not called or iface is nil, returns a plain &net.Dialer{}.
func (d *Direct) Dialer() *net.Dialer {
	if d.iface == nil {
		return &net.Dialer{}
	}
	return &net.Dialer{
		Control: bindToInterface(d.iface.Index, d.iface.Name),
	}
}

// DialerWithDNS returns a physical-interface-bound dialer and resolver so
// control-plane names never resolve back into the system TUN.
func (d *Direct) DialerWithDNS() *net.Dialer {
	if d.iface == nil {
		return &net.Dialer{}
	}
	dialer := &net.Dialer{
		Control: bindToInterface(d.iface.Index, d.iface.Name),
	}
	// d.Resolver uses d.Dialer() (no custom resolver), so no recursion.
	for _, u := range d.upstream {
		if u != "" && u != "SYSTEM" {
			dialer.Resolver = d.Resolver(u)
			break
		}
	}
	return dialer
}

// Resolver returns a *net.Resolver whose DNS queries are sent via d's dialer.
// upstreamAddr: "ip:port". Pass "" or "SYSTEM" for the system resolver (unbound).
func (d *Direct) Resolver(upstreamAddr string) *net.Resolver {
	if upstreamAddr == "" || upstreamAddr == "SYSTEM" {
		return net.DefaultResolver
	}
	dialer := d.Dialer()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", upstreamAddr)
		},
	}
}
