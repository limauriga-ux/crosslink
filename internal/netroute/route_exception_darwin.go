//go:build darwin

package netroute

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/limauriga-ux/crosslink/internal/boundedexec"
)

var routeCombinedOutput = boundedexec.CombinedOutput

// addScopedHostRoute installs a host route for ip that traverses iface's
// default gateway (so the kernel does not loop the packet back through the
// VPN TUN). Returns the gateway it bound the route to — callers persist
// this so a later daemon restart on a different network can recognize the
// route as stale.
func addScopedHostRoute(ip, iface string) (net.IP, error) {
	gateway, err := scopedGateway("default", iface)
	if err != nil {
		return nil, err
	}
	if gateway == nil && !isTunnelInterface(iface) {
		return nil, fmt.Errorf("no gateway for physical iface %s", iface)
	}
	if err := addHostRoute(ip, iface, gateway); err != nil {
		return nil, err
	}
	return gateway, nil
}

func addHostRoute(ip, iface string, gateway net.IP) error {
	if net.ParseIP(ip).To4() == nil {
		return nil
	}
	if route, exact, err := inspectHostRoute(ip); err == nil && exact && route.matches(iface, gateway) {
		// A make-before-break replacement may find its existing live /32 pin.
		// Treat it as success instead of deleting a route still carrying flows.
		return nil
	}
	args := hostRouteArgs("add", ip, iface, gateway)
	out, err := routeCombinedOutput("route", args...)
	if err != nil && strings.Contains(string(out), "File exists") {
		route, exact, inspectErr := inspectHostRoute(ip)
		if inspectErr != nil {
			return fmt.Errorf("route inspect %s after add reported File exists: %w", ip, inspectErr)
		}
		if exact && route.matches(iface, gateway) {
			return nil
		}
		// Delete-and-retry is safe only after positively identifying a
		// conflicting exact /32. A failed or ambiguous inspection must not
		// delete a route that a still-live generation may depend on.
		if !exact {
			return fmt.Errorf("route %v: %s: %w (exact host route could not be verified)", args, out, err)
		}
		// We have positively identified an existing exact host route. Replace
		// its next hop in one routing-table operation so a live old generation
		// never sees the endpoint pin disappear between delete and add.
		crossIface := route.iface != iface
		changeArgs := hostRouteArgs("change", ip, iface, gateway)
		if changeOut, changeErr := routeCombinedOutput("route", changeArgs...); changeErr == nil {
			if crossIface {
				log.Printf("[route] re-pinned %s from %s to %s: any still-live generation on %s has lost its underlay",
					ip, route.iface, iface, route.iface)
			} else {
				log.Printf("[route] re-pinned %s on %s: gateway %s -> %s",
					ip, iface, route.gateway, routeGatewayString(gateway))
			}
			return nil
		} else {
			if errors.Is(changeErr, context.DeadlineExceeded) {
				// A bounded exec timeout leaves RTM_CHANGE's outcome
				// unknown: the kernel may have applied it before the
				// command wrapper timed out. Re-inspect before deciding
				// whether the desired pin is already in place. Never issue
				// a destructive delete on an unconfirmed timeout.
				log.Printf("[route] atomic change %s timed out (%s); re-inspecting before any retry",
					ip, strings.TrimSpace(string(changeOut)))
				after, afterExact, inspectErr := inspectHostRoute(ip)
				if inspectErr != nil {
					return fmt.Errorf("route change %s timed out; outcome unknown and re-inspect failed: %w", ip, inspectErr)
				}
				if afterExact && after.matches(iface, gateway) {
					return nil
				}
				return fmt.Errorf("route change %s timed out; desired host route not confirmed", ip)
			}
			logRouteChangeFallback(ip, changeOut, changeErr)
		}
		if delErr := deleteHostRoute(ip); delErr != nil {
			return fmt.Errorf("route delete %s (before retry): %w", ip, delErr)
		}
		out, err = routeCombinedOutput("route", args...)
	}
	if err != nil {
		return fmt.Errorf("route %v: %s: %w", args, out, err)
	}
	return nil
}

func hostRouteArgs(op, ip, iface string, gateway net.IP) []string {
	args := []string{op, "-host", ip}
	if gateway != nil && gateway.To4() != nil && !gateway.IsUnspecified() {
		return append(args, gateway.String())
	}
	return append(args, "-interface", iface)
}

func logRouteChangeFallback(ip string, out []byte, err error) {
	log.Printf("[route] atomic change %s failed (%s: %v), falling back to delete+add", ip, strings.TrimSpace(string(out)), err)
}

func routeGatewayString(gateway net.IP) string {
	if gateway == nil || gateway.To4() == nil || gateway.IsUnspecified() {
		return "<interface>"
	}
	return gateway.String()
}

type hostRoute struct {
	destination string
	gateway     string
	iface       string
	flags       string
}

func (r hostRoute) matches(iface string, gateway net.IP) bool {
	if r.iface != iface {
		return false
	}
	if gateway != nil && gateway.To4() != nil && !gateway.IsUnspecified() {
		current := net.ParseIP(r.gateway)
		return current != nil && current.Equal(gateway)
	}
	// `route add -host ... -interface ...` is represented either without a
	// gateway line, with a link#N pseudo-gateway, or (on some macOS
	// releases) with the interface name itself.
	gw := strings.TrimSpace(strings.ToLower(r.gateway))
	return gw == "" ||
		strings.HasPrefix(gw, "link#") ||
		gw == strings.ToLower(strings.TrimSpace(iface))
}

func inspectHostRoute(ip string) (hostRoute, bool, error) {
	out, err := routeCombinedOutput("route", "-n", "get", ip)
	if err != nil {
		return hostRoute{}, false, fmt.Errorf("route get %s: %s: %w", ip, out, err)
	}
	var route hostRoute
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "destination:"):
			route.destination = strings.TrimSpace(strings.TrimPrefix(line, "destination:"))
		case strings.HasPrefix(line, "gateway:"):
			route.gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		case strings.HasPrefix(line, "interface:"):
			route.iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		case strings.HasPrefix(line, "flags:"):
			route.flags = strings.TrimSpace(strings.TrimPrefix(line, "flags:"))
		}
	}
	return route, isExactHostDestination(route.destination, route.flags, ip), nil
}

func isExactHostDestination(destination, flags, ip string) bool {
	target := net.ParseIP(ip)
	if target == nil {
		return false
	}
	if !hasHostRouteFlag(flags) {
		return false
	}
	if parsed := net.ParseIP(destination); parsed != nil {
		return parsed.Equal(target)
	}
	parsed, network, err := net.ParseCIDR(destination)
	if err != nil || parsed == nil || network == nil {
		return false
	}
	ones, bits := network.Mask.Size()
	return bits == 32 && ones == 32 && parsed.Equal(target)
}

func hasHostRouteFlag(flags string) bool {
	for _, field := range strings.FieldsFunc(strings.ToUpper(flags), func(r rune) bool {
		return r == '<' || r == '>' || r == ',' || r == ' ' || r == '\t'
	}) {
		if field == "HOST" {
			return true
		}
	}
	return false
}

func deleteHostRoute(ip string) error {
	out, err := routeCombinedOutput("route", "delete", "-host", ip)
	if err != nil {
		text := strings.ToLower(string(out))
		// A missing route already satisfies the requested postcondition.
		if strings.Contains(text, "not in table") || strings.Contains(text, "not found") {
			return nil
		}
		return fmt.Errorf("route delete host %s: %s: %w", ip, out, err)
	}
	return nil
}

func scopedGateway(ip, iface string) (net.IP, error) {
	out, err := routeCombinedOutput("route", "-n", "get", ip, "-ifscope", iface)
	if err != nil {
		return nil, fmt.Errorf("route get %s ifscope %s: %s: %w", ip, iface, out, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "gateway:") {
			continue
		}
		gw := net.ParseIP(strings.TrimSpace(strings.TrimPrefix(line, "gateway:")))
		if gw == nil {
			return nil, nil
		}
		return gw, nil
	}
	return nil, nil
}

func isTunnelInterface(iface string) bool {
	return strings.HasPrefix(iface, "utun") ||
		strings.HasPrefix(iface, "tun") ||
		strings.HasPrefix(iface, "tap")
}

// AddScopedHostRoute installs and persists a host route. Persisting the
// physical gateway lets startup/network-change cleanup remove stale pins
// instead of leaving the control endpoint bound to a previous network.
func AddScopedHostRoute(ip, iface string) error {
	gateway, err := addScopedHostRoute(ip, iface)
	if err != nil {
		return err
	}
	return rememberHostRoute(net.ParseIP(ip), gateway)
}
