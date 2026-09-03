package netroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/limauriga-ux/crosslink/internal/boundedexec"
	"github.com/limauriga-ux/crosslink/internal/managedfs"
)

var (
	hostRouteStateMu   sync.Mutex
	hostRouteStateFile string
)

// ConfigureHostRouteState binds route persistence to the daemon's trusted
// data root. It must be called before any route operation.
func ConfigureHostRouteState(path string) error {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("host route state path must be absolute")
	}
	path = filepath.Clean(path)
	if filepath.Base(path) != "host-routes.json" {
		return errors.New("host route state path must end with host-routes.json")
	}
	hostRouteStateMu.Lock()
	hostRouteStateFile = path
	hostRouteStateMu.Unlock()
	return nil
}

func hostRouteStatePathLocked() (string, error) {
	if hostRouteStateFile == "" {
		return "", errors.New("host route state path is not configured")
	}
	return hostRouteStateFile, nil
}

// persistedRoute records a host route we added together with the physical
// default gateway it was bound to. Storing the gateway lets us decide on
// daemon startup whether a route is still valid (current gateway matches)
// or stale from a previous network (gateway mismatch → delete).
type persistedRoute struct {
	IP string `json:"ip"`
	GW string `json:"gw,omitempty"`
}

// loadPersistedHostRoutes returns a snapshot of the persisted host routes.
// The returned map is ip → gateway (gateway is "" when the record was
// written by an older daemon that did not track gateways).
func loadPersistedHostRoutes() (map[string]string, error) {
	hostRouteStateMu.Lock()
	defer hostRouteStateMu.Unlock()
	return loadPersistedHostRoutesLocked()
}

func rememberHostRoute(ip net.IP, gw net.IP) error {
	if ip == nil || ip.To4() == nil {
		return nil
	}
	hostRouteStateMu.Lock()
	defer hostRouteStateMu.Unlock()
	routes, err := loadPersistedHostRoutesLocked()
	if err != nil {
		return err
	}
	gwStr := ""
	if gw != nil && gw.To4() != nil {
		gwStr = gw.String()
	}
	routes[ip.String()] = gwStr
	return savePersistedHostRoutesLocked(routes)
}

func forgetHostRoute(ip string) error {
	hostRouteStateMu.Lock()
	defer hostRouteStateMu.Unlock()
	routes, err := loadPersistedHostRoutesLocked()
	if err != nil {
		return err
	}
	delete(routes, ip)
	return savePersistedHostRoutesLocked(routes)
}

// CleanupPersistedHostRoutes unconditionally deletes every persisted host
// route from the kernel routing table and clears the on-disk record. Used
// on VPN disconnect when we want a clean slate.
func CleanupPersistedHostRoutes() error {
	routes, stateErr := loadPersistedHostRoutes()
	if stateErr != nil {
		return stateErr
	}
	deleted := make([]string, 0, len(routes))
	var errs []error
	for ip := range routes {
		if err := deleteHostRoute(ip); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted = append(deleted, ip)
	}
	if err := forgetDeletedHostRoutes(deleted); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// CleanupStalePersistedHostRoutes deletes only persisted routes whose
// recorded gateway no longer matches the current physical default gateway.
// Routes without a recorded gateway (legacy format from before v1.0.9) are
// also deleted, since we cannot verify them — better to re-add on next
// dial than to leak a stale route forever.
//
// Called on daemon startup so a process that restarts on a different
// network does not inherit kernel host routes pointing at the previous
// gateway (which surface as `connect: can't assign requested address`).
func CleanupStalePersistedHostRoutes() error {
	currentGW, err := currentDefaultGatewayIPv4()
	var errs []error
	if err != nil {
		// A stale route makes the next dial fail with EADDRNOTAVAIL, whereas
		// deleting a still-valid route is cheap and the next connect reinstalls
		// it. Preserve the pre-timeout behavior: an unavailable gateway probe
		// means "unknown", so treat all persisted routes as stale.
		log.Printf("[route] default-gateway probe failed; treating all persisted host routes as stale: %v", err)
		errs = append(errs, err)
		currentGW = ""
	}
	routes, stateErr := loadPersistedHostRoutes()
	if stateErr != nil {
		errs = append(errs, stateErr)
		return errors.Join(errs...)
	}
	deleted := make([]string, 0, len(routes))
	for ip, gw := range routes {
		if gw != "" && currentGW != "" && gw == currentGW {
			continue
		}
		if err := deleteHostRoute(ip); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted = append(deleted, ip)
	}
	if err := forgetDeletedHostRoutes(deleted); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ScanAndDeleteStaleKernelHostRoutes is the belt-and-suspenders complement
// to CleanupStalePersistedHostRoutes: it walks every IPv4 host route in
// the kernel and deletes any whose next-hop gateway is no longer
// directly reachable on a current local subnet — i.e. routes left
// behind by a previous daemon run on a different network whose entry
// has been lost from host-routes.json (manual `rm`, crash before
// persist, daemon predating gateway tracking).
//
// "Directly reachable" is tested with `route -n get <gw>`: if the result
// shows a `gateway:` line, the kernel itself needs an upstream hop to
// reach the gateway, which makes it an obviously stale next-hop for a
// host route. Conservative: we never touch utun-scoped routes, link-
// local destinations, or routes whose gateway is on a connected subnet.
func ScanAndDeleteStaleKernelHostRoutes() error {
	out, err := boundedexec.Output("netstat", "-rn", "-f", "inet")
	if err != nil {
		return fmt.Errorf("scan kernel host routes: %w", err)
	}
	type row struct {
		dest, gw, iface string
	}
	var stale []row
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dest, gw, flags := fields[0], fields[1], fields[2]
		iface := fields[len(fields)-1]
		if dest == "default" || dest == "Destination" {
			continue
		}
		if strings.HasPrefix(iface, "utun") || strings.HasPrefix(iface, "tun") || iface == "lo0" {
			continue
		}
		// Must be a host route (flags include H) with an IPv4 gateway.
		if !strings.ContainsRune(flags, 'H') {
			continue
		}
		destIP := net.ParseIP(dest)
		gwIP := net.ParseIP(gw)
		if destIP == nil || destIP.To4() == nil {
			continue
		}
		if gwIP == nil || gwIP.To4() == nil {
			// link# or interface-scoped — leave alone.
			continue
		}
		reachable, err := isGatewayDirectlyReachable(gwIP.String())
		if err != nil {
			log.Printf("[route] gateway reachability check %s: %v (leaving route untouched)", gwIP, err)
			continue
		}
		if !reachable {
			stale = append(stale, row{dest, gw, iface})
		}
	}
	if len(stale) == 0 {
		return nil
	}
	deleted := make([]string, 0, len(stale))
	var errs []error
	for _, r := range stale {
		log.Printf("[route] deleting stale kernel host route %s via %s (gw not directly reachable on current subnet)", r.dest, r.gw)
		if err := deleteHostRoute(r.dest); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted = append(deleted, r.dest)
	}
	if err := forgetDeletedHostRoutes(deleted); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// isGatewayDirectlyReachable returns true when `route get <gw>` resolves
// without needing a `gateway:` hop, i.e. the gateway IP itself lives on
// a connected subnet. A false return means the kernel would have to go
// through the default route to reach the gateway — which makes the
// host route using it nonsensical.
func isGatewayDirectlyReachable(gw string) (bool, error) {
	out, err := boundedexec.Output("route", "-n", "get", gw)
	if err != nil {
		return false, fmt.Errorf("route get %s: %w", gw, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "gateway:") {
			return false, nil
		}
	}
	return true, nil
}

// currentDefaultGatewayIPv4 returns the current physical default-gateway IP
// (skipping any utun-scoped default route — those are TUN interfaces we
// manage). Returns "" when no usable default gateway is present, in which
// case the caller treats every persisted route as stale.
func currentDefaultGatewayIPv4() (string, error) {
	out, err := boundedexec.Output("netstat", "-rn", "-f", "inet")
	if err != nil {
		return "", fmt.Errorf("read default gateway: %w", err)
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
		if ip := net.ParseIP(fields[1]); ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", nil
}

// forgetDeletedHostRoutes updates the persisted set after OS commands have
// completed. No external command may run while hostRouteStateMu is held.
func forgetDeletedHostRoutes(deleted []string) error {
	if len(deleted) == 0 {
		return nil
	}
	hostRouteStateMu.Lock()
	defer hostRouteStateMu.Unlock()
	routes, err := loadPersistedHostRoutesLocked()
	if err != nil {
		return err
	}
	for _, ip := range deleted {
		delete(routes, ip)
	}
	return savePersistedHostRoutesLocked(routes)
}

func loadPersistedHostRoutesLocked() (map[string]string, error) {
	routes := make(map[string]string)
	path, err := hostRouteStatePathLocked()
	if err != nil {
		return nil, err
	}
	root, err := managedfs.Open(filepath.Dir(path), false)
	if errors.Is(err, os.ErrNotExist) {
		return routes, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := root.ReadFile(path, 1<<20)
	closeErr := root.Close()
	if errors.Is(err, os.ErrNotExist) {
		return routes, closeErr
	}
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) == 0 {
		return routes, nil
	}
	var newList []persistedRoute
	if err := json.Unmarshal(data, &newList); err == nil {
		for _, route := range newList {
			if parsed := net.ParseIP(route.IP); parsed != nil && parsed.To4() != nil {
				routes[route.IP] = route.GW
			}
		}
		return routes, nil
	}
	var ips []string
	if err := json.Unmarshal(data, &ips); err != nil {
		return nil, fmt.Errorf("parse persisted host routes: %w", err)
	}
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			routes[ip] = ""
		}
	}
	return routes, nil
}

func savePersistedHostRoutesLocked(routes map[string]string) error {
	path, err := hostRouteStatePathLocked()
	if err != nil {
		return err
	}
	list := make([]persistedRoute, 0, len(routes))
	for ip, gw := range routes {
		list = append(list, persistedRoute{IP: ip, GW: gw})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	root, err := managedfs.Open(filepath.Dir(path), true)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.WriteFileAtomic(path, data, 0o600)
}
