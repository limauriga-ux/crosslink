package core

import (
	"net"
	"sort"
	"strings"

	"github.com/limauriga-ux/crosslink/internal/routetable"
)

type tunOwnership struct {
	ownInterface         string
	externalInterfaces   []string
	compatibleInterfaces []string
	publicRouteConflicts []string
}

// inspectTUNOwnership distinguishes CrossLink's configured TUN address from
// other IPv4 tunnel interfaces. IPv6-only Apple system utuns are ignored. A
// competing tunnel is a public-route conflict only when it also installs a /0
// or /1 route, which is how Clash/Mihomo and other full-tunnel clients capture
// traffic.
func inspectTUNOwnership(ownIP string) tunOwnership {
	result := tunOwnership{}
	addresses := make(map[string]string)
	interfaces, _ := net.Interfaces()
	for _, networkInterface := range interfaces {
		if !isTUNInterface(networkInterface.Name) {
			continue
		}
		interfaceAddresses, _ := networkInterface.Addrs()
		for _, raw := range interfaceAddresses {
			ip, _, err := net.ParseCIDR(raw.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			addresses[networkInterface.Name] = ip.String()
			if ownIP != "" && ip.String() == ownIP {
				result.ownInterface = networkInterface.Name
			}
			break
		}
	}

	externalSet := make(map[string]bool)
	for interfaceName, address := range addresses {
		if interfaceName == result.ownInterface {
			continue
		}
		externalSet[interfaceName] = true
		result.externalInterfaces = append(result.externalInterfaces, interfaceLabel(interfaceName, address))
	}

	table := routetable.New("", 0)
	if err := table.RefreshNow(); err == nil {
		entries := table.Entries()
		result.publicRouteConflicts = detectPublicRouteConflicts(entries, externalSet, addresses)
		result.compatibleInterfaces = detectCompatibleSplitTUNs(entries, externalSet, addresses, result.publicRouteConflicts)
	}
	sort.Strings(result.externalInterfaces)
	sort.Strings(result.compatibleInterfaces)
	sort.Strings(result.publicRouteConflicts)
	return result
}

func detectPublicRouteConflicts(entries []routetable.Entry, externalSet map[string]bool, addresses map[string]string) []string {
	conflicts := make([]string, 0)
	seen := make(map[string]bool)
	for _, entry := range entries {
		if !externalSet[entry.Iface] || entry.Dest == nil {
			continue
		}
		ones, bits := entry.Dest.Mask.Size()
		if bits != 32 || ones < 0 || ones > 1 {
			continue
		}
		label := interfaceLabel(entry.Iface, addresses[entry.Iface])
		if !seen[label] {
			seen[label] = true
			conflicts = append(conflicts, label)
		}
	}
	sort.Strings(conflicts)
	return conflicts
}

func detectCompatibleSplitTUNs(entries []routetable.Entry, externalSet map[string]bool, addresses map[string]string, conflicts []string) []string {
	conflictSet := make(map[string]bool, len(conflicts))
	for _, conflict := range conflicts {
		conflictSet[conflict] = true
	}
	hasIPv4Route := make(map[string]bool)
	for _, entry := range entries {
		if externalSet[entry.Iface] && entry.Dest != nil {
			_, bits := entry.Dest.Mask.Size()
			if bits == 32 {
				hasIPv4Route[entry.Iface] = true
			}
		}
	}
	compatible := make([]string, 0)
	for interfaceName := range externalSet {
		label := interfaceLabel(interfaceName, addresses[interfaceName])
		if hasIPv4Route[interfaceName] && !conflictSet[label] {
			compatible = append(compatible, label)
		}
	}
	sort.Strings(compatible)
	return compatible
}

func isTUNInterface(name string) bool {
	return strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap")
}

func interfaceLabel(name, address string) string {
	if address == "" {
		return name
	}
	return name + " (" + address + ")"
}
