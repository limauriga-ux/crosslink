package main

import (
	"context"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/limauriga-ux/crosslink/internal/routetable"
)

// Keep a small polling route snapshot so physical-network recovery wakes the
// CorpLink reconnect loop without coupling it to the sing-box generation.
// addresses are current; that mixed-age snapshot is intentionally conservative
// and may wake early rather than delay recovery.
const networkPollInterval = 2 * time.Second

// watchPhysicalNetwork emits a coalesced event when the physical network
// identity changes. It excludes tunnel/loopback interfaces and only includes
// default routes, so route changes made by our own TUN or host-route management
// cannot trigger a reconnect loop.
func watchPhysicalNetwork(ctx context.Context, changes chan<- struct{}) {
	rt := routetable.New("", networkPollInterval)
	refreshFailed := false
	if err := rt.RefreshNow(); err != nil {
		log.Printf("[reconnect] initial physical-network snapshot failed; polling will retry: %v", err)
		refreshFailed = true
	}

	ticker := time.NewTicker(networkPollInterval)
	defer ticker.Stop()
	snapshot := func() (string, bool) {
		if err := rt.RefreshNow(); err != nil {
			if !refreshFailed {
				log.Printf("[reconnect] physical-network snapshot failed; retaining the last route view: %v", err)
			}
			refreshFailed = true
		} else if refreshFailed {
			log.Printf("[reconnect] physical-network snapshot recovered")
			refreshFailed = false
		}
		return physicalNetworkSignature(rt.Entries())
	}
	runNetworkWatchLoop(ctx, ticker.C, snapshot, changes)
}

// runNetworkWatchLoop contains the network hand-off state machine. The first
// usable snapshot establishes a baseline; only a later change, or a
// unavailable→available transition, wakes the reconnect loop. A failed
// snapshot is itself remembered as unavailable so a brief interface-enumeration
// error cannot lose the hand-off marker.
func runNetworkWatchLoop(
	ctx context.Context,
	ticks <-chan time.Time,
	snapshot func() (string, bool),
	changes chan<- struct{},
) {
	previous, ok := snapshot()
	initialized := ok && previous != ""
	sawUnavailable := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
		current, ok := snapshot()
		if !ok {
			sawUnavailable = initialized
			continue
		}
		if current == "" {
			// Do not tear down on the "between networks" half of a hand-off.
			// Remember the gap and wake once a usable default path returns,
			// even if DHCP assigns the same address/gateway as before.
			sawUnavailable = initialized
			continue
		}
		if initialized && (sawUnavailable || current != previous) {
			select {
			case changes <- struct{}{}:
			default:
			}
		}
		previous, initialized = current, true
		sawUnavailable = false
	}
}

func physicalNetworkSignature(entries []routetable.Entry) (string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	snapshots := make([]networkInterfaceSnapshot, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		snapshot := networkInterfaceSnapshot{name: iface.Name, flags: iface.Flags}
		for _, addr := range addrs {
			host, _, ok := strings.Cut(addr.String(), "/")
			if !ok {
				host = addr.String()
			}
			ip := net.ParseIP(host)
			if ip != nil && ip.To4() != nil {
				snapshot.ipv4 = append(snapshot.ipv4, ip.To4())
			}
		}
		snapshots = append(snapshots, snapshot)
	}
	return physicalNetworkSignatureFrom(entries, snapshots), true
}

type networkInterfaceSnapshot struct {
	name  string
	flags net.Flags
	ipv4  []net.IP
}

func physicalNetworkSignatureFrom(entries []routetable.Entry, ifaces []networkInterfaceSnapshot) string {
	// This daemon's direct endpoint and host-route path is IPv4-only. A
	// v6-only network therefore remains "unavailable" to this watcher until a
	// usable IPv4 default route returns; that is intentional rather than a
	// claim that the host has no IPv6 connectivity.
	usableIfaces := make(map[string][]string)
	parts := make([]string, 0, len(entries)+len(ifaces))
	for _, iface := range ifaces {
		if iface.flags&net.FlagUp == 0 || iface.flags&net.FlagLoopback != 0 || ignoredNetworkInterface(iface.name) {
			continue
		}
		ips := make([]string, 0, len(iface.ipv4))
		for _, ip := range iface.ipv4 {
			if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ip.To4().String())
		}
		if len(ips) == 0 {
			continue
		}
		sort.Strings(ips)
		usableIfaces[iface.name] = ips
	}
	addedIface := make(map[string]struct{})
	for _, entry := range entries {
		ones, bits := entry.Dest.Mask.Size()
		ips, usable := usableIfaces[entry.Iface]
		if bits != 32 || ones != 0 || !usable {
			continue
		}
		gateway := ""
		if entry.Gateway != nil {
			gateway = entry.Gateway.String()
		}
		parts = append(parts, "default|"+entry.Iface+"|"+gateway)
		if _, exists := addedIface[entry.Iface]; !exists {
			parts = append(parts, "if|"+entry.Iface+"|"+strings.Join(ips, ","))
			addedIface[entry.Iface] = struct{}{}
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func ignoredNetworkInterface(name string) bool {
	name = strings.ToLower(name)
	for _, prefix := range []string{
		"utun", "tun", "wg", "wireguard", "tap", "ipsec", "lo",
		"docker", "br-", "veth", "virbr", "awdl", "llw", "anpi", "bridge",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
