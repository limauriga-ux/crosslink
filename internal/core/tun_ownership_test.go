package core

import (
	"net"
	"testing"

	"github.com/limauriga-ux/crosslink/internal/routetable"
)

func TestDetectPublicRouteConflictsIgnoresCorporateSplitRoutes(t *testing.T) {
	entries := []routetable.Entry{
		{Dest: mustIPNet(t, "0.0.0.0/1"), Iface: "utun1024"},
		{Dest: mustIPNet(t, "128.0.0.0/1"), Iface: "utun1024"},
		{Dest: mustIPNet(t, "10.130.0.0/16"), Iface: "utun7"},
		{Dest: mustIPNet(t, "0.0.0.0/1"), Iface: "utun9"},
	}
	conflicts := detectPublicRouteConflicts(
		entries,
		map[string]bool{"utun1024": true, "utun7": true},
		map[string]string{"utun1024": "198.18.0.1", "utun7": "10.10.8.7"},
	)
	if len(conflicts) != 1 || conflicts[0] != "utun1024 (198.18.0.1)" {
		t.Fatalf("conflicts = %#v", conflicts)
	}
}

func TestDetectCompatibleSplitTUNsClassifiesOnlyRoutedNonConflicts(t *testing.T) {
	entries := []routetable.Entry{
		{Dest: mustIPNet(t, "10.130.0.0/16"), Iface: "utun7"},
		{Dest: mustIPNet(t, "0.0.0.0/1"), Iface: "utun8"},
		{Dest: mustIPNet(t, "128.0.0.0/1"), Iface: "utun8"},
		{Dest: mustIPNet(t, "192.168.50.0/24"), Iface: "en0"},
	}
	externalSet := map[string]bool{"utun7": true, "utun8": true, "utun10": true}
	addresses := map[string]string{"utun7": "10.10.8.47", "utun8": "198.18.0.1", "utun10": "100.64.0.2"}
	conflicts := detectPublicRouteConflicts(entries, externalSet, addresses)
	compatible := detectCompatibleSplitTUNs(entries, externalSet, addresses, conflicts)
	if len(compatible) != 1 || compatible[0] != "utun7 (10.10.8.47)" {
		t.Fatalf("compatible TUNs = %#v, conflicts = %#v", compatible, conflicts)
	}
}

func mustIPNet(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatal(err)
	}
	return network
}
