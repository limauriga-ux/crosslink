package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/limauriga-ux/crosslink/internal/routetable"
)

func TestPhysicalNetworkSignatureIgnoresTunnelRoutes(t *testing.T) {
	_, tunNet, _ := net.ParseCIDR("0.0.0.0/1")
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	entries := []routetable.Entry{
		{Dest: tunNet, Iface: "utun7", Gateway: net.ParseIP("172.30.0.1")},
		{Dest: defaultNet, Iface: "en0", Gateway: net.ParseIP("192.168.1.1")},
	}
	got := physicalNetworkSignatureFrom(entries, []networkInterfaceSnapshot{
		{name: "utun7", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("172.30.0.2")}},
		{name: "en0", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("192.168.1.23")}},
	})
	if got == "" {
		t.Fatal("signature is empty")
	}
	if contains := "utun7"; len(got) > 0 && strings.Contains(got, contains) {
		t.Fatalf("signature included tunnel interface %q: %s", contains, got)
	}
	if !strings.Contains(got, "default|en0|192.168.1.1") {
		t.Fatalf("signature omitted physical default route: %s", got)
	}
}

func TestPhysicalNetworkSignatureChangesGateway(t *testing.T) {
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	a := []routetable.Entry{{Dest: defaultNet, Iface: "en0", Gateway: net.ParseIP("192.168.1.1")}}
	b := []routetable.Entry{{Dest: defaultNet, Iface: "en0", Gateway: net.ParseIP("10.0.0.1")}}
	ifaces := []networkInterfaceSnapshot{{name: "en0", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("192.168.1.23")}}}
	sa := physicalNetworkSignatureFrom(a, ifaces)
	sb := physicalNetworkSignatureFrom(b, ifaces)
	if sa == sb {
		t.Fatalf("gateway change did not alter signature: %q", sa)
	}
}

func TestPhysicalNetworkSignatureIgnoresIrrelevantAndLinkLocalInterfaces(t *testing.T) {
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	entries := []routetable.Entry{{Dest: defaultNet, Iface: "en0", Gateway: net.ParseIP("192.168.1.1")}}
	base := []networkInterfaceSnapshot{
		{name: "en0", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("192.168.1.23")}},
	}
	withTransient := append(append([]networkInterfaceSnapshot(nil), base...),
		networkInterfaceSnapshot{name: "awdl0", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("169.254.8.9")}},
		networkInterfaceSnapshot{name: "bridge0", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("169.254.10.11")}},
		networkInterfaceSnapshot{name: "en7", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("169.254.12.13")}},
	)
	if a, b := physicalNetworkSignatureFrom(entries, base), physicalNetworkSignatureFrom(entries, withTransient); a != b {
		t.Fatalf("irrelevant/link-local interfaces changed signature:\nbase: %s\nwith: %s", a, b)
	}
}

func TestPhysicalNetworkSignatureTracksDefaultInterfaceAddress(t *testing.T) {
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	entries := []routetable.Entry{{Dest: defaultNet, Iface: "en0", Gateway: net.ParseIP("192.168.1.1")}}
	a := []networkInterfaceSnapshot{{name: "en0", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("192.168.1.23")}}}
	b := []networkInterfaceSnapshot{{name: "en0", flags: net.FlagUp, ipv4: []net.IP{net.ParseIP("192.168.1.24")}}}
	if sa, sb := physicalNetworkSignatureFrom(entries, a), physicalNetworkSignatureFrom(entries, b); sa == sb {
		t.Fatalf("default-interface address change did not alter signature: %q", sa)
	}
}

func TestRunNetworkWatchLoopIgnoresStableSnapshots(t *testing.T) {
	changes := make(chan struct{}, 1)
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	calls := 0
	done := make(chan struct{})
	go func() {
		runNetworkWatchLoop(ctx, ticks, func() (string, bool) {
			calls++
			if calls == 1 {
				close(ready)
			}
			return "same", true
		}, changes)
		close(done)
	}()
	<-ready
	ticks <- time.Now()
	select {
	case <-changes:
		t.Fatal("stable snapshot emitted a change")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("network watch loop did not stop")
	}
}

func TestRunNetworkWatchLoopWakesAfterUnavailableWithSameSignature(t *testing.T) {
	assertNetworkWatchWake(t, []networkSnapshot{
		{value: "same", ok: true},
		{value: "", ok: true},
		{value: "same", ok: true},
	})
}

func TestRunNetworkWatchLoopKeepsGapAfterSnapshotFailure(t *testing.T) {
	assertNetworkWatchWake(t, []networkSnapshot{
		{value: "same", ok: true},
		{value: "", ok: false},
		{value: "same", ok: true},
	})
}

type networkSnapshot struct {
	value string
	ok    bool
}

func assertNetworkWatchWake(t *testing.T, sequence []networkSnapshot) {
	t.Helper()
	changes := make(chan struct{}, 2)
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan struct{})
	index := 0
	go func() {
		runNetworkWatchLoop(ctx, ticks, func() (string, bool) {
			s := sequence[index]
			index++
			if index == 1 {
				close(ready)
			}
			return s.value, s.ok
		}, changes)
		close(done)
	}()
	<-ready
	ticks <- time.Now()
	ticks <- time.Now()
	select {
	case <-changes:
	case <-time.After(time.Second):
		t.Fatal("network watch loop did not emit a recovery event")
	}
	select {
	case <-changes:
		t.Fatal("network watch loop emitted duplicate recovery events")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("network watch loop did not stop")
	}
}
