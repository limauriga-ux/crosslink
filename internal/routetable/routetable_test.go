package routetable

import (
	"net"
	"testing"
	"time"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestTableLPM(t *testing.T) {
	tbl := &Table{}
	tbl.replace([]Entry{
		{mustCIDR("0.0.0.0/0"), net.ParseIP("192.168.1.1"), "utun4"},
		{mustCIDR("10.0.0.0/8"), net.ParseIP("10.0.0.1"), "utun4"},
		{mustCIDR("192.168.0.0/16"), net.ParseIP("192.168.1.1"), "en0"},
	})

	iface, _, err := tbl.Lookup(net.ParseIP("192.168.5.10"))
	if err != nil {
		t.Fatal(err)
	}
	if iface != "en0" {
		t.Errorf("want en0 got %s", iface)
	}

	iface2, _, err2 := tbl.Lookup(net.ParseIP("8.8.8.8"))
	if err2 != nil {
		t.Fatal(err2)
	}
	if iface2 != "utun4" {
		t.Errorf("want utun4 got %s", iface2)
	}

	iface3, _, err3 := tbl.Lookup(net.ParseIP("10.1.2.3"))
	if err3 != nil {
		t.Fatal(err3)
	}
	if iface3 != "utun4" {
		t.Errorf("want utun4 got %s", iface3)
	}
}

func TestTableNoRoute(t *testing.T) {
	tbl := &Table{}
	tbl.replace([]Entry{}) // empty table
	_, _, err := tbl.Lookup(net.ParseIP("1.2.3.4"))
	if err == nil {
		t.Error("empty table should return error")
	}
}

func TestRouteTableLiveLookup(t *testing.T) {
	rt := New("dummy0", 30*time.Second)
	if err := rt.Start(); err != nil {
		t.Skip("cannot read route table:", err)
	}
	defer rt.Stop()
	// Just check it doesn't panic on a common IP
	rt.Lookup(net.ParseIP("8.8.8.8"))
}

func TestRouteTableSetSkipIfaceInvalidatesCache(t *testing.T) {
	rt := New("utun100", time.Minute)
	rt.lastFetch = time.Now()

	rt.SetSkipIface("utun5")

	if rt.skipIface != "utun5" {
		t.Fatalf("skipIface = %q, want utun5", rt.skipIface)
	}
	if !rt.lastFetch.IsZero() {
		t.Fatalf("lastFetch = %v, want zero", rt.lastFetch)
	}
}
