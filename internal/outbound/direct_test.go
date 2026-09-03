package outbound

import (
	"net"
	"testing"
)

func TestInit_AutoDetect(t *testing.T) {
	d := &Direct{}
	if err := d.Init(); err != nil {
		t.Skip("no physical interface available:", err)
	}
	if d.iface == nil {
		t.Fatal("Init() should set iface")
	}
	t.Logf("detected interface: %s", d.iface.Name)
	// Must not be a VPN/loopback interface
	name := d.iface.Name
	for _, prefix := range []string{"utun", "tun", "tap", "lo", "veth", "docker", "br-"} {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			t.Errorf("detected interface %q looks like a VPN/loopback", name)
		}
	}
}

func TestInit_ExplicitName(t *testing.T) {
	// Use loopback for a predictable interface name
	d := NewDirect("lo0", nil) // lo0 on macOS, lo on Linux
	if err := d.Init(); err != nil {
		d2 := NewDirect("lo", nil)
		if err2 := d2.Init(); err2 != nil {
			t.Skip("neither lo0 nor lo available:", err2)
		}
	}
}

func TestDialer_NotNil(t *testing.T) {
	d := &Direct{}
	dialer := d.Dialer() // before Init — should return plain dialer
	if dialer == nil {
		t.Error("Dialer() must not return nil even when iface is nil")
	}
}

func TestResolver_System(t *testing.T) {
	d := &Direct{}
	r := d.Resolver("SYSTEM")
	if r == nil {
		t.Error("Resolver(SYSTEM) must not return nil")
	}
}

func TestNewDirect(t *testing.T) {
	d := NewDirect("eth0", []string{"8.8.8.8:53"})
	if d == nil {
		t.Fatal("NewDirect() must not return nil")
	}
	if d.IfaceName != "eth0" {
		t.Errorf("expected IfaceName=eth0, got %q", d.IfaceName)
	}
	if len(d.upstream) != 1 || d.upstream[0] != "8.8.8.8:53" {
		t.Errorf("unexpected upstream: %v", d.upstream)
	}
}

func TestResolver_NonSystem(t *testing.T) {
	d := &Direct{}
	r := d.Resolver("8.8.8.8:53")
	if r == nil {
		t.Error("Resolver(upstream) must not return nil")
	}
	// Should be a custom resolver (PreferGo)
	_ = r
}

func TestResolver_EmptyString(t *testing.T) {
	d := &Direct{}
	r := d.Resolver("")
	if r == nil {
		t.Error("Resolver('') must not return nil")
	}
	// Should return system resolver
	if r != net.DefaultResolver {
		t.Error("Resolver('') should return net.DefaultResolver")
	}
}
