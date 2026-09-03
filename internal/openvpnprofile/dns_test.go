package openvpnprofile

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type staticDNSTestDialer struct {
	mu           sync.Mutex
	networks     []string
	destinations []M.Socksaddr
	fail         error
	stall        bool
}

func (d *staticDNSTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.mu.Lock()
	d.networks = append(d.networks, network)
	d.destinations = append(d.destinations, destination)
	d.mu.Unlock()
	if d.fail != nil {
		return nil, d.fail
	}
	client, server := net.Pipe()
	if d.stall {
		go func() {
			<-ctx.Done()
			server.Close()
		}()
		return client, nil
	}
	go serveStaticDNSTestConn(server)
	return client, nil
}

func (d *staticDNSTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func serveStaticDNSTestConn(conn net.Conn) {
	defer conn.Close()
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return
	}
	packet := make([]byte, int(length))
	if err := binary.Read(conn, binary.BigEndian, &packet); err != nil {
		return
	}
	var query mdns.Msg
	if err := query.Unpack(packet); err != nil {
		return
	}
	response := new(mdns.Msg)
	response.SetReply(&query)
	response.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: query.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30},
		A:   net.IPv4(10, 20, 30, 40),
	}}
	encoded, err := response.Pack()
	if err != nil {
		return
	}
	_ = binary.Write(conn, binary.BigEndian, uint16(len(encoded)))
	_, _ = conn.Write(encoded)
}

func TestStaticDNSTransportPreferredDomainsAreSplitOnly(t *testing.T) {
	raw, err := newStaticDNSTransport(context.Background(), nil, StaticDNSTag, StaticDNSOptions{
		Endpoint: EndpointTag,
		Servers:  []string{"10.20.0.53"},
		Domains:  []string{"Corp.Example."},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := raw.(*StaticDNSTransport)
	if !transport.PreferredDomain("api.corp.example") || !transport.PreferredDomain("CORP.EXAMPLE.") {
		t.Fatal("configured split domain did not match")
	}
	if transport.PreferredDomain("notcorp.example") || transport.PreferredDomain("public.example") {
		t.Fatal("static OpenVPN DNS matched an unrelated domain")
	}

	rawDefault, err := newStaticDNSTransport(context.Background(), nil, StaticDNSTag, StaticDNSOptions{
		Endpoint: EndpointTag,
		Servers:  []string{"10.20.0.53"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rawDefault.(*StaticDNSTransport).PreferredDomain("anything.example") {
		t.Fatal("no-domain resolver must become default through rule order, not preferred_by")
	}
}

func TestStaticDNSTransportUsesVPNDialerUDPPort53(t *testing.T) {
	dialer := &staticDNSTestDialer{}
	transport := &StaticDNSTransport{
		servers: []netip.Addr{netip.MustParseAddr("10.20.0.53")},
		dialer:  dialer,
	}
	query := new(mdns.Msg)
	query.SetQuestion("internal.example.", mdns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := transport.Exchange(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 1 || !strings.Contains(response.Answer[0].String(), "10.20.30.40") {
		t.Fatalf("DNS response = %#v", response.Answer)
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.networks) != 1 || dialer.networks[0] != N.NetworkUDP {
		t.Fatalf("dial networks = %#v", dialer.networks)
	}
	if len(dialer.destinations) != 1 || dialer.destinations[0].Addr != netip.MustParseAddr("10.20.0.53") || dialer.destinations[0].Port != 53 {
		t.Fatalf("dial destinations = %#v", dialer.destinations)
	}
}

func TestStaticDNSTransportFailureDoesNotProducePublicFallback(t *testing.T) {
	transport := &StaticDNSTransport{
		servers: []netip.Addr{netip.MustParseAddr("10.20.0.53")},
		dialer:  &staticDNSTestDialer{fail: errors.New("OpenVPN endpoint disconnected")},
	}
	query := new(mdns.Msg)
	query.SetQuestion("public.example.", mdns.TypeA)
	_, err := transport.Exchange(context.Background(), query)
	if err == nil || !strings.Contains(err.Error(), "OpenVPN endpoint disconnected") {
		t.Fatalf("disconnected resolver error = %v", err)
	}
}

func TestStaticDNSTransportHonorsContextTimeout(t *testing.T) {
	transport := &StaticDNSTransport{
		servers: []netip.Addr{netip.MustParseAddr("10.20.0.53")},
		dialer:  &staticDNSTestDialer{stall: true},
	}
	query := new(mdns.Msg)
	query.SetQuestion("public.example.", mdns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := transport.Exchange(ctx, query)
	if err == nil {
		t.Fatal("stalled DNS exchange unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("context timeout took %s", elapsed)
	}
}
