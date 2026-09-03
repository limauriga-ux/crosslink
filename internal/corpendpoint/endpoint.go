package corpendpoint

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	endpointadapter "github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const Type = "corplink"

type Options struct{}

type Endpoint struct {
	endpointadapter.Adapter
	runtime *Runtime
}

var _ adapter.Endpoint = (*Endpoint)(nil)
var _ adapter.OutboundWithPreferredRoutes = (*Endpoint)(nil)

func RegisterEndpoint(registry *endpointadapter.Registry, runtime *Runtime) {
	endpointadapter.Register[Options](registry, Type, func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ Options) (adapter.Endpoint, error) {
		return &Endpoint{
			Adapter: endpointadapter.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, nil),
			runtime: runtime,
		}, nil
	})
}

func (e *Endpoint) Start(adapter.StartStage) error { return nil }
func (e *Endpoint) Close() error                   { return nil }

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	lease, err := e.runtime.Acquire()
	if err != nil {
		return nil, err
	}

	dialNetwork := network
	address := destination.String()
	if network == N.NetworkICMP {
		dialNetwork = "ping"
		address = destination.AddrString()
	}
	conn, err := lease.Device().Net().DialContext(ctx, dialNetwork, address)
	if err != nil {
		lease.Release()
		return nil, err
	}
	e.runtime.RecordSuccess()
	return &leasedConn{Conn: conn, lease: lease}, nil
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	lease, err := e.runtime.Acquire()
	if err != nil {
		return nil, err
	}
	conn, err := lease.Device().Net().DialContext(ctx, N.NetworkUDP, destination.String())
	if err != nil {
		lease.Release()
		return nil, err
	}
	packetConn, ok := conn.(net.PacketConn)
	if !ok {
		_ = conn.Close()
		lease.Release()
		return nil, fmt.Errorf("corporate UDP connection does not implement net.PacketConn: %T", conn)
	}
	e.runtime.RecordSuccess()
	return &leasedPacketConn{PacketConn: packetConn, lease: lease}, nil
}

func (e *Endpoint) PreferredDomain(_ *adapter.InboundContext, domain string) bool {
	return !e.runtime.MatchPublicAuthDomain(domain) && e.runtime.MatchDomain(domain)
}

func (e *Endpoint) PreferredAddress(_ *adapter.InboundContext, address netip.Addr) bool {
	return !e.runtime.MatchPublicAuthAddress(address) && e.runtime.MatchAddress(address)
}
