package corpendpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	outboundadapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	PublicAuthOutboundType = "crosslink-public-auth"
	PublicAuthOutboundTag  = "crosslink-public-auth"
)

type PublicAuthOutboundOptions struct {
	Detour string `json:"detour"`
}

// PublicAuthOutbound is both a dynamic route classifier and a narrow delegate
// to the configured public final. It becomes matchable only while a user-opened
// OpenVPN browser challenge has a live, profile-derived authentication scope.
type PublicAuthOutbound struct {
	outboundadapter.Adapter
	runtime   *Runtime
	manager   adapter.OutboundManager
	detourTag string
	detour    adapter.Outbound
}

var _ adapter.OutboundWithPreferredRoutes = (*PublicAuthOutbound)(nil)

func RegisterPublicAuthOutbound(registry *outboundadapter.Registry, runtime *Runtime) {
	outboundadapter.Register[PublicAuthOutboundOptions](registry, PublicAuthOutboundType, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options PublicAuthOutboundOptions) (adapter.Outbound, error) {
		if options.Detour == "" {
			return nil, errors.New("public authentication outbound detour is empty")
		}
		return &PublicAuthOutbound{
			Adapter:   outboundadapter.NewAdapter(PublicAuthOutboundType, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{options.Detour}),
			runtime:   runtime,
			manager:   service.FromContext[adapter.OutboundManager](ctx),
			detourTag: options.Detour,
		}, nil
	})
}

func (o *PublicAuthOutbound) Start() error {
	if o.manager == nil {
		return errors.New("public authentication outbound manager is unavailable")
	}
	detour, loaded := o.manager.Outbound(o.detourTag)
	if !loaded || detour == o {
		return errors.New("public authentication detour is unavailable")
	}
	o.detour = detour
	return nil
}

func (o *PublicAuthOutbound) Close() error { return nil }

func (o *PublicAuthOutbound) Network() []string {
	if o.detour != nil {
		return o.detour.Network()
	}
	return o.Adapter.Network()
}

func (o *PublicAuthOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.detour == nil {
		return nil, errors.New("public authentication detour is not started")
	}
	return o.detour.DialContext(ctx, network, destination)
}

func (o *PublicAuthOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if o.detour == nil {
		return nil, errors.New("public authentication detour is not started")
	}
	return o.detour.ListenPacket(ctx, destination)
}

func (o *PublicAuthOutbound) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	return publicAuthHTTPS(metadata) && o.runtime.MatchPublicAuthDomain(domain)
}

func (o *PublicAuthOutbound) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	return publicAuthHTTPS(metadata) && o.runtime.MatchPublicAuthAddress(address)
}

func publicAuthHTTPS(metadata *adapter.InboundContext) bool {
	if metadata == nil {
		return false
	}
	switch metadata.Protocol {
	case C.ProtocolTLS, C.ProtocolQUIC:
		return true
	default:
		// Domain-aware mixed inbounds may not need sniffing. Port 443 remains a
		// safe fallback; non-HTTPS enterprise traffic stays fail-closed.
		return metadata.Destination.Port == 443
	}
}
