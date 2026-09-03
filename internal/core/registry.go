package core

import (
	"github.com/limauriga-ux/crosslink/internal/corpendpoint"
	"github.com/limauriga-ux/crosslink/internal/openvpnprofile"

	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	boxdns "github.com/sagernet/sing-box/dns"
	dnstransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/openvpn"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
)

type registries struct {
	inbound     *inbound.Registry
	outbound    *outbound.Registry
	endpoint    *endpoint.Registry
	dns         *boxdns.TransportRegistry
	service     *boxservice.Registry
	certificate *certificate.Registry
}

func newRegistries(runtime *corpendpoint.Runtime) registries {
	inboundRegistry := inbound.NewRegistry()
	tun.RegisterInbound(inboundRegistry)
	mixed.RegisterInbound(inboundRegistry)

	outboundRegistry := outbound.NewRegistry()
	direct.RegisterOutbound(outboundRegistry)
	block.RegisterOutbound(outboundRegistry)
	group.RegisterSelector(outboundRegistry)
	group.RegisterURLTest(outboundRegistry)
	socks.RegisterOutbound(outboundRegistry)
	http.RegisterOutbound(outboundRegistry)
	shadowsocks.RegisterOutbound(outboundRegistry)
	vmess.RegisterOutbound(outboundRegistry)
	vless.RegisterOutbound(outboundRegistry)
	trojan.RegisterOutbound(outboundRegistry)
	anytls.RegisterOutbound(outboundRegistry)
	hysteria.RegisterOutbound(outboundRegistry)
	hysteria2.RegisterOutbound(outboundRegistry)
	tuic.RegisterOutbound(outboundRegistry)
	corpendpoint.RegisterPublicAuthOutbound(outboundRegistry, runtime)

	endpointRegistry := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(endpointRegistry)
	openvpn.RegisterEndpoint(endpointRegistry)
	corpendpoint.RegisterEndpoint(endpointRegistry, runtime)

	dnsRegistry := boxdns.NewTransportRegistry()
	dnstransport.RegisterHTTPS(dnsRegistry)
	dnstransport.RegisterUDP(dnsRegistry)
	openvpn.RegisterDNSTransport(dnsRegistry)
	openvpnprofile.RegisterStaticDNSTransport(dnsRegistry)
	corpendpoint.RegisterDNSTransport(dnsRegistry, runtime)

	return registries{
		inbound:     inboundRegistry,
		outbound:    outboundRegistry,
		endpoint:    endpointRegistry,
		dns:         dnsRegistry,
		service:     boxservice.NewRegistry(),
		certificate: certificate.NewRegistry(),
	}
}

func (r registries) context(ctx context.Context) context.Context {
	return box.Context(ctx, r.inbound, r.outbound, r.endpoint, r.dns, r.service, r.certificate)
}
