package openvpnprofile

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	boxdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const StaticDNSType = "crosslink-openvpn-static"

type StaticDNSOptions struct {
	Endpoint string   `json:"endpoint"`
	Servers  []string `json:"servers"`
	Domains  []string `json:"domains"`
}

type StaticDNSTransport struct {
	tag         string
	ctx         context.Context
	endpointTag string
	servers     []netip.Addr
	domains     []string
	dialer      N.Dialer
}

var _ adapter.DNSTransportWithPreferredDomain = (*StaticDNSTransport)(nil)

func RegisterStaticDNSTransport(registry *boxdns.TransportRegistry) {
	boxdns.RegisterTransport[StaticDNSOptions](registry, StaticDNSType, newStaticDNSTransport)
}

func newStaticDNSTransport(ctx context.Context, _ log.ContextLogger, tag string, options StaticDNSOptions) (adapter.DNSTransport, error) {
	if strings.TrimSpace(options.Endpoint) == "" {
		return nil, fmt.Errorf("OpenVPN static DNS endpoint is empty")
	}
	servers := make([]netip.Addr, 0, len(options.Servers))
	for _, raw := range options.Servers {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !address.IsValid() {
			return nil, fmt.Errorf("invalid OpenVPN static DNS server %q", raw)
		}
		servers = append(servers, address)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("OpenVPN static DNS servers are empty")
	}
	domains := make([]string, 0, len(options.Domains))
	for _, raw := range options.Domains {
		domain := normalizeDomain(raw)
		if err := validateDomain(domain); err != nil {
			return nil, fmt.Errorf("invalid OpenVPN static DNS domain %q: %w", raw, err)
		}
		domains = append(domains, domain)
	}
	return &StaticDNSTransport{
		tag:         tag,
		ctx:         ctx,
		endpointTag: options.Endpoint,
		servers:     servers,
		domains:     domains,
	}, nil
}

func (t *StaticDNSTransport) Type() string           { return StaticDNSType }
func (t *StaticDNSTransport) Tag() string            { return t.tag }
func (t *StaticDNSTransport) Dependencies() []string { return nil }
func (t *StaticDNSTransport) Reset()                 {}
func (t *StaticDNSTransport) Close() error           { return nil }

func (t *StaticDNSTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	manager := service.FromContext[adapter.EndpointManager](t.ctx)
	if manager == nil {
		return fmt.Errorf("OpenVPN endpoint manager is unavailable")
	}
	endpoint, found := manager.Get(t.endpointTag)
	if !found {
		return fmt.Errorf("OpenVPN endpoint %q is unavailable", t.endpointTag)
	}
	t.dialer = endpoint
	return nil
}

func (t *StaticDNSTransport) PreferredDomain(domain string) bool {
	domain = normalizeDomain(domain)
	for _, suffix := range t.domains {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func (t *StaticDNSTransport) Exchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error) {
	if t.dialer == nil {
		return nil, fmt.Errorf("OpenVPN static DNS transport is not started")
	}
	if len(message.Question) != 1 {
		return nil, fmt.Errorf("OpenVPN static DNS exchange requires exactly one question")
	}
	var lastErr error
	for _, server := range t.servers {
		destination := M.SocksaddrFrom(server, 53)
		conn, err := t.dialer.DialContext(ctx, N.NetworkUDP, destination)
		if err != nil {
			lastErr = err
			continue
		}
		response, _, exchangeErr := exchangeStaticDNS(ctx, conn, message)
		if exchangeErr == nil {
			return response, nil
		}
		lastErr = exchangeErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no OpenVPN DNS server was attempted")
	}
	return nil, fmt.Errorf("OpenVPN static DNS exchange: %w", lastErr)
}

func (t *StaticDNSTransport) ExchangeAsync(ctx context.Context, message *mdns.Msg, callback func(*mdns.Msg, error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

func exchangeStaticDNS(ctx context.Context, conn net.Conn, message *mdns.Msg) (*mdns.Msg, time.Duration, error) {
	defer conn.Close()
	client := &mdns.Client{Net: "udp"}
	return client.ExchangeWithConnContext(ctx, message, &mdns.Conn{Conn: conn})
}
