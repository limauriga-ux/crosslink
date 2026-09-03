package corpendpoint

import (
	"context"
	"fmt"
	"net"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	boxdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

const DNSType = "corplink"

type DNSOptions struct {
	PublicTransports []string `json:"public_transports"`
}

type DNSTransport struct {
	tag              string
	runtime          *Runtime
	ctx              context.Context
	publicTags       []string
	publicTransports []adapter.DNSTransport
}

var _ adapter.DNSTransportWithPreferredDomain = (*DNSTransport)(nil)
var _ adapter.DNSTransportWithEnvironment = (*DNSTransport)(nil)

func RegisterDNSTransport(registry *boxdns.TransportRegistry, runtime *Runtime) {
	boxdns.RegisterTransport[DNSOptions](registry, DNSType, func(ctx context.Context, _ log.ContextLogger, tag string, options DNSOptions) (adapter.DNSTransport, error) {
		if len(options.PublicTransports) == 0 {
			return nil, fmt.Errorf("public DNS transports are empty")
		}
		return &DNSTransport{
			tag:        tag,
			runtime:    runtime,
			ctx:        ctx,
			publicTags: append([]string(nil), options.PublicTransports...),
		}, nil
	})
}

func (t *DNSTransport) Type() string { return DNSType }
func (t *DNSTransport) Tag() string  { return t.tag }
func (t *DNSTransport) Dependencies() []string {
	return append([]string(nil), t.publicTags...)
}

// Environment participates in sing-box's DNS cache key. This transport
// multiplexes corporate and public answers, so the route-policy epoch must
// separate answers across reconnects, mode changes, and pushed DNS updates.
func (t *DNSTransport) Environment() []string {
	if t.runtime == nil {
		return nil
	}
	return t.runtime.DNSEnvironment()
}
func (t *DNSTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	manager := service.FromContext[adapter.DNSTransportManager](t.ctx)
	if manager == nil {
		return fmt.Errorf("DNS transport manager is unavailable")
	}
	transports := make([]adapter.DNSTransport, 0, len(t.publicTags))
	for _, tag := range t.publicTags {
		transport, loaded := manager.Transport(tag)
		if !loaded {
			return fmt.Errorf("public DNS transport %q is unavailable", tag)
		}
		transports = append(transports, transport)
	}
	t.publicTransports = transports
	return nil
}
func (t *DNSTransport) Reset() {
	for _, transport := range t.publicTransports {
		transport.Reset()
	}
}
func (t *DNSTransport) Close() error { return nil }

func (t *DNSTransport) PreferredDomain(domain string) bool {
	return t.runtime.MatchPublicAuthDomain(domain) || t.runtime.MatchCorporateDomain(domain)
}

func (t *DNSTransport) Exchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error) {
	if len(message.Question) == 0 {
		return nil, fmt.Errorf("DNS message has no question")
	}
	name := message.Question[0].Name
	if t.runtime.MatchPublicAuthDomain(name) {
		return t.exchangePublic(ctx, message)
	}
	if t.runtime.MatchCorporateDomain(name) {
		return t.exchangeCorporate(ctx, message)
	}
	return t.exchangePublic(ctx, message)
}

func (t *DNSTransport) ExchangeAsync(ctx context.Context, message *mdns.Msg, callback func(response *mdns.Msg, err error)) {
	go func() {
		response, err := t.Exchange(ctx, message)
		callback(response, err)
	}()
}

func (t *DNSTransport) exchangeCorporate(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error) {
	servers := t.runtime.DNSServers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("%w: no corporate DNS server", ErrUnavailable)
	}
	lease, err := t.runtime.Acquire()
	if err != nil {
		return nil, err
	}
	defer lease.Release()

	var lastErr error
	for _, server := range servers {
		conn, dialErr := lease.Device().Net().DialContext(ctx, "tcp", net.JoinHostPort(server.String(), "53"))
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		response, _, exchangeErr := exchangeDNS(ctx, "tcp", conn, message)
		if exchangeErr == nil {
			t.runtime.RecordSuccess()
			return response, nil
		}
		lastErr = exchangeErr
	}
	return nil, fmt.Errorf("corporate DNS exchange: %w", lastErr)
}

func (t *DNSTransport) exchangePublic(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error) {
	if len(t.publicTransports) == 0 {
		return nil, fmt.Errorf("public DNS transports are not started")
	}
	var lastErr error
	for _, transport := range t.publicTransports {
		response, exchangeErr := transport.Exchange(ctx, message.Copy())
		if exchangeErr == nil {
			return response, nil
		}
		lastErr = exchangeErr
	}
	return nil, fmt.Errorf("proxy DoH exchange: %w", lastErr)
}

func exchangeDNS(ctx context.Context, network string, conn net.Conn, message *mdns.Msg) (*mdns.Msg, time.Duration, error) {
	defer conn.Close()
	client := &mdns.Client{Net: network}
	return client.ExchangeWithConnContext(ctx, message, &mdns.Conn{Conn: conn})
}
