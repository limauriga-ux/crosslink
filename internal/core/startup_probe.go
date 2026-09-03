package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	startupProbeHost = "www.gstatic.com"
	startupProbeURL  = "https://www.gstatic.com/generate_204"
)

var runStartupProbe = probePublicPath

// probePublicPath proves both pieces required for safe system capture before a
// freshly-started TUN is allowed to remain installed:
//  1. an uncached hostname can be resolved by the compiled DNS graph;
//  2. the selected public outbound can complete an HTTPS request.
//
// DisableCache forces a live DNS exchange. Failure is handled by
// startCoreLocked closing the entire sing-box instance, which closes the TUN
// fd and removes auto routes.
func probePublicPath(
	ctx context.Context,
	outboundManager adapter.OutboundManager,
	transportManager adapter.DNSTransportManager,
	dnsRouter adapter.DNSRouter,
) error {
	if outboundManager == nil || transportManager == nil || dnsRouter == nil || transportManager.Default() == nil {
		return fmt.Errorf("DNS or outbound graph is unavailable")
	}
	lookupCtx, lookupCancel := context.WithTimeout(ctx, 8*time.Second)
	addresses, err := dnsRouter.Lookup(lookupCtx, startupProbeHost, adapter.DNSQueryOptions{
		Transport:    transportManager.Default(),
		Strategy:     C.DomainStrategyIPv4Only,
		DisableCache: true,
	})
	lookupCancel()
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("uncached DNS lookup failed: %w", err)
	}

	outbound := outboundManager.Default()
	if outbound == nil {
		return fmt.Errorf("public default outbound is unavailable")
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			destination := M.ParseSocksaddr(address)
			if destination.IsDomain() && destination.Fqdn == startupProbeHost {
				destination = M.SocksaddrFrom(addresses[0], destination.Port)
			}
			return outbound.DialContext(ctx, network, destination)
		},
	}
	defer transport.CloseIdleConnections()
	requestCtx, requestCancel := context.WithTimeout(ctx, 10*time.Second)
	defer requestCancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, startupProbeURL, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return fmt.Errorf("public HTTPS probe failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("public HTTPS probe returned %s", response.Status)
	}
	return nil
}
