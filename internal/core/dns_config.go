package core

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	appconfig "github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/corpendpoint"
	physicaloutbound "github.com/limauriga-ux/crosslink/internal/outbound"
)

const (
	bootstrapDNSTag    = "crosslink-bootstrap-dns"
	publicDNSTagPrefix = "crosslink-public-doh-"
)

var detectPhysicalInterface = func() (string, error) {
	direct := physicaloutbound.NewDirect("", appconfig.BootstrapDNSServers())
	if err := direct.Init(); err != nil {
		return "", err
	}
	return direct.ResolvedIfaceName(), nil
}

func buildDNSServers(values []string, publicOutbound, directInterface string) ([]any, error) {
	if directInterface == "" {
		resolved, err := detectPhysicalInterface()
		if err != nil {
			return nil, fmt.Errorf("resolve physical interface for bootstrap DoH: %w", err)
		}
		directInterface = resolved
	}
	if len(values) == 0 {
		values = appconfig.ProxyDoHDefaults()
	}
	publicTags := make([]string, 0, len(values))
	publicServers := make([]any, 0, len(values))
	for index, raw := range values {
		tag := publicDNSTagPrefix + strconv.Itoa(index+1)
		detour := publicOutbound
		bindInterface := ""
		if detour == "" || detour == directTag {
			detour = ""
			bindInterface = directInterface
		}
		server, err := dohServerOptions(raw, tag, detour, bindInterface, bootstrapDNSTag)
		if err != nil {
			return nil, fmt.Errorf("public DoH %d: %w", index+1, err)
		}
		publicTags = append(publicTags, tag)
		publicServers = append(publicServers, server)
	}
	// Bootstrap resolves proxy/control hostnames only. It is deliberately a
	// physical-interface UDP resolver: direct 1.1.1.1:443 is blocked on some
	// networks, while user DNS still stays inside the proxy DoH transports.
	bootstrapHost, bootstrapPort, err := net.SplitHostPort(appconfig.BootstrapDNSServers()[0])
	if err != nil {
		return nil, fmt.Errorf("bootstrap DNS: %w", err)
	}
	port, err := strconv.Atoi(bootstrapPort)
	if err != nil {
		return nil, fmt.Errorf("bootstrap DNS port: %w", err)
	}
	bootstrap := map[string]any{
		"type":           "udp",
		"tag":            bootstrapDNSTag,
		"server":         bootstrapHost,
		"server_port":    port,
		"bind_interface": directInterface,
	}
	servers := []any{
		map[string]any{
			"type":              corpendpoint.DNSType,
			"tag":               dnsTransportTag,
			"public_transports": publicTags,
		},
		bootstrap,
	}
	servers = append(servers, publicServers...)
	return servers, nil
}

func dohServerOptions(rawURL, tag, detour, bindInterface, resolver string) (map[string]any, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("must be an https:// URL with a host")
	}
	port := 443
	if rawPort := parsed.Port(); rawPort != "" {
		port, err = strconv.Atoi(rawPort)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", rawPort)
		}
	}
	path := parsed.EscapedPath()
	if path == "" || path == "/" {
		path = "/dns-query"
	}
	serverHost := proxyDoHDialHost(parsed.Hostname())
	server := map[string]any{
		"type":        "https",
		"tag":         tag,
		"server":      serverHost,
		"server_port": port,
		"path":        path,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": parsed.Hostname(),
		},
	}
	if detour != "" {
		server["detour"] = detour
	} else if bindInterface != "" {
		server["bind_interface"] = bindInterface
	}
	if resolver != "" && net.ParseIP(serverHost) == nil {
		server["domain_resolver"] = resolver
	}
	return server, nil
}

func proxyDoHDialHost(host string) string {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "cloudflare-dns.com":
		return "1.1.1.1"
	case "dns.google":
		return "8.8.8.8"
	default:
		return host
	}
}

func withBootstrapDomainResolver(entry map[string]any) map[string]any {
	server, _ := entry["server"].(string)
	if strings.TrimSpace(server) == "" || net.ParseIP(strings.Trim(server, "[]")) != nil {
		return entry
	}
	clone := make(map[string]any, len(entry)+1)
	for key, value := range entry {
		clone[key] = value
	}
	clone["domain_resolver"] = bootstrapDNSTag
	return clone
}
