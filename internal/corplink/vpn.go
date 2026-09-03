package corplink

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"
)

// VPNNode describes a corplink VPN endpoint.
type VPNNode struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	IP           string `json:"ip"`
	APIPort      int    `json:"api_port"`
	VPNPort      int    `json:"vpn_port"`
	ProtocolMode int    `json:"protocol_mode"` // CorpLink server encoding: 1=UDP, 2=TCP
	Timeout      int    `json:"timeout"`
	LatencyMs    int    `json:"-"` // filled by PingNode, not from API
}

// ListNodes returns available VPN nodes. The list is normally requested
// immediately after another VPN changes macOS interfaces and DNS. Discard an
// idle HTTP/2 connection first so the request cannot hang on the pre-change
// network path while awaiting response headers.
func (c *Client) ListNodes(ctx context.Context) ([]VPNNode, error) {
	c.CloseIdleConnections()
	var resp apiResp[[]VPNNode]
	if err := c.get(ctx, c.apiURL("/api/vpn/list"), &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("list nodes: %s", resp.Message)
	}
	return resp.Data, nil
}

// PingNode measures round-trip latency to a node's API endpoint.
// Uses a short 5-second timeout; returns 9999 on failure.
func (c *Client) PingNode(ctx context.Context, node VPNNode) (int, error) {
	vpnBaseURL := fmt.Sprintf("https://%s:%d", node.IP, node.APIPort)
	c.CopySessionCookiesToURL(vpnBaseURL)
	pingURL := vpnBaseURL + "/vpn/ping?" + osQuery
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	var resp apiResp[any]
	if err := c.get(pingCtx, pingURL, &resp); err != nil {
		return 9999, err
	}
	return int(time.Since(start).Milliseconds()), nil
}

// WGConnInfo holds WireGuard configuration from the server.
type WGConnInfo struct {
	VpnIP           netip.Addr
	ServerPublicKey string // base64
	MTU             int
	DNSServers      []netip.Addr
	SplitRoutes     []string // CIDRs to route via VPN
	DomainSuffixes  []string // domain suffixes to route via VPN
	ProtocolMode    int
	ServerEndpoint  string // "ip:port"
}

type wgConnRespData struct {
	IP        string `json:"ip"`
	PublicKey string `json:"public_key"`
	Setting   struct {
		VpnMTU            int      `json:"vpn_mtu"`
		VpnDNS            string   `json:"vpn_dns"`
		VpnDNSBackup      string   `json:"vpn_dns_backup"`
		VpnDNSDomainSplit []string `json:"vpn_dns_domain_split"`
		VpnRouteSplit     []string `json:"vpn_route_split"`
	} `json:"setting"`
}

// GetWGConfig fetches WireGuard peer configuration for a node.
func (c *Client) GetWGConfig(ctx context.Context, node VPNNode, clientPublicKeyB64, totpSecret string) (*WGConnInfo, error) {
	vpnBaseURL := fmt.Sprintf("https://%s:%d", node.IP, node.APIPort)
	c.CopySessionCookiesToURL(vpnBaseURL)

	otp := ""
	if totpSecret != "" {
		var err error
		otp, err = TOTP(totpSecret)
		if err != nil {
			return nil, fmt.Errorf("totp: %w", err)
		}
	}

	type connReq struct {
		PublicKey string `json:"public_key"`
		OTP       string `json:"otp"`
	}
	var resp apiResp[wgConnRespData]
	if err := c.post(ctx, vpnBaseURL+"/vpn/conn?"+osQuery, connReq{
		PublicKey: clientPublicKeyB64,
		OTP:       otp,
	}, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("get wg config: %s", resp.Message)
	}
	d := resp.Data

	vpnIP, err := netip.ParseAddr(d.IP)
	if err != nil {
		return nil, fmt.Errorf("parse vpn ip %q: %w", d.IP, err)
	}

	var dnsServers []netip.Addr
	for _, s := range []string{d.Setting.VpnDNS, d.Setting.VpnDNSBackup} {
		if s == "" {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			dnsServers = append(dnsServers, a)
		}
	}

	return &WGConnInfo{
		VpnIP:           vpnIP,
		ServerPublicKey: d.PublicKey,
		MTU:             d.Setting.VpnMTU,
		DNSServers:      dnsServers,
		SplitRoutes:     d.Setting.VpnRouteSplit,
		DomainSuffixes:  d.Setting.VpnDNSDomainSplit,
		ProtocolMode:    node.ProtocolMode,
		ServerEndpoint:  fmt.Sprintf("%s:%d", node.IP, node.VPNPort),
	}, nil
}

// VPNSettings holds the dynamic routing settings returned by the VPN server.
// These are refreshed every keep-alive and may change as the corporate network
// adds or removes internal services.
type VPNSettings struct {
	SplitRoutes    []string // CIDRs to route via VPN
	DomainSuffixes []string // domain suffixes to route via VPN
}

// ReportVPN sends a keep-alive report to the VPN node (POST /vpn/report) and
// returns the current server-side VPN routing settings. The caller should apply
// them if they differ from the currently active configuration.
func (c *Client) ReportVPN(ctx context.Context, node VPNNode, vpnIP, publicKeyB64 string) (*VPNSettings, error) {
	vpnBaseURL := fmt.Sprintf("https://%s:%d", node.IP, node.APIPort)
	c.CopySessionCookiesToURL(vpnBaseURL)
	type reportReq struct {
		IP        string `json:"ip"`
		PublicKey string `json:"public_key"`
		Mode      string `json:"mode"`
		Type      string `json:"type"`
	}
	var resp apiResp[wgConnRespData]
	if err := c.post(ctx, vpnBaseURL+"/vpn/report?"+osQuery, reportReq{
		IP:        vpnIP,
		PublicKey: publicKeyB64,
		Mode:      "Split",
		Type:      "100",
	}, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		// code=1000 action="alert" is a soft server notification, not a hard error.
		// Log it at info level and treat as success so keepalive continues normally.
		if resp.Code == 1000 && resp.Action == "alert" {
			if resp.Message != "" {
				log.Printf("[corplink] vpn/report alert: %s", resp.Message)
			}
			return nil, nil
		}
		return nil, fmt.Errorf("vpn report: %s", resp.Message)
	}
	d := resp.Data
	return &VPNSettings{
		SplitRoutes:    d.Setting.VpnRouteSplit,
		DomainSuffixes: d.Setting.VpnDNSDomainSplit,
	}, nil
}
