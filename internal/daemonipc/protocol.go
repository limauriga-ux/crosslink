package daemonipc

// Cmd is a command sent from GUI to daemon over the Unix socket.
type Cmd struct {
	Action      string `json:"action"`
	Company     string `json:"company,omitempty"`
	CodeType    string `json:"code_type,omitempty"`
	Account     string `json:"account,omitempty"`
	Code        string `json:"code,omitempty"`
	Password    string `json:"password,omitempty"`
	Token       string `json:"token,omitempty"`
	NodeID      int    `json:"node_id,omitempty"`
	GroupTag    string `json:"group_tag,omitempty"`
	OutboundTag string `json:"outbound_tag,omitempty"`
	Username    string `json:"username,omitempty"`
	Secret      string `json:"secret,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
	// FollowSplitRoutes is a pointer so an omitted field can preserve the last
	// split/full-tunnel choice.
	FollowSplitRoutes *bool `json:"follow_split_routes,omitempty"`
}

// Response is the daemon's reply.
type Response struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

// VPNNodeDTO is the wire format for a VPN node.
type VPNNodeDTO struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	LatencyMs    int    `json:"latency_ms"`
	ProtocolMode int    `json:"protocol_mode"`
}

type OpenVPNChallengeDTO struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Username      string `json:"username,omitempty"`
	Message       string `json:"message,omitempty"`
	URL           string `json:"url,omitempty"`
	URLAllowed    bool   `json:"url_allowed"`
	SecretMessage string `json:"secret_message,omitempty"`
	Echo          bool   `json:"echo,omitempty"`
	PreviousError string `json:"previous_error,omitempty"`
	Deadline      int64  `json:"deadline,omitempty"`
}

type OpenVPNStatusDTO struct {
	Configured  bool                 `json:"configured"`
	Active      bool                 `json:"active"`
	ProfileName string               `json:"profile_name,omitempty"`
	State       string               `json:"state"`
	Error       string               `json:"error,omitempty"`
	Server      string               `json:"server,omitempty"`
	Network     string               `json:"network,omitempty"`
	Cipher      string               `json:"cipher,omitempty"`
	IPv4        []string             `json:"ipv4,omitempty"`
	IPv6        []string             `json:"ipv6,omitempty"`
	DNS         []string             `json:"dns,omitempty"`
	MTU         uint32               `json:"mtu,omitempty"`
	ConnectedAt int64                `json:"connected_at,omitempty"`
	RouteCount  int                  `json:"route_count,omitempty"`
	DomainCount int                  `json:"domain_count,omitempty"`
	Challenge   *OpenVPNChallengeDTO `json:"challenge,omitempty"`
}

// VPNStatusDTO describes current VPN state.
type VPNStatusDTO struct {
	// DaemonVersion lets a caller identify the running build without diffing
	// binaries. Added because a field diagnosis stalled on "which version is
	// actually running?".
	DaemonVersion                 string   `json:"daemon_version,omitempty"`
	Connected                     bool     `json:"connected"`
	Reconnecting                  bool     `json:"reconnecting,omitempty"`
	NodeName                      string   `json:"node_name,omitempty"`
	VpnIP                         string   `json:"vpn_ip,omitempty"`
	DNS                           string   `json:"dns,omitempty"`
	Protocol                      string   `json:"protocol,omitempty"`     // "TCP" or "UDP"
	ConnectedAt                   int64    `json:"connected_at,omitempty"` // unix timestamp
	MixedAddr                     string   `json:"mixed_addr,omitempty"`   // sing-box mixed inbound
	RouteModeKnown                bool     `json:"route_mode_known,omitempty"`
	FollowSplitRoutes             bool     `json:"follow_split_routes"`
	CorporateRouteCount           int      `json:"corporate_route_count,omitempty"`
	CorporateDomainCount          int      `json:"corporate_domain_count,omitempty"`
	CorporateIgnoredPublicRoutes  int      `json:"corporate_ignored_public_routes,omitempty"`
	CorporateIgnoredPublicDomains int      `json:"corporate_ignored_public_domains,omitempty"`
	CoreRunning                   bool     `json:"core_running,omitempty"`
	TUNEnabled                    bool     `json:"tun_enabled,omitempty"`
	ProxyAvailable                bool     `json:"proxy_available,omitempty"`
	PublicProxyEnabled            bool     `json:"public_proxy_enabled,omitempty"`
	PublicDefault                 string   `json:"public_default,omitempty"`
	PublicSelected                string   `json:"public_selected,omitempty"`
	PublicSelectedType            string   `json:"public_selected_type,omitempty"`
	PublicChain                   []string `json:"public_chain,omitempty"`
	SystemTUNInterface            string   `json:"system_tun_interface,omitempty"`
	ExternalTUNs                  []string `json:"external_tuns,omitempty"`
	CompatibleTUNs                []string `json:"compatible_tuns,omitempty"`
	PublicRouteConflicts          []string `json:"public_route_conflicts,omitempty"`
	DNSMode                       string   `json:"dns_mode,omitempty"`
	DNSServers                    []string `json:"dns_servers,omitempty"`
	DNSProtected                  bool     `json:"dns_protected"`
	DomesticDirect                bool     `json:"domestic_direct"`
	DomesticRuleSets              []string `json:"domestic_rule_sets,omitempty"`

	// Diagnostics. Added because every field investigation so far has stalled
	// on questions the daemon already knew the answer to but only wrote to a
	// root-owned log: is the probe running, what is it deciding, how often has
	// it been overruled, and why did the last reconnect happen.
	ProbeCycles         int64  `json:"probe_cycles,omitempty"`
	ProbeFailures       int64  `json:"probe_failures,omitempty"`
	ProbeConsecutive    int32  `json:"probe_consecutive,omitempty"`
	ProbeThreshold      int32  `json:"probe_threshold,omitempty"`
	ProbeDNSFlakySkips  int64  `json:"probe_dns_flaky_skips,omitempty"`  // saved by tunnel-reachable
	ProbeHostStallSkips int64  `json:"probe_host_stall_skips,omitempty"` // vetoed by the direct-path control
	ProbeLastAt         int64  `json:"probe_last_at,omitempty"`
	ProbeLastOutcome    string `json:"probe_last_outcome,omitempty"` // ok|dns-flaky|host-stalled|dead
	// Cumulative for the daemon's lifetime. The per-connection counters above
	// reset on every reconnect, which erases exactly the rare events worth
	// watching — a control veto happens once in hours, and a reconnect in
	// between would hide that it ever happened.
	ProbeTotalCycles         int64 `json:"probe_total_cycles,omitempty"`
	ProbeTotalFailures       int64 `json:"probe_total_failures,omitempty"`
	ProbeTotalDNSFlakySkips  int64 `json:"probe_total_dns_flaky_skips,omitempty"`
	ProbeTotalHostStallSkips int64 `json:"probe_total_host_stall_skips,omitempty"`
	// TrafficVetoes counts death verdicts overruled because real traffic had
	// recently completed through the tunnel — the strongest evidence of health
	// there is, and cheaper than any probe since the traffic happens anyway.
	ProbeTrafficVetoes      int64  `json:"probe_traffic_vetoes,omitempty"`
	ProbeTotalTrafficVetoes int64  `json:"probe_total_traffic_vetoes,omitempty"`
	LastTunnelOKAt          int64  `json:"last_tunnel_ok_at,omitempty"` // unix; last dial that completed through the tunnel
	LastDeadReason          string `json:"last_dead_reason,omitempty"`
	// LastDeadAt dates the verdict above. It survives reconnects — the verdict
	// exists to explain the reconnect that followed it, so clearing it on
	// reconnect erased the answer exactly when it was wanted. Compare with
	// connected_at to tell whether the verdict caused the current connection.
	LastDeadAt         int64 `json:"last_dead_at,omitempty"`
	ReconnectTotal     int64 `json:"reconnect_total,omitempty"`
	ReconnectLastAt    int64 `json:"reconnect_last_at,omitempty"`
	ReconnectBackoffTo int64 `json:"reconnect_backoff_to,omitempty"` // unix; set while backing off
}

// QRCodeDTO carries the QR login URL and token.
type QRCodeDTO struct {
	LoginURL string `json:"login_url"`
	Token    string `json:"token"`
}

// VPNStatsDTO holds cumulative WireGuard byte counters.
type VPNStatsDTO struct {
	TxBytes int64 `json:"tx_bytes"`
	RxBytes int64 `json:"rx_bytes"`
}

type IPInfoDTO struct {
	IP       string `json:"ip"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
	Loc      string `json:"loc,omitempty"`
	Org      string `json:"org,omitempty"`
	Timezone string `json:"timezone,omitempty"`
}

// Action constants.
const (
	ActionDiscover                 = "discover"
	ActionLoginMethods             = "login_methods"
	ActionSendCode                 = "send_code"
	ActionVerifyCode               = "verify_code"
	ActionLoginPassword            = "login_password"
	ActionGetQRCode                = "get_qrcode"
	ActionPollQR                   = "poll_qr"
	ActionLogout                   = "logout"
	ActionListNodes                = "list_nodes"
	ActionPingNodes                = "ping_nodes"
	ActionListProxyGroups          = "list_proxy_groups"
	ActionSelectProxy              = "select_proxy"
	ActionTestProxyGroup           = "test_proxy_group"
	ActionConnect                  = "connect"
	ActionDisconnect               = "disconnect"
	ActionStatus                   = "status"
	ActionGetStats                 = "get_stats"
	ActionPingSingle               = "ping_single"
	ActionGetPublicIPInfo          = "get_public_ip_info"
	ActionGetCorporateIPInfo       = "get_corporate_ip_info"
	ActionIsAuthenticated          = "is_authenticated"
	ActionCleanupRoutes            = "cleanup_routes"
	ActionSetFollowSplitRoutes     = "set_follow_split_routes"
	ActionShutdown                 = "shutdown"
	ActionReloadConfig             = "reload_config"
	ActionOpenVPNConnect           = "openvpn_connect"
	ActionOpenVPNDisconnect        = "openvpn_disconnect"
	ActionOpenVPNStatus            = "openvpn_status"
	ActionOpenVPNPrepareChallenge  = "openvpn_prepare_challenge"
	ActionOpenVPNCompleteChallenge = "openvpn_complete_challenge"
	ActionOpenVPNCancelChallenge   = "openvpn_cancel_challenge"
	ActionOpenVPNRemoveProfile     = "openvpn_remove_profile"
)
