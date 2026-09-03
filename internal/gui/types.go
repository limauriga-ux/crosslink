package gui

import (
	"net/http"

	"github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/daemonipc"
)

type Options struct {
	// DaemonPath is the user-owned staging copy extracted from the application.
	// A privileged service never executes it directly on macOS; installation
	// copies the checksum-pinned bytes to PrivilegedDaemonPath first.
	DaemonPath string
	// DaemonSHA256 is generated from the embedded helper at build time and is
	// rechecked by the privileged installer after copying the staging file.
	DaemonSHA256 string
	// PrivilegedDaemonPath overrides the fixed service executable path. It is
	// intended for platform-specific packaging and isolated tests.
	PrivilegedDaemonPath string
	// DaemonReplaced is set when the staging copy changed during this GUI run.
	DaemonReplaced bool
	ConfigPath     string
	LogPath        string
	WorkDir        string
	AppVersion     string
	Runner         Runner
	// AuthorizedUID/AuthorizedGID override the desktop identity when
	// AuthorizedIdentitySet is true. Production uses the GUI process identity.
	AuthorizedUID         int
	AuthorizedGID         int
	AuthorizedIdentitySet bool
}

type AppState struct {
	DaemonPath string       `json:"daemon_path"`
	ConfigPath string       `json:"config_path"`
	LogPath    string       `json:"log_path"`
	PidPath    string       `json:"pid_path"`
	Status     DaemonStatus `json:"status"`
}

type ConfigDocument struct {
	OK     bool           `json:"ok"`
	Path   string         `json:"path"`
	Config *config.Config `json:"config,omitempty"`
	Error  string         `json:"error,omitempty"`
}

type ValidationResult struct {
	OK     bool     `json:"ok"`
	Errors []string `json:"errors,omitempty"`
}

type ProxyItemResult struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"`
	DelayMs  int    `json:"delay_ms"`
	Selected bool   `json:"selected,omitempty"`
}

type ProxyGroupResult struct {
	Tag      string            `json:"tag"`
	Type     string            `json:"type"`
	Selected string            `json:"selected,omitempty"`
	Items    []ProxyItemResult `json:"items"`
}

type ProxyGroupsResult struct {
	OK      bool               `json:"ok"`
	Runtime bool               `json:"runtime,omitempty"`
	Groups  []ProxyGroupResult `json:"groups,omitempty"`
	Error   string             `json:"error,omitempty"`
}

type ProxyDelayResult struct {
	OK     bool           `json:"ok"`
	Delays map[string]int `json:"delays,omitempty"`
	Error  string         `json:"error,omitempty"`
}
type ProxyProfileResult struct {
	OK        bool     `json:"ok"`
	Path      string   `json:"path,omitempty"`
	Exists    bool     `json:"exists,omitempty"`
	Content   string   `json:"content,omitempty"`
	Format    string   `json:"format,omitempty"`
	Nodes     int      `json:"nodes,omitempty"`
	Endpoints int      `json:"endpoints,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type RulePlanResult struct {
	OK               bool     `json:"ok"`
	Path             string   `json:"path,omitempty"`
	Prepend          []string `json:"prepend"`
	Append           []string `json:"append"`
	Targets          []string `json:"targets"`
	ProfileRuleCount int      `json:"profile_rule_count"`
	Final            string   `json:"final,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type CommandResult struct {
	OK       bool   `json:"ok"`
	Summary  string `json:"summary,omitempty"`
	Details  string `json:"details,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
}

type DaemonStatus struct {
	State   string `json:"state"`
	PID     int    `json:"pid,omitempty"`
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
}

type TestRequest struct {
	TimeoutMillis int          `json:"timeout_millis,omitempty"`
	Items         []TestTarget `json:"items,omitempty"`
	HTTPClient    *http.Client `json:"-"`
}

type TestTarget struct {
	Name           string `json:"name"`
	URL            string `json:"url,omitempty"`
	Domain         string `json:"domain,omitempty"`
	ExpectedPolicy string `json:"expected_policy,omitempty"`
	Kind           string `json:"kind,omitempty"`
}

type TestReport struct {
	OK      bool         `json:"ok"`
	Results []TestResult `json:"results"`
}

type TestResult struct {
	Name           string `json:"name"`
	URL            string `json:"url,omitempty"`
	Domain         string `json:"domain,omitempty"`
	ExpectedPolicy string `json:"expected_policy,omitempty"`
	Reachable      bool   `json:"reachable"`
	HTTPStatus     int    `json:"http_status,omitempty"`
	RemoteIP       string `json:"remote_ip,omitempty"`
	DurationMillis int64  `json:"duration_millis"`
	Error          string `json:"error,omitempty"`
	// Samples/Successes are set by RunSingleTest when probing repeatedly;
	// DurationMillis is then the mean over successful probes.
	Samples   int `json:"samples,omitempty"`
	Successes int `json:"successes,omitempty"`
}

type ServiceStatus struct {
	Installed   bool `json:"installed"`
	Running     bool `json:"running"`
	NeedsUpdate bool `json:"needs_update"` // plist, helper bytes, ownership, or launch arguments are stale
	// StaleDaemon means the executable on disk changed after the running
	// process started. A full service reinstall supersedes this condition.
	StaleDaemon bool   `json:"stale_daemon"`
	Details     string `json:"details,omitempty"`
	Error       string `json:"error,omitempty"`
}

type WindowState struct {
	Width               int    `json:"width"`
	Height              int    `json:"height"`
	SelectedNodeID      int    `json:"selected_node_id,omitempty"`
	SelectedNodeName    string `json:"selected_node_name,omitempty"`
	SelectedNodeLatency int    `json:"selected_node_latency,omitempty"`
	FollowSplitRoutes   *bool  `json:"follow_split_routes,omitempty"`
	// CustomTestTargets holds user-added connectivity test sites. Only
	// Name and URL are meaningful here.
	CustomTestTargets []TestTarget `json:"custom_test_targets,omitempty"`
	// RemovedTestTargets lists built-in default test target names the user
	// deleted from the tests page, so they stay gone across restarts.
	RemovedTestTargets []string `json:"removed_test_targets,omitempty"`
}

// IPInfoResult holds egress IP metadata from ipinfo.io, queried through an
// explicitly chosen path (direct or via the mixed proxy).
type IPInfoResult struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	IP       string `json:"ip,omitempty"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"` // ISO 3166-1 alpha-2, e.g. "US"
	Loc      string `json:"loc,omitempty"`     // "lat,long"
	Org      string `json:"org,omitempty"`     // "AS3257 GTT Americas, LLC"
	Timezone string `json:"timezone,omitempty"`
}

type LaunchServiceRequest struct {
	Label      string `json:"label"`
	BinaryPath string `json:"binary_path"`
	ConfigPath string `json:"config_path"`
	WorkDir    string `json:"work_dir"`
}

type OpenVPNImportRequest struct {
	OVPNPath       string `json:"ovpn_path"`
	CAPath         string `json:"ca_path,omitempty"`
	PKCS12Path     string `json:"pkcs12_path,omitempty"`
	PKCS12Password string `json:"pkcs12_password,omitempty"`
	LegacyBFCompat bool   `json:"legacy_bf_compat,omitempty"`
}

type OpenVPNProfileResult struct {
	OK                   bool     `json:"ok"`
	Exists               bool     `json:"exists"`
	Path                 string   `json:"path,omitempty"`
	Name                 string   `json:"name,omitempty"`
	Server               string   `json:"server,omitempty"`
	Network              string   `json:"network,omitempty"`
	Routes               int      `json:"routes,omitempty"`
	Domains              int      `json:"domains,omitempty"`
	DNSServers           int      `json:"dns_servers,omitempty"`
	RequiresCredentials  bool     `json:"requires_credentials,omitempty"`
	LegacyCipherFallback bool     `json:"legacy_cipher_fallback,omitempty"`
	CertificateExpiresAt int64    `json:"certificate_expires_at,omitempty"`
	Warnings             []string `json:"warnings"`
	Error                string   `json:"error,omitempty"`
}

type OpenVPNChallengeResult struct {
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

type OpenVPNStatusResult struct {
	OK          bool                    `json:"ok"`
	Configured  bool                    `json:"configured"`
	Active      bool                    `json:"active"`
	ProfileName string                  `json:"profile_name,omitempty"`
	State       string                  `json:"state"`
	Error       string                  `json:"error,omitempty"`
	Server      string                  `json:"server,omitempty"`
	Network     string                  `json:"network,omitempty"`
	Cipher      string                  `json:"cipher,omitempty"`
	IPv4        []string                `json:"ipv4,omitempty"`
	IPv6        []string                `json:"ipv6,omitempty"`
	DNS         []string                `json:"dns,omitempty"`
	MTU         uint32                  `json:"mtu,omitempty"`
	ConnectedAt int64                   `json:"connected_at,omitempty"`
	RouteCount  int                     `json:"route_count,omitempty"`
	DomainCount int                     `json:"domain_count,omitempty"`
	Challenge   *OpenVPNChallengeResult `json:"challenge,omitempty"`
}

// LoginMethodsResult holds available login method names and verify types.
type LoginMethodsResult struct {
	OK          bool     `json:"ok"`
	Methods     []string `json:"methods,omitempty"`
	VerifyTypes []string `json:"verify_types,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// QRCodeResult holds QR login URL and token.
type QRCodeResult struct {
	OK       bool   `json:"ok"`
	LoginURL string `json:"login_url,omitempty"`
	Token    string `json:"token,omitempty"`
	Error    string `json:"error,omitempty"`
}

// VPNNodesResult holds a list of VPN nodes.
type VPNNodesResult struct {
	OK    bool                   `json:"ok"`
	Nodes []daemonipc.VPNNodeDTO `json:"nodes,omitempty"`
	Error string                 `json:"error,omitempty"`
}

// VPNStatusResult holds VPN connection status.
type VPNStatusResult struct {
	OK           bool `json:"ok"`
	Connected    bool `json:"connected"`
	Reconnecting bool `json:"reconnecting,omitempty"`
	// ReconnectBackoffTo is the unix timestamp at which the current
	// auto-reconnect backoff expires. Zero means an attempt is not delayed.
	ReconnectBackoffTo            int64  `json:"reconnect_backoff_to,omitempty"`
	NodeName                      string `json:"node_name,omitempty"`
	VpnIP                         string `json:"vpn_ip,omitempty"`
	DNS                           string `json:"dns,omitempty"`
	Protocol                      string `json:"protocol,omitempty"`
	ConnectedAt                   int64  `json:"connected_at,omitempty"`
	MixedAddr                     string `json:"mixed_addr,omitempty"`
	RouteModeKnown                bool   `json:"route_mode_known,omitempty"`
	FollowSplitRoutes             bool   `json:"follow_split_routes"`
	CorporateRouteCount           int    `json:"corporate_route_count,omitempty"`
	CorporateDomainCount          int    `json:"corporate_domain_count,omitempty"`
	CorporateIgnoredPublicRoutes  int    `json:"corporate_ignored_public_routes,omitempty"`
	CorporateIgnoredPublicDomains int    `json:"corporate_ignored_public_domains,omitempty"`

	Error string `json:"error,omitempty"`

	// Diagnostics mirrored from daemonipc.VPNStatusDTO so the GUI can surface
	// probe/reconnect health without reading the root-owned daemon log.
	DaemonVersion        string   `json:"daemon_version,omitempty"`
	CoreRunning          bool     `json:"core_running,omitempty"`
	TUNEnabled           bool     `json:"tun_enabled,omitempty"`
	ProxyAvailable       bool     `json:"proxy_available,omitempty"`
	PublicProxyEnabled   bool     `json:"public_proxy_enabled,omitempty"`
	PublicDefault        string   `json:"public_default,omitempty"`
	PublicSelected       string   `json:"public_selected,omitempty"`
	PublicSelectedType   string   `json:"public_selected_type,omitempty"`
	PublicChain          []string `json:"public_chain,omitempty"`
	SystemTUNInterface   string   `json:"system_tun_interface,omitempty"`
	ExternalTUNs         []string `json:"external_tuns,omitempty"`
	CompatibleTUNs       []string `json:"compatible_tuns,omitempty"`
	PublicRouteConflicts []string `json:"public_route_conflicts,omitempty"`
	DNSMode              string   `json:"dns_mode,omitempty"`
	DNSServers           []string `json:"dns_servers,omitempty"`
	DNSProtected         bool     `json:"dns_protected"`
	DomesticDirect       bool     `json:"domestic_direct"`
	DomesticRuleSets     []string `json:"domestic_rule_sets,omitempty"`

	ProbeCycles              int64  `json:"probe_cycles,omitempty"`
	ProbeFailures            int64  `json:"probe_failures,omitempty"`
	ProbeConsecutive         int32  `json:"probe_consecutive,omitempty"`
	ProbeThreshold           int32  `json:"probe_threshold,omitempty"`
	ProbeDNSFlakySkips       int64  `json:"probe_dns_flaky_skips,omitempty"`
	ProbeHostStallSkips      int64  `json:"probe_host_stall_skips,omitempty"`
	ProbeLastAt              int64  `json:"probe_last_at,omitempty"`
	ProbeLastOutcome         string `json:"probe_last_outcome,omitempty"`
	ProbeTotalCycles         int64  `json:"probe_total_cycles,omitempty"`
	ProbeTotalFailures       int64  `json:"probe_total_failures,omitempty"`
	ProbeTotalDNSFlakySkips  int64  `json:"probe_total_dns_flaky_skips,omitempty"`
	ProbeTotalHostStallSkips int64  `json:"probe_total_host_stall_skips,omitempty"`
	ProbeTrafficVetoes       int64  `json:"probe_traffic_vetoes,omitempty"`
	ProbeTotalTrafficVetoes  int64  `json:"probe_total_traffic_vetoes,omitempty"`
	LastTunnelOKAt           int64  `json:"last_tunnel_ok_at,omitempty"`
	LastDeadReason           string `json:"last_dead_reason,omitempty"`
	LastDeadAt               int64  `json:"last_dead_at,omitempty"`
	ReconnectTotal           int64  `json:"reconnect_total,omitempty"`
	ReconnectLastAt          int64  `json:"reconnect_last_at,omitempty"`
}

// VPNStatsResult holds cumulative WireGuard byte counters.
type VPNStatsResult struct {
	OK      bool  `json:"ok"`
	TxBytes int64 `json:"tx_bytes"`
	RxBytes int64 `json:"rx_bytes"`
}
