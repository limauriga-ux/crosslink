export type DaemonState = 'running' | 'stopped' | 'starting' | 'stopping' | 'error' | 'unknown'

export interface ConfigDocument {
  tun: { name: string; ip: string; mask: number; mtu: number }
  dns: { upstream: string[] }
  direct_outbound: { interface: string }
  corplink: { company_name: string; insecure_skip_verify: boolean; debug_http_body: boolean }
  openvpn: { profile: string }
  core: { profile: string; rules: string; rule_set_dir: string; state_file: string; domestic_direct: boolean; tun_enabled: boolean; mixed_port: number; log_level: string }
  log: { level: string; file: string; max_size: string; max_age: number }
}

export interface OpenVPNImportRequest {
  ovpn_path: string
  ca_path?: string
  pkcs12_path?: string
  pkcs12_password?: string
  legacy_bf_compat?: boolean
}

export interface OpenVPNProfileResult {
  ok: boolean
  exists: boolean
  path?: string
  name?: string
  server?: string
  network?: string
  routes?: number
  domains?: number
  dns_servers?: number
  requires_credentials?: boolean
  legacy_cipher_fallback?: boolean
  certificate_expires_at?: number
  warnings: string[] | null
  error?: string
}

export interface OpenVPNChallengeResult {
  id: string
  kind: 'credentials' | 'secret' | 'message' | 'open-url' | string
  username?: string
  message?: string
  url?: string
  url_allowed: boolean
  secret_message?: string
  echo?: boolean
  previous_error?: string
  deadline?: number
}

export interface OpenVPNStatusResult {
  ok: boolean
  configured: boolean
  active: boolean
  profile_name?: string
  state: 'disconnected' | 'connecting' | 'auth-pending' | 'connected' | 'error' | 'unavailable' | string
  error?: string
  server?: string
  network?: string
  cipher?: string
  ipv4?: string[] | null
  ipv6?: string[] | null
  dns?: string[] | null
  mtu?: number
  connected_at?: number
  route_count?: number
  domain_count?: number
  challenge?: OpenVPNChallengeResult | null
}

export interface ProxyItemResult {
  tag: string
  type: string
  delay_ms: number
  selected?: boolean
}

export interface ProxyGroupResult {
  tag: string
  type: string
  selected?: string
  items: ProxyItemResult[]
}

export interface ProxyGroupsResult {
  ok: boolean
  runtime?: boolean
  groups?: ProxyGroupResult[]
  error?: string
}

export interface ProxyDelayResult {
  ok: boolean
  delays?: Record<string, number>
  error?: string
}

export interface RulePlanResult {
  ok: boolean
  path?: string
  prepend: string[]
  append: string[]
  targets: string[]
  profile_rule_count: number
  final?: string
  error?: string
}

export interface DaemonStatus {
  state: DaemonState
  pid?: number
  summary?: string
  error?: string
}

export interface AppState {
  daemon_path: string
  config_path: string
  log_path: string
  pid_path?: string
  status: DaemonStatus
}

export interface ConfigResponse {
  ok: boolean
  path: string
  config?: ConfigDocument
  error?: string
}

export interface CommandResult {
  ok: boolean
  summary?: string
  details?: string
  exit_code?: number
}

export interface WindowState {
  width: number
  height: number
  selected_node_id?: number
  selected_node_name?: string
  selected_node_latency?: number
  follow_split_routes?: boolean
  custom_test_targets?: TestTarget[]
  removed_test_targets?: string[]
}

export interface ValidationResult {
  ok: boolean
  errors?: string[]
}

export interface ProxyProfileResult {
	ok: boolean
	path?: string
	exists?: boolean
	content?: string
	format?: string
	nodes?: number
	endpoints?: number
	warnings?: string[]
	error?: string
}

export interface TestTarget {
  name: string
  url?: string
  domain?: string
  expected_policy?: string
  kind?: string
}

export interface TestResult {
  name: string
  url?: string
  domain?: string
  expected_policy?: string
  reachable: boolean
  http_status?: number
  remote_ip?: string
  duration_millis: number
  error?: string
  samples?: number
  successes?: number
}

export interface TestReport {
  ok: boolean
  results: TestResult[]
}

export interface LaunchServiceRequest {
  label: string
  binary_path: string
  config_path: string
  work_dir: string
}

export interface ServiceStatus {
  installed: boolean
  running: boolean
  needs_update?: boolean
  stale_daemon?: boolean
  details?: string
  error?: string
}

// New types for corplink integration
export interface LoginMethodsResult { ok: boolean; methods?: string[]; verify_types?: string[]; error?: string }
export interface QRCodeResult { ok: boolean; login_url?: string; token?: string; error?: string }
export interface VPNNode { id: number; name: string; latency_ms: number; protocol_mode: number }
export interface VPNNodesResult { ok: boolean; nodes?: VPNNode[]; error?: string }
export interface VPNStatusResult {
  ok: boolean
  connected: boolean
  reconnecting?: boolean
  /** Unix timestamp (seconds) at which the current auto-reconnect backoff ends. */
  reconnect_backoff_to?: number
  node_name?: string
  vpn_ip?: string
  dns?: string
  protocol?: string
  connected_at?: number
  mixed_addr?: string
  route_mode_known?: boolean
  follow_split_routes?: boolean
  corporate_route_count?: number
  corporate_domain_count?: number
  corporate_ignored_public_routes?: number
  corporate_ignored_public_domains?: number
  error?: string
  // Diagnostics mirrored from the daemon (see daemonipc.VPNStatusDTO).
  daemon_version?: string
  core_running?: boolean
  tun_enabled?: boolean
  proxy_available?: boolean
  public_proxy_enabled?: boolean
  public_default?: string
  public_selected?: string
  public_selected_type?: string
  public_chain?: string[]
  system_tun_interface?: string
  external_tuns?: string[]
  compatible_tuns?: string[]
  public_route_conflicts?: string[]
  dns_mode?: string
  dns_servers?: string[]
  dns_protected?: boolean
  domestic_direct?: boolean
  domestic_rule_sets?: string[]
  probe_cycles?: number
  probe_failures?: number
  probe_consecutive?: number
  probe_threshold?: number
  probe_dns_flaky_skips?: number
  probe_host_stall_skips?: number
  probe_last_at?: number
  probe_last_outcome?: string
  probe_total_cycles?: number
  probe_total_failures?: number
  probe_total_dns_flaky_skips?: number
  probe_total_host_stall_skips?: number
  probe_traffic_vetoes?: number
  probe_total_traffic_vetoes?: number
  last_tunnel_ok_at?: number
  last_dead_reason?: string
  last_dead_at?: number
  reconnect_total?: number
  reconnect_last_at?: number
}
export interface VPNStatsResult { ok: boolean; tx_bytes: number; rx_bytes: number }

// Egress IP metadata from ipinfo.io, mirrored from gui.IPInfoResult.
export interface IPInfoResult {
  ok: boolean
  error?: string
  ip?: string
  city?: string
  region?: string
  country?: string  // ISO 3166-1 alpha-2, e.g. "US"
  loc?: string      // "lat,long"
  org?: string      // "AS3257 GTT Americas, LLC"
  timezone?: string
}
