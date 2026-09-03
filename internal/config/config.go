package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/limauriga-ux/crosslink/internal/managedfs"
)

// Config is the complete CrossLink-owned configuration. Remote proxy profiles
// are stored separately and may not override these system-level settings.
type Config struct {
	TUN            TUNConfig      `json:"tun"`
	DNS            DNSConfig      `json:"dns"`
	DirectOutbound OutboundConfig `json:"direct_outbound"`
	Corplink       CorplinkConfig `json:"corplink"`
	OpenVPN        OpenVPNConfig  `json:"openvpn"`
	Core           CoreConfig     `json:"core"`
	Log            LogConfig      `json:"log"`

	dataDir    string
	daemonSafe bool
	dataOwner  managedfs.Owner
	hasOwner   bool
}

// SetDaemonOwner records the already-verified owner of the config-bound data
// root. Privileged runtime writers use it to preserve GUI access after an
// atomic replacement.
func (c *Config) SetDaemonOwner(owner managedfs.Owner) {
	if c == nil {
		return
	}
	c.dataOwner = owner
	c.hasOwner = owner.Valid()
}

func (c *Config) DaemonOwner() (managedfs.Owner, bool) {
	if c == nil || !c.hasOwner {
		return managedfs.Owner{}, false
	}
	return c.dataOwner, true
}

type CorplinkConfig struct {
	CompanyName        string   `json:"company_name"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	DebugHTTPBody      bool     `json:"debug_http_body"`
	DirectInterface    string   `json:"-"`
	PublicDNS          []string `json:"-"`
}

// OpenVPNConfig points only to the CrossLink-managed, path-free client
// identity. Connection credentials and active state are daemon memory only.
type OpenVPNConfig struct {
	Profile string `json:"profile"`
}

// CoreConfig controls the embedded sing-box data plane. Profile is an
// optional sanitized sing-box fragment produced by the local profile importer.
// Rules is a separate local injection plan so subscription refreshes cannot
// overwrite user routing policy. DomesticDirect adds bundled CN domain/IP
// rule-sets after all explicit user/profile rules.
type CoreConfig struct {
	Profile        string `json:"profile"`
	Rules          string `json:"rules"`
	RuleSetDir     string `json:"rule_set_dir"`
	StateFile      string `json:"state_file"`
	DomesticDirect bool   `json:"domestic_direct"`
	TUNEnabled     bool   `json:"tun_enabled"`
	MixedPort      int    `json:"mixed_port"`
	LogLevel       string `json:"log_level"`
}

type TUNConfig struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Mask int    `json:"mask"`
	MTU  int    `json:"mtu"`
}

type DNSConfig struct {
	Upstream []string `json:"upstream"`
}

type OutboundConfig struct {
	Interface string `json:"interface"`
}

type LogConfig struct {
	Level   string `json:"level"`
	File    string `json:"file"`
	MaxSize string `json:"max_size"`
	MaxAge  int    `json:"max_age"`
}

func DefaultConfig() *Config {
	return &Config{
		dataDir: "~/.crosslink",
		TUN: TUNConfig{
			Name: defaultTunName(runtime.GOOS),
			IP:   "172.30.77.1",
			Mask: 30,
			MTU:  1420,
		},
		DNS: DNSConfig{
			Upstream: ProxyDoHDefaults(),
		},
		DirectOutbound: OutboundConfig{},
		Corplink: CorplinkConfig{
			InsecureSkipVerify: false,
		},
		OpenVPN: OpenVPNConfig{
			Profile: "~/.crosslink/openvpn/profile.json",
		},
		Core: CoreConfig{
			Profile:        "~/.crosslink/proxy.json",
			Rules:          "~/.crosslink/rules.json",
			RuleSetDir:     "~/.crosslink/rulesets",
			StateFile:      "~/.crosslink/proxy-state.json",
			DomesticDirect: true,
			TUNEnabled:     true,
			MixedPort:      7890,
			LogLevel:       "info",
		},
		Log: LogConfig{
			Level:   "info",
			File:    "~/.crosslink/crosslink.log",
			MaxSize: "100MB",
			MaxAge:  7,
		},
	}
}

func defaultTunName(goos string) string {
	switch goos {
	case "darwin":
		// sing-tun turns an empty name into the next available concrete utunN.
		// The bare name "utun" is invalid on macOS.
		return ""
	case "windows":
		return "CrossLink"
	default:
		return "crosslink0"
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		for _, candidate := range []string{"config.json", ".crosslink.json"} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		return cfg, nil
	}
	if err := cfg.BindConfigPath(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	return mergeAndValidate(cfg, data)
}

func LoadConfigFromBytes(data []byte) (*Config, error) {
	return mergeAndValidate(DefaultConfig(), data)
}

func mergeAndValidate(cfg *Config, data []byte) (*Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if runtime.GOOS == "darwin" {
		name, err := normalizeDarwinTUNName(cfg.TUN.Name)
		if err != nil {
			return nil, err
		}
		cfg.TUN.Name = name
	}
	cfg.DNS.Upstream = migrateLegacyDNS(cfg.DNS.Upstream)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if c.Core.MixedPort < 0 || c.Core.MixedPort > 65535 {
		return fmt.Errorf("core mixed_port must be between 0 and 65535")
	}

	if c.Core.DomesticDirect {
		if _, _, err := c.DomesticRuleSetPaths(); err != nil {
			return err
		}
	}
	if _, _, err := c.OpenVPNProfilePath(); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		name, err := normalizeDarwinTUNName(c.TUN.Name)
		if err != nil {
			return err
		}
		c.TUN.Name = name
	}
	if c.Core.TUNEnabled {
		if ip := net.ParseIP(strings.TrimSpace(c.TUN.IP)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("tun ip must be a valid IPv4 address")
		}
		if c.TUN.Mask < 1 || c.TUN.Mask > 32 {
			return fmt.Errorf("tun mask must be between 1 and 32")
		}
		if c.TUN.MTU < 576 || c.TUN.MTU > 9000 {
			return fmt.Errorf("tun mtu must be between 576 and 9000")
		}
	}
	if len(c.DNS.Upstream) == 0 {
		return fmt.Errorf("dns upstream must contain at least one proxy DoH URL")
	}
	for _, server := range c.DNS.Upstream {
		if _, err := normalizeProxyDoHURL(server); err != nil {
			return fmt.Errorf("dns upstream %q: %w", server, err)
		}
	}
	if c.Log.MaxAge < 1 {
		return fmt.Errorf("log max_age must be at least 1 day")
	}
	return nil
}

// EnsureDataDir creates the config-bound private data root with owner-only
// permissions. GUI setup calls this before a privileged daemon is launched.
func (c *Config) EnsureDataDir() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	dataDir, err := c.DataDir()
	if err != nil {
		return err
	}
	root, err := managedfs.Open(dataDir, true)
	if err != nil {
		return err
	}
	return root.Close()
}

func normalizeDarwinTUNName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || name == "utun" {
		return "", nil
	}
	if !strings.HasPrefix(name, "utun") || len(name) == len("utun") {
		return "", fmt.Errorf("tun name must be empty for automatic allocation or use utunN")
	}
	index, err := strconv.ParseUint(strings.TrimPrefix(name, "utun"), 10, 16)
	if err != nil {
		return "", fmt.Errorf("tun name must be empty for automatic allocation or use utunN")
	}
	return fmt.Sprintf("utun%d", index), nil
}

func (c *Config) BindConfigPath(path string) error {
	if c == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	dataDir := filepath.Dir(absolute)
	if filepath.Base(dataDir) != ".crosslink" {
		dataDir = filepath.Join(dataDir, ".crosslink")
	}
	c.dataDir = dataDir
	return nil
}

func (c *Config) DomesticRuleSetPaths() (dataDir, ruleSetDir string, err error) {
	if c == nil {
		return "", "", fmt.Errorf("config is nil")
	}
	dataDir, err = resolveDataDir(c.dataDir)
	if err != nil {
		return "", "", err
	}

	raw := strings.TrimSpace(c.Core.RuleSetDir)
	switch {
	case raw == "~/.crosslink":
		ruleSetDir = dataDir
	case strings.HasPrefix(raw, "~/.crosslink/"):
		ruleSetDir = filepath.Join(dataDir, strings.TrimPrefix(raw, "~/.crosslink/"))
	case filepath.IsAbs(raw):
		ruleSetDir = raw
	case raw == "":
		return "", "", fmt.Errorf("core rule_set_dir is required when domestic_direct is enabled")
	default:
		return "", "", fmt.Errorf("core rule_set_dir must be absolute or start with ~/.crosslink/")
	}
	ruleSetDir, err = filepath.Abs(ruleSetDir)
	if err != nil {
		return "", "", fmt.Errorf("resolve core rule_set_dir: %w", err)
	}
	relative, err := filepath.Rel(dataDir, ruleSetDir)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", "", fmt.Errorf("core rule_set_dir must be a subdirectory of %s", dataDir)
	}
	return dataDir, ruleSetDir, nil
}

func (c *Config) OpenVPNProfilePath() (dataDir, profilePath string, err error) {
	if c == nil {
		return "", "", fmt.Errorf("config is nil")
	}
	dataDir, err = resolveDataDir(c.dataDir)
	if err != nil {
		return "", "", err
	}
	raw := strings.TrimSpace(c.OpenVPN.Profile)
	switch {
	case strings.HasPrefix(raw, "~/.crosslink/"):
		profilePath = filepath.Join(dataDir, strings.TrimPrefix(raw, "~/.crosslink/"))
	case filepath.IsAbs(raw):
		profilePath = raw
	case raw == "":
		return "", "", fmt.Errorf("openvpn.profile is required")
	default:
		return "", "", fmt.Errorf("openvpn.profile must be absolute or start with ~/.crosslink/")
	}
	profilePath, err = filepath.Abs(profilePath)
	if err != nil {
		return "", "", fmt.Errorf("resolve openvpn.profile: %w", err)
	}
	relative, err := filepath.Rel(dataDir, profilePath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", "", fmt.Errorf("openvpn.profile must be a file below %s", dataDir)
	}
	return dataDir, profilePath, nil
}

var defaultProxyDoH = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
}

func ProxyDoHDefaults() []string {
	return append([]string(nil), defaultProxyDoH...)
}

// BootstrapDNSServers resolve only proxy/control hostnames on the physical
// interface. User DNS queries never use this plaintext bootstrap path.
func BootstrapDNSServers() []string {
	return []string{"114.114.114.114:53", "223.5.5.5:53"}
}

func migrateLegacyDNS(values []string) []string {
	secure := make([]string, 0, len(values))
	for _, value := range values {
		if normalized, err := normalizeProxyDoHURL(value); err == nil {
			secure = append(secure, normalized)
		}
	}
	if len(secure) == 0 {
		return ProxyDoHDefaults()
	}
	return secure
}

func normalizeProxyDoHURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("must use https:// DoH")
	}
	if parsed.Hostname() == "" || parsed.User != nil {
		return "", fmt.Errorf("must contain a host and no credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("query and fragment are not supported")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/dns-query"
	}
	return parsed.String(), nil
}
