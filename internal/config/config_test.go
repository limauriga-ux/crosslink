package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultConfigUsesSecureUnifiedCore(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Corplink.InsecureSkipVerify {
		t.Fatal("TLS verification must be enabled by default")
	}
	if !cfg.Core.TUNEnabled {
		t.Fatal("embedded core TUN must be enabled by default")
	}
	if cfg.Core.MixedPort != 7890 {
		t.Fatalf("mixed port = %d, want 7890", cfg.Core.MixedPort)
	}
	if cfg.Core.Profile != "~/.crosslink/proxy.json" {
		t.Fatalf("profile path = %q", cfg.Core.Profile)
	}
	if cfg.Core.Rules != "~/.crosslink/rules.json" {
		t.Fatalf("rules path = %q", cfg.Core.Rules)
	}
	if !cfg.Core.DomesticDirect || cfg.Core.RuleSetDir != "~/.crosslink/rulesets" {
		t.Fatalf("domestic rules default = enabled:%v dir:%q", cfg.Core.DomesticDirect, cfg.Core.RuleSetDir)
	}
	if len(cfg.DNS.Upstream) == 0 {
		t.Fatal("public DoH defaults are empty")
	}
	for _, upstream := range cfg.DNS.Upstream {
		if !strings.HasPrefix(upstream, "https://") {
			t.Fatalf("insecure DNS default = %q", upstream)
		}
	}
}

func TestPartialConfigMergesIntoDefaults(t *testing.T) {
	cfg, err := LoadConfigFromBytes([]byte(`{
		"core":{"mixed_port":1080},
		"corplink":{"company_name":"acme"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Core.MixedPort != 1080 || !cfg.Core.TUNEnabled {
		t.Fatalf("core = %+v", cfg.Core)
	}
	if cfg.Corplink.CompanyName != "acme" || cfg.Corplink.InsecureSkipVerify {
		t.Fatalf("corplink = %+v", cfg.Corplink)
	}
}

func TestUnknownLegacyFieldsAreRejected(t *testing.T) {
	if _, err := LoadConfigFromBytes([]byte(`{"fakeip":{"pool":"198.18.0.0/15"}}`)); err == nil {
		t.Fatal("legacy fakeip field should not be silently accepted")
	}
}

func TestCoreValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Core.MixedPort = 70000
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid mixed port was accepted")
	}
	cfg = DefaultConfig()
	cfg.TUN.IP = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid TUN IP was accepted")
	}
}

func TestDomesticRuleSetDirectoryMustStayUnderConfigDirectory(t *testing.T) {
	configDir := t.TempDir()
	dataDir := filepath.Join(configDir, ".crosslink")
	configPath := filepath.Join(configDir, "config.json")

	tests := []struct {
		name string
		path string
		ok   bool
	}{
		{name: "default alias", path: "~/.crosslink/rulesets", ok: true},
		{name: "nested absolute", path: filepath.Join(dataDir, "cache", "rules"), ok: true},
		{name: "data directory root", path: dataDir},
		{name: "sibling prefix", path: dataDir + "-evil/rulesets"},
		{name: "parent traversal", path: filepath.Join(dataDir, "..", "escape")},
		{name: "system directory", path: "/tmp/crosslink-rulesets"},
		{name: "empty", path: ""},
		{name: "relative", path: ".crosslink/rulesets"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			if err := cfg.BindConfigPath(configPath); err != nil {
				t.Fatal(err)
			}
			cfg.Core.RuleSetDir = test.path
			err := cfg.Validate()
			if (err == nil) != test.ok {
				t.Fatalf("Validate(%q) error = %v, want ok=%v", test.path, err, test.ok)
			}
			if test.ok {
				resolvedData, resolvedRules, err := cfg.DomesticRuleSetPaths()
				if err != nil || resolvedData != dataDir || !strings.HasPrefix(resolvedRules, dataDir+string(filepath.Separator)) {
					t.Fatalf("resolved paths = %q/%q error=%v", resolvedData, resolvedRules, err)
				}
			}
		})
	}
}

func TestDomesticRuleSetDirectoryIgnoredWhenDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Core.DomesticDirect = false
	cfg.Core.RuleSetDir = "/tmp/outside-crosslink"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled domestic routing validated unused cache path: %v", err)
	}
}

func TestDefaultTunNameForCurrentPlatform(t *testing.T) {
	name := defaultTunName(runtime.GOOS)
	if runtime.GOOS == "darwin" {
		if name != "" {
			t.Fatalf("darwin TUN name = %q, want automatic allocation", name)
		}
		return
	}
	if name == "" {
		t.Fatal("default TUN name is empty")
	}
}

func TestDarwinMigratesLegacyBareTunName(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific config migration")
	}
	cfg, err := LoadConfigFromBytes([]byte(`{"tun":{"name":"utun"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TUN.Name != "" {
		t.Fatalf("migrated TUN name = %q, want automatic allocation", cfg.TUN.Name)
	}
}

func TestDarwinPreservesExplicitTunNumber(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific TUN naming")
	}
	cfg, err := LoadConfigFromBytes([]byte(`{"tun":{"name":" utun12 "}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TUN.Name != "utun12" {
		t.Fatalf("explicit TUN name = %q", cfg.TUN.Name)
	}
}

func TestDarwinRejectsInvalidTunNames(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific TUN naming")
	}
	for _, name := range []string{"tun12", "utun-1", "utunx", "utun12x"} {
		cfg := DefaultConfig()
		cfg.TUN.Name = name
		if err := cfg.Validate(); err == nil {
			t.Fatalf("invalid TUN name %q was accepted", name)
		}
	}
}

func TestLegacyPlainDNSMigratesToProxyDoH(t *testing.T) {
	cfg, err := LoadConfigFromBytes([]byte(`{"dns":{"upstream":["223.5.5.5:53","223.6.6.6:53"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNS.Upstream) != len(ProxyDoHDefaults()) || cfg.DNS.Upstream[0] != ProxyDoHDefaults()[0] {
		t.Fatalf("migrated DNS = %#v", cfg.DNS.Upstream)
	}
}

func TestSecureCustomDoHSurvivesMigration(t *testing.T) {
	cfg, err := LoadConfigFromBytes([]byte(`{"dns":{"upstream":["https://resolver.example/dns-query"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNS.Upstream) != 1 || cfg.DNS.Upstream[0] != "https://resolver.example/dns-query" {
		t.Fatalf("custom DoH = %#v", cfg.DNS.Upstream)
	}
}

func TestConfigRejectsPlaintextDNSOnSave(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNS.Upstream = []string{"1.1.1.1:53"}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("plaintext DNS validation error = %v", err)
	}
}

func TestResolveDaemonRuntimePathsIgnoresAmbientHome(t *testing.T) {
	ownerHome := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	dataDir := filepath.Join(ownerHome, ".crosslink")
	configPath := filepath.Join(dataDir, "config.json")
	paths, err := ResolveDaemonRuntimePaths(configPath, filepath.Join(dataDir, "crosslink.pid"))
	if err != nil {
		t.Fatal(err)
	}
	if paths.ConfigPath != configPath || paths.DataDir != dataDir ||
		paths.PIDFile != filepath.Join(dataDir, "crosslink.pid") ||
		paths.Socket != filepath.Join(dataDir, "daemon.sock") ||
		paths.Session != filepath.Join(dataDir, "corplink_session.json") ||
		paths.HostRouteState != filepath.Join(dataDir, "host-routes.json") {
		t.Fatalf("runtime paths = %+v", paths)
	}
}

func TestResolveDaemonRuntimePathsRejectsAlternatePIDFile(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".crosslink")
	_, err := ResolveDaemonRuntimePaths(filepath.Join(dataDir, "config.json"), filepath.Join(t.TempDir(), "crosslink.pid"))
	if err == nil || !strings.Contains(err.Error(), "must be") {
		t.Fatalf("alternate pid path error = %v", err)
	}
}

func TestLoadDaemonConfigBindsManagedRootAndOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("numeric owner assertions are Unix-specific")
	}
	dataDir := filepath.Join(t.TempDir(), ".crosslink")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dataDir, "config.json")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	cfg, err := LoadDaemonConfig(configPath, os.Getuid(), os.Getgid(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DaemonSafe() {
		t.Fatal("daemon config was not marked safe")
	}
	resolvedData, err := cfg.DataDir()
	if err != nil || resolvedData != dataDir {
		t.Fatalf("data dir = %q, %v", resolvedData, err)
	}
	profilePath, err := cfg.ProxyProfilePath()
	if err != nil || profilePath != filepath.Join(dataDir, "proxy.json") {
		t.Fatalf("profile path = %q, %v", profilePath, err)
	}
}

func TestLoadDaemonConfigRejectsWrongAuthorizedOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("numeric owner assertions are Unix-specific")
	}
	dataDir := filepath.Join(t.TempDir(), ".crosslink")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dataDir, "config.json")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDaemonConfig(configPath, os.Getuid()+1, os.Getgid(), false)
	if err == nil || !strings.Contains(err.Error(), "does not match authorized") {
		t.Fatalf("wrong owner error = %v", err)
	}
}

func TestLoadDaemonConfigRejectsSymlinkDataRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privilege semantics differ on Windows")
	}
	parent := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(parent, ".crosslink")
	if err := os.Symlink(outside, dataDir); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDaemonConfig(filepath.Join(dataDir, "config.json"), os.Getuid(), os.Getgid(), false)
	if err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlink data root error = %v", err)
	}
}

func TestDaemonSafeDataDirRejectsHomeAlias(t *testing.T) {
	cfg := DefaultConfig()
	cfg.daemonSafe = true
	cfg.dataDir = "~/.crosslink"
	if _, err := cfg.DataDir(); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("daemon-safe HOME alias error = %v", err)
	}
}
