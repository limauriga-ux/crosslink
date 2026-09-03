package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/limauriga-ux/crosslink/internal/managedfs"
)

const MaxConfigBytes = 1 << 20

type DaemonRuntimePaths struct {
	ConfigPath     string
	DataDir        string
	PIDFile        string
	Socket         string
	Session        string
	HostRouteState string
}

// ResolveDaemonRuntimePaths derives every daemon-owned path from the one
// trusted config path. A caller-supplied PID path is accepted only when it is
// the fixed file inside that same data root.
func ResolveDaemonRuntimePaths(configPath, pidPath string) (DaemonRuntimePaths, error) {
	absoluteConfig, dataDir, err := ResolveDaemonConfigPath(configPath)
	if err != nil {
		return DaemonRuntimePaths{}, err
	}
	paths := DaemonRuntimePaths{
		ConfigPath:     absoluteConfig,
		DataDir:        dataDir,
		PIDFile:        filepath.Join(dataDir, "crosslink.pid"),
		Socket:         filepath.Join(dataDir, "daemon.sock"),
		Session:        filepath.Join(dataDir, "corplink_session.json"),
		HostRouteState: filepath.Join(dataDir, "host-routes.json"),
	}
	pidPath = strings.TrimSpace(pidPath)
	if pidPath == "" {
		return paths, nil
	}
	if !filepath.IsAbs(pidPath) {
		return DaemonRuntimePaths{}, errors.New("daemon pid file path must be absolute")
	}
	if filepath.Clean(pidPath) != paths.PIDFile {
		return DaemonRuntimePaths{}, fmt.Errorf("daemon pid file path must be %s", paths.PIDFile)
	}
	return paths, nil
}

// ValidateDaemonDataRoot verifies that runtime paths still describe the
// config-derived data root and that its owner is the explicitly selected
// desktop user (or root in root-only service mode). Ownership is read from an
// opened descriptor, never inferred from ambient HOME or a later path lookup.
func ValidateDaemonDataRoot(paths DaemonRuntimePaths, authorizedUID, authorizedGID int, rootOnly bool) (managedfs.Owner, error) {
	resolved, err := ResolveDaemonRuntimePaths(paths.ConfigPath, "")
	if err != nil {
		return managedfs.Owner{}, err
	}
	if filepath.Clean(paths.ConfigPath) != resolved.ConfigPath || filepath.Clean(paths.DataDir) != resolved.DataDir ||
		filepath.Clean(paths.PIDFile) != resolved.PIDFile ||
		filepath.Clean(paths.Socket) != resolved.Socket ||
		filepath.Clean(paths.Session) != resolved.Session ||
		filepath.Clean(paths.HostRouteState) != resolved.HostRouteState {
		return managedfs.Owner{}, errors.New("daemon runtime paths are not derived from config path")
	}
	if runtime.GOOS != "windows" {
		euid := os.Geteuid()
		if rootOnly && euid != 0 {
			return managedfs.Owner{}, errors.New("root-only daemon must run as root")
		}
		if !rootOnly && euid != 0 && (authorizedUID < 0 || euid != authorizedUID) {
			return managedfs.Owner{}, errors.New("non-root daemon uid does not match authorized uid")
		}
	}
	root, err := managedfs.Open(resolved.DataDir, false)
	if err != nil {
		return managedfs.Owner{}, fmt.Errorf("open daemon data root: %w", err)
	}
	defer root.Close()
	owner, err := root.Owner()
	if err != nil {
		return managedfs.Owner{}, fmt.Errorf("read daemon data root owner: %w", err)
	}
	if !owner.Valid() {
		if runtime.GOOS == "windows" {
			return owner, nil
		}
		return managedfs.Owner{}, errors.New("daemon data root owner is unavailable")
	}
	expectedUID, expectedGID := authorizedUID, authorizedGID
	if rootOnly {
		expectedUID, expectedGID = 0, 0
	}
	if expectedUID < 0 || expectedGID < 0 {
		return managedfs.Owner{}, errors.New("daemon authorized uid and gid are required")
	}
	if !rootOnly && expectedUID == 0 {
		return managedfs.Owner{}, errors.New("root daemon requires explicit root-only mode")
	}
	if owner.UID != expectedUID || owner.GID != expectedGID {
		return managedfs.Owner{}, fmt.Errorf("daemon data root owner %d:%d does not match authorized uid/gid %d:%d", owner.UID, owner.GID, expectedUID, expectedGID)
	}
	if err := validateDaemonConfigFile(resolved, owner); err != nil {
		return managedfs.Owner{}, err
	}
	return owner, nil
}

// validateDaemonConfigFile applies the same no-symlink and owner checks to a
// legacy config file that lives beside, rather than inside, the data root.
// The containing directory must itself pass managedfs.Open, which rejects
// group/other-writable roots before a privileged process reads the file.
func validateDaemonConfigFile(paths DaemonRuntimePaths, expected managedfs.Owner) error {
	rootPath := paths.DataDir
	if filepath.Dir(paths.ConfigPath) != paths.DataDir {
		rootPath = filepath.Dir(paths.ConfigPath)
	}
	root, err := managedfs.Open(rootPath, false)
	if err != nil {
		return fmt.Errorf("open daemon config root: %w", err)
	}
	defer root.Close()
	owner, err := root.Owner()
	if err != nil {
		return fmt.Errorf("read daemon config root owner: %w", err)
	}
	if expected.Valid() && owner.Valid() && (owner.UID != expected.UID || owner.GID != expected.GID) {
		return fmt.Errorf("daemon config root owner %d:%d does not match data root owner %d:%d", owner.UID, owner.GID, expected.UID, expected.GID)
	}
	if _, err := root.ReadFile(paths.ConfigPath, MaxConfigBytes); err != nil {
		return fmt.Errorf("validate daemon config file: %w", err)
	}
	return nil
}

// ResolveDaemonConfigPath validates the daemon configuration layout and
// derives the private data root without consulting HOME. The normal layout is
// <data-root>/config.json where <data-root> ends in .crosslink. For the GUI's
// legacy custom-config layout (<parent>/config.json), the data root is the
// sibling <parent>/.crosslink directory.
func ResolveDaemonConfigPath(path string) (configPath, dataDir string, err error) {
	raw := strings.TrimSpace(path)
	if raw == "" {
		return "", "", errors.New("daemon config path is required")
	}
	if !filepath.IsAbs(raw) {
		return "", "", errors.New("daemon config path must be absolute")
	}
	configPath = filepath.Clean(raw)
	if filepath.Base(configPath) != "config.json" {
		return "", "", errors.New("daemon config path must end with config.json")
	}
	parent := filepath.Dir(configPath)
	if filepath.Dir(parent) == parent {
		return "", "", errors.New("daemon config path cannot be directly under a filesystem root")
	}
	if filepath.Base(parent) == ".crosslink" {
		dataDir = parent
	} else {
		dataDir = filepath.Join(parent, ".crosslink")
	}
	if filepath.Dir(dataDir) == dataDir {
		return "", "", errors.New("CrossLink data directory cannot be a filesystem root")
	}
	return configPath, dataDir, nil
}

// LoadDaemonConfig is the privileged loader. It requires an absolute config
// path, verifies the config-derived data root against the authorized identity,
// binds all derived paths to that root, and reads the config through an os.Root
// so a symlink cannot redirect root file access.
func LoadDaemonConfig(path string, authorizedUID, authorizedGID int, rootOnly bool) (*Config, error) {
	absolute, dataDir, err := ResolveDaemonConfigPath(path)
	if err != nil {
		return nil, err
	}
	paths, err := ResolveDaemonRuntimePaths(absolute, "")
	if err != nil {
		return nil, err
	}
	owner, err := ValidateDaemonDataRoot(paths, authorizedUID, authorizedGID, rootOnly)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	cfg.dataDir = dataDir
	cfg.daemonSafe = true
	data, err := readDaemonConfigFile(absolute, dataDir)
	if err != nil {
		return nil, fmt.Errorf("read daemon config %q: %w", absolute, err)
	}
	loaded, err := mergeAndValidate(cfg, data)
	if err != nil {
		return nil, err
	}
	if err := loaded.ValidateDaemonPaths(); err != nil {
		return nil, err
	}
	loaded.SetDaemonOwner(owner)
	return loaded, nil
}

func readDaemonConfigFile(configPath, dataDir string) ([]byte, error) {
	rootPath := dataDir
	if filepath.Dir(configPath) != dataDir {
		rootPath = filepath.Dir(configPath)
	}
	root, err := managedfs.Open(rootPath, false)
	if err != nil {
		return nil, fmt.Errorf("open daemon config root: %w", err)
	}
	defer root.Close()
	return root.ReadFile(configPath, MaxConfigBytes)
}

// DaemonSafe reports whether the config entered through LoadDaemonConfig and
// therefore requires all runtime file access to use the managed root.
func (c *Config) DaemonSafe() bool {
	return c != nil && c.daemonSafe
}

// DataDir returns the absolute CrossLink data root bound to the config path.
func (c *Config) DataDir() (string, error) {
	if c == nil {
		return "", errors.New("config is nil")
	}
	if c.daemonSafe {
		if strings.TrimSpace(c.dataDir) == "" {
			return "", errors.New("daemon config is not bound to a data directory")
		}
		if !filepath.IsAbs(c.dataDir) {
			return "", errors.New("daemon config data directory must be absolute")
		}
	}
	return resolveDataDir(c.dataDir)
}

func resolveDataDir(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "~/.crosslink"
	}
	if raw == "~" || strings.HasPrefix(raw, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home for CrossLink data directory: %w", err)
		}
		if raw == "~" {
			raw = home
		} else {
			raw = filepath.Join(home, strings.TrimPrefix(raw, "~/"))
		}
	}
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("resolve CrossLink data directory: %w", err)
	}
	if filepath.Dir(absolute) == absolute {
		return "", errors.New("CrossLink data directory cannot be a filesystem root")
	}
	return absolute, nil
}

// ValidateDaemonPaths rejects every file path the privileged daemon consumes
// or writes unless it is a file below the config-bound data root.
func (c *Config) ValidateDaemonPaths() error {
	if c == nil {
		return errors.New("config is nil")
	}
	checks := []struct {
		field    string
		value    string
		optional bool
	}{
		{field: "core.profile", value: c.Core.Profile, optional: true},
		{field: "core.rules", value: c.Core.Rules, optional: true},
		{field: "core.state_file", value: c.Core.StateFile},
		{field: "log.file", value: c.Log.File},
	}
	for _, check := range checks {
		if _, err := c.resolveManagedFileBound(check.field, check.value, check.optional, true); err != nil {
			return err
		}
	}
	if c.Core.DomesticDirect {
		if _, _, err := c.DomesticRuleSetPaths(); err != nil {
			return err
		}
	}
	if _, _, err := c.OpenVPNProfilePath(); err != nil {
		return err
	}
	return nil
}

func (c *Config) ProxyProfilePath() (string, error) {
	return c.resolveManagedFile("core.profile", c.Core.Profile, true)
}

func (c *Config) RulePlanPath() (string, error) {
	return c.resolveManagedFile("core.rules", c.Core.Rules, true)
}

func (c *Config) ProxyStatePath() (string, error) {
	return c.resolveManagedFile("core.state_file", c.Core.StateFile, false)
}

func (c *Config) LogFilePath() (string, error) {
	return c.resolveManagedFile("log.file", c.Log.File, false)
}

func (c *Config) resolveManagedFile(field, raw string, optional bool) (string, error) {
	return c.resolveManagedFileBound(field, raw, optional, c.DaemonSafe())
}

func (c *Config) resolveManagedFileBound(field, raw string, optional, requireBound bool) (string, error) {
	dataDir, err := c.DataDir()
	if err != nil {
		return "", err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if optional {
			return "", nil
		}
		return "", fmt.Errorf("%s is required", field)
	}
	var path string
	switch {
	case raw == "~/.crosslink":
		path = dataDir
	case strings.HasPrefix(raw, "~/.crosslink/"):
		path = filepath.Join(dataDir, strings.TrimPrefix(raw, "~/.crosslink/"))
	case filepath.IsAbs(raw):
		path = raw
	default:
		return "", fmt.Errorf("%s must be absolute or start with ~/.crosslink/", field)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", field, err)
	}
	if requireBound {
		relative, relErr := filepath.Rel(dataDir, absolute)
		if relErr != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return "", fmt.Errorf("%s must be a file below %s", field, dataDir)
		}
	}
	return absolute, nil
}

func (c *Config) expandRuntimePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "~/.crosslink" {
		return c.DataDir()
	}
	if strings.HasPrefix(raw, "~/.crosslink/") {
		dataDir, err := c.DataDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dataDir, strings.TrimPrefix(raw, "~/.crosslink/")), nil
	}
	if c.DaemonSafe() {
		return raw, nil
	}
	if raw == "~" || strings.HasPrefix(raw, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if raw == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(raw, "~/")), nil
	}
	return raw, nil
}

func (c *Config) readRuntimeFile(field, raw string, limit int64, optional bool) ([]byte, error) {
	path, err := c.expandRuntimePath(raw)
	if err != nil {
		return nil, err
	}
	if path == "" && optional {
		return nil, os.ErrNotExist
	}
	if !c.DaemonSafe() {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return nil, statErr
		}
		if !info.Mode().IsRegular() {
			file.Close()
			return nil, fmt.Errorf("%s must be a regular file", field)
		}
		if info.Size() > limit {
			file.Close()
			return nil, fmt.Errorf("%s exceeds %d bytes", field, limit)
		}
		content, readErr := io.ReadAll(io.LimitReader(file, limit+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(content)) > limit {
			return nil, fmt.Errorf("%s exceeds %d bytes", field, limit)
		}
		return content, nil
	}
	managedPath, err := c.resolveManagedFile(field, raw, optional)
	if err != nil {
		return nil, err
	}
	dataDir, err := c.DataDir()
	if err != nil {
		return nil, err
	}
	root, err := managedfs.Open(dataDir, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(managedPath, limit)
}

func (c *Config) ReadCoreProfile(limit int64) ([]byte, error) {
	return c.readRuntimeFile("core.profile", c.Core.Profile, limit, true)
}

func (c *Config) ReadRulePlan(limit int64) ([]byte, error) {
	return c.readRuntimeFile("core.rules", c.Core.Rules, limit, true)
}

func (c *Config) ReadProxyState(limit int64) ([]byte, error) {
	return c.readRuntimeFile("core.state_file", c.Core.StateFile, limit, false)
}

func (c *Config) WriteProxyState(content []byte) error {
	path, err := c.ProxyStatePath()
	if err != nil {
		return err
	}
	rootPath, err := c.DataDir()
	if err != nil {
		return err
	}
	if !c.DaemonSafe() {
		path, err = c.expandRuntimePath(c.Core.StateFile)
		if err != nil {
			return err
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}
		rootPath = filepath.Dir(path)
	}
	root, err := managedfs.Open(rootPath, true)
	if err != nil {
		return err
	}
	defer root.Close()
	if owner, ok := c.DaemonOwner(); c.DaemonSafe() && ok {
		return root.WriteFileAtomicOwned(path, content, 0o600, owner.UID, owner.GID)
	}
	return root.WriteFileAtomic(path, content, 0o600)
}
