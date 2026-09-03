package gui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	darwinServiceLabel         = "io.github.limauriga.crosslink.daemon"
	darwinLaunchDaemonPath     = "/Library/LaunchDaemons/io.github.limauriga.crosslink.daemon.plist"
	darwinPrivilegedHelperPath = "/Library/PrivilegedHelperTools/io.github.limauriga.crosslink.daemon"
)

func (s *Service) GetLaunchServiceStatus() ServiceStatus {
	switch runtime.GOOS {
	case "darwin":
		return s.getDarwinLaunchServiceStatus()
	case "linux":
		return s.getLinuxServiceStatus()
	case "windows":
		return s.getWindowsServiceStatus()
	default:
		return ServiceStatus{Installed: false, Running: false, Error: "service management is not supported on this platform"}
	}
}

func (s *Service) getDarwinLaunchServiceStatus() ServiceStatus {
	info, err := os.Lstat(darwinLaunchDaemonPath)
	if err != nil {
		return ServiceStatus{Installed: false, Running: false}
	}
	installed := info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular()
	managed, managedErr := s.managedLaunchServiceRequest(LaunchServiceRequest{})
	needsUpdate := !installed || managedErr != nil || s.darwinServiceNeedsUpdate(managed)

	res := s.runner.Run(nilContext(), RunRequest{
		Path: "launchctl",
		Args: []string{"print", "system/" + darwinServiceLabel},
	})
	running := res.OK
	details := res.Stdout + res.Stderr
	if managedErr != nil {
		details = strings.TrimSpace(details + "\n" + managedErr.Error())
	}

	return ServiceStatus{
		Installed:   installed,
		Running:     running,
		NeedsUpdate: needsUpdate,
		StaleDaemon: running && !needsUpdate && s.daemonReplaced,
		Details:     details,
	}
}

func (s *Service) InstallLaunchService(req LaunchServiceRequest) CommandResult {
	managed, err := s.managedLaunchServiceRequest(req)
	if err != nil {
		return CommandResult{OK: false, Summary: err.Error()}
	}
	if res := s.EnsureUserConfig(managed.ConfigPath); !res.OK {
		return res
	}
	switch runtime.GOOS {
	case "darwin":
		return s.installDarwinLaunchService(managed)
	case "linux", "windows":
		args := append([]string{"install-service"}, s.daemonRunArgs(false)...)
		return s.sourceCommand(args...)
	default:
		return CommandResult{OK: false, Summary: "service install is not supported on this platform"}
	}
}

func (s *Service) StartLaunchService(req LaunchServiceRequest) CommandResult {
	managed, err := s.managedLaunchServiceRequest(req)
	if err != nil {
		return CommandResult{OK: false, Summary: err.Error()}
	}
	if res := s.EnsureUserConfig(managed.ConfigPath); !res.OK {
		return res
	}
	req = managed
	switch runtime.GOOS {
	case "darwin":
		return s.startDarwinLaunchService(req)
	case "linux", "windows":
		args := append([]string{"start"}, s.daemonRunArgs(false)...)
		return s.privilegedCommand(args...)
	default:
		return CommandResult{OK: false, Summary: "service start is not supported on this platform"}
	}
}

func (s *Service) managedLaunchServiceRequest(req LaunchServiceRequest) (LaunchServiceRequest, error) {
	if s.runtimePathErr != nil {
		return LaunchServiceRequest{}, s.runtimePathErr
	}
	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && (s.authorizedUID < 0 || s.authorizedGID < 0) {
		return LaunchServiceRequest{}, fmt.Errorf("desktop uid and gid are unavailable")
	}
	managed := LaunchServiceRequest{
		Label:      darwinServiceLabel,
		BinaryPath: s.daemonPath,
		ConfigPath: s.configPath,
		WorkDir:    s.workDir,
	}
	checks := []struct {
		field string
		got   string
		want  string
	}{
		{field: "label", got: req.Label, want: managed.Label},
		{field: "binary_path", got: req.BinaryPath, want: managed.BinaryPath},
		{field: "config_path", got: req.ConfigPath, want: managed.ConfigPath},
		{field: "work_dir", got: req.WorkDir, want: managed.WorkDir},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.got) == "" {
			continue
		}
		if check.field == "label" {
			if check.got != check.want {
				return LaunchServiceRequest{}, fmt.Errorf("launch service %s is fixed to %q", check.field, check.want)
			}
			continue
		}
		got, gotErr := filepath.Abs(expandHome(check.got))
		want, wantErr := filepath.Abs(expandHome(check.want))
		if gotErr != nil || wantErr != nil || filepath.Clean(got) != filepath.Clean(want) {
			return LaunchServiceRequest{}, fmt.Errorf("launch service %s is fixed to %q", check.field, check.want)
		}
	}
	return managed, nil
}

func (s *Service) startDarwinLaunchService(req LaunchServiceRequest) CommandResult {
	if s.darwinServiceNeedsUpdate(req) {
		return s.installDarwinLaunchService(req)
	}
	script := fmt.Sprintf(
		"launchctl bootstrap system %s 2>/dev/null; true && launchctl enable system/%s && launchctl kickstart -k system/%s",
		shellQuote(darwinLaunchDaemonPath),
		shellQuote(req.Label),
		shellQuote(req.Label),
	)
	osa := fmt.Sprintf("do shell script %s with administrator privileges", appleScriptQuote(script))
	res := s.runner.Run(nilContext(), RunRequest{Path: "osascript", Args: []string{"-e", osa}, Timeout: privilegedRunTimeout})
	return commandResult(res)
}

func (s *Service) installDarwinLaunchService(req LaunchServiceRequest) CommandResult {
	if err := validateDaemonSource(s.daemonSourcePath, s.daemonSHA256); err != nil {
		return CommandResult{OK: false, Summary: err.Error()}
	}
	plist := LaunchDaemonPlist(req, s.pidPath, s.authorizedUID, s.authorizedGID)
	helperDir := filepath.Dir(req.BinaryPath)
	helperTemp := req.BinaryPath + ".new"
	plistTemp := darwinLaunchDaemonPath + ".new"
	script := fmt.Sprintf(
		"set -e; test ! -L %s; /usr/bin/install -d -o root -g wheel -m 0755 %s; /bin/rm -f %s; /usr/bin/install -o root -g wheel -m 0755 %s %s; actual=$(/usr/bin/shasum -a 256 %s); actual=${actual%%%% *}; test \"$actual\" = %s; /bin/mv -f %s %s; /usr/sbin/chown root:wheel %s; /bin/chmod 0755 %s; /bin/rm -f %s; /usr/bin/printf %%s %s > %s; /usr/sbin/chown root:wheel %s; /bin/chmod 0644 %s; /bin/mv -f %s %s; (launchctl bootout system/%s 2>/dev/null || true); launchctl bootstrap system %s; launchctl enable system/%s; launchctl kickstart -k system/%s",
		shellQuote(helperDir), shellQuote(helperDir), shellQuote(helperTemp),
		shellQuote(s.daemonSourcePath), shellQuote(helperTemp), shellQuote(helperTemp), shellQuote(s.daemonSHA256),
		shellQuote(helperTemp), shellQuote(req.BinaryPath), shellQuote(req.BinaryPath), shellQuote(req.BinaryPath),
		shellQuote(plistTemp), shellQuote(plist), shellQuote(plistTemp), shellQuote(plistTemp), shellQuote(plistTemp),
		shellQuote(plistTemp), shellQuote(darwinLaunchDaemonPath), shellQuote(req.Label), shellQuote(darwinLaunchDaemonPath),
		shellQuote(req.Label), shellQuote(req.Label),
	)
	osa := fmt.Sprintf("do shell script %s with administrator privileges", appleScriptQuote(script))
	res := s.runner.Run(nilContext(), RunRequest{Path: "osascript", Args: []string{"-e", osa}, Timeout: privilegedRunTimeout})
	result := commandResult(res)
	if result.OK {
		s.daemonReplaced = false
	}
	return result
}

func (s *Service) UninstallLaunchService() CommandResult {
	switch runtime.GOOS {
	case "darwin":
		return s.uninstallDarwinLaunchService("io.github.limauriga.crosslink.daemon")
	case "linux", "windows":
		return s.privilegedCommand("uninstall-service")
	default:
		return CommandResult{OK: false, Summary: "service uninstall is not supported on this platform"}
	}
}

func (s *Service) uninstallDarwinLaunchService(label string) CommandResult {
	if label == "" {
		label = darwinServiceLabel
	}
	script := fmt.Sprintf(
		"launchctl bootout system/%s 2>/dev/null; true && rm -f %s %s",
		shellQuote(label),
		shellQuote(darwinLaunchDaemonPath),
		shellQuote(darwinPrivilegedHelperPath),
	)
	osa := fmt.Sprintf("do shell script %s with administrator privileges", appleScriptQuote(script))
	res := s.runner.Run(nilContext(), RunRequest{Path: "osascript", Args: []string{"-e", osa}, Timeout: privilegedRunTimeout})
	return commandResult(res)
}

func (s *Service) getLinuxServiceStatus() ServiceStatus {
	unitPath := "/etc/systemd/system/io.github.limauriga.crosslink.daemon.service"
	_, err := os.Stat(unitPath)
	installed := err == nil
	if !installed {
		return ServiceStatus{Installed: false, Running: false}
	}
	res := s.runner.Run(nilContext(), RunRequest{Path: "systemctl", Args: []string{"is-active", "--quiet", "io.github.limauriga.crosslink.daemon.service"}})
	needsUpdate := false
	if s.daemonPath != "" {
		if data, err := os.ReadFile(unitPath); err == nil {
			needsUpdate = !bytes.Contains(data, []byte(s.daemonPath))
		}
	}
	return ServiceStatus{Installed: true, Running: res.OK, NeedsUpdate: needsUpdate, StaleDaemon: res.OK && s.daemonReplaced, Details: res.Stdout + res.Stderr}
}

func (s *Service) getWindowsServiceStatus() ServiceStatus {
	res := s.runner.Run(nilContext(), RunRequest{Path: "sc", Args: []string{"query", "crosslink"}})
	out := res.Stdout + res.Stderr
	if !res.OK {
		return ServiceStatus{Installed: false, Running: false, Details: out}
	}
	running := strings.Contains(out, "RUNNING")
	return ServiceStatus{Installed: true, Running: running, StaleDaemon: running && s.daemonReplaced, Details: out}
}

func LaunchDaemonPlist(req LaunchServiceRequest, pidFile string, authorizedUID, authorizedGID int) string {
	if req.Label == "" {
		req.Label = darwinServiceLabel
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
      <string>%s</string>
      <string>-c</string>
      <string>%s</string>
      <string>--pid-file</string>
      <string>%s</string>
      <string>--user-uid</string>
      <string>%s</string>
      <string>--user-gid</string>
      <string>%s</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>CROSSLINK_DAEMON</key>
      <string>1</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>%s</string>
    <key>StandardOutPath</key>
    <string>/var/log/crosslink.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/crosslink.err.log</string>
  </dict>
</plist>
`, html.EscapeString(req.Label), html.EscapeString(req.BinaryPath), html.EscapeString(req.ConfigPath), html.EscapeString(pidFile), strconv.Itoa(authorizedUID), strconv.Itoa(authorizedGID), html.EscapeString(req.WorkDir))
}

func (s *Service) darwinServiceNeedsUpdate(req LaunchServiceRequest) bool {
	installed, err := os.ReadFile(darwinLaunchDaemonPath)
	if err != nil {
		return true
	}
	expected := []byte(LaunchDaemonPlist(req, s.pidPath, s.authorizedUID, s.authorizedGID))
	if !bytes.Equal(bytes.TrimSpace(installed), bytes.TrimSpace(expected)) {
		return true
	}
	return !privilegedHelperMatches(req.BinaryPath, s.daemonSHA256)
}

func validateDaemonSource(path, expectedSHA256 string) error {
	if len(expectedSHA256) != sha256.Size*2 {
		return fmt.Errorf("embedded daemon SHA-256 is unavailable")
	}
	if _, err := hex.DecodeString(expectedSHA256); err != nil {
		return fmt.Errorf("embedded daemon SHA-256 is invalid: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("read staged daemon: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("staged daemon must be a regular non-symlink file")
	}
	actual, err := fileSHA256(path)
	if err != nil {
		return fmt.Errorf("hash staged daemon: %w", err)
	}
	if actual != expectedSHA256 {
		return fmt.Errorf("staged daemon SHA-256 mismatch: got %s want %s", actual, expectedSHA256)
	}
	return nil
}

func privilegedHelperMatches(path, expectedSHA256 string) bool {
	if expectedSHA256 == "" || !isRootOwnedRegularFile(path) {
		return false
	}
	actual, err := fileSHA256(path)
	return err == nil && actual == expectedSHA256
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func nilContext() context.Context {
	return context.Background()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func appleScriptQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}
