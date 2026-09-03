package gui

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchDaemonPlistUsesFixedRuntimeAndIdentityArguments(t *testing.T) {
	plist := LaunchDaemonPlist(LaunchServiceRequest{
		Label:      darwinServiceLabel,
		BinaryPath: darwinPrivilegedHelperPath,
		ConfigPath: "/Users/alice/.crosslink/config.json",
		WorkDir:    "/Users/alice/.crosslink",
	}, "/Users/alice/.crosslink/crosslink.pid", 501, 20)

	for _, want := range []string{
		"<string>" + darwinPrivilegedHelperPath + "</string>",
		"<string>-c</string>",
		"<string>/Users/alice/.crosslink/config.json</string>",
		"<string>/Users/alice/.crosslink/crosslink.pid</string>",
		"<string>--user-uid</string>",
		"<string>501</string>",
		"<string>--user-gid</string>",
		"<string>20</string>",
		"<string>/Users/alice/.crosslink</string>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
	if strings.Contains(plist, "<string>start</string>") || strings.Contains(plist, "<key>HOME</key>") {
		t.Fatalf("plist contains subcommand or ambient HOME dependency:\n%s", plist)
	}
}

func TestInstallLaunchServicePinsAndCopiesStagedDaemon(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &fakeRunner{}
	source, digest := testDaemonSource(t)
	privileged := filepath.Join(t.TempDir(), "root-helper")
	svc := NewService(Options{
		DaemonPath:            source,
		DaemonSHA256:          digest,
		PrivilegedDaemonPath:  privileged,
		AuthorizedUID:         501,
		AuthorizedGID:         20,
		AuthorizedIdentitySet: true,
		Runner:                runner,
	})
	res := svc.InstallLaunchService(LaunchServiceRequest{
		Label:      darwinServiceLabel,
		BinaryPath: privileged,
		ConfigPath: svc.configPath,
		WorkDir:    svc.workDir,
	})
	if !res.OK {
		t.Fatalf("InstallLaunchService = %+v, want OK", res)
	}
	if len(runner.calls) != 1 || runner.calls[0].Path != "osascript" {
		t.Fatalf("runner calls = %+v", runner.calls)
	}
	script := strings.Join(runner.calls[0].Args, " ")
	for _, want := range []string{source, privileged, digest, "actual=${actual%% *}", "--user-uid", "501", "--user-gid", "20", "administrator privileges"} {
		if !strings.Contains(script, want) {
			t.Fatalf("install script missing %q:\n%s", want, script)
		}
	}
}

func TestStartLaunchServiceReinstallsStaleDefinition(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{}
	source, digest := testDaemonSource(t)
	privileged := filepath.Join(t.TempDir(), "root-helper")
	svc := NewService(Options{
		ConfigPath:            filepath.Join(dir, "config.json"),
		DaemonPath:            source,
		DaemonSHA256:          digest,
		PrivilegedDaemonPath:  privileged,
		AuthorizedUID:         501,
		AuthorizedGID:         20,
		AuthorizedIdentitySet: true,
		Runner:                runner,
	})
	res := svc.startDarwinLaunchService(LaunchServiceRequest{
		Label: darwinServiceLabel, BinaryPath: privileged,
		ConfigPath: svc.configPath, WorkDir: svc.workDir,
	})
	if len(runner.calls) != 1 || !res.OK {
		t.Fatalf("runner calls = %d; result=%+v", len(runner.calls), res)
	}
	args := strings.Join(runner.calls[0].Args, " ")
	for _, want := range []string{
		"administrator privileges",
		"launchctl bootstrap system '" + darwinLaunchDaemonPath + "'",
		"launchctl kickstart -k system/'" + darwinServiceLabel + "'",
		privileged,
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("start args missing %q:\n%s", want, args)
		}
	}
}

func TestUninstallLaunchServiceRemovesDarwinPlist(t *testing.T) {
	runner := &fakeRunner{}
	svc := NewService(Options{Runner: runner})
	res := svc.uninstallDarwinLaunchService("io.github.limauriga.crosslink.daemon")
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1; result=%+v", len(runner.calls), res)
	}
	call := runner.calls[0]
	if call.Path != "osascript" {
		t.Fatalf("uninstall path = %q, want osascript", call.Path)
	}
	args := strings.Join(call.Args, " ")
	for _, want := range []string{
		"administrator privileges",
		"launchctl bootout system/'" + darwinServiceLabel + "'",
		"rm -f '" + darwinLaunchDaemonPath + "' '" + darwinPrivilegedHelperPath + "'",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("uninstall args missing %q:\n%s", want, args)
		}
	}
}

func TestValidateDaemonSourceRejectsTamperAndSymlink(t *testing.T) {
	source, digest := testDaemonSource(t)
	if err := validateDaemonSource(source, digest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateDaemonSource(source, digest); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered source error = %v", err)
	}
	link := filepath.Join(t.TempDir(), "daemon-link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := validateDaemonSource(link, digest); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink source error = %v", err)
	}
}

func testDaemonSource(t *testing.T) (string, string) {
	t.Helper()
	content := []byte("crosslink-test-daemon")
	sum := sha256.Sum256(content)
	path := filepath.Join(t.TempDir(), "crosslink-daemon")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	return path, fmt.Sprintf("%x", sum[:])
}

func TestManagedLaunchRequestUsesConfigBoundDataRoot(t *testing.T) {
	parent := t.TempDir()
	svc := NewService(Options{
		ConfigPath:            filepath.Join(parent, "config.json"),
		DaemonPath:            filepath.Join(parent, "staged-daemon"),
		PrivilegedDaemonPath:  filepath.Join(parent, "root-helper"),
		AuthorizedUID:         501,
		AuthorizedGID:         20,
		AuthorizedIdentitySet: true,
		Runner:                &fakeRunner{},
	})
	managed, err := svc.managedLaunchServiceRequest(LaunchServiceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := filepath.Join(parent, ".crosslink")
	if managed.ConfigPath != filepath.Join(parent, "config.json") || managed.WorkDir != wantRoot || svc.pidPath != filepath.Join(wantRoot, "crosslink.pid") || svc.socketPath() != filepath.Join(wantRoot, "daemon.sock") {
		t.Fatalf("managed request = %+v; pid=%q socket=%q", managed, svc.pidPath, svc.socketPath())
	}
}

func TestManagedLaunchRequestRejectsMalformedConfigRoot(t *testing.T) {
	runner := &fakeRunner{}
	svc := NewService(Options{ConfigPath: "/config.json", Runner: runner})
	result := svc.InstallLaunchService(LaunchServiceRequest{})
	if result.OK || !strings.Contains(result.Summary, "filesystem root") {
		t.Fatalf("malformed launch request = %+v", result)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("privileged runner called for malformed path: %+v", runner.calls)
	}
}
