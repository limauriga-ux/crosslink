package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestWaitForProcessExitReturnsAfterProcessStops(t *testing.T) {
	checks := 0
	err := waitForProcessExit(1234, 100*time.Millisecond, time.Millisecond, func(pid int) bool {
		if pid != 1234 {
			t.Fatalf("pid = %d, want 1234", pid)
		}
		checks++
		return checks < 3
	})
	if err != nil {
		t.Fatalf("waitForProcessExit returned error: %v", err)
	}
	if checks != 3 {
		t.Fatalf("checks = %d, want 3", checks)
	}
}

func TestWaitForProcessExitTimesOut(t *testing.T) {
	err := waitForProcessExit(1234, 3*time.Millisecond, time.Millisecond, func(pid int) bool {
		return true
	})
	if err == nil {
		t.Fatal("waitForProcessExit should time out while process is still running")
	}
}

func TestDaemonArgsStripStartSubcommand(t *testing.T) {
	got := daemonArgs([]string{"crosslink", "start", "-c", "config.json", "--pid-file", "/tmp/crosslink.pid"})
	want := []string{"crosslink", "-c", "config.json", "--pid-file", "/tmp/crosslink.pid"}
	if len(got) != len(want) {
		t.Fatalf("daemonArgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("daemonArgs = %v, want %v", got, want)
		}
	}
}

func TestDaemonArgsKeepFlagOnlyInvocation(t *testing.T) {
	got := daemonArgs([]string{"crosslink", "-c", "config.json"})
	want := []string{"crosslink", "-c", "config.json"}
	if len(got) != len(want) {
		t.Fatalf("daemonArgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("daemonArgs = %v, want %v", got, want)
		}
	}
}

func TestDaemonCommandFromArgs(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"crosslink-daemon", "install-service", "-c", "config.json"}, "install-service"},
		{[]string{"crosslink-daemon", "uninstall-service"}, "uninstall-service"},
		{[]string{"crosslink-daemon", "stop"}, "stop"},
		{[]string{"crosslink-daemon", "-c", "config.json"}, ""},
	}
	for _, tt := range tests {
		if got := daemonCommandFromArgs(tt.args); got != tt.want {
			t.Fatalf("daemonCommandFromArgs(%v) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestLinuxSystemdServiceUnit(t *testing.T) {
	unit := linuxSystemdServiceUnit(
		"/opt/CrossLink/crosslink-daemon",
		"/home/alice/.crosslink/config.json",
		"/home/alice/.crosslink/crosslink.pid",
		"/home/alice/.crosslink",
		1000, 1000, false,
	)
	for _, want := range []string{
		"Description=CrossLink daemon",
		`Environment="CROSSLINK_DAEMON=1"`,
		`WorkingDirectory="/home/alice/.crosslink"`,
		`ExecStart="/opt/CrossLink/crosslink-daemon" "-c" "/home/alice/.crosslink/config.json" "--pid-file" "/home/alice/.crosslink/crosslink.pid" "--user-uid" "1000" "--user-gid" "1000"`,
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("linux systemd unit missing %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "HOME=") {
		t.Fatalf("systemd unit must not depend on ambient HOME:\n%s", unit)
	}
}

func TestCleanupAfterReconnectDisconnectHonorsPreservedGeneration(t *testing.T) {
	calls := 0
	orig := cleanupRoutesAndDNS
	cleanupRoutesAndDNS = func() {
		calls++
	}
	defer func() {
		cleanupRoutesAndDNS = orig
	}()

	cleanupAfterReconnectDisconnect(true)
	if calls != 0 {
		t.Fatalf("preserved reconnect ran network cleanup %d time(s), want 0", calls)
	}
	cleanupAfterReconnectDisconnect(false)
	if calls != 1 {
		t.Fatalf("non-preserved reconnect ran network cleanup %d time(s), want 1", calls)
	}
}

func TestConnectionSupervisorCancelsPreviousSession(t *testing.T) {
	var sup connectionSupervisor
	ctx1, gen1 := sup.Start(context.Background())
	ctx2, gen2 := sup.Start(context.Background())
	if gen2 <= gen1 {
		t.Fatalf("generation did not advance: %d -> %d", gen1, gen2)
	}
	select {
	case <-ctx1.Done():
	case <-time.After(time.Second):
		t.Fatal("previous connection context was not cancelled")
	}
	select {
	case <-ctx2.Done():
		t.Fatal("current connection context should still be active")
	default:
	}
	if sup.IsCurrent(gen1) {
		t.Fatal("old generation should not be current")
	}
	if !sup.IsCurrent(gen2) {
		t.Fatal("new generation should be current")
	}
	sup.Stop()
	select {
	case <-ctx2.Done():
	case <-time.After(time.Second):
		t.Fatal("current connection context was not cancelled by Stop")
	}
}
