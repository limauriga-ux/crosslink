package gui

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/limauriga-ux/crosslink/internal/daemonipc"
)

func TestOpenVPNStatusResultMapsChallengeAndArrays(t *testing.T) {
	result := openVPNStatusResult(&daemonipc.Response{OK: true, Data: daemonipc.OpenVPNStatusDTO{
		Configured: true,
		Active:     true,
		State:      "auth-pending",
		IPv4:       []string{"10.8.0.2/24"},
		DNS:        []string{"10.20.0.53"},
		Challenge: &daemonipc.OpenVPNChallengeDTO{
			ID: "challenge", Kind: "open-url", URL: "https://login.example/", Deadline: 1234,
		},
	}}, nil)
	if !result.OK || !result.Configured || !result.Active || result.State != "auth-pending" || len(result.IPv4) != 1 || len(result.DNS) != 1 {
		t.Fatalf("result = %+v", result)
	}
	if result.Challenge == nil || result.Challenge.ID != "challenge" || result.Challenge.URL != "https://login.example/" || result.Challenge.Deadline != 1234 {
		t.Fatalf("challenge = %+v", result.Challenge)
	}
}

func TestOpenVPNStatusResultMapsChallengeOwnershipVerdict(t *testing.T) {
	allowed := openVPNStatusResult(&daemonipc.Response{OK: true, Data: daemonipc.OpenVPNStatusDTO{
		Challenge: &daemonipc.OpenVPNChallengeDTO{
			ID: "challenge", Kind: "open-url", URL: "https://sso.example.com/", URLAllowed: true,
		},
	}}, nil)
	if allowed.Challenge == nil || !allowed.Challenge.URLAllowed {
		t.Fatalf("allowed challenge = %+v", allowed.Challenge)
	}
	// An old daemon omits url_allowed; the verdict must default to denied.
	denied := openVPNStatusResult(&daemonipc.Response{OK: true, Data: daemonipc.OpenVPNStatusDTO{
		Challenge: &daemonipc.OpenVPNChallengeDTO{
			ID: "challenge", Kind: "open-url", URL: "https://evil.example.net/",
		},
	}}, nil)
	if denied.Challenge == nil || denied.Challenge.URLAllowed {
		t.Fatalf("denied challenge = %+v", denied.Challenge)
	}
}

func TestOpenVPNStatusResultPreservesDaemonErrors(t *testing.T) {
	if result := openVPNStatusResult(nil, errors.New("socket down")); result.OK || result.State != "unavailable" || result.Error == "" {
		t.Fatalf("transport result = %+v", result)
	}
	if result := openVPNStatusResult(&daemonipc.Response{OK: false, Error: "stale challenge"}, nil); result.OK || result.State != "error" || result.Error != "stale challenge" {
		t.Fatalf("daemon result = %+v", result)
	}
}

func TestPrepareOpenVPNChallengeSendsDaemonAction(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "cl-gui-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	service := NewService(Options{Runner: &fakeRunner{}})
	if err := os.MkdirAll(filepath.Join(home, ".crosslink"), 0o700); err != nil {
		t.Fatal(err)
	}
	var received daemonipc.Cmd
	server := daemonipc.NewServer(service.socketPath(), func(command daemonipc.Cmd) daemonipc.Response {
		received = command
		return daemonipc.Response{OK: true}
	})
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)

	result := service.PrepareOpenVPNChallenge("challenge-1")
	if !result.OK {
		t.Fatalf("prepare result = %+v", result)
	}
	if received.Action != daemonipc.ActionOpenVPNPrepareChallenge || received.ChallengeID != "challenge-1" {
		t.Fatalf("prepare command = %+v", received)
	}
}

// newOpenVPNGuardService stands up a Service whose daemon is "running" (pid
// file points at this process) and whose IPC socket handles the daemon-owned
// atomic profile-removal action.
func newOpenVPNGuardService(t *testing.T, active bool) (*Service, string) {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "cl-gui-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	svc := NewService(Options{Runner: &fakeRunner{}})
	if err := os.MkdirAll(filepath.Join(home, ".crosslink"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(home, ".crosslink", "openvpn", "profile.json")
	server := daemonipc.NewServer(svc.socketPath(), func(cmd daemonipc.Cmd) daemonipc.Response {
		if cmd.Action != daemonipc.ActionOpenVPNRemoveProfile {
			return daemonipc.Response{OK: false, Error: "unexpected daemon action " + cmd.Action}
		}
		if active {
			return daemonipc.Response{OK: false, Error: "OpenVPN is active; disconnect it first"}
		}
		if err := os.Remove(profilePath); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true}
	})
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	return svc, home
}

func writePlaceholderManagedProfile(t *testing.T, home string) string {
	t.Helper()
	profilePath := filepath.Join(home, ".crosslink", "openvpn", "profile.json")
	if err := os.MkdirAll(filepath.Dir(profilePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return profilePath
}

func TestRemoveOpenVPNProfileRefusesWhileDaemonReportsActive(t *testing.T) {
	svc, home := newOpenVPNGuardService(t, true)
	profilePath := writePlaceholderManagedProfile(t, home)

	result := svc.RemoveOpenVPNProfile()
	if result.OK || result.Exists {
		t.Fatalf("remove = %+v, want refusal while endpoint is active", result)
	}
	if !strings.Contains(strings.ToLower(result.Error), "disconnect") {
		t.Fatalf("refusal error = %q, want disconnect-first guidance", result.Error)
	}
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("managed profile was removed despite active endpoint: %v", err)
	}
}

func TestRemoveOpenVPNProfileProceedsWhenDaemonReportsInactive(t *testing.T) {
	svc, home := newOpenVPNGuardService(t, false)
	profilePath := writePlaceholderManagedProfile(t, home)

	result := svc.RemoveOpenVPNProfile()
	if !result.OK || result.Exists {
		t.Fatalf("remove = %+v, want success after inactive status", result)
	}
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Fatalf("managed profile still present: %v", err)
	}
}

func TestRemoveOpenVPNProfileWithoutDaemonSkipsActivityGuard(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	svc := NewService(Options{Runner: &fakeRunner{}})
	if err := os.MkdirAll(filepath.Join(home, ".crosslink"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No pid file and no socket: nothing can hold an active endpoint.
	profilePath := writePlaceholderManagedProfile(t, home)

	result := svc.RemoveOpenVPNProfile()
	if !result.OK || result.Exists {
		t.Fatalf("remove = %+v, want success without a running daemon", result)
	}
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Fatalf("managed profile still present: %v", err)
	}
}
