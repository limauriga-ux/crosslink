package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/limauriga-ux/crosslink/internal/config"
	vpnpkg "github.com/limauriga-ux/crosslink/internal/core"
	"github.com/limauriga-ux/crosslink/internal/corplink"
	"github.com/limauriga-ux/crosslink/internal/daemonipc"
)

func TestOpenVPNStatusDTOCopiesChallengeWithoutCredentials(t *testing.T) {
	deadline := time.Now().Add(time.Minute).Unix()
	status := openVPNStatusDTO(vpnpkg.OpenVPNStatus{
		Configured: true,
		Active:     true,
		State:      "auth-pending",
		IPv4:       []string{netip.MustParsePrefix("10.8.0.2/24").String()},
		DNS:        []string{"10.20.0.53"},
		Challenge: &vpnpkg.OpenVPNChallenge{
			ID: "challenge", Kind: "secret", Username: "employee", Message: "OTP", URLAllowed: true, Deadline: deadline,
		},
	})
	if !status.Configured || !status.Active || status.State != "auth-pending" || len(status.IPv4) != 1 || len(status.DNS) != 1 {
		t.Fatalf("status = %+v", status)
	}
	if status.Challenge == nil || status.Challenge.ID != "challenge" || status.Challenge.Username != "employee" || !status.Challenge.URLAllowed || status.Challenge.Deadline != deadline {
		t.Fatalf("challenge = %+v", status.Challenge)
	}
}

func TestOpenVPNRemoveProfileActionDeletesInactiveManagedFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := config.DefaultConfig()
	configFile := filepath.Join(home, ".crosslink", "config.json")
	if err := cfg.BindConfigPath(configFile); err != nil {
		t.Fatal(err)
	}
	_, profilePath, err := cfg.OpenVPNProfilePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(profilePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := newDaemonConfigState(cfg, configFile)
	manager := corplink.NewManagerWithConfig(filepath.Join(home, ".crosslink", "corplink_session.json"), cfg.Corplink)
	vpnManager := vpnpkg.New(cfg)

	remove := func() daemonipc.Response {
		return dispatchHandler(context.Background(), daemonipc.Cmd{Action: daemonipc.ActionOpenVPNRemoveProfile}, manager.Client(), manager, vpnManager, state, nil)
	}
	if response := remove(); !response.OK {
		t.Fatalf("remove response = %+v", response)
	}
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Fatalf("managed profile still present: %v", err)
	}
	if response := remove(); !response.OK {
		t.Fatalf("idempotent remove response = %+v", response)
	}
}

func TestDaemonConfigStatePublishesImmutableSnapshots(t *testing.T) {
	first := &config.Config{}
	first.Core.Profile = "first.json"
	state := newDaemonConfigState(first, "first-config.json")
	second := &config.Config{}
	second.Core.Profile = "second.json"

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for range 1000 {
			state.Store(first)
			state.Store(second)
		}
	}()
	go func() {
		defer wait.Done()
		for range 2000 {
			profile := state.Load().Core.Profile
			if profile != "first.json" && profile != "second.json" {
				t.Errorf("published profile = %q", profile)
				return
			}
		}
	}()
	wait.Wait()
}
