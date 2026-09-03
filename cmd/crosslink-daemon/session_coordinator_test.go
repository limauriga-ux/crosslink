package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/limauriga-ux/crosslink/internal/corplink"
	"github.com/limauriga-ux/crosslink/internal/daemonipc"
)

func TestSessionCoordinatorSerializesReportAndReconnect(t *testing.T) {
	oldRef := sessionRef{node: corplink.VPNNode{ID: 1}, vpnIP: "10.0.0.1", pubB64: "old-key"}
	coordinator := newSessionCoordinator(oldRef)
	reportStarted := make(chan struct{})
	releaseReport := make(chan struct{})
	reportDone := make(chan error, 1)
	go func() {
		_, err := coordinator.Report(context.Background(), func(_ context.Context, got sessionRef) (*corplink.VPNSettings, error) {
			if got.pubB64 != oldRef.pubB64 {
				t.Errorf("report key = %q, want %q", got.pubB64, oldRef.pubB64)
			}
			close(reportStarted)
			<-releaseReport
			return nil, nil
		})
		reportDone <- err
	}()
	<-reportStarted

	reconnectStarted := make(chan struct{})
	reconnectDone := make(chan bool, 1)
	go func() {
		_, _, adopted := coordinator.Reconnect(func() (daemonipc.Response, connectDetails) {
			close(reconnectStarted)
			return daemonipc.Response{OK: true}, connectDetails{
				node:             corplink.VPNNode{ID: 2},
				wgInfo:           &corplink.WGConnInfo{VpnIP: netip.MustParseAddr("10.0.0.2")},
				pubB64:           "new-key",
				serverRegistered: true,
			}
		}, func() bool { return true })
		reconnectDone <- adopted
	}()

	select {
	case <-reconnectStarted:
		t.Fatal("reconnect crossed an in-flight report")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseReport)
	if err := <-reportDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-reconnectStarted:
	case <-time.After(time.Second):
		t.Fatal("reconnect did not start after report completed")
	}
	if !<-reconnectDone {
		t.Fatal("new session was not adopted")
	}

	_, err := coordinator.Report(context.Background(), func(_ context.Context, got sessionRef) (*corplink.VPNSettings, error) {
		if got.pubB64 != "new-key" || got.vpnIP != "10.0.0.2" || got.node.ID != 2 {
			t.Fatalf("published session = %+v, want new identity", got)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSessionCoordinatorPausesReportsAfterFailedReconnect(t *testing.T) {
	coordinator := newSessionCoordinator(sessionRef{pubB64: "old-key"})
	resp, _, adopted := coordinator.Reconnect(func() (daemonipc.Response, connectDetails) {
		return daemonipc.Response{OK: false, Error: "local setup failed"}, connectDetails{serverRegistered: true}
	}, func() bool { return true })
	if resp.OK || adopted {
		t.Fatal("failed reconnect must not be adopted")
	}

	called := false
	_, err := coordinator.Report(context.Background(), func(context.Context, sessionRef) (*corplink.VPNSettings, error) {
		called = true
		return nil, nil
	})
	if !errors.Is(err, errSessionUnavailable) {
		t.Fatalf("report error = %v, want errSessionUnavailable", err)
	}
	if called {
		t.Fatal("old session was reported after reconnect failure")
	}
}

func TestSessionCoordinatorResumesOldSessionBeforeRegistrationFailure(t *testing.T) {
	coordinator := newSessionCoordinator(sessionRef{pubB64: "old-key"})
	resp, _, adopted := coordinator.Reconnect(func() (daemonipc.Response, connectDetails) {
		return daemonipc.Response{OK: false, Error: "list nodes failed"}, connectDetails{}
	}, func() bool { return true })
	if resp.OK || adopted {
		t.Fatal("failed reconnect must not be adopted")
	}

	called := false
	_, err := coordinator.Report(context.Background(), func(_ context.Context, ref sessionRef) (*corplink.VPNSettings, error) {
		called = true
		if ref.pubB64 != "old-key" {
			t.Fatalf("report key = %q, want old-key", ref.pubB64)
		}
		return nil, nil
	})
	if err != nil || !called {
		t.Fatalf("old session did not resume: called=%v err=%v", called, err)
	}
}
