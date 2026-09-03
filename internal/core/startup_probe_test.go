package core

import (
	"errors"
	"strings"
	"testing"
)

func TestGuardSystemCaptureRollsBackTUNOnProbeFailure(t *testing.T) {
	probeErr := errors.New("DNS unavailable")
	closed := false
	err := guardSystemCapture(true, func() error { return probeErr }, func() error {
		closed = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "TUN rolled back") || !errors.Is(err, probeErr) {
		t.Fatalf("guard error = %v", err)
	}
	if !closed {
		t.Fatal("failed startup probe left the core/TUN open")
	}
}

func TestGuardSystemCaptureSkipsProbeWithoutTUN(t *testing.T) {
	probed := false
	closed := false
	err := guardSystemCapture(false, func() error {
		probed = true
		return errors.New("should not run")
	}, func() error {
		closed = true
		return nil
	})
	if err != nil || probed || closed {
		t.Fatalf("guard without TUN: err=%v probed=%v closed=%v", err, probed, closed)
	}
}
