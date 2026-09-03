package main

import (
	"testing"
	"time"
)

func TestReconnectBackoffGrowsAndCaps(t *testing.T) {
	want := []time.Duration{
		30 * time.Second, // after 1st failure
		time.Minute,      // 2nd
		2 * time.Minute,  // 3rd
		4 * time.Minute,  // 4th
		8 * time.Minute,  // 5th
		10 * time.Minute, // 6th: capped
		10 * time.Minute, // stays capped forever
	}
	for i, w := range want {
		if got := reconnectBackoff(i + 1); got != w {
			t.Fatalf("reconnectBackoff(%d) = %s, want %s", i+1, got, w)
		}
	}
	if got := reconnectBackoff(100); got != 10*time.Minute {
		t.Fatalf("reconnectBackoff(100) = %s, want cap", got)
	}
}

func boolPtr(v bool) *bool { return &v }

func TestResolveConnectModeKeepsPreviousWhenAbsent(t *testing.T) {
	if got := resolveConnectMode(true, true, nil); !got {
		t.Fatal("absent field did not preserve previous split-tunnel mode")
	}
}

func TestResolveConnectModeExplicitlyOverrides(t *testing.T) {
	if got := resolveConnectMode(true, true, boolPtr(false)); got {
		t.Fatal("explicit false did not select full corporate tunnel")
	}
}

func TestResolveConnectModeDefaultsBeforeFirstConnect(t *testing.T) {
	if got := resolveConnectMode(false, false, nil); got {
		t.Fatal("first connect without a field should default to full tunnel")
	}
}
