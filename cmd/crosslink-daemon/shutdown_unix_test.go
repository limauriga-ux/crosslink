//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestUnixReloadSignalsAreSeparateFromShutdownSignals(t *testing.T) {
	contains := func(signals []os.Signal, want os.Signal) bool {
		for _, sig := range signals {
			if sig == want {
				return true
			}
		}
		return false
	}
	if !contains(reloadSigs, syscall.SIGHUP) {
		t.Fatal("reload signals do not include SIGHUP")
	}
	if contains(shutdownSigs, syscall.SIGHUP) {
		t.Fatal("SIGHUP must not share the forced-shutdown channel")
	}
}
