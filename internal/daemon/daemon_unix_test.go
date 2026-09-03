//go:build darwin || linux

package daemon

import (
	"syscall"
	"testing"
)

func TestIsRunningTreatsPermissionDeniedAsRunning(t *testing.T) {
	oldKillSignal := killSignal
	t.Cleanup(func() { killSignal = oldKillSignal })
	killSignal = func(pid int, sig syscall.Signal) error {
		if pid != 1234 || sig != 0 {
			t.Fatalf("killSignal(%d, %d), want 1234, 0", pid, sig)
		}
		return syscall.EPERM
	}

	if !IsRunning(1234) {
		t.Fatal("EPERM from kill(pid, 0) means the process exists")
	}
}
