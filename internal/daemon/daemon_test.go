package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPidFileWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "test.pid")

	// Write
	if err := WritePidFile(pidFile, 12345); err != nil {
		t.Fatalf("WritePidFile error: %v", err)
	}

	// Read
	pid, err := ReadPidFile(pidFile)
	if err != nil {
		t.Fatalf("ReadPidFile error: %v", err)
	}
	if pid != 12345 {
		t.Fatalf("pid = %d, want 12345", pid)
	}

	// Remove
	if err := RemovePidFile(pidFile); err != nil {
		t.Fatalf("RemovePidFile error: %v", err)
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatal("pid file should be removed")
	}
}

func TestIsRunning(t *testing.T) {
	// Test with current process PID (should be running)
	if !IsRunning(os.Getpid()) {
		t.Fatal("current process should be running")
	}
	// Test with a fake PID (should not be running, hopefully)
	if IsRunning(999999) {
		t.Fatal("fake PID should not be running")
	}
}
