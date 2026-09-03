//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareSecureLogFileRejectsLeafSymlink(t *testing.T) {
	rootPath := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target.log")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(rootPath, "crosslink.log")
	if err := os.Symlink(target, logPath); err != nil {
		t.Fatal(err)
	}

	err := prepareSecureLogFile(rootPath, logPath, os.Getuid(), -1)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("log symlink error = %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "untouched" {
		t.Fatalf("symlink target = %q, %v", content, err)
	}
}

func TestPrepareSecureLogFileCreatesOwnerOnlyRegularFile(t *testing.T) {
	rootPath := t.TempDir()
	logPath := filepath.Join(rootPath, "crosslink.log")
	if err := prepareSecureLogFile(rootPath, logPath, os.Getuid(), -1); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("secured log mode = %v", info.Mode())
	}
}

func TestPrepareSecureLogFileRejectsWrongRootOwner(t *testing.T) {
	rootPath := t.TempDir()
	logPath := filepath.Join(rootPath, "crosslink.log")
	err := prepareSecureLogFile(rootPath, logPath, os.Getuid()+1, -1)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong log owner error = %v", err)
	}
	if _, statErr := os.Lstat(logPath); !os.IsNotExist(statErr) {
		t.Fatalf("log file created despite owner mismatch: %v", statErr)
	}
}
