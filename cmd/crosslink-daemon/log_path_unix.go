//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/managedfs"
)

const privilegedDaemonLogPath = "/var/log/crosslink.log"

func daemonLogPath(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("config is nil")
	}
	if cfg.DaemonSafe() && os.Geteuid() == 0 {
		return privilegedDaemonLogPath, nil
	}
	return cfg.LogFilePath()
}

// prepareDaemonLog makes lumberjack's subsequent path-based opens safe from
// unprivileged symlink swaps: the containing root must be a real directory,
// owned by the expected identity, and not writable by group/other; the leaf is
// opened without following a symlink and verified against its lstat result.
func prepareDaemonLog(cfg *config.Config, path string) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if cfg.DaemonSafe() && os.Geteuid() == 0 {
		if filepath.Clean(path) != privilegedDaemonLogPath {
			return fmt.Errorf("privileged daemon log path must be %s", privilegedDaemonLogPath)
		}
		return prepareSecureLogFile(filepath.Dir(path), path, 0, -1)
	}
	dataDir, err := cfg.DataDir()
	if err != nil {
		return err
	}
	expectedUID, expectedGID := os.Geteuid(), os.Getegid()
	if owner, ok := cfg.DaemonOwner(); ok {
		expectedUID, expectedGID = owner.UID, owner.GID
	}
	return prepareSecureLogFile(dataDir, path, expectedUID, expectedGID)
}

func prepareSecureLogFile(rootPath, path string, expectedUID, expectedGID int) error {
	root, err := managedfs.Open(rootPath, false)
	if err != nil {
		return fmt.Errorf("open log root: %w", err)
	}
	defer root.Close()
	owner, err := root.Owner()
	if err != nil {
		return fmt.Errorf("read log root owner: %w", err)
	}
	if !owner.Valid() || owner.UID != expectedUID || (expectedGID >= 0 && owner.GID != expectedGID) {
		return fmt.Errorf("log root owner %d:%d does not match expected owner %d:%d", owner.UID, owner.GID, expectedUID, expectedGID)
	}
	if os.Geteuid() == 0 {
		return root.EnsureRegularFileOwned(path, 0o600, expectedUID, owner.GID)
	}
	return root.EnsureRegularFile(path, 0o600)
}
