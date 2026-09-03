//go:build windows

package main

import (
	"fmt"

	"github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/managedfs"
)

func daemonLogPath(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("config is nil")
	}
	return cfg.LogFilePath()
}

func prepareDaemonLog(cfg *config.Config, path string) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	dataDir, err := cfg.DataDir()
	if err != nil {
		return err
	}
	root, err := managedfs.Open(dataDir, false)
	if err != nil {
		return fmt.Errorf("open log root: %w", err)
	}
	defer root.Close()
	return root.EnsureRegularFile(path, 0o600)
}
