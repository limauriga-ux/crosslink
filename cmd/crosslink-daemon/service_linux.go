//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const linuxSystemdServiceName = "io.github.limauriga.crosslink.daemon.service"

func isWindowsService() bool {
	return false
}

func runService() error {
	return fmt.Errorf("service mode is only supported on Windows")
}

func installService(configPath, pidFile string, authorizedUID, authorizedGID int, rootOnly bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	workDir := filepath.Dir(pidFile)
	if workDir == "." || workDir == "" {
		return fmt.Errorf("service pid file must have an absolute managed directory")
	}
	unit := linuxSystemdServiceUnit(exe, configPath, pidFile, workDir, authorizedUID, authorizedGID, rootOnly)
	unitPath := filepath.Join("/etc/systemd/system", linuxSystemdServiceName)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s: %w", out, err)
	}
	if out, err := exec.Command("systemctl", "enable", "--now", linuxSystemdServiceName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable --now: %s: %w", out, err)
	}
	fmt.Println("service installed")
	return nil
}

func uninstallService() error {
	exec.Command("systemctl", "disable", "--now", linuxSystemdServiceName).Run() //nolint:errcheck
	unitPath := filepath.Join("/etc/systemd/system", linuxSystemdServiceName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s: %w", out, err)
	}
	fmt.Println("service removed")
	return nil
}
