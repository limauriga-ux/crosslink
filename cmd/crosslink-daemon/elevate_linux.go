//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
)

func ensureAdmin() error {
	if os.Getuid() == 0 {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("permission denied: crosslink requires root privileges")
	}

	// Try pkexec (GUI polkit prompt on desktop Linux)
	cmd := exec.Command("pkexec", append([]string{exe}, os.Args[1:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		os.Exit(0)
	}

	return fmt.Errorf("permission denied: crosslink requires root privileges (try: sudo %s)", os.Args[0])
}
