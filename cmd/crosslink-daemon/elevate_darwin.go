//go:build darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func ensureAdmin() error {
	if os.Getuid() == 0 {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("permission denied: crosslink requires root privileges")
	}

	// Build a safe argument string
	var parts []string
	for i, a := range os.Args {
		if i == 0 {
			continue
		}
		parts = append(parts, strings.ReplaceAll(a, `"`, `\"`))
	}
	argStr := strings.Join(parts, " ")

	script := fmt.Sprintf(`do shell script "%s %s" with administrator privileges with prompt "crosslink needs root access to create TUN device"`, exe, argStr)
	// This command is interactive, so it gets a longer bound than route/DNS
	// utilities, but it must still not leave the launcher hung forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	if err := cmd.Run(); err == nil {
		os.Exit(0)
	}

	return fmt.Errorf("permission denied: crosslink requires root privileges (try: sudo %s)", os.Args[0])
}
