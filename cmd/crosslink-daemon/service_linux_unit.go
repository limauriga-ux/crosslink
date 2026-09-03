package main

import (
	"fmt"
	"strconv"
	"strings"
)

func linuxSystemdServiceUnit(exe, configPath, pidFile, workDir string, authorizedUID, authorizedGID int, rootOnly bool) string {
	args := []string{"-c", configPath, "--pid-file", pidFile}
	args = append(args, daemonIdentityArgs(authorizedUID, authorizedGID, rootOnly)...)
	execStart := systemdQuote(exe)
	for _, arg := range args {
		execStart += " " + systemdQuote(arg)
	}
	return fmt.Sprintf(`[Unit]
Description=CrossLink daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=%s
WorkingDirectory=%s
ExecStart=%s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`, systemdQuote("CROSSLINK_DAEMON=1"), systemdQuote(workDir), execStart)
}

func systemdQuote(s string) string {
	// strconv.Quote produces systemd-compatible C escaping. Reject newlines
	// before quoting so one argument can never create another unit directive.
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return strconv.Quote(s)
}
