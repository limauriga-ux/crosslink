//go:build darwin || linux

package main

import (
	"os"
	"syscall"
)

func signalProcessStop(p *os.Process) error {
	return p.Signal(syscall.SIGTERM)
}
