//go:build windows

package main

import "os"

func signalProcessStop(p *os.Process) error {
	return p.Kill()
}
