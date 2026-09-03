//go:build windows

package main

import "os"

// shutdownSigs are signals that trigger graceful shutdown.
var shutdownSigs = []os.Signal{os.Interrupt}

// reloadSigs are reserved for config reload (not supported on Windows).
var reloadSigs = []os.Signal{}
