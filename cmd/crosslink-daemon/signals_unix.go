//go:build darwin || linux

package main

import (
	"os"
	"syscall"
)

// shutdownSigs are signals that trigger graceful shutdown.
var shutdownSigs = []os.Signal{syscall.SIGINT, syscall.SIGTERM}

// reloadSigs are reserved for config reload. The daemon registers them so
// SIGHUP cannot trigger Go's default termination; actual reload is IPC-only.
var reloadSigs = []os.Signal{syscall.SIGHUP}
