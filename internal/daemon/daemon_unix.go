//go:build darwin || linux

package daemon

import "syscall"

var killSignal = syscall.Kill

func IsRunning(pid int) bool {
	err := killSignal(pid, 0)
	return err == nil || err == syscall.EPERM
}
