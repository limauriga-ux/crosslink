//go:build darwin || linux

package daemon

import (
	"os"
	"syscall"
)

// Detach starts the current program as a session-detached child process.
// Parent returns after child is started. Child continues in background.
func Detach(args []string) (int, error) {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer null.Close()

	env := append(os.Environ(), "CROSSLINK_DAEMON=1")
	procAttr := &os.ProcAttr{
		Env: env,
		Files: []*os.File{
			null,
			null,
			null,
		},
		Sys: &syscall.SysProcAttr{Setsid: true},
	}

	p, err := os.StartProcess(os.Args[0], args, procAttr)
	if err != nil {
		return 0, err
	}
	return p.Pid, nil
}
