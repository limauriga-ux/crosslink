//go:build windows

package daemon

import "os"

// Detach starts the current program as a detached child process.
// Parent returns after child is started. Child continues in background.
func Detach(args []string) (int, error) {
	env := append(os.Environ(), "CROSSLINK_DAEMON=1")
	procAttr := &os.ProcAttr{
		Env: env,
		Files: []*os.File{
			os.Stdin,
			os.Stdout,
			os.Stderr,
		},
	}

	p, err := os.StartProcess(os.Args[0], args, procAttr)
	if err != nil {
		return 0, err
	}
	return p.Pid, nil
}
