// Package boundedexec runs non-interactive operating-system commands with a
// hard deadline. Lifecycle and shutdown code must not wait forever for route,
// interface, or DNS utilities that are stuck in the kernel.
package boundedexec

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

const DefaultTimeout = 5 * time.Second

type outputMode uint8

const (
	noOutput outputMode = iota
	stdoutOnly
	combinedOutput
)

func Run(name string, args ...string) error {
	_, err := run(DefaultTimeout, nil, nil, nil, noOutput, name, args...)
	return err
}

func Output(name string, args ...string) ([]byte, error) {
	return run(DefaultTimeout, nil, nil, nil, stdoutOnly, name, args...)
}

func CombinedOutput(name string, args ...string) ([]byte, error) {
	return run(DefaultTimeout, nil, nil, nil, combinedOutput, name, args...)
}

// RunWithIO is the bounded equivalent of configuring Stdin, Stdout, and
// Stderr on exec.Cmd and then calling Run.
func RunWithIO(stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	_, err := run(DefaultTimeout, stdin, stdout, stderr, noOutput, name, args...)
	return err
}

func run(timeout time.Duration, stdin io.Reader, stdout, stderr io.Writer, mode outputMode, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	// Context expiry kills the direct child, but an orphaned descendant can
	// keep an Output/CombinedOutput pipe open forever. WaitDelay bounds that
	// second wait and closes the pipes after the child has been killed.
	cmd.WaitDelay = time.Second
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	var out []byte
	var err error
	switch mode {
	case combinedOutput:
		out, err = cmd.CombinedOutput()
	case stdoutOnly:
		out, err = cmd.Output()
	case noOutput:
		err = cmd.Run()
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return out, fmt.Errorf("%s exceeded %s: %w", name, timeout, ctxErr)
		}
		return out, err
	}
	return out, nil
}
