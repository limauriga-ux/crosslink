package gui

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

type Runner interface {
	Run(ctx context.Context, req RunRequest) RunResult
}

type RunRequest struct {
	Path string
	Args []string
	Dir  string
	// Timeout, when > 0, overrides the runner's default timeout. Use a long
	// value for commands that wait on user input such as the admin-password
	// dialog raised by `osascript ... with administrator privileges` — a
	// short default kills the dialog before the user can finish typing.
	Timeout time.Duration
}

type RunResult struct {
	OK       bool
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
	Error    string
}

type ExecRunner struct {
	Timeout time.Duration
}

func (r ExecRunner) Run(ctx context.Context, req RunRequest) RunResult {
	timeout := r.Timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, req.Path, req.Args...)
	cmd.Dir = req.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := RunResult{
		OK:     err == nil,
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.Error = ctx.Err().Error()
		return res
	}
	if err != nil {
		res.Error = err.Error()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		}
	}
	return res
}
