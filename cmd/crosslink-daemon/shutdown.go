package main

import (
	"context"
	"errors"
	"log"
	"os"
	"sync/atomic"
	"time"
)

const (
	// daemonShutdownTimeout bounds the whole teardown, including waiting for
	// in-flight IPC handlers. A forced return lets the process-level caller
	// exit without waiting for an uncooperative cleanup goroutine.
	daemonShutdownTimeout = 15 * time.Second
	// Leave a small process/signal margin so the CLI stop command does not
	// deliver a second SIGTERM before the daemon's own shutdown deadline.
	daemonStopWaitTimeout = daemonShutdownTimeout + time.Second

	shutdownStepStopAccepting = "StopAccepting"
	shutdownStepBackground    = "background cancellation/stop"
	shutdownStepVPNDisconnect = "VPN Disconnect"
	shutdownStepIPCWait       = "IPC handler Wait"
)

var errForcedShutdown = errors.New("daemon shutdown forced")

type daemonCleanup func(enterStep func(string))

func waitForDaemonShutdown(
	ctx context.Context,
	shutdownCh <-chan os.Signal,
	reloadCh <-chan os.Signal,
	timeout time.Duration,
	cleanup daemonCleanup,
	onReload func(os.Signal),
) error {
	for {
		select {
		case sig := <-shutdownCh:
			log.Printf("[main] received %v, shutting down", sig)
			return finishDaemonShutdown(shutdownCh, reloadCh, timeout, cleanup, onReload)
		case sig := <-reloadCh:
			if onReload != nil {
				onReload(sig)
			}
		case <-ctx.Done():
			log.Printf("[main] context cancelled, shutting down")
			return finishDaemonShutdown(shutdownCh, reloadCh, timeout, cleanup, onReload)
		}
	}
}

func finishDaemonShutdown(
	shutdownCh <-chan os.Signal,
	reloadCh <-chan os.Signal,
	timeout time.Duration,
	cleanup daemonCleanup,
	onReload func(os.Signal),
) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var lastCleanupStep atomic.Value
	lastCleanupStep.Store("not started")

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		cleanup(func(step string) {
			lastCleanupStep.Store(step)
		})
	}()

	for {
		select {
		case <-cleanupDone:
			return nil
		case sig := <-shutdownCh:
			log.Printf(
				"[main] received %v during shutdown, forcing exit; last_cleanup_step=%q",
				sig,
				lastCleanupStep.Load(),
			)
			return errForcedShutdown
		case sig := <-reloadCh:
			if onReload != nil {
				onReload(sig)
			}
		case <-timer.C:
			log.Printf(
				"[main] shutdown exceeded %s, forcing exit; last_cleanup_step=%q",
				timeout,
				lastCleanupStep.Load(),
			)
			return errForcedShutdown
		}
	}
}
