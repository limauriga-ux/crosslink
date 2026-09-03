package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForDaemonShutdownCompletesCleanupOnce(t *testing.T) {
	shutdownCh := make(chan os.Signal, 2)
	var cleanupCalls atomic.Int32
	shutdownCh <- os.Interrupt

	err := waitForDaemonShutdown(
		context.Background(),
		shutdownCh,
		nil,
		time.Second,
		func(func(string)) {
			cleanupCalls.Add(1)
		},
		nil,
	)
	if err != nil {
		t.Fatalf("waitForDaemonShutdown returned error: %v", err)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestWaitForDaemonShutdownContextStartsCleanupOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var cleanupCalls atomic.Int32
	err := waitForDaemonShutdown(
		ctx,
		nil,
		nil,
		time.Second,
		func(func(string)) {
			cleanupCalls.Add(1)
		},
		nil,
	)
	if err != nil {
		t.Fatalf("waitForDaemonShutdown returned error: %v", err)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestWaitForDaemonShutdownSignalForcesAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	shutdownCh := make(chan os.Signal, 2)
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	cleanupFinished := make(chan struct{})

	result := make(chan error, 1)
	go func() {
		result <- waitForDaemonShutdown(
			ctx,
			shutdownCh,
			nil,
			time.Second,
			func(func(string)) {
				close(cleanupStarted)
				<-releaseCleanup
				close(cleanupFinished)
			},
			nil,
		)
	}()

	cancel()
	waitForTestSignal(t, cleanupStarted, "cleanup start")
	shutdownCh <- os.Interrupt
	if err := waitForTestError(t, result); !errors.Is(err, errForcedShutdown) {
		t.Fatalf("waitForDaemonShutdown error = %v, want errForcedShutdown", err)
	}

	close(releaseCleanup)
	waitForTestSignal(t, cleanupFinished, "cleanup finish")
}

func TestWaitForDaemonShutdownSecondSignalForcesExit(t *testing.T) {
	shutdownCh := make(chan os.Signal, 2)
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	cleanupFinished := make(chan struct{})
	var cleanupCalls atomic.Int32
	var logs bytes.Buffer
	restoreLogOutput := captureTestLogs(&logs)
	defer restoreLogOutput()

	result := make(chan error, 1)
	go func() {
		result <- waitForDaemonShutdown(
			context.Background(),
			shutdownCh,
			nil,
			time.Second,
			func(enterStep func(string)) {
				enterStep(shutdownStepVPNDisconnect)
				cleanupCalls.Add(1)
				close(cleanupStarted)
				<-releaseCleanup
				close(cleanupFinished)
			},
			nil,
		)
	}()

	shutdownCh <- os.Interrupt
	waitForTestSignal(t, cleanupStarted, "cleanup start")
	shutdownCh <- os.Interrupt

	err := waitForTestError(t, result)
	if !errors.Is(err, errForcedShutdown) {
		t.Fatalf("waitForDaemonShutdown error = %v, want errForcedShutdown", err)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
	if got := logs.String(); !strings.Contains(got, `last_cleanup_step="`+shutdownStepVPNDisconnect+`"`) {
		t.Fatalf("forced-shutdown log missing last cleanup step:\n%s", got)
	}

	close(releaseCleanup)
	waitForTestSignal(t, cleanupFinished, "cleanup finish")
}

func TestWaitForDaemonShutdownDeadlineForcesExit(t *testing.T) {
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	cleanupFinished := make(chan struct{})
	var logs bytes.Buffer
	restoreLogOutput := captureTestLogs(&logs)
	defer restoreLogOutput()

	result := make(chan error, 1)
	go func() {
		result <- waitForDaemonShutdown(
			context.Background(),
			func() <-chan os.Signal {
				ch := make(chan os.Signal, 2)
				ch <- os.Interrupt
				return ch
			}(),
			nil,
			20*time.Millisecond,
			func(enterStep func(string)) {
				enterStep(shutdownStepIPCWait)
				close(cleanupStarted)
				<-releaseCleanup
				close(cleanupFinished)
			},
			nil,
		)
	}()

	waitForTestSignal(t, cleanupStarted, "cleanup start")
	err := waitForTestError(t, result)
	if !errors.Is(err, errForcedShutdown) {
		t.Fatalf("waitForDaemonShutdown error = %v, want errForcedShutdown", err)
	}
	if got := logs.String(); !strings.Contains(got, `last_cleanup_step="`+shutdownStepIPCWait+`"`) {
		t.Fatalf("forced-shutdown log missing last cleanup step:\n%s", got)
	}

	close(releaseCleanup)
	waitForTestSignal(t, cleanupFinished, "cleanup finish")
}

func TestWaitForDaemonShutdownIgnoresReloadSignal(t *testing.T) {
	shutdownCh := make(chan os.Signal, 2)
	reloadCh := make(chan os.Signal, 1)
	reloadSeen := make(chan os.Signal, 1)
	var cleanupCalls atomic.Int32

	result := make(chan error, 1)
	go func() {
		result <- waitForDaemonShutdown(
			context.Background(),
			shutdownCh,
			reloadCh,
			time.Second,
			func(func(string)) {
				cleanupCalls.Add(1)
			},
			func(sig os.Signal) {
				reloadSeen <- sig
			},
		)
	}()

	reloadCh <- os.Interrupt
	select {
	case <-reloadSeen:
	case <-time.After(time.Second):
		t.Fatal("reload signal was not observed")
	}
	if got := cleanupCalls.Load(); got != 0 {
		t.Fatalf("cleanup calls after reload = %d, want 0", got)
	}
	select {
	case err := <-result:
		t.Fatalf("reload ended shutdown loop with error: %v", err)
	default:
	}

	shutdownCh <- os.Interrupt
	if err := waitForTestError(t, result); err != nil {
		t.Fatalf("waitForDaemonShutdown returned error: %v", err)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func waitForTestError(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shutdown result")
		return nil
	}
}

func waitForTestSignal(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func captureTestLogs(dst *bytes.Buffer) func() {
	originalOutput := log.Writer()
	originalFlags := log.Flags()
	originalPrefix := log.Prefix()
	log.SetOutput(dst)
	log.SetFlags(0)
	log.SetPrefix("")
	return func() {
		log.SetOutput(originalOutput)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
	}
}
