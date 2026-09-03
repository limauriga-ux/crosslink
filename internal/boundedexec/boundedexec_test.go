package boundedexec

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunEnforcesDeadline(t *testing.T) {
	start := time.Now()
	_, err := run(20*time.Millisecond, nil, nil, nil, noOutput, "sh", "-c", "sleep 10")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bounded command returned after %s", elapsed)
	}
}

func TestCombinedOutputBoundsOrphanedPipe(t *testing.T) {
	start := time.Now()
	_, err := run(20*time.Millisecond, nil, nil, nil, combinedOutput,
		"sh", "-c", "sleep 10 & exec sleep 10")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run error = %v, want context deadline exceeded", err)
	}
	// Context timeout plus the one-second WaitDelay should be the complete
	// bound even though the orphan inherited the command's output pipe.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("orphaned output pipe kept command alive for %s", elapsed)
	}
}
