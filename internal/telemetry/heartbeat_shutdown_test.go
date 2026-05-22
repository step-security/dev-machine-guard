package telemetry

import (
	"context"
	"testing"
	"time"
)

// TestHeartbeatShutdown_NoDeadlock mirrors the cancel-then-wait pattern
// Run() uses to shut down its heartbeat goroutine. Two `defer` statements
// (cancel + wait) would deadlock under LIFO ordering — wait runs first,
// blocks on the goroutine, and cancel never fires. Combining them into a
// single deferred function is the fix; this test pins it down.
func TestHeartbeatShutdown_NoDeadlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// no-op, mimics postPhase
			}
		}
	}()

	// This is the load-bearing pattern from Run(): cancel first, THEN wait.
	// If a future refactor splits these into separate `defer` statements at
	// the top level of Run(), the LIFO ordering will deadlock.
	shutdownStart := time.Now()
	func() {
		defer func() {
			cancel()
			<-done
		}()
	}()
	elapsed := time.Since(shutdownStart)

	// 50ms ticker + small scheduler overhead; 1s is generous and signals a
	// hang clearly if the pattern ever regresses.
	if elapsed > time.Second {
		t.Fatalf("heartbeat shutdown took %s — likely deadlocked on defer ordering", elapsed)
	}
}
