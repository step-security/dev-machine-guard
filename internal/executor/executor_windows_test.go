//go:build windows

package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// hang.cmd starts a nested cmd (the grandchild) that inherits stdout and keeps
// appending to ticks.txt. Without a tree kill and WaitDelay, Wait blocks until
// it exits despite the timeout; without job membership it outlives the run.
func TestRunWithTimeout_KillsGrandchildHoldingStdout(t *testing.T) {
	dir := t.TempDir()
	ticks := filepath.Join(dir, "ticks.txt")
	loop := filepath.Join(dir, "loop.cmd")
	loopBody := "@echo off\r\n:loop\r\necho tick>>\"" + ticks + "\"\r\nping -n 2 127.0.0.1 >nul\r\ngoto loop\r\n"
	if err := os.WriteFile(loop, []byte(loopBody), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "hang.cmd")
	body := "@echo off\r\necho started\r\ncmd /c \"" + loop + "\"\r\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	const timeout = 2 * time.Second
	start := time.Now()
	_, _, code, err := (&Real{}).RunWithTimeout(context.Background(), timeout, "cmd", "/c", script)
	elapsed := time.Since(start)

	if code != 124 || err == nil {
		t.Errorf("want timeout (124), got code=%d err=%v", code, err)
	}
	// WaitDelay alone would return at ~timeout+2s; the job kill is faster.
	if elapsed > timeout+3*time.Second {
		t.Fatalf("RunWithTimeout took %s, want < %s", elapsed, timeout+3*time.Second)
	}

	before, err := os.ReadFile(ticks)
	if err != nil || len(before) == 0 {
		t.Fatalf("grandchild never ran: %v", err)
	}
	time.Sleep(3 * time.Second)
	after, _ := os.ReadFile(ticks)
	if len(after) != len(before) {
		t.Errorf("grandchild still running after timeout: ticks grew %d -> %d bytes", len(before), len(after))
	}
}
