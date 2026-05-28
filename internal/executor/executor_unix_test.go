//go:build !windows

package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRunWithTimeoutHangsOnUnreapedChild reproduces the Antigravity hang
// (StepSecurity Device Agent v1.11.6, Coveo deployment). The IDE detector
// invokes `Contents/MacOS/Antigravity --version`; Antigravity is Electron-
// based and forks helper processes (GPU, renderer, utility) that inherit
// the parent's stdout/stderr. When the 10s context timeout fires, Go sends
// SIGKILL to the parent PID only — not the process group — so the helpers
// keep the inherited pipe write-ends open, and cmd.Wait() blocks forever
// waiting for an EOF that never arrives.
//
// This test models the failure with a bash script that backgrounds a long
// sleep (the "helper") before the "parent" exits. On the current Real.Run
// implementation the call blocks until the sleep completes, demonstrating
// that the context timeout is ignored. After the fix (Setpgid + cmd.Cancel
// killing the process group, plus cmd.WaitDelay) it should return within
// roughly the requested timeout.
func TestRunWithTimeoutHangsOnUnreapedChild(t *testing.T) {
	tmp := t.TempDir()
	script := filepath.Join(tmp, "fake-version.sh")
	// Background `sleep` inherits stdout/stderr from the script. The script
	// itself exits immediately after echoing — matching Electron's "print
	// version, exit, leave helpers running" behavior.
	body := "#!/bin/bash\nsleep 60 &\necho version-1.0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	r := &Real{}
	const timeout = 2 * time.Second

	start := time.Now()
	_, _, _, _ = r.RunWithTimeout(context.Background(), timeout, script)
	elapsed := time.Since(start)

	// With setupKillgroupOnCancel in place, the context timeout fires,
	// kill -PGID reaps the backgrounded sleep, and Wait returns within
	// WaitDelay (2s) of the timeout. Allow 7s of slack for slow CI runners.
	// Without the fix the test hangs ~60s (the sleep duration); >7s here
	// would mean the process-group kill or WaitDelay regressed.
	if elapsed > 7*time.Second {
		t.Fatalf(
			"RunWithTimeout hung for %s (expected ~%s). "+
				"The context timeout fired but cmd.Wait() blocked because a "+
				"backgrounded child still holds stdout open. Same failure mode "+
				"as running /Applications/Antigravity.app/Contents/MacOS/Antigravity --version.",
			elapsed, timeout,
		)
	}
}
