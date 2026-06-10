//go:build !windows

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// TestRunAsUser_FoldsStderrIntoError verifies RunAsUser surfaces a failing
// command's stderr in the returned error rather than a bare "exited with code
// N". This is what lets the node scanner record a self-explanatory telemetry
// Error (e.g. "command not found") instead of an opaque exit code when npm/yarn
// can't be resolved under the LaunchAgent's stripped PATH. Real shell, real
// exec — consistent with the Antigravity test above.
func TestRunAsUser_FoldsStderrIntoError(t *testing.T) {
	r := &Real{}
	if r.IsRoot() {
		// The root path shells out via `sudo -H -u <user>`; sudo presence and
		// policy vary across CI images. The non-root branch — the common case,
		// and what GitHub-hosted runners use — exercises the same stderr-fold
		// code, so skip rather than depend on sudo being available here.
		t.Skip("skipping as root: RunAsUser's root branch depends on sudo")
	}

	// username "" → resolveUserShell returns "" → shell defaults to /bin/bash;
	// non-root → `/bin/bash -l -c "<rc-source>; echo ... 1>&2; exit 3"`.
	_, err := r.RunAsUser(context.Background(), "", "echo 'boom-on-stderr' 1>&2; exit 3")
	if err == nil {
		t.Fatal("expected an error for a command that exits non-zero")
	}
	if !strings.Contains(err.Error(), "boom-on-stderr") {
		t.Errorf("error %q does not contain the command's stderr — stderr was discarded", err.Error())
	}
	if !strings.Contains(err.Error(), "code 3") {
		t.Errorf("error %q does not report the exit code", err.Error())
	}
}

// TestRunAsUser_RecoversStrippedPATH is the precise reproduction of the
// production failure and the proof the fix resolves it. Under an MDM
// LaunchAgent, launchd runs the agent as the console user with a stripped PATH
// (/usr/bin:/bin:/usr/sbin:/sbin); npm/yarn/pnpm installed via nvm/fnm/homebrew
// live on a PATH entry that exists only in the user's shell rc file. A bare
// exec can't find them — the pre-fix non-root behavior, surfacing as exit -1,
// empty output, version "unknown" — while RunAsUser, which sources the rc file
// in a login shell, does.
//
// The fake binary has a unique name so it is guaranteed absent from the real
// stripped PATH and reachable only via the temp rc file — exactly like an
// nvm-managed npm.
func TestRunAsUser_RecoversStrippedPATH(t *testing.T) {
	r := &Real{}
	if r.IsRoot() {
		t.Skip("skipping as root: this models the non-root LaunchAgent path (no sudo)")
	}

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "nvm", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A uniquely-named fake "npm" that prints a version — stands in for the
	// nvm-managed npm that lives outside launchd's stripped PATH.
	fakeBin := filepath.Join(binDir, "fakenpm-dmgtest")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho 10.9.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// rc files that prepend binDir to PATH — what nvm/fnm/homebrew write. Cover
	// both bash and zsh so the test is shell-agnostic.
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	rc := "export PATH=\"" + binDir + ":$PATH\"\n"
	for _, name := range []string{".bashrc", ".zshrc"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(rc), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Recreate launchd's environment: a stripped PATH, and HOME pointing at the
	// temp rc files so RunAsUser's `~` resolves there. t.Setenv restores both
	// after the test.
	t.Setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
	t.Setenv("HOME", home)

	// 1) RECREATE — a bare exec of the binary fails: it is not on the stripped
	//    PATH. This is the pre-fix non-root path (Real.Run returns exit -1).
	_, _, bareCode, bareErr := r.Run(context.Background(), "fakenpm-dmgtest", "--version")
	if bareErr == nil {
		t.Fatalf("bare exec unexpectedly succeeded (exit=%d) — premise broken: the fake binary must be off the stripped PATH", bareCode)
	}
	t.Logf("RECREATE: bare exec under launchd's stripped PATH → exit=%d, err=%v (matches the production -1/not-found)", bareCode, bareErr)

	// 2) RESOLVE — RunAsUser sources the rc file in a login shell, so the binary
	//    is found and runs. This is the fix.
	out, err := r.RunAsUser(context.Background(), "", "fakenpm-dmgtest --version")
	if err != nil {
		t.Fatalf("RunAsUser failed to resolve a binary the rc file adds to PATH: %v", err)
	}
	if strings.TrimSpace(out) != "10.9.0" {
		t.Errorf("RunAsUser output = %q, want 10.9.0 — rc-sourced PATH not applied", out)
	}
	t.Logf("RESOLVE: RunAsUser (login shell + rc source) → output=%q (binary found via the rc-file PATH)", strings.TrimSpace(out))
}
