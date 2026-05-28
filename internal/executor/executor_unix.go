//go:build !windows

package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// setupKillgroupOnCancel arranges for cmd's whole process group to be killed
// when ctx fires, and bounds how long Wait() will block on hung pipe copies.
//
// Without this, exec.CommandContext only SIGKILLs the immediate child PID on
// timeout. If that child has forked grandchildren that inherit stdout/stderr
// (Electron helpers, npm sandbox workers, bash backgrounded subprocesses),
// the pipes remain open from the surviving descendants and cmd.Wait() blocks
// forever — the deadline is effectively ignored. Seen in production as
// node_scan hangs averaging 3.6 min per project under a 30s per-call ceiling.
//
// Setpgid: true makes cmd its own process group leader, so kill(-pid, SIGKILL)
// reaches the whole subtree. cmd.Cancel runs on ctx cancel/deadline.
// WaitDelay bounds the pipe-copy wait independently of the kill — if a child
// somehow survives the group kill (e.g. PID reused), Wait still returns.
func setupKillgroupOnCancel(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative PID targets the process group leader's group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
}

func (r *Real) IsRoot() bool {
	return os.Getuid() == 0
}

func (r *Real) DiskCapacityBytes(path string) uint64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	// f_blocks is in units of f_frsize (fundamental block size) per POSIX.
	// f_bsize is the preferred I/O size, which can differ from f_frsize on
	// some Linux filesystems and would misreport capacity. Darwin's Statfs_t
	// has no Frsize field — statfsFragmentSize falls back to Bsize there.
	return uint64(stat.Blocks) * statfsFragmentSize(&stat)
}

// resolveUserShell returns the given user's configured login shell on macOS by
// consulting Directory Services (dscl). Returns "" on non-darwin platforms, if
// the lookup fails, or if the resolved path isn't an executable file — in which
// case callers should fall back to /bin/bash.
//
// Matters when
// the user's PATH (including npm/pnpm/yarn via nvm/fnm/homebrew) is configured
// only in zsh profile files (.zprofile/.zshrc) — bash -l on such a user sources
// nothing and runs with a stripped PATH, producing empty package scans.
func (r *Real) resolveUserShell(ctx context.Context, username string) string {
	if runtime.GOOS != "darwin" || username == "" {
		return ""
	}
	stdout, _, _, err := r.Run(ctx, "dscl", ".", "-read", "/Users/"+username, "UserShell")
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(stdout))
	if len(fields) < 2 {
		return ""
	}
	shell := fields[1]
	info, err := os.Stat(shell)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return ""
	}
	return shell
}

func (r *Real) RunAsUser(ctx context.Context, username, command string) (string, error) {
	if !r.IsRoot() {
		stdout, _, exitCode, err := r.Run(ctx, "bash", "-c", command)
		if err != nil {
			return strings.TrimSpace(stdout), err
		}
		if exitCode != 0 {
			return strings.TrimSpace(stdout), fmt.Errorf("command exited with code %d", exitCode)
		}
		return strings.TrimSpace(stdout), nil
	}
	shell := r.resolveUserShell(ctx, username)
	if shell == "" {
		shell = "/bin/bash"
	}

	// Source the shell's interactive rc file for full PATH.
	// Login shells (-l) source .zprofile/.bash_profile but skip .zshrc/.bashrc,
	// where most users add PATH entries for nvm, n, fnm, bun, npm-global, etc.
	rcSource := "[ -f ~/.bashrc ] && . ~/.bashrc 2>/dev/null; "
	if strings.HasSuffix(shell, "zsh") {
		rcSource = "[ -f ~/.zshrc ] && . ~/.zshrc 2>/dev/null; "
	}

	stdout, _, exitCode, err := r.Run(ctx, "sudo", "-H", "-u", username, shell, "-l", "-c", rcSource+command)
	if err != nil {
		return strings.TrimSpace(stdout), err
	}
	if exitCode != 0 {
		return strings.TrimSpace(stdout), fmt.Errorf("command exited with code %d", exitCode)
	}
	return strings.TrimSpace(stdout), nil
}
