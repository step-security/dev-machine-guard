//go:build !windows

package executor

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func (r *Real) IsRoot() bool {
	return os.Getuid() == 0
}

// resolveUserShell returns the given user's configured login shell on macOS by
// consulting Directory Services (dscl). Returns "" on non-darwin platforms, if
// the lookup fails, or if the resolved path isn't an executable file — in which
// case callers should fall back to /bin/bash.
//
// Mirrors stepsecurity-dev-machine-guard.sh:run_as_logged_in_user. Matters when
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
