package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// RunUninstall is the entry point for `hooks uninstall`.
//
// agent is the --agent flag value; "" means "every detected agent".
// stdout/stderr are wired from os.Stdout/os.Stderr by main.
//
// Returns the desired process exit code:
//   - 0 on success, no-op (no DMG-owned entries found), no agents
//     detected, or the root-with-no-console-user no-op.
//   - 1 on self-path resolution failure, unsupported --agent, or any
//     adapter Uninstall error.
//
// Flow:
//  1. resolve target user (root + no console user → log + exit 0)
//  2. resolve absolute, symlink-resolved DMG binary path (the
//     uninstall matcher needs it to identify DMG-owned entries)
//  3. select adapters per --agent or detection on $PATH
//  4. per-adapter Uninstall, then chown rewritten outputs to target
//     user under root
//  5. emit per-adapter summary to stdout
//
// No enterprise-config gate: uninstall must work even after the
// customer has revoked credentials or rotated keys — otherwise we'd
// trap users with hook entries pointing at a binary that can no
// longer authenticate.
//
// Adapter Uninstall errors don't abort the loop — the remaining
// adapters still get a chance. The aggregate exit code is 1 if any
// adapter failed.
func RunUninstall(ctx context.Context, exec executor.Executor, agent string, stdout, stderr io.Writer) int {
	target, ok := ResolveTargetUser(exec, stderr)
	if !ok {
		return 0
	}

	binaryPath, err := resolveBinary()
	if err != nil {
		fmt.Fprintf(stderr, "stepsecurity-dev-machine-guard: cannot resolve own binary path: %v\n", err)
		AppendError("uninstall", "selfpath_failed", err.Error(), "")
		return 1
	}

	adapters, err := selectAdapters(ctx, agent, target.HomeDir, binaryPath, exec)
	if err != nil {
		fmt.Fprintf(stderr, "stepsecurity-dev-machine-guard: %v\n", err)
		AppendError("uninstall", "select_adapters_failed", err.Error(), "")
		return 1
	}
	if len(adapters) == 0 {
		fmt.Fprintln(stdout, "No supported AI coding agents detected on $PATH.")
		fmt.Fprintf(stdout, "Pass --agent <name> to uninstall for a specific agent (supported: %s).\n",
			strings.Join(SupportedAgents, ", "))
		return 0
	}

	exit := 0
	for _, a := range adapters {
		res, err := a.Uninstall(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "%s: uninstall failed: %v\n", a.Name(), err)
			AppendError("uninstall", "adapter_uninstall_failed",
				fmt.Sprintf("%s: %v", a.Name(), err), "")
			exit = 1
			continue
		}
		// Same chown rationale as install: a sudo-driven rewrite
		// must not leave the user's settings owned by root.
		// UninstallResult never carries CreatedDirs — uninstall only
		// rewrites files that already existed.
		ChownToTarget(exec, uninstallChownPaths(res), target)
		printUninstallResult(stdout, a.Name(), res)
	}
	return exit
}

// uninstallChownPaths is the chown sweep set for a single adapter's
// UninstallResult. WrittenFiles ∪ BackupFiles only — see RunUninstall
// for why no CreatedDirs.
func uninstallChownPaths(r adapter.UninstallResult) []string {
	out := make([]string, 0, len(r.WrittenFiles)+len(r.BackupFiles))
	out = append(out, r.WrittenFiles...)
	out = append(out, r.BackupFiles...)
	return out
}

// printUninstallResult renders one adapter's UninstallResult.
//
// On the "nothing to remove" path the adapter populates Notes only
// (no WrittenFiles, no HooksRemoved); the user still gets a header
// line so multi-adapter summaries don't render as a single empty
// section followed by the next adapter's output.
func printUninstallResult(w io.Writer, name string, r adapter.UninstallResult) {
	fmt.Fprintf(w, "%s:\n", name)
	if len(r.HooksRemoved) > 0 {
		fmt.Fprintf(w, "  removed: %v\n", r.HooksRemoved)
	}
	for _, f := range r.WrittenFiles {
		fmt.Fprintf(w, "  wrote: %s\n", f)
	}
	for _, f := range r.BackupFiles {
		fmt.Fprintf(w, "  backup: %s\n", f)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}
