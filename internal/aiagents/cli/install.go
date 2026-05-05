package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// resolveBinary is the seam install/uninstall use to obtain the
// absolute, symlink-resolved DMG binary path. Production calls
// Resolve(); tests override to avoid depending on a real on-disk
// binary or to drive the resolver-failure branch.
var resolveBinary = Resolve

// RunInstall is the entry point for `hooks install`.
//
// agent is the --agent flag value; "" means "every detected agent".
// stdout/stderr are the writers main wires from os.Stdout/os.Stderr.
//
// Returns the desired process exit code:
//   - 0 on success, idempotent no-op, no agents detected, or the
//     root-with-no-console-user no-op (plan §1.5).
//   - 1 on enterprise-config gate failure, self-path resolution
//     failure, unsupported --agent, or any adapter Install error.
//
// Flow (plan §1.6):
//  1. enterprise-config gate (stricter than IsEnterpriseMode — all
//     three credentials present and non-placeholder; plan §1.8)
//  2. resolve target user (root + no console user → log + exit 0)
//  3. resolve absolute, symlink-resolved DMG binary path
//  4. select adapters per --agent or detection on $PATH
//  5. per-adapter Install, then chown all outputs to target user
//     under root (plan §1.6)
//  6. emit per-adapter summary to stdout
//
// Adapter Install errors don't abort the loop — the remaining
// adapters still get a chance. The aggregate exit code is 1 if any
// adapter failed.
func RunInstall(ctx context.Context, exec executor.Executor, agent string, stdout, stderr io.Writer) int {
	if _, ok := ingest.Snapshot(); !ok {
		fmt.Fprintln(stderr, "Enterprise configuration not found or incomplete.")
		fmt.Fprintln(stderr, "Run `stepsecurity-dev-machine-guard configure` to set customer_id, api_endpoint, and api_key.")
		AppendError("install", "enterprise_config_missing", "ingest.Snapshot returned not-ok", "")
		return 1
	}

	target, ok := ResolveTargetUser(exec, stderr)
	if !ok {
		return 0
	}

	binaryPath, err := resolveBinary()
	if err != nil {
		fmt.Fprintf(stderr, "stepsecurity-dev-machine-guard: cannot resolve own binary path: %v\n", err)
		AppendError("install", "selfpath_failed", err.Error(), "")
		return 1
	}

	adapters, err := selectAdapters(ctx, agent, target.HomeDir, binaryPath, exec)
	if err != nil {
		fmt.Fprintf(stderr, "stepsecurity-dev-machine-guard: %v\n", err)
		AppendError("install", "select_adapters_failed", err.Error(), "")
		return 1
	}
	if len(adapters) == 0 {
		fmt.Fprintln(stdout, "No supported AI coding agents detected on $PATH.")
		fmt.Fprintf(stdout, "Pass --agent <name> to install for a specific agent (supported: %s).\n",
			strings.Join(SupportedAgents, ", "))
		return 0
	}

	exit := 0
	for _, a := range adapters {
		res, err := a.Install(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "%s: install failed: %v\n", a.Name(), err)
			AppendError("install", "adapter_install_failed",
				fmt.Sprintf("%s: %v", a.Name(), err), "")
			exit = 1
			// Skip chown on failure: the partial state is already
			// inconsistent, and a chown sweep can't unbreak it.
			continue
		}
		// Plan §1.6: under root, chown every file written or
		// created (settings, .dmg-backup.* siblings, parent dirs).
		// ChownToTarget short-circuits to a no-op when not root.
		ChownToTarget(exec, installChownPaths(res), target)
		printInstallResult(stdout, a.Name(), res)
	}
	return exit
}

// installChownPaths is the chown sweep set for a single adapter's
// InstallResult. Order is shallowest-parent-first (CreatedDirs are
// pushed by the adapter in that order) so a recursive chown could
// stop at a parent without revisiting children — though the current
// helper chowns each entry individually.
func installChownPaths(r adapter.InstallResult) []string {
	out := make([]string, 0, len(r.CreatedDirs)+len(r.WrittenFiles)+len(r.BackupFiles))
	out = append(out, r.CreatedDirs...)
	out = append(out, r.WrittenFiles...)
	out = append(out, r.BackupFiles...)
	return out
}

// printInstallResult renders one adapter's InstallResult for the
// user. The format is intentionally line-oriented rather than tabular
// so partial output during multi-agent installs reads naturally.
func printInstallResult(w io.Writer, name string, r adapter.InstallResult) {
	fmt.Fprintf(w, "%s:\n", name)
	if len(r.HooksAdded) > 0 {
		fmt.Fprintf(w, "  added: %v\n", r.HooksAdded)
	}
	if len(r.HooksKept) > 0 {
		fmt.Fprintf(w, "  unchanged: %v\n", r.HooksKept)
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
