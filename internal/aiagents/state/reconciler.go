package state

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// HookCommandFn is the install/uninstall seam shape. Production wires
// these to internal/aiagents/cli.RunInstall and .RunUninstall in
// main.go (state can't import cli without a cycle, so the seam stays
// a plain function type).
type HookCommandFn func(ctx context.Context, exec executor.Executor, agent string, stdout, stderr io.Writer) int

// Reconciler turns a desired enable/disable into local actions. One
// instance per main.go call site; the struct holds the wiring and no
// per-call state.
type Reconciler struct {
	Exec        executor.Executor
	Fetcher     Fetcher
	CustomerID  string
	DeviceID    string
	Agent       string // "" = every detected agent
	Stdout      io.Writer
	Stderr      io.Writer
	InstallFn   HookCommandFn
	UninstallFn HookCommandFn
}

// Reconcile fetches desired state and calls InstallFn / UninstallFn to
// converge settings.json (Claude Code) and config.toml (Codex) to
// match. Both seams are idempotent — install is a no-op when entries
// are already present, uninstall is a no-op when none are. The
// presence of the managed entry in the agent's settings file is the
// single source of truth; no on-disk state is kept by this package.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	if r.Fetcher == nil {
		return errors.New("state: nil fetcher")
	}

	res, err := r.Fetcher.Fetch(ctx, r.CustomerID, r.DeviceID)
	if err != nil {
		return fmt.Errorf("state: fetch: %w", err)
	}

	switch {
	case res.Enabled:
		if r.InstallFn == nil {
			return errors.New("state: nil InstallFn")
		}
		if code := r.InstallFn(ctx, r.Exec, r.Agent, r.Stdout, r.Stderr); code != 0 {
			return fmt.Errorf("state: install exited %d", code)
		}
	default:
		if r.UninstallFn == nil {
			return errors.New("state: nil UninstallFn")
		}
		if code := r.UninstallFn(ctx, r.Exec, r.Agent, r.Stdout, r.Stderr); code != 0 {
			return fmt.Errorf("state: uninstall exited %d", code)
		}
	}
	return nil
}
