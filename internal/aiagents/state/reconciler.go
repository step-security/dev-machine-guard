package state

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

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
	Now         func() time.Time
}

// Reconcile fetches desired state, writes the cache, and converges
// settings to match by calling InstallFn / UninstallFn. Both are
// idempotent so we don't need to detect the current state — install
// is a no-op when entries are already in place, uninstall is a no-op
// when no DMG-owned entries exist.
//
// Order: cache write first, then settings reconciliation. If the
// settings reconciliation fails, the cache still reflects the desired
// state — the hot path honors the new value immediately, and the next
// tick retries the settings change.
//
// Errors are returned to the caller for logging via cli.AppendError;
// Reconcile itself never panics into the caller's hot path.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	if r.Fetcher == nil {
		return errors.New("state: nil fetcher")
	}

	res, err := r.Fetcher.Fetch(ctx, r.CustomerID, r.DeviceID)
	if err != nil {
		return fmt.Errorf("state: fetch: %w", err)
	}

	now := time.Now().UTC
	if r.Now != nil {
		now = r.Now
	}
	next := Default()
	next.FetchedAt = now()
	next.Source = SourcePoll
	next.Hooks.Enabled = res.Enabled

	if err := Write(next); err != nil {
		return fmt.Errorf("state: write cache: %w", err)
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
