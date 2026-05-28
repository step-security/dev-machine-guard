package telemetry

import (
	"context"
	"time"

	"github.com/step-security/dev-machine-guard/internal/progress"
)

// phaseBudgets caps how long each analysis phase can run before the agent
// abandons its in-flight subprocesses and continues to the next phase.
// Budgets are chosen well above the p99 healthy duration observed in
// production heartbeat data — they exist to bound the pathological tail,
// not to clip normal scans.
//
// Order of overrides at a single phase site:
//  1. STEPSEC_PHASE_BUDGET_<NAME> env var (Go duration, e.g. "10m") — if set
//  2. this map's entry
//  3. defaultPhaseBudget (5m) when neither is set
//
// A budget of 0 disables the per-phase deadline for that phase (the parent
// scan deadline still applies).
var phaseBudgets = map[string]time.Duration{
	"device_info":      30 * time.Second,
	"ide_scan":         2 * time.Minute,
	"extension_scan":   2 * time.Minute,
	"ai_tools_scan":    5 * time.Minute,
	"mcp_config_scan":  1 * time.Minute,
	"brew_scan":        5 * time.Minute,
	"python_scan":      10 * time.Minute,
	"syspkg_scan":      5 * time.Minute,
	"node_scan":        15 * time.Minute,
	"telemetry_upload": 10 * time.Minute,
}

const defaultPhaseBudget = 5 * time.Minute

// startPhase opens a new phase and returns a derived context that carries
// the phase's budget as its deadline. Callers must invoke endPhase (or
// otherwise call the returned cancel func) before opening the next phase.
//
// The caller continues to own postPhase() — endPhase only handles the
// tracker.Finish + cancel + deadline-overrun log line so the per-phase
// edit at each site stays small.
func startPhase(parent context.Context, tracker *PhaseTracker, name string) (context.Context, context.CancelFunc) {
	tracker.Start(name)
	budget := phaseBudgets[name]
	if budget == 0 {
		budget = defaultPhaseBudget
	}
	return context.WithTimeout(parent, budget)
}

// endPhase finishes the in-flight phase, releases its deadline context,
// and logs a warning if the phase exhausted its budget. Designed so each
// phase site reads as:
//
//	phaseCtx, phaseCancel := startPhase(ctx, tracker, "ide_scan")
//	... body uses phaseCtx ...
//	endPhase(phaseCtx, phaseCancel, tracker, log, "ide_scan")
//	postPhase()
func endPhase(phaseCtx context.Context, cancel context.CancelFunc,
	tracker *PhaseTracker, log *progress.Logger, name string) {
	if phaseCtx.Err() == context.DeadlineExceeded {
		budget := phaseBudgets[name]
		if budget == 0 {
			budget = defaultPhaseBudget
		}
		log.Warn("phase %s exceeded budget %s — continuing with partial results", name, budget)
	}
	cancel()
	tracker.Finish()
}
