package telemetry

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/progress"
)

// phaseBudgets caps how long each analysis phase can run before the agent
// abandons its in-flight subprocesses and continues to the next phase.
// Budgets are chosen well above the p99 healthy duration observed in
// production heartbeat data — they exist to bound the pathological tail,
// not to clip normal scans.
//
// Order of overrides at a single phase site (resolved by resolvePhaseBudget):
//  1. STEPSEC_PHASE_BUDGET_<NAME> env var — <NAME> is the phase name
//     upper-cased (e.g. node_scan → STEPSEC_PHASE_BUDGET_NODE_SCAN=20m).
//     "0" or "off" disables the deadline; an unparseable value is ignored.
//  2. this map's entry (an explicit 0 here also disables the deadline)
//  3. defaultPhaseBudget (5m) when the phase has no entry above
//
// "Disabled" means no per-phase deadline; the parent scan deadline
// (STEPSEC_MAX_SCAN_DURATION) and the whole-process watchdog still apply.
var phaseBudgets = map[string]time.Duration{
	"scheduler_info":      15 * time.Second,
	"device_info":         30 * time.Second,
	"ide_scan":            2 * time.Minute,
	"extension_scan":      2 * time.Minute,
	"ai_tools_scan":       5 * time.Minute,
	"mcp_config_scan":     1 * time.Minute,
	"malicious_file_scan": 10 * time.Minute,
	"brew_scan":           5 * time.Minute,
	"python_scan":         10 * time.Minute,
	"syspkg_scan":         5 * time.Minute,
	"node_scan":           15 * time.Minute,
	"telemetry_upload":    10 * time.Minute,
}

const defaultPhaseBudget = 5 * time.Minute

// resolvePhaseBudget computes a phase's effective budget, honoring (in order)
// the STEPSEC_PHASE_BUDGET_<NAME> env override, the phaseBudgets map entry,
// then defaultPhaseBudget. The bool is false when the phase has NO deadline:
// either source can disable it ("0"/"off" in the env var, or an explicit 0 in
// the map). A missing map entry — distinct from an entry of 0 — falls back to
// defaultPhaseBudget. An unparseable/empty env value is ignored so a typo in
// an unattended scheduler context can't strip every phase's deadline.
func resolvePhaseBudget(name string) (time.Duration, bool) {
	if v := os.Getenv("STEPSEC_PHASE_BUDGET_" + strings.ToUpper(name)); v != "" {
		switch {
		case v == "0" || v == "off":
			return 0, false
		default:
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				return d, true
			}
			// Unparseable or non-positive: ignore and fall through.
		}
	}
	if budget, ok := phaseBudgets[name]; ok {
		if budget <= 0 {
			return 0, false // explicit 0 in the map disables the deadline
		}
		return budget, true
	}
	return defaultPhaseBudget, true
}

// startPhase opens a new phase and returns a derived context that carries
// the phase's budget as its deadline. Callers must invoke endPhase (or
// otherwise call the returned cancel func) before opening the next phase.
// When the phase budget is disabled (see resolvePhaseBudget) the returned
// context carries no per-phase deadline — only the parent scan deadline.
//
// The caller continues to own postPhase() — endPhase only handles the
// tracker.Finish + cancel + deadline-overrun log line so the per-phase
// edit at each site stays small.
func startPhase(parent context.Context, tracker *PhaseTracker, name string) (context.Context, context.CancelFunc) {
	tracker.Start(name)
	budget, hasDeadline := resolvePhaseBudget(name)
	if !hasDeadline {
		return context.WithCancel(parent)
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
		// Only reachable when the phase had a deadline, so hasDeadline is true
		// and budget is the real value used to set the timeout.
		budget, _ := resolvePhaseBudget(name)
		log.Warn("phase %s exceeded budget %s — continuing with partial results", name, budget)
	}
	cancel()
	tracker.Finish()
}
