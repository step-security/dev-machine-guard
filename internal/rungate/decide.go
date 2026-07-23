package rungate

import (
	"time"
)

// offlineCacheMinFloor is the minimum freshness window for the cached
// directive when the backend is unreachable. The window is
// max(offlineCacheMinFloor, 2×interval): generous because the cache stores an
// interval (recomputed against LastFullRunAt every wakeup), never a literal
// skip — so even a week-old cache can only delay one interval, and expiring
// it merely reverts to today's scan-every-wakeup behavior.
const offlineCacheMinFloor = 7 * 24 * time.Hour

// Inputs is everything Decide consumes. Pure data — the orchestration in
// Evaluate gathers it; tests construct it directly.
type Inputs struct {
	// ForceScan: --force-scan / STEPSEC_FORCE_SCAN=1.
	ForceScan bool
	// FeatureEnabled: featuregate.IsEnabled(FeatureRunGate) (incl. override).
	FeatureEnabled bool
	// KillSwitch: STEPSEC_DISABLE_RUN_GATE=1.
	KillSwitch bool
	// LockHeldByLivePID: another instance is mid-scan (lock.Holder).
	LockHeldByLivePID bool
	// Directive is the backend's answer; nil when the check-in failed.
	Directive *Directive
	// State is the on-disk cache; nil when absent/corrupt/future-schema.
	State *State
	Now   time.Time
}

// Decision is the gate's verdict. Reason values are log-facing:
// forced | feature_disabled | kill_switch | lock_held | directive (server
// answer, subreason attached by the caller) | offline_cache_skip |
// offline_fail_open.
type Decision struct {
	Skip           bool
	Reason         string
	NextEligibleAt int64 // unix sec; informational, set on skips when known
}

// Decide applies the gate's precedence. Pure.
//
// Order matters: the explicit escapes (force, feature gate, kill switch) win
// over everything; the lock peek beats the directive so an overlapping wakeup
// during a long scan backs off quietly WITHOUT a network call (Evaluate
// orders the I/O the same way); the server directive beats the cache; the
// cache only speaks when the backend didn't.
func Decide(in Inputs) Decision {
	if in.ForceScan {
		return Decision{Skip: false, Reason: "forced"}
	}
	if !in.FeatureEnabled {
		return Decision{Skip: false, Reason: "feature_disabled"}
	}
	if in.KillSwitch {
		return Decision{Skip: false, Reason: "kill_switch"}
	}
	if in.LockHeldByLivePID {
		return Decision{Skip: true, Reason: "lock_held"}
	}
	if d := in.Directive; d != nil {
		if d.ShouldSkip() {
			return Decision{Skip: true, Reason: "directive:" + d.Reason, NextEligibleAt: d.NextEligibleAt}
		}
		return Decision{Skip: false, Reason: "directive:" + d.Reason}
	}
	return decideOffline(in.State, in.Now)
}

// decideOffline is the check-in-failed path: replay the cached interval
// against the local last-full-run stamp. Every missing precondition fails
// open — no cache, gating off at last contact, no interval, never completed a
// run, or a cache older than max(floor, 2×interval).
func decideOffline(st *State, now time.Time) Decision {
	if st == nil || !st.GatingEnabled || st.EffectiveIntervalMinutes <= 0 || st.LastFullRunAt <= 0 {
		return Decision{Skip: false, Reason: "offline_fail_open"}
	}
	interval := time.Duration(st.EffectiveIntervalMinutes) * time.Minute
	staleness := max(2*interval, offlineCacheMinFloor)
	if st.DirectiveFetchedAt <= 0 || now.Sub(time.Unix(st.DirectiveFetchedAt, 0)) >= staleness {
		return Decision{Skip: false, Reason: "offline_fail_open"}
	}
	sinceLast := now.Sub(time.Unix(st.LastFullRunAt, 0))
	if sinceLast >= interval {
		return Decision{Skip: false, Reason: "offline_fail_open"}
	}
	return Decision{
		Skip:           true,
		Reason:         "offline_cache_skip",
		NextEligibleAt: st.LastFullRunAt + int64(st.EffectiveIntervalMinutes)*60,
	}
}
