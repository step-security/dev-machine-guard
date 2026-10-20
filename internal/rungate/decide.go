package rungate

import (
	"time"

	"github.com/step-security/dev-machine-guard/internal/heartbeat"
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
//
// There is deliberately no agent-side feature flag here: the feature is
// controlled entirely by the backend's run-directive response (dormant when
// the backend answers "always scan"), so it can be turned on or off from the
// backend without shipping a new agent.
type Inputs struct {
	// ForceScan: --force-scan / STEPSEC_FORCE_SCAN=1.
	ForceScan bool
	// KillSwitch: STEPSEC_DISABLE_RUN_GATE=1 (per-device local escape).
	KillSwitch bool
	// Directive is the backend's answer; nil when the check-in failed.
	Directive *Directive
	// State is the on-disk cache (in last-run.json); nil when
	// absent/corrupt/future-schema/never-checked-in.
	State *heartbeat.RunGate
	Now   time.Time
}

// Decision is the gate's verdict. Reason values are log-facing:
// forced | kill_switch | directive (server answer, subreason attached by the
// caller) | offline_cache_skip | offline_fail_open.
type Decision struct {
	Skip           bool
	Reason         string
	NextEligibleAt int64 // unix sec; informational, set on skips when known
}

// Decide applies the gate's precedence. Pure.
//
// Order matters: the local escapes (force, kill switch) win over everything;
// the server directive decides due-vs-not; the cache only speaks when the
// backend didn't. There is deliberately no lock check here — a not-due wakeup
// skips on the directive before the run ever tries to acquire the lock, and a
// DUE wakeup that collides with a still-running scan is allowed through to
// lock.Acquire so it reports the contention (a scan overrunning its own
// interval is worth surfacing), consistent with the pre-gating behavior.
func Decide(in Inputs) Decision {
	if in.ForceScan {
		return Decision{Skip: false, Reason: "forced"}
	}
	if in.KillSwitch {
		return Decision{Skip: false, Reason: "kill_switch"}
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
// run, a cache older than max(floor, 2×interval), or stamps in the future
// (clock moved backwards — otherwise it would skip until real time caught up).
func decideOffline(st *heartbeat.RunGate, now time.Time) Decision {
	if st == nil || !st.GatingEnabled || st.EffectiveIntervalMinutes <= 0 || st.LastFullRunAt <= 0 {
		return Decision{Skip: false, Reason: "offline_fail_open"}
	}
	interval := time.Duration(st.EffectiveIntervalMinutes) * time.Minute
	staleness := max(2*interval, offlineCacheMinFloor)
	cacheAge := now.Sub(time.Unix(st.DirectiveFetchedAt, 0))
	if st.DirectiveFetchedAt <= 0 || cacheAge < 0 || cacheAge >= staleness {
		return Decision{Skip: false, Reason: "offline_fail_open"}
	}
	sinceLast := now.Sub(time.Unix(st.LastFullRunAt, 0))
	if sinceLast < 0 || sinceLast >= interval {
		return Decision{Skip: false, Reason: "offline_fail_open"}
	}
	return Decision{
		Skip:           true,
		Reason:         "offline_cache_skip",
		NextEligibleAt: st.LastFullRunAt + int64(st.EffectiveIntervalMinutes)*60,
	}
}
