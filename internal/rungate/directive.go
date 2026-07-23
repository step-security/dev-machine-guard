// Package rungate implements the server-driven run gate: on every invocation
// the agent asks the backend's run-directive endpoint whether a full scan is
// due and exits quietly when it isn't. The scan cadence lives in the backend
// (per tenant, with temporary overrides and per-device refresh), so customers
// point their MDM/scheduler at a simple hourly launch and control the real
// frequency from the dashboard.
//
// Every failure path fails OPEN (the scan runs): a tenant that never opted
// in, an unreachable backend, a malformed response, an unresolvable device
// id, or unusable local state must never suppress scanning. The only
// deliberate skips are a backend "skip" directive, the offline cached-interval
// fallback, and the quiet back-off while another instance holds the lock.
package rungate

// Wire contract for GET /developer-mdm-agent/run-directive. Mode and reason
// strings are wire-permanent and mirrored by the backend's
// run_directive_handler.go.
const (
	ModeFull = "full"
	ModeSkip = "skip"
)

// Directive is the backend's check-in answer. EffectiveIntervalMinutes rides
// along so the agent can cache it as its offline fallback gate; NextEligibleAt
// is informational (skip responses only).
type Directive struct {
	Mode                     string `json:"mode"`
	Reason                   string `json:"reason"`
	GatingEnabled            bool   `json:"gating_enabled"`
	EffectiveIntervalMinutes int    `json:"effective_interval_minutes"`
	NextEligibleAt           int64  `json:"next_eligible_at"`
	CheckedAt                int64  `json:"checked_at"`
}

// directiveEnvelope is the response wrapper, kept additive like the
// run-config envelope so future siblings don't break old agents.
type directiveEnvelope struct {
	Directive Directive `json:"directive"`
}

// ShouldSkip is the single reader of Mode. Anything that is not exactly
// ModeSkip — including future modes like "partial" — means the scan proceeds,
// so new server behavior degrades to a full scan on old agents, never to a
// silent skip.
func (d Directive) ShouldSkip() bool { return d.Mode == ModeSkip }
