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

// WSLDirective is the tenant-wide switch for scanning inside WSL distros. It
// rides the same run-config response as ScanDirective — which the agent already
// fetches before every scan — so enabling it costs no extra call and needs no
// per-device state. The granularity is deliberately tenant-only: there is no
// per-device or per-group gating for WSL scanning.
//
// It fails CLOSED, unlike the scan gate. An absent block, a backend that
// predates the field, a failed check-in, or a bypassed gate all leave distro
// scanning off. Host-side WSL *detection* is unaffected: it is GA and needs no
// directive.
type WSLDirective struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"`
}

// runConfigEnvelope is the subset of the run-config response the gate reads.
// The scan directive rides run-config alongside detection_rules and policy;
// those siblings are intentionally ignored here (the scan path fetches them
// itself). A pointer so a missing field is distinguishable from a zero value.
type runConfigEnvelope struct {
	ScanDirective *Directive    `json:"scan_directive"`
	WSLDirective  *WSLDirective `json:"wsl_directive"`
}

// ShouldSkip is the single reader of Mode. Anything that is not exactly
// ModeSkip — including future modes like "partial" — means the scan proceeds,
// so new server behavior degrades to a full scan on old agents, never to a
// silent skip.
func (d Directive) ShouldSkip() bool { return d.Mode == ModeSkip }
