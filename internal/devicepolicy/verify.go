package devicepolicy

// Compliance states the agent may report. These mirror the agent-reportable
// subset of agent-api's policies.State* enum byte-for-byte — the backend
// rejects any value outside its agentReportableStates set, so these strings
// MUST stay in sync with internal/developer-mdm/policies/models.go. The
// backend-derived states (not_assigned, agent_unsupported, agent_stale) are
// never reported by the agent.
const (
	StateCompliant          = "compliant"
	StatePending            = "pending"
	StatePolicyNotApplied   = "policy_not_applied"
	StateDriftDetected      = "drift_detected"
	StateMDMManaged         = "mdm_managed"
	StateWriteFailed        = "write_failed"
	StateVerificationFailed = "verification_failed"
)

// CategoryIDEExtension is the only policy category enforced in v1. It matches
// agent-api's CategoryIDEExtension and is the value passed as ?category= on the
// run-config fetch and echoed in the compliance report.
const CategoryIDEExtension = "ide_extension"

// TargetVSCode is the only IDE target enforced in v1. Policy identity is
// (category, target); an empty target defaults to vscode for ide_extension, so
// future IDE families (jetbrains, …) become a new target rather than a new
// category or a state migration. Matches agent-api's TargetVSCode and is the
// value passed as ?target= on the run-config fetch and echoed in the compliance
// report.
const TargetVSCode = "vscode"

// VerifyInput is the result set the verifier reasons over. It is intentionally
// pure data: the writer performs the I/O (write + readback), so Verify itself
// touches nothing.
type VerifyInput struct {
	// WriteOK is true when the settings write returned no error.
	WriteOK bool
	// ReadbackMatch is true when the value read back after the write equals the
	// value the agent intended to write. A false value here (with WriteOK true)
	// is the on-device signal that the write did not actually take.
	ReadbackMatch bool
}

// Verify maps a write/readback result to the compliance state, with a fixed
// precedence:
//
//  1. Write failed → write_failed.
//  2. Write succeeded but the readback differs → policy_not_applied.
//  3. Otherwise → compliant.
//
// `compliant` means exactly what the PRD's weak-verification model allows: the
// desired policy is present in the user-scope settings.json
// (readback-confirmed) — NOT a per-extension disabled confirmation.
//
// The remaining agent states are decided by the reconciler's ladder, not here,
// because none is derivable from these two inputs alone: mdm_managed (a real
// managed policy found by the probe), drift_detected (the on-disk value
// diverged from the recorded written value and was re-applied — it upgrades a
// would-be compliant), and verification_failed (the read itself errored).
func Verify(in VerifyInput) string {
	if !in.WriteOK {
		return StateWriteFailed
	}
	if !in.ReadbackMatch {
		return StatePolicyNotApplied
	}
	return StateCompliant
}
