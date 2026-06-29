package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// samplePolicy is the compacted compiled policy — the exact value the
// reconciler writes and records (it compacts the fetched payload first).
const samplePolicy = `{"github.copilot":true,"ms-python.python":"1.2.3"}`

// samplePolicyWire is the same policy as the backend might format it on the
// wire. The reconciler must normalize this to samplePolicy before comparing
// or writing.
const samplePolicyWire = "{\n  \"github.copilot\": true,\n  \"ms-python.python\": \"1.2.3\"\n}"

// --- fakes -----------------------------------------------------------------

type fakeFetcher struct {
	ep  EffectivePolicy
	err error
}

func (f *fakeFetcher) Fetch(_ context.Context, _, _, _, _ string) (EffectivePolicy, error) {
	return f.ep, f.err
}

type fakeReporter struct {
	reports []ComplianceReport
	err     error
}

func (r *fakeReporter) Report(_ context.Context, _, _ string, rep ComplianceReport) error {
	r.reports = append(r.reports, rep)
	return r.err
}

type fakeWriter struct {
	value            string
	present          bool
	readErr          error
	writeErr         error
	readbackOverride string // when set, Write returns this instead of echoing input
	writes           []string
	clears           int
	reads            int
}

func (w *fakeWriter) Read() (string, bool, error) {
	w.reads++
	return w.value, w.present, w.readErr
}

func (w *fakeWriter) Write(v string) (string, error) {
	w.writes = append(w.writes, v)
	if w.writeErr != nil {
		return "", w.writeErr
	}
	w.value, w.present = v, true
	if w.readbackOverride != "" {
		return w.readbackOverride, nil
	}
	return v, nil
}

func (w *fakeWriter) Clear() error {
	w.clears++
	w.value, w.present = "", false
	return nil
}

func (w *fakeWriter) Location() string { return "fake://settings.json" }

// --- helpers ---------------------------------------------------------------

func withTempCache(t *testing.T) {
	t.Helper()
	restore := SetCachePathForTest(filepath.Join(t.TempDir(), CacheFilename))
	t.Cleanup(restore)
}

// newRec builds a reconciler over fakes. The managed-policy probe is stubbed
// to "not managed" so results never depend on the host machine; tests for the
// mdm_managed path override r.Probe.
func newRec(t *testing.T, ep EffectivePolicy, fetchErr error, w *fakeWriter) (*Reconciler, *fakeReporter) {
	t.Helper()
	withTempCache(t)
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:    &fakeFetcher{ep: ep, err: fetchErr},
		Reporter:   rep,
		Writer:     w,
		CustomerID: "cust",
		DeviceID:   "dev-1",
		Platform:   "linux",
		Probe:      func() (bool, string) { return false, "" },
		Now:        func() time.Time { return time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC) },
	}
	return r, rep
}

func policyEP(hash string) EffectivePolicy {
	return EffectivePolicy{
		Category: CategoryIDEExtension,
		Clear:    false,
		Policy:   json.RawMessage(samplePolicyWire),
		Hash:     hash,
	}
}

func lastReport(t *testing.T, rep *fakeReporter) ComplianceReport {
	t.Helper()
	if len(rep.reports) != 1 {
		t.Fatalf("expected exactly 1 report, got %d: %+v", len(rep.reports), rep.reports)
	}
	return rep.reports[0]
}

// --- tests -----------------------------------------------------------------

func TestEnforceWritesCompactedPolicyAndReportsCompliant(t *testing.T) {
	w := &fakeWriter{}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// The wire payload is formatted; the written value must be its compaction.
	if len(w.writes) != 1 || w.writes[0] != samplePolicy {
		t.Fatalf("expected compacted policy written once, got %v", w.writes)
	}
	got := lastReport(t, rep)
	if got.State != StateCompliant {
		t.Fatalf("state = %q, want compliant", got.State)
	}
	// Compliance is reported under the reconciled target.
	if got.Target != TargetVSCode {
		t.Fatalf("report target = %q, want %q", got.Target, TargetVSCode)
	}
	// applied_hash echoed verbatim (never recomputed).
	if got.AppliedHash != "sha256:H" {
		t.Fatalf("applied_hash = %q, want sha256:H", got.AppliedHash)
	}
	// Ownership recorded.
	st, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode)
	if !ok || st.WrittenValue != samplePolicy || st.AppliedHash != "sha256:H" {
		t.Fatalf("cache = %+v ok=%v", st, ok)
	}
}

func TestEnforceIdempotentSecondRunWritesNothing(t *testing.T) {
	withTempCache(t)
	// Seed prior ownership + on-disk value matching the desired policy.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:H", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: samplePolicy, present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher: &fakeFetcher{ep: policyEP("sha256:H")}, Reporter: rep, Writer: w,
		CustomerID: "c", DeviceID: "d", Platform: "linux",
		Probe: func() (bool, string) { return false, "" },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 0 {
		t.Fatalf("idempotent run must not write, got %v", w.writes)
	}
	got := lastReport(t, rep)
	if got.State != StateCompliant || got.AppliedHash != "sha256:H" {
		t.Fatalf("report = %+v, want compliant + echoed hash", got)
	}
}

func TestClearRemovesAgentOwnedPolicy(t *testing.T) {
	withTempCache(t)
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:H", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: samplePolicy, present: true} // on-disk == what we wrote → owned
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:  &fakeFetcher{ep: EffectivePolicy{Category: CategoryIDEExtension, Clear: true}},
		Reporter: rep, Writer: w, CustomerID: "c", DeviceID: "d", Platform: "linux",
		Probe: func() (bool, string) { return false, "" },
		Now:   func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if w.clears != 1 {
		t.Fatalf("owned policy should be cleared once, clears=%d", w.clears)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("clear must not report a compliance state, got %+v", rep.reports)
	}
	if st, _ := ReadAppliedState(CategoryIDEExtension, TargetVSCode); st.WrittenValue != "" {
		t.Fatalf("ownership record should be dropped, got %+v", st)
	}
}

func TestClearLeavesValueAgentDidNotWrite(t *testing.T) {
	withTempCache(t)
	// We recorded writing "mine", but on disk is "theirs" — the user (or some
	// other tool) changed it. Unassignment must not destroy their value.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{WrittenValue: "mine"}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: "theirs", present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:  &fakeFetcher{ep: EffectivePolicy{Category: CategoryIDEExtension, Clear: true}},
		Reporter: rep, Writer: w, CustomerID: "c", DeviceID: "d", Platform: "linux",
		Probe: func() (bool, string) { return false, "" },
		Now:   func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if w.clears != 0 {
		t.Fatalf("a value the agent did not write must NOT be cleared, clears=%d", w.clears)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("clear path reports nothing, got %+v", rep.reports)
	}
}

func TestEnforceManagedPolicyProbeYieldsMDMManaged(t *testing.T) {
	// A real MDM policy at the OS policy location outranks user settings inside
	// VS Code: the agent yields without reading or writing settings.json.
	w := &fakeWriter{}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w)
	r.Probe = func() (bool, string) { return true, `HKLM\...\VSCode [AllowedExtensions]` }
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if w.reads != 0 || len(w.writes) != 0 || w.clears != 0 {
		t.Fatalf("managed probe must short-circuit before any settings I/O: reads=%d writes=%v clears=%d",
			w.reads, w.writes, w.clears)
	}
	got := lastReport(t, rep)
	if got.State != StateMDMManaged {
		t.Fatalf("state = %q, want mdm_managed", got.State)
	}
	if got.AppliedHash != "" {
		t.Fatalf("applied_hash should be empty when nothing applied, got %q", got.AppliedHash)
	}
}

func TestEnforceOverwritesPreexistingUserValue(t *testing.T) {
	// A pre-existing extensions.allowed in the USER's settings (no ownership
	// record, no managed policy) is exactly what enforcement is for: the
	// compiled policy replaces it. This is the old foreign-value yield
	// inverted — settings.json is the enforcement surface now, and the real
	// MDM case is handled by the probe.
	cases := []struct {
		name  string
		value string
	}{
		{"user's own allow-list", `{"user.choice":true}`},
		{"value byte-equal to desired policy", samplePolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{value: tc.value, present: true}
			r, rep := newRec(t, policyEP("sha256:H"), nil, w)
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if len(w.writes) != 1 || w.writes[0] != samplePolicy {
				t.Fatalf("expected the policy written once, got %v", w.writes)
			}
			got := lastReport(t, rep)
			// No ownership record → this is first enforcement, not drift.
			if got.State != StateCompliant || got.AppliedHash != "sha256:H" {
				t.Fatalf("report = %+v, want compliant + echoed hash", got)
			}
		})
	}
}

func TestEnforceDriftReappliesAndReportsDriftDetected(t *testing.T) {
	// The agent wrote the policy before; the user edited or removed it. The
	// reconciler converges it back and reports drift_detected (readback
	// confirmed → applied_hash still echoed).
	cases := []struct {
		name    string
		value   string
		present bool
	}{
		{"key edited by user", `{"user.tampered":true}`, true},
		{"key removed by user", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTempCache(t)
			if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:H", WrittenValue: samplePolicy}); err != nil {
				t.Fatal(err)
			}
			w := &fakeWriter{value: tc.value, present: tc.present}
			rep := &fakeReporter{}
			r := &Reconciler{
				Fetcher: &fakeFetcher{ep: policyEP("sha256:H")}, Reporter: rep, Writer: w,
				CustomerID: "c", DeviceID: "d", Platform: "linux",
				Probe: func() (bool, string) { return false, "" },
				Now:   func() time.Time { return time.Unix(0, 0).UTC() },
			}
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if len(w.writes) != 1 || w.writes[0] != samplePolicy {
				t.Fatalf("drift must re-apply the policy, writes=%v", w.writes)
			}
			got := lastReport(t, rep)
			if got.State != StateDriftDetected {
				t.Fatalf("state = %q, want drift_detected", got.State)
			}
			if got.AppliedHash != "sha256:H" {
				t.Fatalf("applied_hash = %q, want echoed hash (re-apply was readback-confirmed)", got.AppliedHash)
			}
			// Next cycle: converged, hash unchanged → plain compliant again.
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("second Reconcile: %v", err)
			}
			if len(w.writes) != 1 {
				t.Fatalf("second cycle must be idempotent, writes=%v", w.writes)
			}
			if rep.reports[1].State != StateCompliant {
				t.Fatalf("second cycle state = %q, want compliant", rep.reports[1].State)
			}
		})
	}
}

func TestEnforceWriteFailureReportsWriteFailed(t *testing.T) {
	w := &fakeWriter{writeErr: errors.New("permission denied")}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w)
	err := r.Reconcile(context.Background())
	if err == nil {
		t.Fatal("write failure should surface an error")
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
}

func TestEnforceReadbackMismatchReportsPolicyNotApplied(t *testing.T) {
	w := &fakeWriter{readbackOverride: `{"*":true}`} // write landed differently than intended
	r, rep := newRec(t, policyEP("sha256:H"), nil, w)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := lastReport(t, rep)
	if got.State != StatePolicyNotApplied {
		t.Fatalf("state = %q, want policy_not_applied", got.State)
	}
	if got.AppliedHash != "" {
		t.Fatalf("applied_hash must be empty without readback confirmation, got %q", got.AppliedHash)
	}
	// Ownership IS recorded even on a readback mismatch — it tracks what the
	// agent wrote, not what it verified; next-cycle recovery depends on it
	// (value-based ownership only takes effect if the value actually landed).
	if st, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok || st.WrittenValue != samplePolicy {
		t.Fatalf("cache must record the written value even on readback mismatch, got %+v ok=%v", st, ok)
	}
}

func TestEnforceReadbackMismatchRecoversNextCycle(t *testing.T) {
	// Cycle 1: the write lands but readback transiently mismatches →
	// policy_not_applied. Cycle 2: the on-disk value IS what we wrote; with
	// ownership recorded the agent reclaims it and reports compliant — it must
	// not classify its own write as drift and churn rewrites forever.
	w := &fakeWriter{readbackOverride: `{"*":true}`}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if rep.reports[0].State != StatePolicyNotApplied {
		t.Fatalf("cycle 1 state = %q, want policy_not_applied", rep.reports[0].State)
	}

	w.readbackOverride = "" // transient condition gone; disk holds our value
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if len(rep.reports) != 2 || rep.reports[1].State != StateCompliant {
		t.Fatalf("cycle 2 reports = %+v, want second report compliant", rep.reports)
	}
	if len(w.writes) != 1 {
		t.Fatalf("cycle 2 must be idempotent (no rewrite), writes=%v", w.writes)
	}
}

func TestEnforceReadErrorReportsVerificationFailed(t *testing.T) {
	// Includes the unsalvageable-settings.json case: the writer refuses to
	// parse it, the reconciler can't decide idempotency/drift.
	w := &fakeWriter{readErr: errors.New("settings.json is not valid JSONC")}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w)
	err := r.Reconcile(context.Background())
	if err == nil {
		t.Fatal("read error should surface")
	}
	if got := lastReport(t, rep); got.State != StateVerificationFailed {
		t.Fatalf("state = %q, want verification_failed", got.State)
	}
}

func TestMalformedFetchIsNoOp(t *testing.T) {
	w := &fakeWriter{value: "existing", present: true}
	r, rep := newRec(t, EffectivePolicy{}, errors.New("malformed"), w)
	probed := false
	r.Probe = func() (bool, string) { probed = true; return false, "" }
	err := r.Reconcile(context.Background())
	if err == nil {
		t.Fatal("fetch error should surface")
	}
	if len(w.writes) != 0 || w.clears != 0 || w.reads != 0 || probed {
		t.Fatalf("malformed fetch must touch nothing: writes=%v clears=%d reads=%d probed=%v",
			w.writes, w.clears, w.reads, probed)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("malformed fetch must not report, got %+v", rep.reports)
	}
}

func TestNilWriterPlatformIsNoOp(t *testing.T) {
	withTempCache(t)
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:  &fakeFetcher{ep: policyEP("sha256:H")},
		Reporter: rep, Writer: nil, CustomerID: "c", DeviceID: "d", Platform: "freebsd",
		Probe: func() (bool, string) { return false, "" },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("nil-writer platform should no-op without error, got %v", err)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("unsupported platform reports nothing, got %+v", rep.reports)
	}
}

func TestReconcileNoOpsWhenPolicyAbsent(t *testing.T) {
	// Run-config carried no policy directive (zero EffectivePolicy, nil error).
	// This is NOT a clear: the on-disk value, ownership record, and reporter must
	// all be left untouched. A transient policy drop must never wipe enforcement.
	withTempCache(t)
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:H", WrittenValue: samplePolicy}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: samplePolicy, present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:  &fakeFetcher{ep: EffectivePolicy{}}, // present()==false
		Reporter: rep, Writer: w, CustomerID: "c", DeviceID: "d", Platform: "linux",
		Probe: func() (bool, string) { return false, "" },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("absent policy should no-op without error, got %v", err)
	}
	if len(w.writes) != 0 || w.clears != 0 || w.reads != 0 {
		t.Fatalf("absent policy must touch nothing: writes=%v clears=%d reads=%d", w.writes, w.clears, w.reads)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("absent policy must not report, got %+v", rep.reports)
	}
	// Ownership record must stand for next cycle's idempotency check.
	if st, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok || st.WrittenValue != samplePolicy {
		t.Fatalf("ownership record must be untouched, got %+v ok=%v", st, ok)
	}
}

func TestEnforceStateUnwritablePreflightWritesNothing(t *testing.T) {
	// If the ownership store can't be persisted, the policy must never be
	// written: an enforced value with no record would be orphaned (a later
	// clear refuses to remove it, and every cycle would misread it as drift
	// of unknown origin).
	w := &fakeWriter{}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w)
	r.writeState = func(string, string, AppliedTargetState) error { return errors.New("disk full") }
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("unwritable ownership store should surface an error")
	}
	if len(w.writes) != 0 {
		t.Fatalf("policy must NOT be written when ownership can't be recorded, writes=%v", w.writes)
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
}

func TestEnforceStatePersistFailureRollsBackWrite(t *testing.T) {
	// Preflight succeeds but the post-write persist fails: the agent undoes the
	// just-written value (no prior value → remove the key) so it never leaves
	// an enforced policy it has no ownership record for.
	w := &fakeWriter{}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w)
	calls := 0
	r.writeState = func(string, string, AppliedTargetState) error {
		calls++
		if calls == 1 {
			return nil // preflight probe
		}
		return errors.New("disk full")
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("persist failure should surface an error")
	}
	if len(w.writes) != 1 || w.writes[0] != samplePolicy {
		t.Fatalf("writes = %v, want exactly one write of the policy", w.writes)
	}
	if w.clears != 1 || w.present {
		t.Fatalf("rolled-back write should remove the key, clears=%d present=%v", w.clears, w.present)
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
}

func TestEnforceStatePersistFailureRestoresPreviousOwnedValue(t *testing.T) {
	// Same as above but a previous owned value existed: rollback restores it,
	// keeping the (intact, atomic) old state file and the disk consistent.
	withTempCache(t)
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:OLD", WrittenValue: "old-value"}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: "old-value", present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher: &fakeFetcher{ep: policyEP("sha256:NEW")}, Reporter: rep, Writer: w,
		CustomerID: "c", DeviceID: "d", Platform: "linux",
		Probe: func() (bool, string) { return false, "" },
		Now:   func() time.Time { return time.Unix(0, 0).UTC() },
	}
	r.writeState = func(_, _ string, s AppliedTargetState) error {
		if s.WrittenValue == samplePolicy {
			return errors.New("disk full") // fail only the post-write persist
		}
		return nil // preflight probe succeeds
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("persist failure should surface an error")
	}
	if len(w.writes) != 2 || w.writes[0] != samplePolicy || w.writes[1] != "old-value" {
		t.Fatalf("writes = %v, want [new policy, restored old-value]", w.writes)
	}
	if w.value != "old-value" || !w.present {
		t.Fatalf("on-disk should be restored to old-value, got %q present=%v", w.value, w.present)
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
}

func TestEnforcePolicyChangeRewrites(t *testing.T) {
	withTempCache(t)
	// We own "old-value" and it is still intact on disk; the backend now sends
	// a new policy with a new hash. This is a policy CHANGE, not drift — the
	// report is plain compliant.
	if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: "sha256:OLD", WrittenValue: "old-value"}); err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{value: "old-value", present: true}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher: &fakeFetcher{ep: policyEP("sha256:NEW")}, Reporter: rep, Writer: w,
		CustomerID: "c", DeviceID: "d", Platform: "linux",
		Probe: func() (bool, string) { return false, "" },
		Now:   func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 1 || w.writes[0] != samplePolicy {
		t.Fatalf("owned policy change should rewrite to new value, writes=%v", w.writes)
	}
	if got := lastReport(t, rep); got.State != StateCompliant || got.AppliedHash != "sha256:NEW" {
		t.Fatalf("report = %+v, want compliant + sha256:NEW", got)
	}
}

func TestEnforceRefusesToClobberFutureSchemaStateFile(t *testing.T) {
	// Headline guarantee: an older agent meeting a NEWER agent's state file must
	// not overwrite it. The preflight write hits errFutureSchema → the cycle
	// reports write_failed, never touches settings.json, and leaves the future
	// file byte-identical (its category metadata preserved for the newer agent).
	path := filepath.Join(t.TempDir(), CacheFilename)
	future := `{"schema_version":999,"categories":{"future_cat":{"applied_hash":"sha256:z","written_value":"{}","fetched_at":"2026-06-08T00:00:00Z"}}}` + "\n"
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetCachePathForTest(path)
	defer restore()

	w := &fakeWriter{}
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher: &fakeFetcher{ep: policyEP("sha256:H")}, Reporter: rep, Writer: w,
		CustomerID: "c", DeviceID: "d", Platform: "linux",
		Probe: func() (bool, string) { return false, "" },
		Now:   func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("refusing to clobber a future-schema state file should surface an error")
	}
	if len(w.writes) != 0 {
		t.Fatalf("settings.json must not be written when the future state file is refused, writes=%v", w.writes)
	}
	if got := lastReport(t, rep); got.State != StateWriteFailed {
		t.Fatalf("state = %q, want write_failed", got.State)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != future {
		t.Fatalf("future-schema state file must be left byte-identical; got %q", string(after))
	}
}

func TestReconcilePreservesSiblingTargetOwnership(t *testing.T) {
	// A reconcile for vscode must never disturb another target's ownership record
	// living under the same category. Seed a jetbrains sibling, run a vscode
	// enforce, and confirm the jetbrains record stands byte-for-byte while the
	// vscode record is freshly written. newRec sets up the temp cache, so the
	// sibling must be seeded AFTER it (not before) to land in the same file.
	w := &fakeWriter{}
	r, rep := newRec(t, policyEP("sha256:H"), nil, w) // Target empty → defaults to vscode
	jb := AppliedTargetState{AppliedHash: "sha256:JB", WrittenValue: "jetbrains-value"}
	if err := WriteAppliedState(CategoryIDEExtension, "jetbrains", jb); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// vscode enforced and recorded.
	if got := lastReport(t, rep); got.Target != TargetVSCode || got.State != StateCompliant {
		t.Fatalf("report = %+v, want vscode + compliant", got)
	}
	if vs, ok := ReadAppliedState(CategoryIDEExtension, TargetVSCode); !ok || vs.WrittenValue != samplePolicy {
		t.Fatalf("vscode ownership not recorded: got %+v ok=%v", vs, ok)
	}
	// jetbrains sibling untouched.
	if got, ok := ReadAppliedState(CategoryIDEExtension, "jetbrains"); !ok || got != jb {
		t.Fatalf("sibling jetbrains ownership must survive a vscode reconcile: got %+v ok=%v", got, ok)
	}
}
