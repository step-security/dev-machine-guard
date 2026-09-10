package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests here drive the reconciler with the seams the ~/.npmrc path sets
// (Render, Converged, ProbeExpected, RestoreSnapshot, OwnsByMarker). The
// existing reconcile_test.go covers the settings.json path with every seam at
// its zero value; together they show the ladder serves both targets from one
// body — the seams change behavior ONLY when set.

// --- state fixture ----------------------------------------------------------

// npmStore is these tests' handle on the ONE state file (device-policy-state.json,
// redirected to a temp dir for the test). There is no npm-specific store to fake:
// the npm category records ownership under categories.package_config.targets.npm
// through the same ReadAppliedState / WriteAppliedState / ClearAppliedState the
// IDE lane uses, so assertions read the real file back. The counters prove the
// ladder went through the store, and writeErr / dropErr / failWriteFrom inject
// persist failures through the reconciler's writeState / clearState seams —
// failWriteFrom is how a test fails the POST-WRITE persist specifically.
type npmStore struct {
	path          string
	writeErr      error
	dropErr       error
	failWriteFrom int // when >0, the Nth persist and every one after it fails
	writes        int
	drops         int
}

func newNPMStore(t *testing.T) *npmStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), CacheFilename)
	t.Cleanup(SetCachePathForTest(path))
	return &npmStore{path: path}
}

// seed writes a record straight to the file, bypassing the counters: it is the
// state the cycle STARTS from, not something the reconciler did.
func (s *npmStore) seed(t *testing.T, cat, tgt string, st AppliedTargetState) *npmStore {
	t.Helper()
	if err := WriteAppliedState(cat, tgt, st); err != nil {
		t.Fatalf("seeding %s/%s: %v", cat, tgt, err)
	}
	return s
}

func (s *npmStore) get(cat, tgt string) (AppliedTargetState, bool) {
	return ReadAppliedState(cat, tgt)
}

// exists reports whether the state file was created at all.
func (s *npmStore) exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// --- npm fixtures -----------------------------------------------------------

// npmPolicyWire stands in for the fetched npm policy payload (passed verbatim to
// the Render seam). npmRendered is what the fake renderer turns it into — the
// value the reconciler writes and compares, standing in for the managed body
// RenderNPMRCBlock produces.
const npmPolicyWire = `{"registry":"https://npm.pkg.example/","always_auth":true}`
const npmRendered = "registry=https://npm.pkg.example/\nalways-auth=true"

func npmRenderOK(json.RawMessage) (string, error) { return npmRendered, nil }

func npmPolicyEP(hash string) EffectivePolicy {
	return EffectivePolicy{
		Category: CategoryPackageConfig,
		Target:   TargetNPM,
		Clear:    false,
		Policy:   json.RawMessage(npmPolicyWire),
		Hash:     hash,
	}
}

// newNPMRec builds a marker-owned reconciler wired like the ~/.npmrc path:
// OwnsByMarker, OwnershipKey, a Render seam that produces the managed block, a
// content-aware ProbeExpected, and a Converged seam. It mirrors
// runPackageConfigEnforce's wiring, so a seam the production path sets and this
// one does not would show up as a behavior difference. Defaults: Render → the
// fixed block, probe → not managed, Converged → false (proceed to write). Tests
// override a single seam to exercise one rung. Ownership lands in st's file — the
// same shared state file the IDE lane writes.
func newNPMRec(t *testing.T, ep EffectivePolicy, w *fakeWriter, st *npmStore) (*Reconciler, *fakeReporter) {
	t.Helper()
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:       &fakeFetcher{ep: ep},
		Reporter:      rep,
		Writer:        w,
		CustomerID:    "cust",
		DeviceID:      "SERIAL-1",
		Platform:      "darwin",
		Category:      CategoryPackageConfig,
		Target:        TargetNPM,
		OwnsByMarker:  true,
		OwnershipKey:  NPMOwnedKey,
		Render:        npmRenderOK,
		ProbeExpected: func(string) (bool, string) { return false, "" },
		Converged:     func(string) (bool, error) { return false, nil },
		Now:           func() time.Time { return time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC) },
	}
	// The counters and fault injection sit on the real store calls, so a test can
	// both fail a persist and assert what the file ended up holding.
	r.writeState = func(cat, tgt string, s AppliedTargetState) error {
		st.writes++
		if st.failWriteFrom > 0 && st.writes >= st.failWriteFrom {
			return errors.New("state persist failed")
		}
		if st.writeErr != nil {
			return st.writeErr
		}
		return WriteAppliedState(cat, tgt, s)
	}
	r.clearState = func(cat, tgt string) error {
		st.drops++
		if st.dropErr != nil {
			return st.dropErr
		}
		return ClearAppliedState(cat, tgt)
	}
	return r, rep
}

// --- tests ------------------------------------------------------------------

func TestNPMEnforceRendersBlockAndWrites(t *testing.T) {
	w := &fakeWriter{}
	st := newNPMStore(t)
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// The rendered block is written verbatim — the Render seam, not compactJSON.
	if len(w.writes) != 1 || w.writes[0] != npmRendered {
		t.Fatalf("expected the rendered block written once, got %v", w.writes)
	}
	got := lastReport(t, rep)
	if got.State != StateCompliant || got.Category != CategoryPackageConfig || got.Target != TargetNPM {
		t.Fatalf("report = %+v, want compliant package_config/npm", got)
	}
	if got.AppliedHash != "sha256:N" {
		t.Fatalf("applied_hash = %q, want sha256:N", got.AppliedHash)
	}
	if got.EvaluatedHash != "sha256:N" {
		t.Fatalf("evaluated_hash = %q, want sha256:N", got.EvaluatedHash)
	}
	// Ownership recorded in the one shared state file, under this category/target.
	if st.writes == 0 {
		t.Fatal("ownership must be recorded in the state file")
	}
	rec, ok := st.get(CategoryPackageConfig, TargetNPM)
	if !ok || rec.WrittenSettings[NPMOwnedKey] != npmRendered || rec.AppliedHash != "sha256:N" {
		t.Fatalf("state record = %+v ok=%v, want the rendered block + hash", rec, ok)
	}
}

func TestNPMSettingsDMGReportIncludesAggregateMatchWithPrebuiltWriter(t *testing.T) {
	w := &fakeWriter{}
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, newNPMStore(t))
	r.Render = func(json.RawMessage) (string, error) { return stdSettingsBody, nil }
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	r.Converged = func(expected string) (bool, error) { return w.present && w.value == expected, nil }
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	w.value = "registry=https://drift.example/"
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("drift Reconcile: %v", err)
	}
	if len(w.writes) != 2 {
		t.Fatalf("writes = %d, want apply, no-op, and drift repair", len(w.writes))
	}

	for i, got := range rep.reports {
		wantState := StateCompliant
		if i == 2 {
			wantState = StateDriftDetected
		}
		if got.State != wantState {
			t.Fatalf("report[%d] state = %q, want %q", i, got.State, wantState)
		}
		var observed map[string]json.RawMessage
		if err := json.Unmarshal(got.Observed, &observed); err != nil {
			t.Fatalf("report[%d] observed is not a JSON object: %v (%s)", i, err, got.Observed)
		}
		if len(observed) != 4 || string(observed[observedKeySettingsStatus]) != `"match"` {
			t.Fatalf("report[%d] observed = %s, want four-key bag with matching settings", i, got.Observed)
		}
		for _, sensitive := range []string{"save-exact", "EXAMPLE_NPM_TOKEN", "engine-strict"} {
			if strings.Contains(string(got.Observed), sensitive) {
				t.Fatalf("report[%d] contains %q: %s", i, sensitive, got.Observed)
			}
		}
	}
}

func TestNPMNullSettingRejectedBeforeWriterInitialization(t *testing.T) {
	// A null settings member must fail at the policy boundary before target-user
	// resolution or any filesystem access.
	st := newNPMStore(t)
	ep := npmPolicyEP("sha256:N")
	ep.Policy = json.RawMessage(`{"ecosystem":"npm","registry_url":"https://registry-int.stepsecurity.io/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"ssabc123"},"settings":{"save-exact":null}}`)
	r, rep := newNPMRec(t, ep, nil, st)
	r.Render = func(policy json.RawMessage) (string, error) { return RenderNPMRCBlock(policy, stdSerial) }
	initialized := false
	r.InitWriter = func() error {
		initialized = true
		return nil
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("a null settings member must surface an error")
	}
	if initialized {
		t.Fatal("writer initialized before settings validation")
	}
	if got := lastReport(t, rep); got.State != StatePolicyNotApplied {
		t.Fatalf("state = %q, want policy_not_applied", got.State)
	}
}

func TestNPMProbeExpectedReceivesRenderedBlockAndYields(t *testing.T) {
	// The content-aware probe receives the RENDERED block (not the raw policy) —
	// the ~/.npmrc file is user-writable, so a bare marker is not proof; the probe
	// compares the desired state. When it reports the MDM lane already governs the
	// same state, the reconciler yields mdm_managed without touching the file.
	w := &fakeWriter{value: "whatever", present: true}
	st := newNPMStore(t)
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	var gotArg string
	r.ProbeExpected = func(expected string) (bool, string) {
		gotArg = expected
		return true, "managed npm config present"
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if gotArg != npmRendered {
		t.Fatalf("ProbeExpected received %q, want the rendered block %q", gotArg, npmRendered)
	}
	if w.reads != 0 || len(w.writes) != 0 {
		t.Fatalf("managed probe must short-circuit before any file I/O: reads=%d writes=%v", w.reads, w.writes)
	}
	if got := lastReport(t, rep); got.State != StateMDMManaged || got.AppliedHash != "" {
		t.Fatalf("report = %+v, want mdm_managed with no applied_hash", got)
	}
}

func TestNPMConvergedSeamOverridesBodyEquality(t *testing.T) {
	// Body equality alone is not convergence for ~/.npmrc: a `registry=` line
	// appended BELOW the block leaves the block bytes identical yet overrides it.
	// The Converged seam owns that decision. Here on-disk == the rendered block
	// (body-equal) and the recorded hash matches, but Converged=false → the
	// reconciler still rewrites, where plain body-equality would have skipped.
	w := &fakeWriter{value: npmRendered, present: true}
	st := newNPMStore(t).seed(t, CategoryPackageConfig, TargetNPM,
		AppliedTargetState{AppliedHash: "sha256:N", WrittenSettings: npmOwnRec(npmRendered)})
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	r.Converged = func(string) (bool, error) { return false, nil }
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 1 {
		t.Fatalf("Converged=false must force a rewrite even when body-equal, writes=%v", w.writes)
	}
	if got := lastReport(t, rep); got.State != StateCompliant {
		t.Fatalf("state = %q, want compliant", got.State)
	}
}

func TestNPMConvergedTrueIsIdempotent(t *testing.T) {
	// Converged=true AND the recorded hash matches → the block is fully in place
	// and effective. No write; still reports compliant so the backend sees a fresh
	// evaluation.
	w := &fakeWriter{value: npmRendered, present: true}
	st := newNPMStore(t).seed(t, CategoryPackageConfig, TargetNPM,
		AppliedTargetState{AppliedHash: "sha256:N", WrittenSettings: npmOwnRec(npmRendered)})
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	r.Converged = func(string) (bool, error) { return true, nil }
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(w.writes) != 0 {
		t.Fatalf("converged + hash unchanged must not write, got %v", w.writes)
	}
	if got := lastReport(t, rep); got.State != StateCompliant || got.AppliedHash != "sha256:N" {
		t.Fatalf("report = %+v, want compliant + echoed hash", got)
	}
}

func TestNPMAdoptsAlreadyConvergedState(t *testing.T) {
	// The exact block is fully applied on disk (Converged=true) but the state file
	// carries no matching hash — our record is stale or gone, or the cycle that
	// applied it resolved a different home for the file. The reconciler must adopt
	// the on-disk state (no rewrite, no false drift) and report compliant, recording
	// the current hash for next cycle.
	cases := []struct {
		name string
		seed *AppliedTargetState
	}{
		{"no record at all", nil},
		{"stale hash recorded", &AppliedTargetState{AppliedHash: "sha256:OLD", WrittenSettings: npmOwnRec(npmRendered)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newNPMStore(t)
			if tc.seed != nil {
				st.seed(t, CategoryPackageConfig, TargetNPM, *tc.seed)
			}
			w := &fakeWriter{value: npmRendered, present: true}
			r, rep := newNPMRec(t, npmPolicyEP("sha256:NEW"), w, st)
			r.Converged = func(string) (bool, error) { return true, nil }
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if len(w.writes) != 0 {
				t.Fatalf("already-converged state must not rewrite, writes=%v", w.writes)
			}
			if got := lastReport(t, rep); got.State != StateCompliant || got.AppliedHash != "sha256:NEW" {
				t.Fatalf("report = %+v, want compliant + adopted hash", got)
			}
			rec, ok := st.get(CategoryPackageConfig, TargetNPM)
			if !ok || rec.AppliedHash != "sha256:NEW" || rec.WrittenSettings[NPMOwnedKey] != npmRendered {
				t.Fatalf("state not adopted: rec=%+v ok=%v", rec, ok)
			}
		})
	}
}

func TestNPMLegacySecretStateMigratesWithoutConfigWrite(t *testing.T) {
	w := &fakeWriter{value: npmRendered, present: true}
	st := newNPMStore(t).seed(t, CategoryPackageConfig, TargetNPM, AppliedTargetState{
		AppliedHash:     "sha256:N",
		WrittenSettings: npmOwnRec(npmRendered),
	})
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	r.OwnershipStateValue = NPMOwnershipValue
	r.Converged = func(string) (bool, error) { return true, nil }

	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 0 {
		t.Fatalf("legacy state migration rewrote config: %v", w.writes)
	}
	record, ok := st.get(CategoryPackageConfig, TargetNPM)
	if !ok || record.WrittenSettings[NPMOwnedKey] != NPMOwnershipValue {
		t.Fatalf("migrated state = %+v, %v; want secret-free ownership", record, ok)
	}
	if got := lastReport(t, rep).State; got != StateCompliant {
		t.Fatalf("state = %q, want compliant", got)
	}
}

func TestFullStateConvergenceFailureWithSameHashReportsDrift(t *testing.T) {
	w := &fakeWriter{value: npmRendered, present: true}
	st := newNPMStore(t).seed(t, CategoryPackageConfig, TargetNPM, AppliedTargetState{
		AppliedHash:     "sha256:N",
		WrittenSettings: npmOwnRec(npmRendered),
	})
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	r.Converged = func(string) (bool, error) { return false, nil }
	r.FullStateDrift = true

	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := lastReport(t, rep).State; got != StateDriftDetected {
		t.Fatalf("state = %q, want drift_detected", got)
	}
}

func TestNPMReadErrorClassification(t *testing.T) {
	// A structural refusal on the initial read (the target cannot be enforced at
	// all — wraps ErrTargetUnusable) is a write-class fact → write_failed; a plain
	// unreadable file stays verification_failed.
	cases := []struct {
		name  string
		err   error
		state string
	}{
		{"structural refusal", fmt.Errorf("npmrc: %w", ErrTargetUnusable), StateWriteFailed},
		{"plain unreadable", errors.New("permission denied"), StateVerificationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{readErr: tc.err}
			st := newNPMStore(t)
			r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
			if err := r.Reconcile(context.Background()); err == nil {
				t.Fatal("a read error must surface")
			}
			if len(w.writes) != 0 {
				t.Fatalf("nothing must be written on a read error, writes=%v", w.writes)
			}
			if got := lastReport(t, rep); got.State != tc.state {
				t.Fatalf("state = %q, want %q", got.State, tc.state)
			}
		})
	}
}

func TestNPMConvergedErrorClassification(t *testing.T) {
	// The Converged seam runs its OWN secure read; a structural refusal there is
	// the same write-class fact as a refusal on the initial read.
	cases := []struct {
		name  string
		err   error
		state string
	}{
		{"structural refusal", fmt.Errorf("npmrc: %w", ErrTargetUnusable), StateWriteFailed},
		{"plain error", errors.New("stat failed"), StateVerificationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{value: "x", present: true}
			st := newNPMStore(t)
			r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
			r.Converged = func(string) (bool, error) { return false, tc.err }
			if err := r.Reconcile(context.Background()); err == nil {
				t.Fatal("a convergence-check error must surface")
			}
			if len(w.writes) != 0 {
				t.Fatalf("nothing must be written on a convergence error, writes=%v", w.writes)
			}
			if got := lastReport(t, rep); got.State != tc.state {
				t.Fatalf("state = %q, want %q", got.State, tc.state)
			}
		})
	}
}

func TestNPMClearByMarkerAlwaysClearsAndDrops(t *testing.T) {
	// Marker-based ownership: on unassignment the block is removed UNCONDITIONALLY
	// (Clear is scoped to our own markers) and the record dropped UNCONDITIONALLY —
	// even with no record, and without reading the file — so a lost/empty/drifted
	// record can never strand a token-bearing block.
	cases := []struct {
		name string
		seed *AppliedTargetState
	}{
		{"no record", nil},
		{"stale record", &AppliedTargetState{WrittenSettings: npmOwnRec("old-block")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newNPMStore(t)
			if tc.seed != nil {
				st.seed(t, CategoryPackageConfig, TargetNPM, *tc.seed)
			}
			w := &fakeWriter{value: "a-managed-block", present: true}
			ep := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetNPM, Clear: true, Hash: "sha256:CLEAR"}
			r, rep := newNPMRec(t, ep, w, st)
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if w.clears != 1 {
				t.Fatalf("marker clear must call Clear exactly once, clears=%d", w.clears)
			}
			if w.reads != 0 {
				t.Fatalf("marker clear must not read the file, reads=%d", w.reads)
			}
			if st.drops != 1 {
				t.Fatalf("marker clear must Drop the record unconditionally, drops=%d", st.drops)
			}
			if _, ok := st.get(CategoryPackageConfig, TargetNPM); ok {
				t.Fatal("state record must be gone after a marker clear")
			}
			if len(rep.reports) != 0 {
				t.Fatalf("clear reports no compliance state, got %+v", rep.reports)
			}
		})
	}
}

func TestNPMRestoreSnapshotRollbackClassification(t *testing.T) {
	// After the block is written, the post-write ownership persist fails. The npm
	// writer reverts its whole-file change from a snapshot (RestoreSnapshot seam),
	// and the OUTCOME is classified: a clean restore → write_failed (the write was
	// cleanly undone); a failed/aborted restore → verification_failed (on-disk
	// state now unknown). The generic re-write path is NOT used — Writer.Write ran
	// once (the enforce) and Clear never ran.
	cases := []struct {
		name       string
		restoreErr error
		wantState  string
	}{
		{"restore succeeds", nil, StateWriteFailed},
		{"restore fails", errors.New("path moved under us"), StateVerificationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{}
			st := newNPMStore(t)
			st.failWriteFrom = 2 // preflight ok, post-write persist fails
			r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
			restored := 0
			r.RestoreSnapshot = func() error { restored++; return tc.restoreErr }
			if err := r.Reconcile(context.Background()); err == nil {
				t.Fatal("a post-write persist failure must surface an error")
			}
			if restored != 1 {
				t.Fatalf("RestoreSnapshot must run exactly once, ran %d", restored)
			}
			if len(w.writes) != 1 {
				t.Fatalf("the generic re-write path must NOT run; Writer.Write should have run once, got %v", w.writes)
			}
			if w.clears != 0 {
				t.Fatalf("RestoreSnapshot replaces the generic clear-based rollback, clears=%d", w.clears)
			}
			if got := lastReport(t, rep); got.State != tc.wantState {
				t.Fatalf("state = %q, want %q", got.State, tc.wantState)
			}
		})
	}
}

func TestNPMWriteErrorClassification(t *testing.T) {
	// A Writer.Write failure is write_failed by default; the one exception is a
	// writer that landed bytes it could neither verify nor roll back
	// (ErrWriteUnverified) → verification_failed, since on-disk state is then
	// indeterminate. The IDE writer never returns the sentinel, so its Write
	// failures stay write_failed (proven in TestSeamFallbacksMatchIDEBehavior).
	cases := []struct {
		name  string
		err   error
		state string
	}{
		{"plain write failure", errors.New("disk full"), StateWriteFailed},
		{"unverified rollback", fmt.Errorf("npmrc: commit: %w", ErrWriteUnverified), StateVerificationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{writeErr: tc.err}
			st := newNPMStore(t)
			r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
			if err := r.Reconcile(context.Background()); err == nil {
				t.Fatal("a write error must surface")
			}
			if len(w.writes) != 1 {
				t.Fatalf("Write should have been attempted once, got %v", w.writes)
			}
			got := lastReport(t, rep)
			if got.State != tc.state {
				t.Fatalf("state = %q, want %q", got.State, tc.state)
			}
			if got.EvaluatedHash != "sha256:N" {
				t.Fatalf("evaluated_hash = %q, want sha256:N", got.EvaluatedHash)
			}
		})
	}
}

func TestNPMWriterInitErrClassification(t *testing.T) {
	// Writer construction failed (Writer nil, WriterInitErr set). The reconciler
	// classifies AFTER the fetch by what run-config asked for — it never touches
	// disk or state, since there is no resolved target user to act against.
	npmEnforce := npmPolicyEP("sha256:N")
	npmClear := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetNPM, Clear: true}
	cases := []struct {
		name        string
		ep          EffectivePolicy
		initErr     error
		wantErr     bool
		wantReports []string
	}{
		{"no target user + enforce → policy_not_applied", npmEnforce, ErrNoTargetUser, true, []string{StatePolicyNotApplied}},
		{"other failure + enforce → write_failed", npmEnforce, errors.New("home unopenable"), true, []string{StateWriteFailed}},
		{"clear + no writer → retain, no report", npmClear, ErrNoTargetUser, false, nil},
		{"absent + no writer → silent", EffectivePolicy{}, ErrNoTargetUser, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTempCache(t)
			rep := &fakeReporter{}
			r := &Reconciler{
				Fetcher:       &fakeFetcher{ep: tc.ep},
				Reporter:      rep,
				Writer:        nil,
				WriterInitErr: tc.initErr,
				CustomerID:    "cust",
				DeviceID:      "SERIAL-1",
				Platform:      "darwin",
				Category:      CategoryPackageConfig,
				Target:        TargetNPM,
				OwnsByMarker:  true,
			}
			err := r.Reconcile(context.Background())
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if len(rep.reports) != len(tc.wantReports) {
				t.Fatalf("reports = %+v, want %v", rep.reports, tc.wantReports)
			}
			for i, want := range tc.wantReports {
				if rep.reports[i].State != want {
					t.Fatalf("report[%d] state = %q, want %q", i, rep.reports[i].State, want)
				}
				if rep.reports[i].Category != CategoryPackageConfig || rep.reports[i].Target != TargetNPM {
					t.Fatalf("report[%d] identity = %q/%q, want package_config/npm",
						i, rep.reports[i].Category, rep.reports[i].Target)
				}
				if rep.reports[i].EvaluatedHash != tc.ep.Hash {
					t.Fatalf("report[%d] evaluated_hash = %q, want %q", i, rep.reports[i].EvaluatedHash, tc.ep.Hash)
				}
			}
		})
	}
}

func TestNPMAbsentPolicyDoesNotReport(t *testing.T) {
	r, rep := newNPMRec(t, EffectivePolicy{}, &fakeWriter{}, newNPMStore(t))
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("absent policy must not report, got %+v", rep.reports)
	}
}

func TestNPMFetchFailureDoesNotReport(t *testing.T) {
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), &fakeWriter{}, newNPMStore(t))
	r.Fetcher = &fakeFetcher{err: errors.New("fetch failed")}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("fetch failure must surface")
	}
	if len(rep.reports) != 0 {
		t.Fatalf("fetch failure must not report, got %+v", rep.reports)
	}
}

func TestNPMStateLivesInTheOneSharedFile(t *testing.T) {
	// npm ownership goes in device-policy-state.json under
	// categories.package_config.targets.npm — the same file, and the same
	// category→target shape, as every other lane. The npm category gets NO file of
	// its own: this asserts the record's location on disk, and that reconciling npm
	// creates that one file and nothing else beside it (a lock artifact aside — it
	// carries no state).
	w := &fakeWriter{}
	st := newNPMStore(t)
	r, _ := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM); !ok {
		t.Fatal("the npm record must be readable through the shared accessors")
	}

	raw, err := os.ReadFile(st.path)
	if err != nil {
		t.Fatalf("reading %s: %v", CacheFilename, err)
	}
	var f AppliedStateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("on-disk file is not an AppliedStateFile: %v (%s)", err, raw)
	}
	if f.SchemaVersion != CacheSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", f.SchemaVersion, CacheSchemaVersion)
	}
	rec, ok := f.Categories[CategoryPackageConfig].Targets[TargetNPM]
	if !ok {
		t.Fatalf("categories.%s.targets.%s missing: %s", CategoryPackageConfig, TargetNPM, raw)
	}
	if rec.WrittenSettings[NPMOwnedKey] != npmRendered {
		t.Fatalf("record = %+v, want the rendered block under %s", rec, NPMOwnedKey)
	}

	// One JSON state file in the directory, whatever else the run leaves behind.
	entries, err := os.ReadDir(filepath.Dir(st.path))
	if err != nil {
		t.Fatal(err)
	}
	var jsonFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			jsonFiles = append(jsonFiles, e.Name())
		}
	}
	if len(jsonFiles) != 1 || jsonFiles[0] != CacheFilename {
		t.Fatalf("state directory holds %v, want only %s", jsonFiles, CacheFilename)
	}
}

func TestSeamFallbacksMatchIDEBehavior(t *testing.T) {
	// Every seam at its zero value must reproduce the settings.json behavior — the
	// fallbacks the IDE wiring relies on (it sets none of the seams). This pins the
	// nil-seam contract directly, next to the reconcile_test.go path that exercises
	// it end to end.
	r := &Reconciler{}

	// renderValue → compacted policy JSON, not a rendered block.
	got, err := r.renderValue(json.RawMessage(samplePolicyWire))
	if err != nil || got != samplePolicy {
		t.Fatalf("renderValue fallback = %q err=%v, want %q", got, err, samplePolicy)
	}

	// converged → plain body equality over the already-read value.
	if ok, _ := r.converged("v", "v", true); !ok {
		t.Fatal("converged fallback must be true when present and body-equal")
	}
	if ok, _ := r.converged("v", "v", false); ok {
		t.Fatal("converged fallback must be false when not present")
	}
	if ok, _ := r.converged("v", "other", true); ok {
		t.Fatal("converged fallback must be false when the body differs")
	}

	// classifyReadError → verification_failed for a plain error (the IDE writer
	// never wraps ErrTargetUnusable); write_failed only for the structural sentinel.
	if s := classifyReadError(errors.New("plain")); s != StateVerificationFailed {
		t.Fatalf("classifyReadError(plain) = %q, want verification_failed", s)
	}
	if s := classifyReadError(fmt.Errorf("x: %w", ErrTargetUnusable)); s != StateWriteFailed {
		t.Fatalf("classifyReadError(unusable) = %q, want write_failed", s)
	}

	// classifyWriteError → write_failed by default (the IDE writer never returns the
	// unverified-rollback sentinel); verification_failed only for ErrWriteUnverified.
	if s := classifyWriteError(errors.New("plain")); s != StateWriteFailed {
		t.Fatalf("classifyWriteError(plain) = %q, want write_failed", s)
	}
	if s := classifyWriteError(fmt.Errorf("x: %w", ErrWriteUnverified)); s != StateVerificationFailed {
		t.Fatalf("classifyWriteError(unverified) = %q, want verification_failed", s)
	}
}

// ---------------------------------------------------------------------------
// enforcement channel fork (npm): dmg writes, mdm verifies only
// ---------------------------------------------------------------------------

// npmObservedFake is the observed bag a wired ProbeContentNPM would return. Built
// here rather than imported from the probe so a change to the real probe's shape
// shows up as a wiring test failure, not silently.
func npmObservedFake() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		observedKeyEcosystem:       json.RawMessage(`"npm"`),
		observedKeyRegistryURL:     json.RawMessage(`"https://npm.pkg.example/javascript"`),
		observedKeyAuthTokenStatus: json.RawMessage(`"match"`),
	}
}

func npmSettingsObservedFake(status string) map[string]json.RawMessage {
	observed := npmObservedFake()
	observed[observedKeySettingsStatus] = json.RawMessage(`"` + status + `"`)
	return observed
}

// npmMDMEP is an npm policy directive on the verify-only channel.
func npmMDMEP(hash string) EffectivePolicy {
	ep := npmPolicyEP(hash)
	ep.Enforcement = "mdm"
	return ep
}

func TestNPMDMGChannelStillWrites(t *testing.T) {
	// The explicit "dmg" channel and an absent one are the same write-and-verify
	// path: the fork must not change the DMG lane the rest of this file covers.
	for _, channel := range []string{"", "dmg", "DMG", "  dmg  ", "wat"} {
		t.Run("channel="+channel, func(t *testing.T) {
			w := &fakeWriter{}
			st := newNPMStore(t)
			ep := npmPolicyEP("sha256:N")
			ep.Enforcement = channel
			r, rep := newNPMRec(t, ep, w, st)
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if len(w.writes) != 1 || w.writes[0] != npmRendered {
				t.Fatalf("the dmg lane must write the rendered block once, got %v", w.writes)
			}
			// An unrecognized channel resolves to dmg and REPORTS dmg, so the
			// backend's exact-match gate sees the channel that actually ran.
			if got := lastReport(t, rep).EvaluatedEnforcement; got != enforcementDMG {
				t.Fatalf("evaluated_enforcement = %q, want %q", got, enforcementDMG)
			}
		})
	}
}

func TestNPMMDMChannelVerifiesAndNeverWrites(t *testing.T) {
	w := &fakeWriter{}
	st := newNPMStore(t)
	r, rep := newNPMRec(t, npmMDMEP("sha256:N"), w, st)
	r.ProbeContent = func(expected string) (bool, map[string]json.RawMessage, error) {
		// verifyMDM renders the desired value FIRST and hands it over — the npm probe
		// needs it to decide auth_token_status on-device.
		if expected != npmRendered {
			t.Fatalf("probe expected = %q, want the rendered block %q", expected, npmRendered)
		}
		return true, npmObservedFake(), nil
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	rec := lastReport(t, rep)
	if rec.State != StateMDMManaged {
		t.Fatalf("state = %q, want %q", rec.State, StateMDMManaged)
	}
	if rec.EvaluatedEnforcement != enforcementMDM {
		t.Fatalf("evaluated_enforcement = %q, want %q", rec.EvaluatedEnforcement, enforcementMDM)
	}
	// The agent applied nothing, so it must claim nothing.
	if rec.AppliedHash != "" {
		t.Fatalf("applied_hash = %q, want empty in mdm mode", rec.AppliedHash)
	}
	if rec.EvaluatedHash != "sha256:N" {
		t.Fatalf("evaluated_hash = %q, want sha256:N", rec.EvaluatedHash)
	}
	var observed map[string]json.RawMessage
	if err := json.Unmarshal(rec.Observed, &observed); err != nil {
		t.Fatalf("observed is not a JSON object: %v (%s)", err, rec.Observed)
	}
	if len(observed) != 3 || string(observed[observedKeyAuthTokenStatus]) != `"match"` {
		t.Fatalf("observed = %s, want the three-key bag", rec.Observed)
	}
	// MDM owns nothing on disk: no write, no clear, no read, and the ownership
	// store is never touched.
	if len(w.writes) != 0 || w.clears != 0 || w.reads != 0 {
		t.Fatalf("mdm mode touched the writer: writes=%v clears=%d reads=%d", w.writes, w.clears, w.reads)
	}
	if st.writes != 0 || st.drops != 0 {
		t.Fatalf("mdm mode touched the state store: writes=%d drops=%d", st.writes, st.drops)
	}
	// Nothing was recorded, so the state file was never even created.
	if st.exists() {
		t.Fatal("mdm mode must not create the state file — it owns nothing to record")
	}
}

func TestNPMMDMChannelReportsAggregateSettingsStatus(t *testing.T) {
	w := &fakeWriter{}
	r, rep := newNPMRec(t, npmMDMEP("sha256:N"), w, newNPMStore(t))
	r.Render = func(json.RawMessage) (string, error) { return stdSettingsBody, nil }
	r.ProbeContent = func(expected string) (bool, map[string]json.RawMessage, error) {
		if expected != stdSettingsBody {
			t.Fatalf("expected = %q, want settings body", expected)
		}
		return true, npmSettingsObservedFake(settingsMismatch), nil
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	report := lastReport(t, rep)
	if report.State != StateMDMManaged {
		t.Fatalf("state = %q, want %q", report.State, StateMDMManaged)
	}
	var observed map[string]json.RawMessage
	if err := json.Unmarshal(report.Observed, &observed); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 4 {
		t.Fatalf("observed key count = %d, want 4", len(observed))
	}
	if string(observed[observedKeySettingsStatus]) != `"mismatch"` {
		t.Fatalf("settings_status = %s, want mismatch", observed[observedKeySettingsStatus])
	}
	for _, sensitive := range []string{"save-exact", "EXAMPLE_NPM_TOKEN", "engine-strict"} {
		if strings.Contains(string(report.Observed), sensitive) {
			t.Fatalf("report contains %q: %s", sensitive, report.Observed)
		}
	}
	if len(w.writes) != 0 {
		t.Fatalf("MDM observation wrote through the writer: %v", w.writes)
	}
	if w.clears != 0 {
		t.Fatalf("MDM observation clear count = %d, want 0", w.clears)
	}
	if w.reads != 0 {
		t.Fatalf("MDM observation read count = %d, want 0", w.reads)
	}
}

func TestNPMMDMChannelStatesFromProbe(t *testing.T) {
	cases := []struct {
		name    string
		probe   func(string) (bool, map[string]json.RawMessage, error)
		state   string
		wantObs bool
	}{
		{
			name:    "marker present → mdm_managed with observed",
			probe:   func(string) (bool, map[string]json.RawMessage, error) { return true, npmObservedFake(), nil },
			state:   StateMDMManaged,
			wantObs: true,
		},
		{
			name:  "no marker → policy_not_applied, no observed",
			probe: func(string) (bool, map[string]json.RawMessage, error) { return false, nil, nil },
			state: StatePolicyNotApplied,
		},
		{
			name: "unreadable/malformed → verification_failed, no observed",
			probe: func(string) (bool, map[string]json.RawMessage, error) {
				return false, nil, errors.New("npmrc: file contains an INI section header")
			},
			state: StateVerificationFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{}
			r, rep := newNPMRec(t, npmMDMEP("sha256:N"), w, newNPMStore(t))
			r.ProbeContent = tc.probe
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			rec := lastReport(t, rep)
			if rec.State != tc.state {
				t.Fatalf("state = %q, want %q", rec.State, tc.state)
			}
			if rec.EvaluatedEnforcement != enforcementMDM {
				t.Fatalf("evaluated_enforcement = %q, want %q", rec.EvaluatedEnforcement, enforcementMDM)
			}
			if gotObs := len(rec.Observed) > 0; gotObs != tc.wantObs {
				t.Fatalf("observed present = %v, want %v (%s)", gotObs, tc.wantObs, rec.Observed)
			}
			if len(w.writes) != 0 || w.clears != 0 {
				t.Fatalf("mdm mode must not touch the writer, got writes=%v clears=%d", w.writes, w.clears)
			}
		})
	}
}

func TestNPMMDMChannelRenderFailureIsVerificationFailed(t *testing.T) {
	// In MDM mode a policy the renderer rejects means there is no desired value to
	// verify against, so nothing could be checked — verification_failed, not the
	// DMG lane's policy_not_applied (which asserts a failed APPLY).
	w := &fakeWriter{}
	r, rep := newNPMRec(t, npmMDMEP("sha256:N"), w, newNPMStore(t))
	r.Render = func(json.RawMessage) (string, error) { return "", errors.New("bad policy") }
	probed := false
	r.ProbeContent = func(string) (bool, map[string]json.RawMessage, error) {
		probed = true
		return true, npmObservedFake(), nil
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := lastReport(t, rep).State; got != StateVerificationFailed {
		t.Fatalf("state = %q, want %q", got, StateVerificationFailed)
	}
	if probed {
		t.Fatal("the probe must not run without a desired value to compare against")
	}
	if len(w.writes) != 0 {
		t.Fatalf("mdm mode must never write, got %v", w.writes)
	}
}

func TestNPMMDMChannelClearIsANoOp(t *testing.T) {
	// enforcement=mdm + clear: the MDM lane owns nothing the agent could remove, and
	// there is nothing to verify either. No write, no clear, no state change, and no
	// report (an unassigned device is backend-derived).
	w := &fakeWriter{}
	st := newNPMStore(t).seed(t, CategoryPackageConfig, TargetNPM,
		AppliedTargetState{AppliedHash: "sha256:OLD", WrittenSettings: npmOwnRec(npmRendered)})
	ep := npmMDMEP("")
	ep.Clear = true
	ep.Policy = nil
	r, rep := newNPMRec(t, ep, w, st)
	r.ProbeContent = func(string) (bool, map[string]json.RawMessage, error) {
		t.Fatal("a clear directive must not reach the probe")
		return false, nil, nil
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(rep.reports) != 0 {
		t.Fatalf("mdm clear must not report, got %+v", rep.reports)
	}
	if len(w.writes) != 0 || w.clears != 0 {
		t.Fatalf("mdm clear must not touch the writer, got writes=%v clears=%d", w.writes, w.clears)
	}
	if _, ok := st.get(CategoryPackageConfig, TargetNPM); !ok {
		t.Fatal("mdm clear must leave the ownership record alone — it owns nothing to drop")
	}
}

func TestNPMMDMChannelRunsWithNoWriter(t *testing.T) {
	// The MDM fork sits ABOVE the writer gates, so a cycle with no constructible
	// writer still verifies and reports — the DMG lane's handleNoWriter
	// classification must not swallow it.
	st := newNPMStore(t)
	r, rep := newNPMRec(t, npmMDMEP("sha256:N"), nil, st)
	r.Writer = nil
	r.Converged = nil
	r.RestoreSnapshot = nil
	r.WriterInitErr = fmt.Errorf("resolve target user: %w", ErrNoTargetUser)
	r.ProbeContent = func(string) (bool, map[string]json.RawMessage, error) { return true, npmObservedFake(), nil }
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	rec := lastReport(t, rep)
	if rec.State != StateMDMManaged || rec.EvaluatedEnforcement != enforcementMDM {
		t.Fatalf("report = %+v, want mdm_managed on the mdm channel", rec)
	}
}

func TestNPMMDMChannelNoProbeSeamIsVerificationFailed(t *testing.T) {
	// The category-aware fallback. ProbeContent is nil whenever the writer could not
	// be constructed (it is bound off the writer), and the generic default probes VS
	// CODE policy locations — which for an npm category would report another
	// category's policy. A non-ide category with no seam must error instead.
	//
	// verification_failed is the discriminating outcome: had it fallen through to
	// ProbeManagedContent, a machine with no VS Code policy would have answered
	// present=false and reported the clean policy_not_applied.
	st := newNPMStore(t)
	r, rep := newNPMRec(t, npmMDMEP("sha256:N"), nil, st)
	r.Writer = nil
	r.Converged = nil
	r.RestoreSnapshot = nil
	r.WriterInitErr = fmt.Errorf("resolve target user: %w", ErrNoTargetUser)
	r.ProbeContent = nil
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	rec := lastReport(t, rep)
	if rec.State != StateVerificationFailed {
		t.Fatalf("state = %q, want %q (never a VS Code probe for an npm category)", rec.State, StateVerificationFailed)
	}
	if len(rec.Observed) != 0 {
		t.Fatalf("a failed verification must carry no observed bag, got %s", rec.Observed)
	}
}

func TestIDEMDMChannelKeepsItsDefaultProbe(t *testing.T) {
	// The mirror of the case above: for ide_extension the nil-seam fallback is still
	// ProbeManagedContent, so making the fallback category-aware must not have
	// changed the VS Code lane. probe_other/darwin/linux/windows all answer for a
	// machine with no managed policy, so this asserts the clean not-applied outcome
	// rather than the npm error.
	withTempCache(t)
	rep := &fakeReporter{}
	r := &Reconciler{
		Fetcher:    &fakeFetcher{ep: func() EffectivePolicy { ep := policyEP("sha256:H"); ep.Enforcement = "mdm"; return ep }()},
		Reporter:   rep,
		Writer:     &fakeWriter{},
		CustomerID: "cust",
		DeviceID:   "dev-1",
		Platform:   "linux",
		Now:        func() time.Time { return time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC) },
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := lastReport(t, rep)
	if got.State != StatePolicyNotApplied && got.State != StateMDMManaged {
		t.Fatalf("state = %q, want the OS probe's verdict (policy_not_applied or mdm_managed), not an error", got.State)
	}
	if got.EvaluatedHash != "" {
		t.Fatalf("evaluated_hash = %q, want empty for ide_extension", got.EvaluatedHash)
	}
}

// ---------------------------------------------------------------------------
// Cache collapse: one WrittenSettings entry drives the whole npm DMG lifecycle
// ---------------------------------------------------------------------------

func TestNPMOwnershipLifecycleThroughWrittenSettings(t *testing.T) {
	// The collapse of the retired single-value WrittenValue field into one
	// WrittenSettings entry must leave the npm DMG lane behaving identically:
	// enforce records ownership, a hand-edit is detected as drift and converged
	// back, and clear removes the block by marker and drops the record — all of it
	// against the one shared state file, under package_config/npm.
	w := &fakeWriter{}
	st := newNPMStore(t)
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	// Converged mirrors the writer: the block is in place iff the last write stands.
	r.Converged = func(expected string) (bool, error) { return w.present && w.value == expected, nil }

	// 1. Enforce → the block is written and ownership recorded under NPMOwnedKey.
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	rec, ok := st.get(CategoryPackageConfig, TargetNPM)
	if !ok || len(rec.WrittenSettings) != 1 || rec.WrittenSettings[NPMOwnedKey] != npmRendered {
		t.Fatalf("ownership = %+v, want exactly one %s entry", rec.WrittenSettings, NPMOwnedKey)
	}
	if got := lastReport(t, rep).State; got != StateCompliant {
		t.Fatalf("first enforce state = %q, want compliant", got)
	}

	// 2. Hand-edit the file, then re-enforce with the SAME hash. The recorded entry
	// no longer matches disk → drift, converged back in the same cycle.
	w.value, w.present = "registry=https://hand-edited.example/", true
	rep.reports = nil
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("re-enforce after hand-edit: %v", err)
	}
	if got := lastReport(t, rep).State; got != StateDriftDetected {
		t.Fatalf("state after hand-edit = %q, want drift_detected", got)
	}
	if len(w.writes) != 2 || w.writes[1] != npmRendered {
		t.Fatalf("drift must re-apply the rendered block, got %v", w.writes)
	}
	if rec, _ := st.get(CategoryPackageConfig, TargetNPM); rec.WrittenSettings[NPMOwnedKey] != npmRendered {
		t.Fatalf("ownership after drift = %+v, want the re-applied block", rec.WrittenSettings)
	}

	// 3. A third cycle with the block intact is idempotent — no write, still
	// compliant (not drift): the ownership entry now agrees with disk.
	rep.reports = nil
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("idempotent cycle: %v", err)
	}
	if len(w.writes) != 2 {
		t.Fatalf("a converged cycle must not write, got %v", w.writes)
	}
	if got := lastReport(t, rep).State; got != StateCompliant {
		t.Fatalf("idempotent state = %q, want compliant", got)
	}

	// 4. Clear → marker-based, so the block goes and the record is dropped
	// unconditionally (clear never consults the ownership entry).
	clearEP := npmPolicyEP("")
	clearEP.Clear = true
	clearEP.Policy = nil
	r.Fetcher = &fakeFetcher{ep: clearEP}
	rep.reports = nil
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if w.clears != 1 {
		t.Fatalf("clear must remove the block, clears=%d", w.clears)
	}
	if _, ok := st.get(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("clear must drop the ownership record")
	}
	if len(rep.reports) != 0 {
		t.Fatalf("clear must not report (backend-derived), got %+v", rep.reports)
	}
}

func TestNPMEnforceIgnoresForeignOwnershipKeys(t *testing.T) {
	// The npm lane reads and writes exactly its own WrittenSettings key. A record
	// carrying only some other lane's key means "this lane owns nothing", so an
	// unconverged file is a plain first enforce — NOT drift (drift asserts the agent's
	// own value was changed) — and the post-write persist records the npm key alone,
	// never inheriting the foreign one.
	w := &fakeWriter{}
	st := newNPMStore(t).seed(t, CategoryPackageConfig, TargetNPM, AppliedTargetState{
		AppliedHash:     "sha256:N",
		WrittenSettings: map[string]string{allowedExtensionsSettingKey: "not-ours"},
	})
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := lastReport(t, rep).State; got != StateCompliant {
		t.Fatalf("state = %q, want compliant (a foreign key is not npm drift)", got)
	}
	rec, _ := st.get(CategoryPackageConfig, TargetNPM)
	if len(rec.WrittenSettings) != 1 || rec.WrittenSettings[NPMOwnedKey] != npmRendered {
		t.Fatalf("ownership = %+v, want only the npm entry recorded", rec.WrittenSettings)
	}
}

// ---------------------------------------------------------------------------
// Secret hygiene
// ---------------------------------------------------------------------------

func TestNPMNeverLogsOrReportsTheToken(t *testing.T) {
	// The rendered block carries the device token, and the reconciler handles it on
	// every rung (render → probe → write → ownership → report). None of the api_key,
	// the composed token, or the serial may reach a log line or any report field.
	const apiKey = "ssSECRETKEY123"
	const serial = "SERIAL-ABC"
	const rendered = "registry=https://t.registry.stepsecurity.io/javascript\n" +
		"//t.registry.stepsecurity.io/javascript/:_authToken=" + apiKey + "::dev:" + serial

	var logged strings.Builder
	run := func(channel string, probe func(string) (bool, map[string]json.RawMessage, error)) {
		w := &fakeWriter{}
		ep := npmPolicyEP("sha256:N")
		ep.Enforcement = channel
		r, rep := newNPMRec(t, ep, w, newNPMStore(t))
		r.Render = func(json.RawMessage) (string, error) { return rendered, nil }
		r.Converged = func(expected string) (bool, error) { return w.present && w.value == expected, nil }
		r.ProbeContent = probe
		r.Logf = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&logged, format+"\n", args...)
		}
		if err := r.Reconcile(context.Background()); err != nil {
			t.Fatalf("channel %q: %v", channel, err)
		}
		for _, got := range rep.reports {
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{apiKey, apiKey + "::dev:" + serial, serial} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("channel %q report leaks %q: %s", channel, secret, raw)
				}
			}
		}
	}

	// The DMG write lane handles the token most (render, write, ownership record)...
	run("dmg", nil)
	// ...and the MDM lane renders it to hand the tenant key to the probe.
	run("mdm", func(string) (bool, map[string]json.RawMessage, error) { return true, npmObservedFake(), nil })

	for _, secret := range []string{apiKey, apiKey + "::dev:" + serial, serial} {
		if strings.Contains(logged.String(), secret) {
			t.Fatalf("logs leak %q:\n%s", secret, logged.String())
		}
	}
	if logged.Len() == 0 {
		t.Fatal("the test proved nothing — no log lines were captured")
	}
}

func TestNPMSettingsOnlyDMGReportCarriesSettingsStatusOnly(t *testing.T) {
	w := &fakeWriter{}
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, newNPMStore(t))
	r.Render = func(json.RawMessage) (string, error) { return stdSettingsOnlyBody, nil }
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := lastReport(t, rep)
	if got.State != StateCompliant {
		t.Fatalf("state = %q, want %q", got.State, StateCompliant)
	}
	var observed map[string]json.RawMessage
	if err := json.Unmarshal(got.Observed, &observed); err != nil {
		t.Fatalf("observed is not a JSON object: %v (%s)", err, got.Observed)
	}
	if len(observed) != 2 || string(observed[observedKeyEcosystem]) != `"npm"` || string(observed[observedKeySettingsStatus]) != `"match"` {
		t.Fatalf("observed = %s, want ecosystem and settings_status only", got.Observed)
	}
	for _, sensitive := range []string{"packages.example.com", "EXAMPLE_NPM_TOKEN", "save-exact"} {
		if strings.Contains(string(got.Observed), sensitive) {
			t.Fatalf("report contains %q: %s", sensitive, got.Observed)
		}
	}
}
