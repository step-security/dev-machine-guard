package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The tests here drive the reconciler with the seams the ~/.npmrc path sets
// (Render, Converged, ProbeExpected, RestoreSnapshot, OwnsByMarker, State). The
// existing reconcile_test.go covers the settings.json path with every seam at
// its zero value; together they show the ladder serves both targets from one
// body — the seams change behavior ONLY when set.

// --- in-memory StateStore fake ---------------------------------------------

// memStateStore is an in-memory StateStore for the npm reconcile tests. The npm
// category always drives ownership through the State seam (never the shared
// package-level cache), so these tests inject this instead of using
// withTempCache. It counts calls so a test can assert the ladder routed through
// the store, and failWriteFrom forces the post-write persist to fail.
type memStateStore struct {
	m             map[string]AppliedTargetState
	writeErr      error
	dropErr       error
	failWriteFrom int // when >0, Write errors on the Nth call and after
	writes        int
	drops         int
	reads         int
}

func msKey(cat, tgt string) string { return cat + "\x00" + tgt }

func (s *memStateStore) Read(cat, tgt string) (AppliedTargetState, bool) {
	s.reads++
	st, ok := s.m[msKey(cat, tgt)]
	return st, ok
}

func (s *memStateStore) Write(cat, tgt string, st AppliedTargetState) error {
	s.writes++
	if s.failWriteFrom > 0 && s.writes >= s.failWriteFrom {
		return errors.New("state store write failed")
	}
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.m == nil {
		s.m = map[string]AppliedTargetState{}
	}
	s.m[msKey(cat, tgt)] = st
	return nil
}

func (s *memStateStore) Drop(cat, tgt string) error {
	s.drops++
	if s.dropErr != nil {
		return s.dropErr
	}
	delete(s.m, msKey(cat, tgt))
	return nil
}

func (s *memStateStore) get(cat, tgt string) (AppliedTargetState, bool) {
	st, ok := s.m[msKey(cat, tgt)]
	return st, ok
}

// --- npm fixtures -----------------------------------------------------------

// npmPolicyWire stands in for the fetched npm policy payload (passed verbatim to
// the Render seam). npmRendered is what the fake renderer turns it into — the
// value the reconciler writes and compares, standing in for the two managed
// content lines RenderNPMRCBlock produces.
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

// newNPMRec builds a marker-owned, State-backed reconciler wired like the
// ~/.npmrc path: OwnsByMarker, a Render seam that produces the managed block, a
// content-aware ProbeExpected, and a Converged seam. Defaults: Render → the
// fixed block, probe → not managed, Converged → false (proceed to write). Tests
// override a single seam to exercise one rung. No withTempCache — State routes
// every ownership access away from the shared file.
func newNPMRec(t *testing.T, ep EffectivePolicy, w *fakeWriter, st *memStateStore) (*Reconciler, *fakeReporter) {
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
		State:         st,
		Render:        npmRenderOK,
		ProbeExpected: func(string) (bool, string) { return false, "" },
		Converged:     func(string) (bool, error) { return false, nil },
		Now:           func() time.Time { return time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC) },
	}
	return r, rep
}

// --- tests ------------------------------------------------------------------

func TestNPMEnforceRendersBlockAndWrites(t *testing.T) {
	w := &fakeWriter{}
	st := &memStateStore{}
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
	// Ownership recorded through the State seam (never the shared file).
	if st.writes == 0 {
		t.Fatal("ownership must be recorded through the State seam")
	}
	rec, ok := st.get(CategoryPackageConfig, TargetNPM)
	if !ok || rec.WrittenValue != npmRendered || rec.AppliedHash != "sha256:N" {
		t.Fatalf("state record = %+v ok=%v, want the rendered block + hash", rec, ok)
	}
}

func TestNPMRenderFailureReportsPolicyNotApplied(t *testing.T) {
	// A malformed npm policy the renderer rejects: nothing is applied and the
	// cycle reports policy_not_applied (not a silent no-op). Render runs FIRST, so
	// the writer is never read or written and the probe never runs.
	w := &fakeWriter{}
	st := &memStateStore{}
	r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	probed := false
	r.ProbeExpected = func(string) (bool, string) { probed = true; return false, "" }
	r.Render = func(json.RawMessage) (string, error) { return "", errors.New("policy missing registry") }
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("a render failure must surface an error")
	}
	if w.reads != 0 || len(w.writes) != 0 || w.clears != 0 || probed {
		t.Fatalf("render failure must touch nothing: reads=%d writes=%v clears=%d probed=%v",
			w.reads, w.writes, w.clears, probed)
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
	st := &memStateStore{}
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
	st := &memStateStore{m: map[string]AppliedTargetState{
		msKey(CategoryPackageConfig, TargetNPM): {AppliedHash: "sha256:N", WrittenValue: npmRendered},
	}}
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
	st := &memStateStore{m: map[string]AppliedTargetState{
		msKey(CategoryPackageConfig, TargetNPM): {AppliedHash: "sha256:N", WrittenValue: npmRendered},
	}}
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
	// Cross-mode store split: the exact block is fully applied on disk
	// (Converged=true) but THIS store carries no matching hash — the other
	// privilege mode applied and recorded it in its own per-mode store, or our
	// record is stale. The reconciler must adopt the on-disk state (no rewrite, no
	// false drift) and report compliant, recording the current hash for next cycle.
	cases := []struct {
		name string
		st   *memStateStore
	}{
		{"empty store (other mode applied)", &memStateStore{}},
		{"stale hash in store", &memStateStore{m: map[string]AppliedTargetState{
			msKey(CategoryPackageConfig, TargetNPM): {AppliedHash: "sha256:OLD", WrittenValue: npmRendered},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{value: npmRendered, present: true}
			r, rep := newNPMRec(t, npmPolicyEP("sha256:NEW"), w, tc.st)
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
			rec, ok := tc.st.get(CategoryPackageConfig, TargetNPM)
			if !ok || rec.AppliedHash != "sha256:NEW" || rec.WrittenValue != npmRendered {
				t.Fatalf("state not adopted: rec=%+v ok=%v", rec, ok)
			}
		})
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
			st := &memStateStore{}
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
			st := &memStateStore{}
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
		st   *memStateStore
	}{
		{"no record", &memStateStore{}},
		{"stale record", &memStateStore{m: map[string]AppliedTargetState{
			msKey(CategoryPackageConfig, TargetNPM): {WrittenValue: "old-block"},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{value: "a-managed-block", present: true}
			ep := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetNPM, Clear: true}
			r, rep := newNPMRec(t, ep, w, tc.st)
			if err := r.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if w.clears != 1 {
				t.Fatalf("marker clear must call Clear exactly once, clears=%d", w.clears)
			}
			if w.reads != 0 {
				t.Fatalf("marker clear must not read the file, reads=%d", w.reads)
			}
			if tc.st.drops != 1 {
				t.Fatalf("marker clear must Drop the record unconditionally, drops=%d", tc.st.drops)
			}
			if _, ok := tc.st.get(CategoryPackageConfig, TargetNPM); ok {
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
			st := &memStateStore{failWriteFrom: 2} // preflight ok, post-write persist fails
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
			st := &memStateStore{}
			r, rep := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
			if err := r.Reconcile(context.Background()); err == nil {
				t.Fatal("a write error must surface")
			}
			if len(w.writes) != 1 {
				t.Fatalf("Write should have been attempted once, got %v", w.writes)
			}
			if got := lastReport(t, rep); got.State != tc.state {
				t.Fatalf("state = %q, want %q", got.State, tc.state)
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
			}
		})
	}
}

func TestNPMStateRoutingBypassesSharedFile(t *testing.T) {
	// With the State seam set, every ownership access routes to the injected store;
	// the shared device-policy-state.json is never created or read. This keeps the
	// npm record out of the shared file's unlocked read-modify-write.
	path := filepath.Join(t.TempDir(), CacheFilename)
	restore := SetCachePathForTest(path)
	defer restore()

	w := &fakeWriter{}
	st := &memStateStore{}
	r, _ := newNPMRec(t, npmPolicyEP("sha256:N"), w, st)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if st.writes == 0 {
		t.Fatal("ownership must have routed through the State seam")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("shared state file must never be created when State is set; stat err = %v", err)
	}
	if _, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("shared store must hold no npm record")
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
