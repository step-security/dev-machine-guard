package devicepolicy

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Reconciler converges the user-scope VS Code settings.json to the backend's
// effective policy for one device, once per scheduled cycle. It is OS-agnostic:
// the settings Writer, the managed-policy Probe, the policy Fetcher, and the
// compliance Reporter are all injected, so the whole flow is fake-testable
// with no real I/O.
type Reconciler struct {
	Fetcher  Fetcher
	Reporter Reporter
	// Writer is the settings.json writer, or nil when the platform has no
	// resolvable settings path. A nil Writer makes Reconcile a no-op.
	Writer Writer

	CustomerID string
	DeviceID   string
	Platform   string // reported in compliance; e.g. "windows", "linux", "darwin"
	Category   string // defaults to ide_extension
	Target     string // defaults to vscode

	// Probe reports whether a real MDM/admin-managed AllowedExtensions policy
	// exists at this OS's policy location (registry / policy.json / managed
	// preferences). Such a policy outranks user settings inside VS Code, so the
	// agent yields (mdm_managed) instead of writing a value VS Code would
	// ignore. nil → ProbeManagedPolicy (the per-OS implementation); tests
	// inject a stub so results never depend on the host machine.
	Probe func() (managed bool, detail string)

	// Now and Logf are optional seams. Now defaults to time.Now().UTC; Logf to a
	// no-op.
	Now  func() time.Time
	Logf func(format string, args ...any)

	// writeState and clearState are test seams over the ownership store
	// (WriteAppliedState / ClearAppliedState). nil → the real implementation.
	writeState func(category, target string, s AppliedTargetState) error
	clearState func(category, target string) error
}

func (r *Reconciler) persistState(cat, tgt string, s AppliedTargetState) error {
	if r.writeState != nil {
		return r.writeState(cat, tgt, s)
	}
	return WriteAppliedState(cat, tgt, s)
}

func (r *Reconciler) dropState(cat, tgt string) error {
	if r.clearState != nil {
		return r.clearState(cat, tgt)
	}
	return ClearAppliedState(cat, tgt)
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func (r *Reconciler) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *Reconciler) category() string {
	if r.Category != "" {
		return r.Category
	}
	return CategoryIDEExtension
}

func (r *Reconciler) target() string {
	if r.Target != "" {
		return r.Target
	}
	return TargetVSCode
}

func (r *Reconciler) probe() (bool, string) {
	if r.Probe != nil {
		return r.Probe()
	}
	return ProbeManagedPolicy()
}

// Reconcile runs one enforcement cycle. It NEVER panics into the caller's hot
// path; failures are returned for logging. The contract:
//
//   - fetch error (transport / non-200 / malformed) → NO-OP, error returned.
//     Enforcement on disk is never wiped on a transient or malformed response.
//   - platform not enforceable (nil Writer) → silent no-op.
//   - absent policy (run-config carried no `policy` directive for this
//     category/target) → silent no-op; the on-disk value and ownership record
//     stand. This is NOT a clear — removal happens only on an explicit clear.
//   - clear result → remove ONLY the agent-owned settings key; a value the
//     agent has no record of writing is left untouched. No compliance report
//     (an unassigned device is backend-derived).
//   - policy result → probe → ownership/drift-checked write + readback +
//     verify + report (handleEnforce).
func (r *Reconciler) Reconcile(ctx context.Context) error {
	if r.Fetcher == nil {
		return errors.New("devicepolicy: nil fetcher")
	}
	cat := r.category()
	tgt := r.target()

	ep, err := r.Fetcher.Fetch(ctx, r.CustomerID, r.DeviceID, cat, tgt)
	if err != nil {
		// Malformed/transient: do nothing. The on-disk policy (if any) stands.
		return fmt.Errorf("devicepolicy: fetch: %w", err)
	}

	if r.Writer == nil {
		r.logf("devicepolicy: no settings path on this platform; skipping (category=%s target=%s)", cat, tgt)
		return nil
	}

	if !ep.present() {
		// Run-config carried no policy directive for this category/target — no value
		// to enforce and no explicit clear. Leave the on-disk value and ownership
		// record untouched; a transient drop must never wipe enforcement.
		r.logf("devicepolicy: run-config carried no policy for %s/%s; leaving on-disk state untouched", cat, tgt)
		return nil
	}

	if ep.Clear {
		return r.handleClear(cat, tgt)
	}
	return r.handleEnforce(ctx, cat, tgt, ep)
}

// handleClear removes the agent-owned settings key on unassignment. It clears
// the on-disk value ONLY when it still equals what the agent last wrote
// (ownership); a value the agent has no record of writing — the user's own
// extensions.allowed predates enforcement, or the record was lost — is left
// intact.
func (r *Reconciler) handleClear(cat, tgt string) error {
	prev, hadPrev := ReadAppliedState(cat, tgt)
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		return fmt.Errorf("devicepolicy: clear: read %s: %w", r.Writer.Location(), err)
	}

	owns := present && prev.WrittenValue != "" && onDisk == prev.WrittenValue
	switch {
	case owns:
		if err := r.Writer.Clear(); err != nil {
			return fmt.Errorf("devicepolicy: clear %s: %w", r.Writer.Location(), err)
		}
		r.logf("devicepolicy: cleared agent-owned policy at %s", r.Writer.Location())
	case present:
		// A value the agent did not write — leave it to whoever set it.
		r.logf("devicepolicy: clear requested but %s holds a value the agent did not write; leaving it", r.Writer.Location())
	}

	// Drop our ownership record whenever we hold an entry for this category.
	// Beyond the obvious case (we owned a value), this also reclaims an empty
	// record a preflight may have left after its settings write later failed.
	// An absent entry → no-op (idempotent).
	if hadPrev {
		if err := r.dropState(cat, tgt); err != nil {
			return fmt.Errorf("devicepolicy: clear: update state: %w", err)
		}
	}
	return nil
}

// handleEnforce converges settings.json to the compiled policy and reports.
// The ladder, in order:
//
//	probe (managed policy exists → mdm_managed, never write)
//	→ read current value
//	→ idempotency (hash unchanged ∧ on-disk converged → report, no write)
//	→ preflight ownership-store writability
//	→ drift detection (on-disk diverged from the recorded written value)
//	→ merge-write + readback
//	→ persist ownership on every successful write (rollback if that fails)
//	→ Verify → report (drift upgrades a would-be compliant to drift_detected)
func (r *Reconciler) handleEnforce(ctx context.Context, cat, tgt string, ep EffectivePolicy) error {
	// The compiled policy compacted: the canonical comparison form for
	// readback, idempotency, and ownership. (The backend's hash still travels
	// verbatim; only the value bytes are normalized for comparison.)
	newValue, err := compactJSON(ep.Policy)
	if err != nil {
		// Defensive: the fetcher already validated object shape, so this is a
		// malformed-payload class failure → no-op, never write.
		return fmt.Errorf("devicepolicy: enforce: compact policy: %w", err)
	}

	// 1. Managed-policy probe. A policy at the OS policy location outranks
	// user settings inside VS Code — writing would be ineffective at best and
	// fight the MDM at worst. Yield and report.
	if managed, detail := r.probe(); managed {
		r.logf("devicepolicy: managed policy present at %s → mdm_managed (yielding)", detail)
		return r.report(ctx, cat, tgt, StateMDMManaged, "")
	}

	// 2. Read the current settings value.
	prev, hadPrev := ReadAppliedState(cat, tgt)
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		// Couldn't read to decide idempotency/drift → verification_failed.
		// This includes an unsalvageable settings.json (not valid JSONC), which
		// the writer refuses to touch.
		_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
		return fmt.Errorf("devicepolicy: enforce: read %s: %w", r.Writer.Location(), err)
	}

	// 3. Idempotency: the desired policy is already in place and unchanged.
	// No write — but still report so the backend sees a fresh evaluation.
	if present && onDisk == newValue && prev.AppliedHash == ep.Hash {
		r.logf("devicepolicy: policy already applied (hash unchanged) — no write")
		return r.report(ctx, cat, tgt, StateCompliant, ep.Hash)
	}

	// 4. Drift: the agent wrote a value before, and what is on disk now is not
	// it (edited or removed — typically the user hand-editing settings.json).
	// Enforcement means converging it back; the distinct state lets the
	// backend surface that it happened.
	drifted := hadPrev && prev.WrittenValue != "" && (!present || onDisk != prev.WrittenValue)
	if drifted {
		r.logf("devicepolicy: %s diverged from the recorded written value → re-applying (drift)", r.Writer.Location())
	}

	// 5. Preflight: prove the ownership store is writable BEFORE mutating the
	// settings file. An enforced value with no ownership record is orphaned —
	// a later clear refuses to remove it. Re-persisting the current state is a
	// meaning-preserving writability probe.
	probe := prev
	if !hadPrev {
		probe = AppliedTargetState{FetchedAt: r.now()}
	}
	if perr := r.persistState(cat, tgt, probe); perr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: ownership state not writable, refusing to write policy: %w", perr)
	}

	// 6. Merge-write + readback.
	rb, werr := r.Writer.Write(newValue)
	if werr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: write %s: %w", r.Writer.Location(), werr)
	}
	readbackMatch := rb == newValue

	// 7. Ownership is recorded on EVERY successful write — it means "what the
	// agent wrote", not "what it verified". On a readback mismatch the write
	// may still have landed; without a record the next cycle would classify
	// the agent's own value as drift forever. Value-based ownership
	// self-corrects: the record only takes effect when the on-disk value
	// actually equals it.
	if err := r.persistState(cat, tgt, AppliedTargetState{
		AppliedHash:  ep.Hash,
		WrittenValue: newValue,
		FetchedAt:    r.now(),
	}); err != nil {
		// The write happened but ownership couldn't be recorded — undo it so
		// no unrecorded value is left behind, and report a failed write.
		r.rollbackWrite(onDisk, present)
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: update state: %w", err)
	}
	r.logf("devicepolicy: wrote policy to %s (readback_match=%v)", r.Writer.Location(), readbackMatch)

	state := Verify(VerifyInput{WriteOK: true, ReadbackMatch: readbackMatch})
	if drifted && state == StateCompliant {
		state = StateDriftDetected
	}

	// applied_hash is echoed only when we are confident the policy is applied
	// (readback-confirmed) — compliant, or drift_detected (drift that was
	// successfully re-applied). It is the backend's hash verbatim — never
	// recomputed — so the backend's byte-exact applied==desired check gates
	// `compliant`.
	appliedHash := ""
	if state == StateCompliant || state == StateDriftDetected {
		appliedHash = ep.Hash
	}
	return r.report(ctx, cat, tgt, state, appliedHash)
}

// rollbackWrite restores the settings key to its pre-cycle condition after the
// post-write ownership persist failed. WriteAppliedState is atomic
// (temp+rename), so the failed persist left the previous state file intact —
// restoring the previous on-disk value keeps record and disk consistent.
// Best-effort: a rollback failure is logged, and the divergence surfaces as
// drift on the next cycle.
func (r *Reconciler) rollbackWrite(prevOnDisk string, prevPresent bool) {
	var err error
	if prevPresent {
		_, err = r.Writer.Write(prevOnDisk)
	} else {
		err = r.Writer.Clear()
	}
	if err != nil {
		r.logf("devicepolicy: rollback at %s failed: %v", r.Writer.Location(), err)
	}
}

func (r *Reconciler) report(ctx context.Context, cat, tgt, state, appliedHash string) error {
	r.logf("devicepolicy: reporting state=%s category=%s target=%s", state, cat, tgt)
	if r.Reporter == nil {
		return nil
	}
	rep := ComplianceReport{
		Category:     cat,
		Target:       tgt,
		State:        state,
		AppliedHash:  appliedHash,
		AgentVersion: AgentVersion(),
		Platform:     r.Platform,
	}
	if err := r.Reporter.Report(ctx, r.CustomerID, r.DeviceID, rep); err != nil {
		return fmt.Errorf("devicepolicy: report %s: %w", state, err)
	}
	return nil
}
