package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// enforcementDMG and enforcementMDM are the enforcement channels carried in
// ep.Enforcement. DMG (or empty) is the write-and-verify path; MDM is
// verify-only — the agent probes the OS-managed policy and reports what it
// observed, and never writes, patches, or clears settings.json.
const (
	enforcementDMG = "dmg"
	enforcementMDM = "mdm"
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

	// ProbeContent reads the OS-managed VS Code policy values (keyed by setting
	// id) for the verify-only path. nil → ProbeManagedContent (the per-OS
	// implementation); tests inject a stub. The DMG path never calls it.
	ProbeContent func() (present bool, observed map[string]json.RawMessage, err error)

	// Now and Logf are optional seams. Now defaults to time.Now().UTC; Logf to a
	// no-op.
	Now  func() time.Time
	Logf func(format string, args ...any)

	// writeState and clearState are test seams over the ownership store
	// (WriteAppliedState / ClearAppliedState). nil → the real implementation.
	writeState func(category, target string, s AppliedTargetState) error
	clearState func(category, target string) error

	// enforcement is the normalized channel the current cycle ran (lower-cased,
	// trimmed ep.Enforcement), stamped onto every report as EvaluatedEnforcement
	// so it matches the backend's exact-match gate. Per-cycle scratch.
	enforcement string
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

func (r *Reconciler) probeContent() (bool, map[string]json.RawMessage, error) {
	if r.ProbeContent != nil {
		return r.ProbeContent()
	}
	return ProbeManagedContent()
}

// Reconcile runs one enforcement cycle. It NEVER panics into the caller's hot
// path; failures are returned for logging. The contract:
//
//   - fetch error (transport / non-200 / malformed) → NO-OP, error returned.
//     Enforcement on disk is never wiped on a transient or malformed response.
//   - MDM enforcement (ep.Enforcement=="mdm") → verify-only: probe the OS-managed
//     policy and report what was observed; never writes or clears settings.json.
//     Checked right after fetch, before the gates below, so it runs even with a
//     nil Writer or a clear directive.
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
	// Normalize once for routing AND reporting: the backend gates on an exact
	// "mdm"/"dmg", so EvaluatedEnforcement must carry the canonical value, not
	// whatever casing/spacing arrived.
	r.enforcement = strings.ToLower(strings.TrimSpace(ep.Enforcement))

	// MDM is verify-only and owns nothing on disk, so it routes before the
	// Writer/clear checks below.
	switch r.enforcement {
	case enforcementMDM:
		return r.verifyMDM(ctx, cat, tgt, ep)
	case enforcementDMG, "":
	default:
		r.logf("devicepolicy: unknown enforcement %q; running DMG path", ep.Enforcement)
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

// verifyMDM is the verify-only path: it never opens settings.json (an external
// MDM owns the VS Code policy), probes the OS-managed policy, and reports what
// it saw. It does not compare observed against ep.Policy or decide drift — the
// backend does that on read — and applied_hash is always empty.
func (r *Reconciler) verifyMDM(ctx context.Context, cat, tgt string, ep EffectivePolicy) error {
	if ep.Clear || !ep.present() {
		r.logf("devicepolicy: mdm enforcement with no active policy for %s/%s; nothing to verify", cat, tgt)
		return nil
	}

	present, observed, err := r.probeContent()
	if err != nil {
		r.logf("devicepolicy: mdm content probe failed: %v → verification_failed", err)
		return r.sendReport(ctx, ComplianceReport{Category: cat, Target: tgt, State: StateVerificationFailed})
	}

	if !present {
		r.logf("devicepolicy: mdm enforcement but no managed VS Code policy present → policy_not_applied")
		return r.sendReport(ctx, ComplianceReport{Category: cat, Target: tgt, State: StatePolicyNotApplied})
	}

	raw, err := json.Marshal(observed)
	if err != nil {
		// observed is built from our own parsers; a marshal failure is not expected.
		r.logf("devicepolicy: mdm marshal observed failed: %v → verification_failed", err)
		return r.sendReport(ctx, ComplianceReport{Category: cat, Target: tgt, State: StateVerificationFailed})
	}
	r.logf("devicepolicy: mdm managed policy present → mdm_managed (%d observed key(s))", len(observed))
	return r.sendReport(ctx, ComplianceReport{
		Category: cat,
		Target:   tgt,
		State:    StateMDMManaged,
		Observed: raw,
	})
}

// handleClear removes the agent-owned settings on unassignment, then drops the
// ownership record. It dispatches on the Writer: a managed multi-key writer
// clears each owned key independently (clearManaged); any other Writer keeps
// the single-key path (clearSingle). Both are ownership-gated: a value the
// agent has no record of writing is left intact.
func (r *Reconciler) handleClear(cat, tgt string) error {
	prev, hadPrev := ReadAppliedState(cat, tgt)
	if mw, ok := r.Writer.(managedSettingsWriter); ok {
		return r.clearManaged(cat, tgt, prev, hadPrev, mw)
	}
	return r.clearSingle(cat, tgt, prev, hadPrev)
}

// clearSingle is the single-key unassignment path. It clears the on-disk value
// ONLY when it still equals what the agent last wrote (ownership); a value the
// agent has no record of writing — the user's own extensions.allowed predates
// enforcement, or the record was lost — is left intact.
func (r *Reconciler) clearSingle(cat, tgt string, prev AppliedTargetState, hadPrev bool) error {
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

	return r.dropClearedState(cat, tgt, hadPrev)
}

// clearManaged is the managed multi-key unassignment path. It removes each
// agent-OWNED key INDEPENDENTLY, and only when its on-disk value still equals
// what the agent wrote (per-key ownership); a foreign-valued or absent key is
// preserved. The candidate set is exactly the recorded ownership (not a static
// key list), so any key the agent ever wrote is cleared without code change.
// One atomic write carries only the owned-key removes.
func (r *Reconciler) clearManaged(cat, tgt string, prev AppliedTargetState, hadPrev bool, mw managedSettingsWriter) error {
	owned := ownedKeys(prev, hadPrev)
	keys := sortedKeys(owned) // only owned keys can be removed; sorted → deterministic
	cur, err := mw.ReadManaged(keys)
	if err != nil {
		return fmt.Errorf("devicepolicy: clear: read %s: %w", r.Writer.Location(), err)
	}
	var ops []settingOp
	for _, key := range keys {
		ov := owned[key]
		if ov != "" && cur[key].Present && cur[key].Raw == ov {
			ops = append(ops, settingOp{Key: key, Remove: true})
		}
	}
	if len(ops) > 0 {
		if _, err := mw.ApplyManaged(ops); err != nil {
			return fmt.Errorf("devicepolicy: clear %s: %w", r.Writer.Location(), err)
		}
		r.logf("devicepolicy: cleared %d agent-owned key(s) at %s", len(ops), r.Writer.Location())
	} else {
		r.logf("devicepolicy: clear requested but %s holds no agent-owned value; leaving it", r.Writer.Location())
	}

	return r.dropClearedState(cat, tgt, hadPrev)
}

// dropClearedState drops the ownership record whenever an entry exists for this
// (category, target). Beyond the obvious case (we owned a value), this reclaims
// an empty record a preflight may have left after its settings write later
// failed. An absent entry → no-op (idempotent).
func (r *Reconciler) dropClearedState(cat, tgt string, hadPrev bool) error {
	if hadPrev {
		if err := r.dropState(cat, tgt); err != nil {
			return fmt.Errorf("devicepolicy: clear: update state: %w", err)
		}
	}
	return nil
}

// handleEnforce converges settings.json to the compiled policy and reports. It
// runs the shared head of the ladder (compact the allowlist, then the
// managed-policy probe), then dispatches on the Writer: a managed multi-key
// writer converges the full SET of managed keys (enforceManaged); any other
// Writer keeps the single-key path (enforceSingle).
//
//	probe (managed policy exists → mdm_managed, never write)
//	→ read current value(s)
//	→ idempotency (hash unchanged ∧ every managed key converged → report, no write)
//	→ preflight ownership-store writability
//	→ drift detection (an OWNED key diverged from its recorded written value)
//	→ merge-write + readback
//	→ persist ownership on every successful write (rollback if that fails)
//	→ Verify → report (drift upgrades a would-be compliant to drift_detected)
func (r *Reconciler) handleEnforce(ctx context.Context, cat, tgt string, ep EffectivePolicy) error {
	// Compact every value in the settings map to its canonical comparison form
	// (setting id → compacted value): the form used for readback, idempotency,
	// and ownership. (The backend's hash still travels verbatim; only the value
	// bytes are normalized for comparison.)
	desired, err := compactSettings(ep.Policy)
	if err != nil {
		// Defensive: the fetcher already validated the settings map decodes, so a
		// value that will not compact is a malformed-payload class failure → no-op,
		// never write.
		return fmt.Errorf("devicepolicy: enforce: compact policy: %w", err)
	}

	// Managed-policy probe. A policy at the OS policy location outranks user
	// settings inside VS Code — writing would be ineffective at best and fight
	// the MDM at worst. Yield and report. (Presence of EITHER managed policy
	// key yields; see the probe.)
	if managed, detail := r.probe(); managed {
		r.logf("devicepolicy: managed policy present at %s → mdm_managed (yielding)", detail)
		return r.report(ctx, cat, tgt, StateMDMManaged, "")
	}

	if mw, ok := r.Writer.(managedSettingsWriter); ok {
		return r.enforceManaged(ctx, cat, tgt, ep, desired, mw)
	}
	// Single-key fallback: a plain Writer manages only extensions.allowed; other
	// settings need the managed writer. The production settings writer is always
	// managed, so this path is the fake/degraded case.
	newValue, ok := desired[allowedExtensionsSettingKey]
	if !ok {
		_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
		return fmt.Errorf("devicepolicy: enforce: settings missing %q for single-key writer", allowedExtensionsSettingKey)
	}
	if len(desired) > 1 {
		// A multi-key policy on a single-key writer enforces only the allowlist;
		// surface it so a partial-enforce is never invisible.
		r.logf("devicepolicy: single-key writer at %s enforces only %s; %d other setting(s) dropped",
			r.Writer.Location(), allowedExtensionsSettingKey, len(desired)-1)
	}
	return r.enforceSingle(ctx, cat, tgt, ep, newValue)
}

// enforceSingle is the single-key convergence path (any Writer without the
// managed multi-key API). It is unchanged from the original enforce: it manages
// exactly the extensions.allowed key.
func (r *Reconciler) enforceSingle(ctx context.Context, cat, tgt string, ep EffectivePolicy, newValue string) error {
	// Read the current settings value.
	prev, hadPrev := ReadAppliedState(cat, tgt)
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		// Couldn't read to decide idempotency/drift → verification_failed.
		// This includes an unsalvageable settings.json (not valid JSONC), which
		// the writer refuses to touch.
		_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
		return fmt.Errorf("devicepolicy: enforce: read %s: %w", r.Writer.Location(), err)
	}

	// Idempotency: the desired policy is already in place and unchanged. No
	// write — but still report so the backend sees a fresh evaluation.
	if present && onDisk == newValue && prev.AppliedHash == ep.Hash {
		r.logf("devicepolicy: policy already applied (hash unchanged) — no write")
		return r.report(ctx, cat, tgt, StateCompliant, ep.Hash)
	}

	// Drift: the agent wrote a value before, and what is on disk now is not it
	// (edited or removed — typically the user hand-editing settings.json).
	// Enforcement means converging it back; the distinct state lets the backend
	// surface that it happened.
	drifted := hadPrev && prev.WrittenValue != "" && (!present || onDisk != prev.WrittenValue)
	if drifted {
		r.logf("devicepolicy: %s diverged from the recorded written value → re-applying (drift)", r.Writer.Location())
	}

	// Preflight: prove the ownership store is writable BEFORE mutating the
	// settings file. An enforced value with no ownership record is orphaned — a
	// later clear refuses to remove it. Re-persisting the current state is a
	// meaning-preserving writability probe.
	probe := prev
	if !hadPrev {
		probe = AppliedTargetState{FetchedAt: r.now()}
	}
	if perr := r.persistState(cat, tgt, probe); perr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: ownership state not writable, refusing to write policy: %w", perr)
	}

	// Merge-write + readback.
	rb, werr := r.Writer.Write(newValue)
	if werr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: write %s: %w", r.Writer.Location(), werr)
	}
	readbackMatch := rb == newValue

	// Ownership is recorded on EVERY successful write — it means "what the agent
	// wrote", not "what it verified". On a readback mismatch the write may still
	// have landed; without a record the next cycle would classify the agent's
	// own value as drift forever. Value-based ownership self-corrects: the
	// record only takes effect when the on-disk value actually equals it.
	if err := r.persistState(cat, tgt, AppliedTargetState{
		AppliedHash:  ep.Hash,
		WrittenValue: newValue,
		FetchedAt:    r.now(),
	}); err != nil {
		// The write happened but ownership couldn't be recorded — undo it so no
		// unrecorded value is left behind, and report a failed write.
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

// enforceManaged is the managed multi-key convergence path. It is fully driven
// by the settings map: every setting the backend sent is authoritatively Set,
// and any key the agent previously owned that is NO LONGER in the map is an
// ownership-gated Remove (only a value the agent itself wrote), else preserved
// (a foreign or absent value is never deleted). No setting id is special-cased,
// so a new managed key rides through with no change here.
func (r *Reconciler) enforceManaged(ctx context.Context, cat, tgt string, ep EffectivePolicy, desired map[string]string, mw managedSettingsWriter) error {
	prev, hadPrev := ReadAppliedState(cat, tgt)
	owned := ownedKeys(prev, hadPrev)

	// 1. Read every key this cycle may touch: the union of the settings map's keys
	// (to Set) and the owned keys (Set again, or an ownership-gated Remove when a
	// key has left the map). Sorted so reads, convergence, and writes are
	// deterministic.
	keys := sortedUnion(desired, owned)
	cur, err := mw.ReadManaged(keys)
	if err != nil {
		_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
		return fmt.Errorf("devicepolicy: enforce: read %s: %w", r.Writer.Location(), err)
	}

	// 2. Build the desired end-state ops, one per key in the union:
	//   - present in the settings map          → Set to its compiled value;
	//   - owned, gone from the map, and its
	//     on-disk value still matches           → ownership-gated Remove;
	//   - otherwise (foreign or absent value)   → preserve (never delete).
	ops := make([]settingOp, 0, len(keys))
	for _, key := range keys {
		if v, ok := desired[key]; ok {
			ops = append(ops, settingOp{Key: key, Set: true, Value: json.RawMessage(v)})
			continue
		}
		if ov := owned[key]; ov != "" && cur[key].Present && cur[key].Raw == ov {
			ops = append(ops, settingOp{Key: key, Remove: true})
		} else {
			ops = append(ops, settingOp{Key: key})
		}
	}

	// 3. Convergence over the FULL desired end-state, computed BEFORE the
	// idempotency short-circuit. It covers every managed key, so drift on any one
	// key with an unchanged hash re-applies rather than short-circuiting to
	// compliant.
	converged := true
	for _, op := range ops {
		if !opConverged(op, cur) {
			converged = false
			break
		}
	}
	if converged && prev.AppliedHash == ep.Hash {
		r.logf("devicepolicy: policy already applied (hash unchanged) — no write")
		return r.report(ctx, cat, tgt, StateCompliant, ep.Hash)
	}

	// 4. Drift: an OWNED key diverged from its recorded written value (edited or
	// removed). Only owned keys count — a foreign value is not the agent's drift.
	drifted := false
	for key, ov := range owned {
		if !cur[key].Present || cur[key].Raw != ov {
			drifted = true
			break
		}
	}
	if drifted {
		r.logf("devicepolicy: %s diverged from a recorded written value → re-applying (drift)", r.Writer.Location())
	}

	// 5. Snapshot the full pre-write state for an atomic multi-key rollback.
	snapshot := make(map[string]settingValue, len(cur))
	for k, sv := range cur {
		snapshot[k] = sv
	}

	// 6. Preflight: prove the ownership store is writable BEFORE mutating the
	// settings file (same rationale as the single-key path).
	probe := prev
	if !hadPrev {
		probe = AppliedTargetState{FetchedAt: r.now()}
	}
	if perr := r.persistState(cat, tgt, probe); perr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: ownership state not writable, refusing to write policy: %w", perr)
	}

	// 7. Write the mutating ops in one atomic patch; a preserve contributes
	// nothing.
	writeOps := make([]settingOp, 0, len(ops))
	for _, op := range ops {
		if op.Set || op.Remove {
			writeOps = append(writeOps, op)
		}
	}
	readback, werr := mw.ApplyManaged(writeOps)
	if werr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: write %s: %w", r.Writer.Location(), werr)
	}

	// 8. Readback over every mutating op — value + presence prove the requested
	// mutation (a bare string cannot distinguish absent from present-empty).
	readbackMatch := true
	for _, op := range writeOps {
		if !opConverged(op, readback) {
			readbackMatch = false
			break
		}
	}

	// 9. Persist ownership: every key the agent Set this cycle (i.e. the whole
	// settings map), keyed by setting id → the exact value written. A Remove or
	// preserve key asserts no ownership this cycle (omitted). WrittenValue is the
	// single-key path's field and is left untouched here.
	ownedAfter := make(map[string]string, len(desired))
	for key, v := range desired {
		ownedAfter[key] = v
	}
	if err := r.persistState(cat, tgt, AppliedTargetState{
		AppliedHash:     ep.Hash,
		WrittenSettings: ownedAfter,
		FetchedAt:       r.now(),
	}); err != nil {
		// The write happened but ownership couldn't be recorded — roll back ALL
		// keys atomically so no unrecorded value is left behind. A clean undo →
		// write_failed; a failed restore leaves the on-disk state uncertain →
		// verification_failed.
		if rerr := mw.RestoreManaged(snapshot); rerr != nil {
			r.logf("devicepolicy: rollback at %s failed: %v", r.Writer.Location(), rerr)
			_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
			return fmt.Errorf("devicepolicy: enforce: update state (rollback failed: %v): %w", rerr, err)
		}
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: update state: %w", err)
	}
	r.logf("devicepolicy: wrote policy to %s (readback_match=%v)", r.Writer.Location(), readbackMatch)

	state := Verify(VerifyInput{WriteOK: true, ReadbackMatch: readbackMatch})
	if drifted && state == StateCompliant {
		state = StateDriftDetected
	}

	// applied_hash is echoed only when readback-confirmed (compliant or
	// drift_detected). It is the backend's hash verbatim — never recomputed — so
	// the backend's byte-exact applied==desired check gates `compliant`.
	appliedHash := ""
	if state == StateCompliant || state == StateDriftDetected {
		appliedHash = ep.Hash
	}
	return r.report(ctx, cat, tgt, state, appliedHash)
}

// compactSettings compacts every value in the settings map to its canonical
// comparison form, returning setting id → compacted value. Compaction
// normalizes whitespace so on-disk readback and next-cycle ownership compare
// byte-exactly regardless of the backend's wire formatting; member order within
// each value is preserved (it is the backend's canonical, hashed order).
func compactSettings(settings map[string]json.RawMessage) (map[string]string, error) {
	out := make(map[string]string, len(settings))
	for k, raw := range settings {
		c, err := compactJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("devicepolicy: compact policy key %q: %w", k, err)
		}
		out[k] = c
	}
	return out, nil
}

// sortedUnion returns the sorted union of two key sets — every settings key a
// cycle may touch (a Set from the settings map, or an ownership-gated
// Remove/preserve for an owned key no longer in it). The stable order makes
// reads, convergence, writes, and logs deterministic.
func sortedUnion(a, b map[string]string) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		set[k] = struct{}{}
	}
	for k := range b {
		set[k] = struct{}{}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedKeys returns m's keys in sorted order, for a deterministic write.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// opConverged reports whether on-disk state m already satisfies op: a Set
// converges when the key is present with the exact value; a Remove when the key
// is absent; a preserve (neither Set nor Remove) is always satisfied.
func opConverged(op settingOp, m map[string]settingValue) bool {
	sv := m[op.Key]
	switch {
	case op.Set:
		return sv.Present && sv.Raw == string(op.Value)
	case op.Remove:
		return !sv.Present
	default:
		return true
	}
}

// ownedKeys folds an ownership record into a flat map of setting id → the exact
// value the agent last wrote, skipping empty entries. Every managed key — the
// allowlist included — lives in WrittenSettings. Drift detection and
// ownership-gated removal act only on keys the agent actually wrote.
func ownedKeys(prev AppliedTargetState, hadPrev bool) map[string]string {
	owned := map[string]string{}
	if !hadPrev {
		return owned
	}
	for k, v := range prev.WrittenSettings {
		if v != "" {
			owned[k] = v
		}
	}
	return owned
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

// report submits a write-path compliance report.
func (r *Reconciler) report(ctx context.Context, cat, tgt, state, appliedHash string) error {
	return r.sendReport(ctx, ComplianceReport{
		Category:    cat,
		Target:      tgt,
		State:       state,
		AppliedHash: appliedHash,
	})
}

// sendReport stamps the shared fields (agent version, platform,
// EvaluatedEnforcement) and submits. Callers fill Category/Target/State and the
// lane-specific field: AppliedHash for the write path, Observed for MDM.
func (r *Reconciler) sendReport(ctx context.Context, rep ComplianceReport) error {
	rep.AgentVersion = AgentVersion()
	rep.Platform = r.Platform
	rep.EvaluatedEnforcement = r.enforcement
	r.logf("devicepolicy: reporting state=%s category=%s target=%s", rep.State, rep.Category, rep.Target)
	if r.Reporter == nil {
		return nil
	}
	if err := r.Reporter.Report(ctx, r.CustomerID, r.DeviceID, rep); err != nil {
		return fmt.Errorf("devicepolicy: report %s: %w", rep.State, err)
	}
	return nil
}
