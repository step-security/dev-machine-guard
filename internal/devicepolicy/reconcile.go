package devicepolicy

import (
	"context"
	"encoding/json"
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

	// The seams below adapt the ladder to a target whose ownership and
	// convergence model differs from the single-JSON-key settings.json writer
	// (concretely the ~/.npmrc block writer, npmrc.go). EVERY seam nil/false
	// reproduces the settings.json behavior byte-for-byte — the IDE wiring sets
	// none of them, so its path is unchanged.

	// Converged, when set, REPLACES the generic body-equality idempotency test
	// (present && on-disk == desired) with a target-specific full-state check —
	// e.g. the ~/.npmrc writer also verifies its block is effective (nothing
	// overrides it below) and carries sane metadata (0600, owned by the target
	// user). Body equality alone is a hole there: a `registry=` line appended
	// below an unchanged block leaves the body equal but defeats precedence.
	Converged func(expected string) (bool, error)

	// Render, when set, derives the value to write/compare from the raw policy —
	// e.g. rendering the two ~/.npmrc content lines from the npm policy object
	// and the device serial. nil → the value is the compacted policy JSON
	// (settings.json). A render failure is a malformed backend payload and is
	// reported as policy_not_applied.
	Render func(policy json.RawMessage) (string, error)

	// ProbeExpected, when set, REPLACES Probe for this cycle and receives the
	// rendered value so a content-aware probe can decide whether the MDM lane has
	// achieved the SAME desired state (the ~/.npmrc file is user-writable, so a
	// bare marker is not proof). nil → Probe.
	ProbeExpected func(expected string) (managed bool, detail string)

	// RestoreSnapshot, when set, is the rollback used after a post-write ownership
	// persist fails: the writer reverts its whole-file transformation from a
	// snapshot and its RESULT is classified — restore succeeded → write_failed
	// (the enforce write was undone), restore failed/aborted → verification_failed
	// (on-disk state now unknown). nil → the generic best-effort re-write of the
	// previous value (always write_failed), which suits a single settings key.
	RestoreSnapshot func() error

	// OwnsByMarker switches handleClear from value-based ownership (clear only
	// when on-disk still equals the recorded written value) to marker-based:
	// always call Writer.Clear() and drop the state record unconditionally. It
	// suits a writer whose Clear is intrinsically scoped to its own markers, so a
	// lost/drifted/empty record must not strand a token-bearing block on disk.
	OwnsByMarker bool

	// WriterInitErr carries a writer-construction failure (Writer is then nil).
	// The reconciler classifies it AFTER the fetch: absent policy → silent no-op,
	// clear → retain all state (no target to act against), enforce →
	// policy_not_applied for ErrNoTargetUser else write_failed. nil with a nil
	// Writer is the ordinary unsupported-platform silent no-op.
	WriterInitErr error

	// State, when set, is the ownership store this cycle reads and writes through,
	// replacing the package-level shared-file functions. The npm category uses
	// its own per-mode/per-user store so its record can never share the IDE
	// file's unlocked read-modify-write. nil → the shared package-level store
	// (settings.json), byte-identical to before.
	State StateStore

	// Now and Logf are optional seams. Now defaults to time.Now().UTC; Logf to a
	// no-op.
	Now  func() time.Time
	Logf func(format string, args ...any)

	// writeState and clearState are test seams over the ownership store
	// (WriteAppliedState / ClearAppliedState). nil → the real implementation.
	// They apply only to the shared store (State == nil).
	writeState func(category, target string, s AppliedTargetState) error
	clearState func(category, target string) error
}

// readState / persistState / dropState route through the injected StateStore
// when one is set, and otherwise fall back to the shared package-level store
// (with the writeState/clearState test seams) exactly as before — so the IDE
// wiring, which sets no State, is unchanged.
func (r *Reconciler) readState(cat, tgt string) (AppliedTargetState, bool) {
	if r.State != nil {
		return r.State.Read(cat, tgt)
	}
	return ReadAppliedState(cat, tgt)
}

func (r *Reconciler) persistState(cat, tgt string, s AppliedTargetState) error {
	if r.State != nil {
		return r.State.Write(cat, tgt, s)
	}
	if r.writeState != nil {
		return r.writeState(cat, tgt, s)
	}
	return WriteAppliedState(cat, tgt, s)
}

func (r *Reconciler) dropState(cat, tgt string) error {
	if r.State != nil {
		return r.State.Drop(cat, tgt)
	}
	if r.clearState != nil {
		return r.clearState(cat, tgt)
	}
	return ClearAppliedState(cat, tgt)
}

// renderValue produces the value to write/compare: the rendered block via the
// Render seam, or the compacted policy JSON for settings.json.
func (r *Reconciler) renderValue(policy json.RawMessage) (string, error) {
	if r.Render != nil {
		return r.Render(policy)
	}
	return compactJSON(policy)
}

// converged answers "is the desired value already fully in place?". With the
// Converged seam it delegates to the writer's full-state check; otherwise it is
// the generic body-equality test over the already-read on-disk value.
func (r *Reconciler) converged(expected, onDisk string, present bool) (bool, error) {
	if r.Converged != nil {
		return r.Converged(expected)
	}
	return present && onDisk == expected, nil
}

// probeExpected reports whether a managed policy already governs this target.
// The content-aware ProbeExpected seam (needs the rendered value) wins; else the
// legacy content-blind Probe.
func (r *Reconciler) probeExpected(expected string) (bool, string) {
	if r.ProbeExpected != nil {
		return r.ProbeExpected(expected)
	}
	return r.probe()
}

// rollback undoes the just-committed write after the post-write ownership
// persist failed, and returns the compliance state the outcome warrants.
//
// With the RestoreSnapshot seam, the writer performs a whole-file transactional
// restore whose success is meaningful: restore succeeded → write_failed (the
// enforce write was cleanly undone); restore failed/aborted (e.g. the resolved
// path moved between write and rollback) → verification_failed (on-disk state is
// now unknown). Without the seam it falls back to the generic best-effort
// re-write of the previous value, which always yields write_failed — correct for
// a single settings key and byte-identical for the IDE path.
func (r *Reconciler) rollback(prevOnDisk string, prevPresent bool) (state string, err error) {
	if r.RestoreSnapshot != nil {
		if rerr := r.RestoreSnapshot(); rerr != nil {
			return StateVerificationFailed, rerr
		}
		return StateWriteFailed, nil
	}
	r.rollbackWrite(prevOnDisk, prevPresent)
	return StateWriteFailed, nil
}

// classifyReadError maps a Writer read/convergence error to a compliance state.
// A structural refusal (the target cannot be enforced at all — wraps
// ErrTargetUnusable) is a write-class fact; everything else (permission denied,
// transient I/O) stays verification_failed. The IDE writer never wraps the
// sentinel, so this always returns verification_failed for it.
func classifyReadError(err error) string {
	if errors.Is(err, ErrTargetUnusable) {
		return StateWriteFailed
	}
	return StateVerificationFailed
}

// classifyWriteError maps a Writer.Write / Writer.Clear failure to a compliance
// state. A write that errored is write_failed by default — the value did not take
// effect. The one exception is a writer that landed new bytes it could neither
// verify NOR roll back (ErrWriteUnverified): on-disk state is then indeterminate,
// which is verification_failed, not a clean write failure. The IDE writer never
// returns that sentinel, so this is always write_failed for it.
func classifyWriteError(err error) string {
	if errors.Is(err, ErrWriteUnverified) {
		return StateVerificationFailed
	}
	return StateWriteFailed
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
//   - platform not enforceable (nil Writer, nil WriterInitErr) → silent no-op.
//   - writer could not be constructed (nil Writer, WriterInitErr set) →
//     classified AFTER the fetch by what run-config asked for: absent → silent;
//     clear → no-op retaining ALL state (no resolved target to act against);
//     enforce → policy_not_applied (ErrNoTargetUser) or write_failed (other).
//   - absent policy (run-config carried no `policy` directive for this
//     category/target) → silent no-op; the on-disk value and ownership record
//     stand. This is NOT a clear — removal happens only on an explicit clear.
//   - clear result → remove ONLY the agent-owned value; a value the agent has no
//     record of writing is left untouched (value-based ownership) or the block
//     is removed and the record dropped (marker-based ownership, OwnsByMarker).
//     No compliance report (an unassigned device is backend-derived).
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
		// No usable writer. Two shapes: an unsupported platform (no init error →
		// the long-standing silent skip) or a construction failure (init error →
		// classified against the fetched directive, since reporting before the
		// fetch would fire even when run-config would have said "no policy").
		if r.WriterInitErr == nil {
			r.logf("devicepolicy: no settings path on this platform; skipping (category=%s target=%s)", cat, tgt)
			return nil
		}
		return r.handleNoWriter(ctx, cat, tgt, ep)
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

// handleNoWriter classifies a cycle whose writer could not be constructed
// (WriterInitErr set, Writer nil). It never touches disk or state — there is no
// resolved target user to act against — and decides purely from the fetched
// directive:
//
//   - absent policy → silent no-op (nothing to enforce, nothing to clear);
//   - clear → no-op that RETAINS every state record. With ErrNoTargetUser there
//     is no uid to even select a per-user record, and dropping records blindly
//     would erase the bookkeeping that other users still carry a token-bearing
//     block pending cleanup. The backend re-sends clear each cycle, so cleanup
//     happens when a writer is next constructible (a real user is present);
//   - enforce → report why nothing was applied: policy_not_applied when this
//     machine state simply has no enforceable target user (ErrNoTargetUser),
//     write_failed for any other construction failure (home unresolvable/
//     unopenable — an infrastructure problem worth surfacing louder).
func (r *Reconciler) handleNoWriter(ctx context.Context, cat, tgt string, ep EffectivePolicy) error {
	if !ep.present() {
		r.logf("devicepolicy: no enforceable target user and run-config carried no policy for %s/%s; nothing to do", cat, tgt)
		return nil
	}
	if ep.Clear {
		r.logf("devicepolicy: clear requested for %s/%s but no enforceable target user; retaining all state (cleared when a user is present)", cat, tgt)
		return nil
	}
	state := StateWriteFailed
	if errors.Is(r.WriterInitErr, ErrNoTargetUser) {
		state = StatePolicyNotApplied
	}
	_ = r.report(ctx, cat, tgt, state, "")
	return fmt.Errorf("devicepolicy: enforce %s/%s: no usable writer: %w", cat, tgt, r.WriterInitErr)
}

// handleClear removes the agent-owned value on unassignment. Two ownership
// models, selected by OwnsByMarker:
//
//   - value-based (default, settings.json): clear the on-disk value ONLY when it
//     still equals what the agent last wrote; a value the agent has no record of
//     writing — the user's own extensions.allowed predates enforcement, or the
//     record was lost — is left intact, and the state record is dropped only
//     when one existed.
//   - marker-based (OwnsByMarker, ~/.npmrc): handleClearByMarker.
func (r *Reconciler) handleClear(cat, tgt string) error {
	if r.OwnsByMarker {
		return r.handleClearByMarker(cat, tgt)
	}

	prev, hadPrev := r.readState(cat, tgt)
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

// handleClearByMarker removes the managed block regardless of recorded state.
// Ownership is intrinsic to the writer's own markers — its Clear only ever
// removes content between OUR markers and un-prefixes OUR commented lines, never
// anything else — so a value-equality gate is both unnecessary and unsafe here:
// lost or corrupt state, a drifted block, or an empty marker shell would
// otherwise strand a token-bearing block on disk forever after unassignment.
// Clear is called unconditionally (a no-op when there is no block) and the state
// record is dropped UNCONDITIONALLY afterward — a store read that failed or lied
// (no record found) must not leave an orphan behind; Drop is idempotent.
func (r *Reconciler) handleClearByMarker(cat, tgt string) error {
	if err := r.Writer.Clear(); err != nil {
		return fmt.Errorf("devicepolicy: clear %s: %w", r.Writer.Location(), err)
	}
	r.logf("devicepolicy: cleared managed block at %s", r.Writer.Location())
	if err := r.dropState(cat, tgt); err != nil {
		return fmt.Errorf("devicepolicy: clear: update state: %w", err)
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
	// The value to enforce: the rendered block (Render seam) or the compacted
	// policy JSON. Computed FIRST because the content-aware probe below needs it.
	// (The backend's hash still travels verbatim; only the value bytes are
	// normalized for comparison.)
	newValue, err := r.renderValue(ep.Policy)
	if err != nil {
		if r.Render != nil {
			// A malformed backend payload the renderer rejected: nothing was
			// applied and nothing will be. Make it visible rather than a silent
			// no-op. (The default compactJSON path only fails on bytes the fetcher
			// already rejected as a non-object, so it keeps its silent return.)
			_ = r.report(ctx, cat, tgt, StatePolicyNotApplied, "")
			return fmt.Errorf("devicepolicy: enforce: render policy: %w", err)
		}
		return fmt.Errorf("devicepolicy: enforce: compact policy: %w", err)
	}

	// 1. Managed-policy probe. A real managed policy outranks the value the agent
	// would write — writing would be ineffective at best and fight the MDM at
	// worst. Yield and report.
	if managed, detail := r.probeExpected(newValue); managed {
		r.logf("devicepolicy: managed policy present at %s → mdm_managed (yielding)", detail)
		return r.report(ctx, cat, tgt, StateMDMManaged, "")
	}

	// 2. Read the current value.
	prev, hadPrev := r.readState(cat, tgt)
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		// Couldn't read to decide idempotency/drift. A structural refusal (the
		// target cannot be enforced) is write_failed; a plain unreadable/unparseable
		// file is verification_failed. classifyReadError always returns the latter
		// for the IDE writer, which never wraps ErrTargetUnusable.
		state := classifyReadError(err)
		_ = r.report(ctx, cat, tgt, state, "")
		return fmt.Errorf("devicepolicy: enforce: read %s: %w", r.Writer.Location(), err)
	}

	// 3. Idempotency: the desired value is already fully in place and the hash is
	// unchanged. No write — but still report so the backend sees a fresh
	// evaluation. The convergence test is the writer's when the Converged seam is
	// set (it also checks effectiveness and metadata), else plain body equality.
	converged, cerr := r.converged(newValue, onDisk, present)
	if cerr != nil {
		// Converged runs its own secure read; a structural refusal there is the
		// same write-class fact as an initial read refusal.
		state := classifyReadError(cerr)
		_ = r.report(ctx, cat, tgt, state, "")
		return fmt.Errorf("devicepolicy: enforce: convergence check %s: %w", r.Writer.Location(), cerr)
	}
	if converged && prev.AppliedHash == ep.Hash {
		r.logf("devicepolicy: policy already applied (hash unchanged) — no write")
		return r.report(ctx, cat, tgt, StateCompliant, ep.Hash)
	}

	// The full-state convergence seam (npm) proves the exact desired block is on
	// disk, effective, and correctly owned — a strictly stronger fact than body
	// equality — yet THIS cycle's store does not carry this hash. That happens when
	// the other privilege mode applied it and recorded in its own per-mode store,
	// or our record is stale. Adopt the on-disk state into this store rather than
	// churn a redundant rewrite or misreport it as drift, and report compliant.
	// Best-effort: the block is already applied, so a store hiccup only defers the
	// record one cycle. Gated on the Converged seam so the settings.json path
	// (body equality, shared store) is byte-identical to before.
	if converged && r.Converged != nil {
		if perr := r.persistState(cat, tgt, AppliedTargetState{
			AppliedHash:  ep.Hash,
			WrittenValue: newValue,
			FetchedAt:    r.now(),
		}); perr != nil {
			r.logf("devicepolicy: could not adopt already-converged state at %s: %v", r.Writer.Location(), perr)
		}
		r.logf("devicepolicy: %s already holds the desired block (adopted) — no write", r.Writer.Location())
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
		// write_failed by default; verification_failed only when the writer landed
		// bytes it could neither verify nor roll back (on-disk state indeterminate).
		_ = r.report(ctx, cat, tgt, classifyWriteError(werr), "")
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
		// The write happened but ownership couldn't be recorded — undo it so no
		// unrecorded value is left behind. The rollback outcome decides the state:
		// cleanly undone → write_failed; restore failed/aborted → verification_failed.
		state, rbErr := r.rollback(onDisk, present)
		if rbErr != nil {
			r.logf("devicepolicy: rollback at %s failed: %v", r.Writer.Location(), rbErr)
		}
		_ = r.report(ctx, cat, tgt, state, "")
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
