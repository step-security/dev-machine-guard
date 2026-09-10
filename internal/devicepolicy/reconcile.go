package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
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

	// OwnershipTarget changes only the local state key. Reports still use Target.
	OwnershipTarget string

	// OwnershipStateValue replaces the rendered single-value ownership payload.
	// Empty preserves existing IDE and npm behavior.
	OwnershipStateValue string

	// Probe reports whether a real MDM/admin-managed AllowedExtensions policy
	// exists at this OS's policy location (registry / policy.json / managed
	// preferences). Such a policy outranks user settings inside VS Code, so the
	// agent yields (mdm_managed) instead of writing a value VS Code would
	// ignore. nil → ProbeManagedPolicy (the per-OS implementation); tests
	// inject a stub so results never depend on the host machine.
	Probe func() (managed bool, detail string)

	// ProbeContent reads the effective externally-managed configuration for the
	// verify-only path and returns it as the observed bag. expected is this
	// cycle's rendered desired value: the VS Code probe ignores it (the backend
	// compares OS-managed values), while the ~/.npmrc probe needs it to decide
	// auth_token_status on-device — the desired tenant key must never leave the
	// machine, so only the verdict is reported. nil → the per-OS
	// ProbeManagedContent for ide_extension, and an error (→ verification_failed)
	// for any other category: falling back to the VS Code probe would report
	// another category's policy. The DMG path never calls it.
	ProbeContent func(expected string) (present bool, observed map[string]json.RawMessage, err error)

	// OwnershipKey is the WrittenSettings key the single-value paths record
	// ownership under (drift, adopt, persist, and the value-based clear all read
	// the same one). The managed multi-key path keys by real setting id and
	// ignores this. Empty → allowedExtensionsSettingKey, the only key a plain VS
	// Code Writer manages; the npm lane sets NPMOwnedKey.
	OwnershipKey string

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
	// FullStateDrift reports a failed target-specific convergence check under an
	// unchanged hash as drift even when the marker body itself is unchanged.
	FullStateDrift bool

	// Render, when set, derives the value to write/compare from the raw policy —
	// e.g. rendering the ~/.npmrc managed body from the npm policy object and the
	// device serial. nil → the value is the compacted policy JSON
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

	// CompleteState adds non-secret ownership metadata discovered by a writer
	// after a successful write or adoption. PrepareWrite and PrepareClear validate
	// that metadata before the corresponding mutation.
	CompleteState func(previous AppliedTargetState, hadPrevious bool, current *AppliedTargetState) error
	PrepareWrite  func(previous AppliedTargetState, hadPrevious bool) error
	PrepareClear  func(previous AppliedTargetState, hadPrevious bool) error

	// WriterInitErr carries a writer-construction failure (Writer is then nil).
	// The reconciler classifies it AFTER the fetch: absent policy → silent no-op,
	// clear → retain all state (no target to act against), enforce →
	// policy_not_applied for ErrNoTargetUser else write_failed. nil with a nil
	// Writer is the ordinary unsupported-platform silent no-op.
	WriterInitErr error

	// InitWriter initializes the npm writer after an active policy has rendered,
	// or before an explicit DMG clear. It is nil for every other target. This
	// preserves the npm trust-boundary ordering: malformed compiled settings are
	// rejected before resolving the target user or opening their home.
	InitWriter func() error

	// Now and Logf are optional seams. Now defaults to time.Now().UTC; Logf to a
	// no-op.
	Now  func() time.Time
	Logf func(format string, args ...any)
	// Warnf records actionable failures at the default log level. Logf stays diagnostic-only.
	Warnf func(format string, args ...any)

	// writeState and clearState are test seams over the ownership store
	// (WriteAppliedState / ClearAppliedState). nil → the real implementation.
	writeState func(category, target string, s AppliedTargetState) error
	clearState func(category, target string) error
	probeState func() error

	// enforcement is the canonical channel the current cycle actually ran —
	// always "dmg" or "mdm" (an empty or unrecognized ep.Enforcement resolves to
	// "dmg"). Stamped onto every report as EvaluatedEnforcement so it matches the
	// backend's exact-match gate. Per-cycle scratch.
	enforcement string
	// evaluatedHash is the active npm policy hash fetched for this cycle.
	evaluatedHash string
	// renderedValue caches the trust-boundary render for the current cycle.
	renderedValue string
	rendered      bool
}

// readState / persistState / dropState are every category's access to the one
// state file (device-policy-state.json), keyed by (category, target). No category
// has a store of its own: the file's read-modify-write preserves every other
// category and target, and takes a cross-process lock so two agent processes
// reconciling different categories cannot drop each other's record. The
// writeState/clearState test seams inject persist failures.
func (r *Reconciler) readState(cat string) (AppliedTargetState, bool) {
	return ReadAppliedState(cat, r.stateTarget())
}

func (r *Reconciler) persistState(cat string, s AppliedTargetState) error {
	tgt := r.stateTarget()
	if r.writeState != nil {
		return r.writeState(cat, tgt, s)
	}
	return WriteAppliedState(cat, tgt, s)
}

func (r *Reconciler) dropState(cat string) error {
	tgt := r.stateTarget()
	if r.clearState != nil {
		return r.clearState(cat, tgt)
	}
	return ClearAppliedState(cat, tgt)
}

func (r *Reconciler) probeOwnershipState(cat string, previous AppliedTargetState, hadPrevious bool) error {
	if r.probeState != nil {
		return r.probeState()
	}
	// Preserve the existing injected write seam for tests that distinguish the
	// pre-write and post-write ownership-store failures.
	if r.writeState != nil {
		if !hadPrevious {
			previous = AppliedTargetState{FetchedAt: r.now()}
		}
		return r.persistState(cat, previous)
	}
	return ProbeAppliedStateWritable()
}

// renderValue produces the value to write/compare: the rendered block via the
// Render seam, or the compacted policy JSON for settings.json.
func (r *Reconciler) renderValue(policy json.RawMessage) (string, error) {
	if r.rendered {
		return r.renderedValue, nil
	}
	if r.Render != nil {
		return r.Render(policy)
	}
	return compactJSON(policy)
}

func (r *Reconciler) prepareRenderedValue(policy json.RawMessage) error {
	value, err := r.renderValue(policy)
	if err != nil {
		return err
	}
	r.renderedValue = value
	r.rendered = true
	return nil
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
	if errors.Is(err, ErrTargetUnusable) || errors.Is(err, secureuserfile.ErrTargetUnusable) {
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
	if errors.Is(err, ErrWriteUnverified) || errors.Is(err, secureuserfile.ErrWriteUnverified) {
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

func (r *Reconciler) warnf(format string, args ...any) {
	if r.Warnf != nil {
		r.Warnf("devicepolicy: category=%s target=%s %s", r.category(), r.target(), redact.String(fmt.Sprintf(format, args...)))
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

func (r *Reconciler) stateTarget() string {
	if r.OwnershipTarget != "" {
		return r.OwnershipTarget
	}
	return r.target()
}

func (r *Reconciler) stateValue(rendered string) string {
	if r.OwnershipStateValue != "" {
		return r.OwnershipStateValue
	}
	return rendered
}

func (r *Reconciler) completedState(previous AppliedTargetState, hadPrevious bool, hash, key, value string) (AppliedTargetState, error) {
	state := AppliedTargetState{
		AppliedHash:     hash,
		WrittenSettings: map[string]string{key: r.stateValue(value)},
		FetchedAt:       r.now(),
	}
	if r.CompleteState != nil {
		if err := r.CompleteState(previous, hadPrevious, &state); err != nil {
			return AppliedTargetState{}, err
		}
	}
	return state, nil
}

func (r *Reconciler) probe() (bool, string) {
	if r.Probe != nil {
		return r.Probe()
	}
	return ProbeManagedPolicy()
}

// probeContent reads the effective externally-managed configuration for the
// verify-only path. The fallback is CATEGORY-AWARE: only ide_extension may fall
// back to the OS policy reader. Any other category with no seam (e.g. an npm
// cycle whose writer could not be constructed, so ProbeContentNPM was never
// bound) errors → verification_failed, an honest "could not verify". Falling
// through to ProbeManagedContent there would report VS Code policy values as an
// npm observation.
func (r *Reconciler) probeContent(expected string) (bool, map[string]json.RawMessage, error) {
	if r.ProbeContent != nil {
		return r.ProbeContent(expected)
	}
	if r.category() == CategoryIDEExtension {
		return ProbeManagedContent(expected)
	}
	return false, nil, fmt.Errorf("devicepolicy: no content probe for %s", r.category())
}

// ownershipKey is the WrittenSettings key the single-value paths record
// ownership under. Empty OwnershipKey → the allowlist setting id, the only key a
// plain VS Code Writer manages.
func (r *Reconciler) ownershipKey() string {
	if r.OwnershipKey != "" {
		return r.OwnershipKey
	}
	return allowedExtensionsSettingKey
}

// Reconcile runs one enforcement cycle. It NEVER panics into the caller's hot
// path; failures are returned for logging. The contract:
//
//   - fetch error (transport / non-200 / malformed) → NO-OP, error returned.
//     Enforcement on disk is never wiped on a transient or malformed response.
//   - MDM enforcement (ep.Enforcement=="mdm") → verify-only: probe the
//     externally-managed configuration and report what was observed; never
//     writes, patches, or clears. Checked right after fetch, before the gates
//     below, so it runs even with a nil Writer, a WriterInitErr, or a clear
//     directive.
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
	r.evaluatedHash = ""
	r.renderedValue = ""
	r.rendered = false
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
	if cat == CategoryPackageConfig && tgt == TargetNPM && ep.present() && !ep.Clear {
		r.evaluatedHash = ep.Hash
	}
	// Resolve the requested channel to the canonical one this cycle actually
	// runs, and stamp THAT on every report as EvaluatedEnforcement: the backend
	// gates on an exact "mdm"/"dmg", so the report must name the channel that ran
	// — never the raw request. An empty or unrecognized channel runs, and
	// reports, the DMG path. MDM is verify-only and owns nothing on disk, so it
	// routes before the Writer/clear checks below.
	switch strings.ToLower(strings.TrimSpace(ep.Enforcement)) {
	case enforcementMDM:
		r.enforcement = enforcementMDM
	case enforcementDMG, "":
		r.enforcement = enforcementDMG
	default:
		r.logf("devicepolicy: unknown enforcement %q; running DMG path", ep.Enforcement)
		r.enforcement = enforcementDMG
	}

	needsWriter := ep.present() && (r.enforcement == enforcementDMG || !ep.Clear)
	if r.InitWriter != nil && needsWriter {
		if ep.present() && !ep.Clear {
			if err := r.prepareRenderedValue(ep.Policy); err != nil {
				if r.enforcement == enforcementMDM {
					r.warnf("mdm render desired value failed: %v; verification_failed", err)
					return r.sendReport(ctx, ComplianceReport{Category: cat, Target: tgt, State: StateVerificationFailed})
				}
				_ = r.report(ctx, cat, tgt, StatePolicyNotApplied, "")
				return fmt.Errorf("devicepolicy: enforce: render policy: %w", err)
			}
		}
		r.WriterInitErr = r.InitWriter()
	}

	if r.enforcement == enforcementMDM {
		return r.verifyMDM(ctx, cat, tgt, ep)
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

// verifyMDM is the verify-only path: it never opens the target file (an external
// MDM owns the configuration), probes what is effective, and reports what it saw.
// It does not compare observed against ep.Policy or decide drift — the backend
// does that on read — and applied_hash is always empty.
//
// The desired value is rendered first and handed to the probe. The VS Code probe
// ignores it; the ~/.npmrc probe needs it to decide auth_token_status on-device,
// because the tenant key must never leave the machine. A render failure means the
// backend payload is malformed, so nothing could be verified against it →
// verification_failed.
func (r *Reconciler) verifyMDM(ctx context.Context, cat, tgt string, ep EffectivePolicy) error {
	if ep.Clear || !ep.present() {
		r.logf("devicepolicy: mdm enforcement with no active policy for %s/%s; nothing to verify", cat, tgt)
		return nil
	}

	expected, err := r.renderValue(ep.Policy)
	if err != nil {
		r.warnf("mdm render desired value failed: %v; verification_failed", err)
		return r.sendReport(ctx, ComplianceReport{Category: cat, Target: tgt, State: StateVerificationFailed})
	}

	present, observed, err := r.probeContent(expected)
	if err != nil {
		r.warnf("mdm content probe failed: %v; verification_failed", err)
		return r.sendReport(ctx, ComplianceReport{Category: cat, Target: tgt, State: StateVerificationFailed})
	}

	if !present {
		r.logf("devicepolicy: mdm enforcement but no externally-managed policy present → policy_not_applied")
		return r.sendReport(ctx, ComplianceReport{Category: cat, Target: tgt, State: StatePolicyNotApplied})
	}

	raw, err := json.Marshal(observed)
	if err != nil {
		// observed is built from our own parsers; a marshal failure is not expected.
		r.warnf("mdm marshal observed failed: %v; verification_failed", err)
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
//
// Within the value-based model it dispatches on the Writer: a managed multi-key
// writer clears each owned key independently (clearManaged); any other Writer
// keeps the single-key path (clearSingle).
func (r *Reconciler) handleClear(cat, tgt string) error {
	if r.OwnsByMarker {
		return r.handleClearByMarker(cat, tgt)
	}

	prev, hadPrev := r.readState(cat)
	if mw, ok := r.Writer.(managedSettingsWriter); ok {
		return r.clearManaged(cat, tgt, prev, hadPrev, mw)
	}
	return r.clearSingle(cat, tgt, prev, hadPrev)
}

// clearSingle is the single-value unassignment path. It clears the on-disk value
// ONLY when it still equals what the agent last wrote (ownership); a value the
// agent has no record of writing — the user's own extensions.allowed predates
// enforcement, or the record was lost — is left intact.
func (r *Reconciler) clearSingle(cat, tgt string, prev AppliedTargetState, hadPrev bool) error {
	onDisk, present, err := r.Writer.Read()
	if err != nil {
		return fmt.Errorf("devicepolicy: clear: read %s: %w", r.Writer.Location(), err)
	}

	prevWritten := prev.WrittenSettings[r.ownershipKey()]
	owns := present && prevWritten != "" && onDisk == prevWritten
	switch {
	case owns:
		changed, cerr := r.Writer.Clear()
		if cerr != nil {
			return fmt.Errorf("devicepolicy: clear %s: %w", r.Writer.Location(), cerr)
		}
		if changed {
			r.logf("devicepolicy: cleared agent-owned policy at %s", r.Writer.Location())
		}
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
		if err := r.dropState(cat); err != nil {
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
	prev, hadPrev := r.readState(cat)
	if r.PrepareClear != nil {
		if err := r.PrepareClear(prev, hadPrev); err != nil {
			return fmt.Errorf("devicepolicy: prepare clear %s: %w", r.Writer.Location(), err)
		}
	}
	changed, err := r.Writer.Clear()
	if err != nil {
		return fmt.Errorf("devicepolicy: clear %s: %w", r.Writer.Location(), err)
	}
	if changed {
		r.logf("devicepolicy: cleared managed block at %s", r.Writer.Location())
	} else {
		r.logf("devicepolicy: clear requested but %s holds no managed block; nothing to remove", r.Writer.Location())
	}
	if err := r.dropState(cat); err != nil {
		return fmt.Errorf("devicepolicy: clear: update state: %w", err)
	}
	return nil
}

// handleEnforce converges the target to the compiled policy and reports. It runs
// the shared head of the ladder (render the desired value, then the
// managed-policy probe), then dispatches on the Writer: a managed multi-key
// writer converges the full SET of managed keys (enforceManaged); any other
// Writer keeps the single-value path (enforceSingle — the VS Code degraded case
// and the ~/.npmrc block writer). The ladder, in order:
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
	// The value the probe reasons about, and — on the single-value path — the value
	// to write: the rendered block (Render seam) or the compacted policy JSON.
	// Computed FIRST because the content-aware probe below needs it. (The
	// backend's hash still travels verbatim; only the value bytes are normalized
	// for comparison.)
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
	r.renderedValue = newValue
	r.rendered = true

	// 1. Managed-policy probe. A real managed policy outranks the value the agent
	// would write — writing would be ineffective at best and fight the MDM at
	// worst. Yield and report. (For VS Code, presence of EITHER managed policy key
	// yields; see the probe.)
	if managed, detail := r.probeExpected(newValue); managed {
		r.logf("devicepolicy: managed policy present at %s → mdm_managed (yielding)", detail)
		return r.report(ctx, cat, tgt, StateMDMManaged, "")
	}

	if mw, ok := r.Writer.(managedSettingsWriter); ok {
		desired, derr := compactPolicySettings(ep.Policy)
		if derr != nil {
			// Defensive: the fetcher already validated object shape, so a value that
			// will not decode/compact is a malformed-payload class failure → no-op,
			// never write.
			return fmt.Errorf("devicepolicy: enforce: compact policy: %w", derr)
		}
		return r.enforceManaged(ctx, cat, tgt, ep, desired, mw)
	}

	if r.Render == nil {
		// Single-key fallback for a plain settings Writer: it manages only
		// extensions.allowed, so the compacted whole-policy object newValue holds is
		// not what to write — pick the allowlist value out of the settings map. The
		// production settings writer is always managed, so this path is the
		// fake/degraded case. A Writer WITH a Render seam (the ~/.npmrc block
		// writer) writes its rendered value and never consults the map.
		desired, derr := compactPolicySettings(ep.Policy)
		if derr != nil {
			return fmt.Errorf("devicepolicy: enforce: compact policy: %w", derr)
		}
		v, ok := desired[allowedExtensionsSettingKey]
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
		newValue = v
	}
	return r.enforceSingle(ctx, cat, tgt, ep, newValue)
}

// enforceSingle is the single-VALUE convergence path (any Writer without the
// managed multi-key API): the ~/.npmrc block writer, whose whole managed block is
// one opaque value, and the degraded VS Code Writer, which manages exactly the
// extensions.allowed key. Ownership is recorded under one WrittenSettings entry
// keyed by r.ownershipKey().
func (r *Reconciler) enforceSingle(ctx context.Context, cat, tgt string, ep EffectivePolicy, newValue string) error {
	ownKey := r.ownershipKey()

	// 2. Read ownership state and validate it before any convergence return.
	prev, hadPrev := r.readState(cat)
	if r.PrepareWrite != nil {
		if err := r.PrepareWrite(prev, hadPrev); err != nil {
			_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
			return fmt.Errorf("devicepolicy: enforce: prepare write %s: %w", r.Writer.Location(), err)
		}
	}
	prevWritten := prev.WrittenSettings[ownKey]
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
	if converged && prev.AppliedHash == ep.Hash && (r.OwnershipStateValue == "" || prevWritten == r.stateValue(newValue)) {
		r.logf("devicepolicy: policy already applied (hash unchanged) - no write")
		return r.report(ctx, cat, tgt, StateCompliant, ep.Hash)
	}

	// The full-state convergence seam (npm) proves the exact desired block is on
	// disk, effective, and correctly owned — a strictly stronger fact than body
	// equality — yet the state file does not carry this hash. That happens when our
	// record is stale or was removed by hand, or when the cycle that applied it
	// resolved a different home for the state file (a root daemon and the user's own
	// cycle do not always agree on one). Adopt the on-disk state rather than churn a
	// redundant rewrite or misreport it as drift, and report compliant. Best-effort:
	// the block is already applied, so a persist hiccup only defers the record one
	// cycle. Gated on the Converged seam so the settings.json path (body equality)
	// is byte-identical to before.
	if converged && r.Converged != nil {
		state, serr := r.completedState(prev, hadPrev, ep.Hash, ownKey, newValue)
		if serr != nil {
			_ = r.report(ctx, cat, tgt, StateVerificationFailed, "")
			return fmt.Errorf("devicepolicy: complete adopted state: %w", serr)
		}
		if perr := r.persistState(cat, state); perr != nil {
			r.warnf("could not record ownership at %s: %v; file unchanged", r.Writer.Location(), perr)
		}
		r.logf("devicepolicy: %s already holds the desired block (adopted) — no write", r.Writer.Location())
		return r.report(ctx, cat, tgt, StateCompliant, ep.Hash)
	}

	// 4. Drift: the agent wrote a value before, and what is on disk now is not
	// it (edited or removed — typically the user hand-editing settings.json).
	// Enforcement means converging it back; the distinct state lets the
	// backend surface that it happened.
	drifted := hadPrev && prevWritten != "" && (!present || onDisk != prevWritten)
	if (r.OwnershipStateValue != "" || r.FullStateDrift) && r.Converged != nil {
		// A fixed marker proves ownership, not content equality. Under the same
		// desired hash, failed target-specific convergence is drift; a new hash is
		// a desired-policy transition.
		drifted = hadPrev && prevWritten != "" && prev.AppliedHash == ep.Hash && !converged
	}
	if drifted {
		r.logf("devicepolicy: %s diverged from the recorded written value → re-applying (drift)", r.Writer.Location())
	}
	// Preflight: prove the ownership store is writable BEFORE mutating the
	// settings file. An enforced value with no ownership record is orphaned — a
	// later clear refuses to remove it. Re-persisting the current state is a
	// meaning-preserving writability probe.
	if perr := r.probeOwnershipState(cat, prev, hadPrev); perr != nil {
		_ = r.report(ctx, cat, tgt, StateWriteFailed, "")
		return fmt.Errorf("devicepolicy: enforce: ownership state not writable, refusing to write policy: %w", perr)
	}

	// Merge-write + readback.
	rb, werr := r.Writer.Write(newValue)
	if werr != nil {
		// write_failed by default; verification_failed only when the writer landed
		// bytes it could neither verify nor roll back (on-disk state indeterminate).
		_ = r.report(ctx, cat, tgt, classifyWriteError(werr), "")
		return fmt.Errorf("devicepolicy: enforce: write %s: %w", r.Writer.Location(), werr)
	}
	readbackMatch := rb == newValue
	if !readbackMatch {
		r.warnf("readback mismatch at %s; policy not verified", r.Writer.Location())
	}

	// Ownership is recorded on EVERY successful write. By default it records the
	// rendered value; a fixed-state marker component records its non-secret
	// identity instead and delegates exact content checks to Converged. On a
	// readback mismatch the write may still have landed, so the record is retained
	// for next-cycle recovery.
	stateRecord, stateErr := r.completedState(prev, hadPrev, ep.Hash, ownKey, newValue)
	if stateErr == nil {
		stateErr = r.persistState(cat, stateRecord)
	}
	if stateErr != nil {
		// The write happened but ownership couldn't be recorded — undo it so no
		// unrecorded value is left behind. The rollback outcome decides the state:
		// cleanly undone → write_failed; restore failed/aborted → verification_failed.
		state, rbErr := r.rollback(onDisk, present)
		if rbErr != nil {
			r.warnf("rollback at %s failed: %v", r.Writer.Location(), rbErr)
		}
		_ = r.report(ctx, cat, tgt, state, "")
		return fmt.Errorf("devicepolicy: enforce: update state: %w", stateErr)
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
	prev, hadPrev := r.readState(cat)
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
	if perr := r.probeOwnershipState(cat, prev, hadPrev); perr != nil {
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
	// preserve key asserts no ownership this cycle (omitted).
	ownedAfter := make(map[string]string, len(desired))
	for key, v := range desired {
		ownedAfter[key] = v
	}
	if err := r.persistState(cat, AppliedTargetState{
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
	if !readbackMatch {
		r.warnf("readback mismatch at %s; policy not verified", r.Writer.Location())
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

// compactPolicySettings decodes the raw policy object into the VS Code settings
// map (setting id → compiled value) and compacts every value to its canonical
// comparison form. Compaction normalizes whitespace so on-disk readback and
// next-cycle ownership compare byte-exactly regardless of the backend's wire
// formatting; member order within each value is preserved (it is the backend's
// canonical, hashed order). The raw policy travels category-agnostically (npm's
// object is not a settings map), so the decode lives here rather than in the
// fetcher.
func compactPolicySettings(policy json.RawMessage) (map[string]string, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(policy, &settings); err != nil {
		return nil, fmt.Errorf("devicepolicy: decode settings map: %w", err)
	}
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
// value the agent last wrote, skipping empty entries. WrittenSettings is the only
// ownership field: every managed key — the allowlist included — and every
// single-value lane's one entry live in it. Drift detection and ownership-gated
// removal act only on keys the agent actually wrote. A pre-collapse state file
// carrying only the retired written_value key decodes to an empty map, i.e.
// "owns nothing", and the next enforce re-converges and re-records (pre-GA — no
// shipped state to migrate).
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
		_, err = r.Writer.Clear()
	}
	if err != nil {
		r.warnf("rollback at %s failed: %v", r.Writer.Location(), err)
	}
}

// report submits a write-path compliance report.
func (r *Reconciler) report(ctx context.Context, cat, tgt, state, appliedHash string) error {
	rep := ComplianceReport{
		Category:    cat,
		Target:      tgt,
		State:       state,
		AppliedHash: appliedHash,
	}
	if cat == CategoryPackageConfig && tgt == TargetNPM && (state == StateCompliant || state == StateDriftDetected) {
		observed, err := npmCompliantObserved(r.renderedValue)
		if err != nil {
			return err
		}
		if observed != nil {
			rep.Observed, err = json.Marshal(observed)
			if err != nil {
				return err
			}
		}
	}
	return r.sendReport(ctx, rep)
}

// sendReport stamps the shared fields (agent version, platform,
// EvaluatedEnforcement, and npm's fetched EvaluatedHash) and submits. Callers
// fill Category/Target/State and the lane-specific field: AppliedHash for the
// write path, Observed for MDM.
func (r *Reconciler) sendReport(ctx context.Context, rep ComplianceReport) error {
	if rep.EvaluatedHash == "" {
		rep.EvaluatedHash = r.evaluatedHash
	}
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
