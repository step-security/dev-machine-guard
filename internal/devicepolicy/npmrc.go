package devicepolicy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

// This file backs the package_config#npm policy category: it converges a
// managed block inside the console user's ~/.npmrc so npm (and the pnpm / yarn
// v1 / bun tools that read the same file) resolves packages through the
// tenant's StepSecurity secure registry and/or a policy-managed set of scalar
// npm settings (a third-party default or scoped registry with an
// environment-referenced token, plus ordinary options). It parallels the VS Code
// settings.json writer (settings_writer.go) but the target is a file the agent
// may run as root against a user-owned tree, so every file operation goes
// through os.Root rather than atomicfile — see the security notes on
// NPMRCWriter below.

// Ownership markers for the managed block. The BEGIN/END pair delimits exactly
// the bytes the agent owns; nothing outside it is ever rewritten. BEGIN carries
// the "-- managed by dmg" suffix so it is distinguishable from the MDM script's
// own header (which ends "-- managed by mdm") — the two lanes must never claim
// each other's block.
const (
	npmrcBeginMarker = "# BEGIN StepSecurity Secure Registry -- managed by dmg"
	npmrcEndMarker   = "# END StepSecurity Secure Registry"
	// npmrcMDMMarker is the header the published MDM remediation script writes.
	// The probe treats its presence (outside our block) as the first signal
	// that the MDM lane is managing this file.
	npmrcMDMMarker = "# StepSecurity Secure Registry -- managed by mdm"
	// npmrcMDMBeginMarker and npmrcMDMEndMarker bound the variable-size block
	// emitted by MDM when npm settings are present.
	npmrcMDMBeginMarker = "# BEGIN StepSecurity Secure Registry -- managed by mdm"
	npmrcMDMEndMarker   = "# END StepSecurity Secure Registry -- managed by mdm"
)

// NPMOwnedKey is the WrittenSettings key the npm lane records ownership under.
const NPMOwnedKey = "npmrc"

// NPMOwnershipValue is the secret-free identity persisted for marker-owned npm
// configuration. Exact content and effectiveness are verified from disk.
const NPMOwnershipValue = "dmg_marker_v1"

// The observed-bag keys and verdicts of the MDM verify-only report. They are
// WIRE-PERMANENT: the backend accepts the base three-key StepSecurity shape, the
// four-key combined shape, and the two-key settings-only shape (ecosystem plus
// settings_status). Both secret-bearing domains are reduced to status enums
// on-device.
const (
	observedKeyEcosystem   = "ecosystem"
	observedKeyRegistryURL = "registry_url"
	// #nosec G101 -- a JSON field NAME, not a credential; the value it carries is
	// one of the three verdicts below and never token material.
	observedKeyAuthTokenStatus = "auth_token_status"
	observedKeySettingsStatus  = "settings_status"

	authTokenMatch    = "match"
	authTokenMismatch = "mismatch"
	authTokenAbsent   = "absent"
	settingsMatch     = "match"
	settingsMismatch  = "mismatch"
	settingsAbsent    = "absent"
)

// npmrcMaxRegistryURLBytes caps the observed registry_url before transmission.
// The value is read off a user-writable file and the backend rejects anything
// longer, so an oversize value is refused on-device rather than sent to fail
// there.
const npmrcMaxRegistryURLBytes = 2048

// npmrcDMGPrefix is prepended to a user's active bare `registry=` line when the
// managed block is applied, so the original survives (commented) and can be
// restored on clear. It is deliberately distinct from the MDM script's
// `# [stepsecurity] ` prefix: each lane only ever un-comments its own prefix,
// so they cannot resurrect each other's work.
const (
	npmrcDMGPrefix = "# [stepsecurity-dmg] "
	npmrcMDMPrefix = "# [stepsecurity] "
)

const (
	// npmrcMaxBytes caps the file the writer will read, snapshot, back up, or
	// transform. A pathological multi-megabyte .npmrc must not balloon memory
	// or the backup set; exceeding it is a structural refusal, not a transform.
	npmrcMaxBytes = 1 << 20
	// npmrcMaxRenderedBytes caps the complete rendered body. Anything past
	// this is a malformed policy, not a block to write.
	npmrcMaxRenderedBytes     = 4 << 10
	npmrcMaxSettings          = 50
	npmrcMaxSettingKeyBytes   = 512
	npmrcMaxSettingValueBytes = 4096
	// npmrcMaxKeyBytes / npmrcMaxSerialBytes bound the two variable-length
	// fields the renderer accepts.
	npmrcMaxKeyBytes    = 256
	npmrcMaxSerialBytes = 128
	// npmrcMaxHostBytes is the RFC 1123 hostname length ceiling.
	npmrcMaxHostBytes = 253
	// npmrcMaxSymlinkDepth bounds the .npmrc symlink chain the resolver will
	// follow before declaring a loop.
	npmrcMaxSymlinkDepth = 8
	// npmrcMaxBackups is the retained backup count beside the resolved leaf.
	npmrcMaxBackups = 3
	// npmrcFileMode is the mode every file the writer creates or rewrites lands
	// with. A token-bearing file is never group/other-readable.
	npmrcFileMode os.FileMode = 0o600
)

// Structural errors. Every "this target cannot be enforced" condition wraps
// ErrTargetUnusable so the reconciler can classify the whole class as
// write_failed regardless of whether a read or a write surfaced it, while a
// plain permission-denied / transient I/O error (which does not wrap it) stays
// verification_failed. ErrNoTargetUser is separate: it means there is no
// enforceable user on this machine state (LocalSystem, a non-interactive
// Windows session, or root with no resolvable GUI user), which the reconciler
// reports as policy_not_applied, not write_failed.
var (
	ErrTargetUnusable  = errors.New("npmrc: target unusable")
	ErrNoTargetUser    = errors.New("npmrc: no enforceable target user")
	ErrAbsoluteSymlink = fmt.Errorf("npmrc: .npmrc is an absolute symlink: %w", ErrTargetUnusable)
	ErrSymlinkLoop     = fmt.Errorf("npmrc: .npmrc symlink chain too deep: %w", ErrTargetUnusable)
	ErrDanglingSymlink = fmt.Errorf("npmrc: .npmrc symlink target does not exist: %w", ErrTargetUnusable)
)

// ErrWriteUnverified means a mutating op landed new bytes it could then neither
// verify NOR roll back — the post-rename identity re-check failed and the restore
// to the pre-state also failed. On-disk state is therefore indeterminate (not the
// clean "write failed, disk untouched" case), which the reconciler classifies as
// verification_failed rather than write_failed. It deliberately does NOT wrap
// ErrTargetUnusable, so the write-path classifier routes it to verification_failed.
var ErrWriteUnverified = errors.New("npmrc: write could not be verified or rolled back")

// NPMRCWriter converges the managed block in one user's ~/.npmrc. It satisfies
// the Writer interface (Read/Write/Clear/Location) and adds the concrete-type
// methods the reconciler seams need — Converged, ProbeExpected, RestoreSnapshot
// — none of which fit the settings.json-shaped interface.
//
// Threat model: the agent can run as root (macOS LaunchDaemon) against a home
// directory the target user controls. A user who can plant symlinks or swap
// directory entries mid-operation must not be able to steer a root-owned write,
// a root read, or a token-bearing backup outside their own regular .npmrc. The
// writer therefore anchors every operation to a directory file descriptor via
// os.Root, resolves the .npmrc symlink chain explicitly, pins the resolved
// parent with a second os.Root, re-verifies file identity after every open, and
// performs all metadata changes on open handles (never by path). It never uses
// atomicfile, whose predictable, symlink-following backup names are exactly the
// attack this design closes.
type NPMRCWriter struct {
	exec       executor.Executor
	targetUser *user.User
	home       string
	uid, gid   int // parsed from targetUser; only meaningful where enforcePOSIXMetadata

	root       *os.Root // directory fd over the target home, held for the writer's lifetime
	owners     ownerReader
	secureHome *secureuserfile.Home
	logf       func(format string, args ...any)

	// pending is the memory-only snapshot captured at the start of the last
	// mutating op (Write/Clear) and retained on success so a later
	// RestoreSnapshot can undo it. It is never persisted.
	pending *pendingSnapshot

	ownedCreated bool
	ownedLeaf    string
}

// pendingSnapshot is the pre-mutation state one Write or Clear can roll back to.
type pendingSnapshot struct {
	existed bool
	data    []byte
	mode    os.FileMode
	// leaf is the resolved leaf path relative to the home root at capture time.
	// RestoreSnapshot re-resolves and refuses to write if the chain now points
	// somewhere else.
	leaf string
	// committed is the identity (post-rename FileInfo) of the file this writer
	// last left at the leaf. RestoreSnapshot requires the on-disk leaf to still be
	// SameFile as this before reverting: a relative path can be unchanged while the
	// parent directory or the leaf inode was swapped underneath it, and reverting
	// into that would write stale bytes into someone else's file.
	committed os.FileInfo
	removed   bool
}

// ownerReader reads the uid/gid owning an open file. enforcePOSIXMetadata
// platforms return the real owner; elsewhere (Windows, ACL model) enforced is
// false and the caller skips every ownership decision. Tests inject a fake to
// exercise wrong-owner branches without root.
type ownerReader interface {
	ownerUIDGID(f *os.File) (uid, gid uint32, enforced bool, err error)
}

// NewNPMRCWriter resolves the console user and opens a directory fd over their
// home. It returns ErrNoTargetUser when this machine state has no enforceable
// user (Windows LocalSystem or a non-interactive session, root with no GUI
// user); any other error is an infrastructure failure (home unresolvable or
// unopenable). The caller defers Close to release the directory fd.
func NewNPMRCWriter(exec executor.Executor) (*NPMRCWriter, error) {
	secureHome, err := secureuserfile.OpenUserHome(exec)
	if err != nil {
		if errors.Is(err, secureuserfile.ErrNoTargetUser) {
			return nil, fmt.Errorf("%w: %v", ErrNoTargetUser, err)
		}
		return nil, err
	}
	u := secureHome.User()
	if u == nil || u.HomeDir == "" {
		_ = secureHome.Close()
		return nil, fmt.Errorf("npmrc: resolved user has no home directory")
	}

	root, err := os.OpenRoot(u.HomeDir)
	if err != nil {
		_ = secureHome.Close()
		return nil, fmt.Errorf("npmrc: open home root %q: %w", u.HomeDir, err)
	}

	w := &NPMRCWriter{
		exec:       exec,
		targetUser: u,
		home:       u.HomeDir,
		root:       root,
		owners:     newOwnerReader(),
		secureHome: secureHome,
	}
	if enforcePOSIXMetadata {
		// Uid/Gid are numeric on POSIX. A parse failure means we cannot chown to
		// the target user, which defeats the whole point of resolving them.
		uid, uerr := strconv.Atoi(u.Uid)
		gid, gerr := strconv.Atoi(u.Gid)
		if uerr != nil || gerr != nil {
			_ = root.Close()
			_ = secureHome.Close()
			return nil, fmt.Errorf("npmrc: target user %q has non-numeric uid/gid", u.Username)
		}
		w.uid, w.gid = uid, gid
	}
	return w, nil
}

// Close releases the home directory fd. Safe to call more than once.
func (w *NPMRCWriter) Close() error {
	if w == nil || w.root == nil {
		return nil
	}
	err := w.root.Close()
	w.root = nil
	if w.secureHome != nil {
		err = errors.Join(err, w.secureHome.Close())
		w.secureHome = nil
	}
	w.pending = nil
	return err
}

// Location is a human-readable target description for logs. It never includes
// file contents or key material.
func (w *NPMRCWriter) Location() string {
	return filepath.Join(w.home, ".npmrc") + " [npm secure registry]"
}

// SetLogf installs an optional diagnostic sink for non-fatal events (a missing
// END marker stripped to EOF, a backup-rotation prune failure, a snapshot
// restore that aborted). It is never handed file contents or key material.
func (w *NPMRCWriter) SetLogf(logf func(format string, args ...any)) { w.logf = logf }

// CompleteState records only non-secret facts needed for exact restoration.
func (w *NPMRCWriter) CompleteState(previous AppliedTargetState, hadPrevious bool, current *AppliedTargetState) error {
	current.FileCreated = previous.FileCreated
	current.ResolvedPath = previous.ResolvedPath
	if w.pending != nil {
		if !hadPrevious {
			current.FileCreated = !w.pending.existed
		}
		current.ResolvedPath = w.pending.leaf
		return nil
	}
	rt, err := w.resolveLeaf()
	if err != nil {
		return err
	}
	defer rt.close()
	current.ResolvedPath = rt.rel
	return nil
}

// PrepareClear pins the target and creation fact recorded by apply.
func (w *NPMRCWriter) PrepareClear(previous AppliedTargetState, hadPrevious bool) error {
	if hadPrevious && previous.FileCreated && previous.ResolvedPath == "" {
		return fmt.Errorf("npmrc: created-file ownership has no resolved target: %w", ErrTargetUnusable)
	}
	w.ownedCreated = hadPrevious && previous.FileCreated
	w.ownedLeaf = previous.ResolvedPath
	return nil
}

func (w *NPMRCWriter) log(format string, args ...any) {
	if w.logf != nil {
		w.logf(format, args...)
	}
}

// ---------------------------------------------------------------------------
// Symlink-chain resolution
// ---------------------------------------------------------------------------

// resolvedTarget is the outcome of walking the ~/.npmrc symlink chain: a child
// os.Root pinned at the resolved leaf's real parent directory plus the leaf's
// basename within it. Every subsequent operation uses (child, base) so a swap
// of an ancestor directory after resolution cannot redirect the open or rename
// — a directory fd references the original directory even if it is later moved.
type resolvedTarget struct {
	child      *os.Root // caller closes
	base       string   // leaf basename within child
	rel        string   // leaf path relative to the home root (parentDir/base)
	viaSymlink bool     // the leaf was reached by following at least one link
	existed    bool     // the leaf exists (Lstat succeeded)
}

func (rt *resolvedTarget) close() {
	if rt != nil && rt.child != nil {
		_ = rt.child.Close()
	}
}

// resolveLeaf walks the .npmrc chain relative to the home root and pins the
// resolved parent. It rejects, before any file open:
//   - an absolute symlink target (ErrAbsoluteSymlink) — even one pointing back
//     inside the home; enforcing through an absolute link is out of scope;
//   - a raw target ending in a path separator or "/." (ErrTargetUnusable),
//     checked BEFORE cleaning: `.npmrc -> "file/"` fails kernel resolution with
//     ENOTDIR when `file` is not a directory, so npm never reads it; cleaning
//     would erase that evidence and let a bogus write report success;
//   - a chain deeper than npmrcMaxSymlinkDepth (ErrSymlinkLoop);
//   - a dangling target (ErrDanglingSymlink);
//   - a chain escaping the home (os.Root refuses; surfaces as ErrTargetUnusable).
func (w *NPMRCWriter) resolveLeaf() (*resolvedTarget, error) {
	cur := ".npmrc"
	viaSymlink := false

	for depth := 0; ; depth++ {
		if depth > npmrcMaxSymlinkDepth {
			return nil, ErrSymlinkLoop
		}
		fi, err := w.root.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			if viaSymlink {
				// A link resolved to a name that does not exist.
				return nil, ErrDanglingSymlink
			}
			// The plain .npmrc simply does not exist yet.
			return w.pin(cur, false, false)
		}
		if err != nil {
			return nil, fmt.Errorf("npmrc: lstat %q: %w", cur, err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			// Regular (or other) leaf reached.
			return w.pin(cur, viaSymlink, true)
		}

		target, err := w.root.Readlink(cur)
		if err != nil {
			return nil, fmt.Errorf("npmrc: readlink %q: %w", cur, err)
		}
		if isAbsSymlinkTarget(target) {
			return nil, ErrAbsoluteSymlink
		}
		if endsInSeparatorOrDot(target) {
			return nil, fmt.Errorf("npmrc: symlink target %q is directory-shaped: %w", target, ErrTargetUnusable)
		}
		next := filepath.Clean(filepath.Join(filepath.Dir(cur), target))
		if next == ".." || strings.HasPrefix(next, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("npmrc: symlink escapes home: %w", ErrTargetUnusable)
		}
		cur = next
		viaSymlink = true
	}
}

// pin opens a child os.Root at the resolved leaf's parent directory so every
// later op is anchored to that directory fd.
func (w *NPMRCWriter) pin(rel string, viaSymlink, existed bool) (*resolvedTarget, error) {
	parent := filepath.Dir(rel)
	base := filepath.Base(rel)
	if base == "." || base == ".." || strings.ContainsRune(base, filepath.Separator) {
		return nil, fmt.Errorf("npmrc: resolved leaf %q is not a basename: %w", rel, ErrTargetUnusable)
	}
	child, err := w.root.OpenRoot(parent)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			// The parent exists but is unreadable (permissions / transient). That is
			// not a structural refusal: surface it as a plain error so the reconciler
			// classifies it verification_failed and retries, rather than the
			// write_failed reserved for a target that can never be enforced.
			return nil, fmt.Errorf("npmrc: pin parent %q: %w", parent, err)
		}
		// A parent that is itself a symlink escaping the home, or a non-directory
		// component, lands here: structurally unenforceable.
		return nil, fmt.Errorf("npmrc: pin parent %q: %w", parent, ErrTargetUnusable)
	}
	return &resolvedTarget{child: child, base: base, rel: rel, viaSymlink: viaSymlink, existed: existed}, nil
}

// isAbsSymlinkTarget reports whether a raw link target is absolute. filepath.IsAbs
// covers POSIX "/..." and Windows drive/UNC forms; a leading separator is caught
// explicitly so a POSIX target evaluated on any host is still rejected.
func isAbsSymlinkTarget(target string) bool {
	if target == "" {
		return false
	}
	if target[0] == '/' || target[0] == filepath.Separator {
		return true
	}
	return filepath.IsAbs(target)
}

// endsInSeparatorOrDot reports whether a raw (uncleaned) symlink target is
// directory-shaped — ending in a separator or in "/." — the GO-2026-4970
// trigger the resolver refuses before filepath.Clean can erase the evidence.
func endsInSeparatorOrDot(target string) bool {
	if target == "" {
		return false
	}
	last := target[len(target)-1]
	if last == '/' || last == filepath.Separator {
		return true
	}
	if target == "." || strings.HasSuffix(target, "/.") {
		return true
	}
	if filepath.Separator != '/' && strings.HasSuffix(target, string(filepath.Separator)+".") {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Bounded, identity-checked reads
// ---------------------------------------------------------------------------

// readCurrent opens the resolved leaf and returns its bytes, existence, and
// mode. It enforces the full open-identity discipline: a Lstat pre-screen that
// fast-fails an obvious FIFO/device, an O_NONBLOCK open so a FIFO cannot block
// the daemon, a post-open regular-file check, a re-Lstat + SameFile identity
// check to close the resolve→open swap race, an ownership rule (the resolved
// leaf must be owned by the target user — root-owned included is refused, since
// this writer always chowns its own output to that user and so never leaves a
// root-owned leaf behind), and a size cap. An absent file returns
// (nil, false, 0, nil).
func (w *NPMRCWriter) readCurrent(rt *resolvedTarget) ([]byte, bool, os.FileMode, error) {
	li, err := rt.child.Lstat(rt.base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, 0, nil
	}
	if err != nil {
		return nil, false, 0, fmt.Errorf("npmrc: lstat leaf %q: %w", rt.base, err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		// The chain was resolved to a regular leaf; a symlink here means the
		// entry was swapped after resolution.
		return nil, false, 0, fmt.Errorf("npmrc: leaf %q became a symlink: %w", rt.base, ErrTargetUnusable)
	}
	if !li.Mode().IsRegular() {
		return nil, false, 0, fmt.Errorf("npmrc: leaf %q is not a regular file: %w", rt.base, ErrTargetUnusable)
	}

	f, err := rt.child.OpenFile(rt.base, os.O_RDONLY|nonblockOpenFlag(), 0)
	if err != nil {
		return nil, false, 0, fmt.Errorf("npmrc: open leaf %q: %w", rt.base, err)
	}
	defer f.Close()

	hi, err := f.Stat()
	if err != nil {
		return nil, false, 0, fmt.Errorf("npmrc: stat leaf handle: %w", err)
	}
	if !hi.Mode().IsRegular() {
		return nil, false, 0, fmt.Errorf("npmrc: opened leaf %q is not a regular file: %w", rt.base, ErrTargetUnusable)
	}

	// Re-Lstat through the pinned child and require the same inode: an in-root
	// symlink swapped in between the pre-screen and the open would have been
	// followed by os.Root to another file, which this rejects.
	li2, err := rt.child.Lstat(rt.base)
	if err != nil {
		return nil, false, 0, fmt.Errorf("npmrc: re-lstat leaf %q: %w", rt.base, err)
	}
	if li2.Mode()&fs.ModeSymlink != 0 || !li2.Mode().IsRegular() || !os.SameFile(li2, hi) {
		return nil, false, 0, fmt.Errorf("npmrc: leaf %q changed during open: %w", rt.base, ErrTargetUnusable)
	}

	if err := w.checkOwner(f, rt); err != nil {
		return nil, false, 0, err
	}

	data, err := io.ReadAll(io.LimitReader(f, npmrcMaxBytes+1))
	if err != nil {
		return nil, false, 0, fmt.Errorf("npmrc: read leaf %q: %w", rt.base, err)
	}
	if len(data) > npmrcMaxBytes {
		return nil, false, 0, fmt.Errorf("npmrc: leaf %q exceeds %d bytes: %w", rt.base, npmrcMaxBytes, ErrTargetUnusable)
	}
	return data, true, hi.Mode().Perm(), nil
}

// checkOwner enforces the ownership rule for an existing target: on POSIX the
// resolved leaf must be owned by the target user, full stop. A leaf owned by
// anyone else — root included — is refused. A user could otherwise point .npmrc
// at a root-owned file in their home and have the daemon read it, copy its bytes
// into a user-readable backup, and rewrite it user-owned, disclosing and mutating
// a file they could not otherwise touch. And since this writer always chowns its
// own output to the target user (applyMetadata), a root-owned leaf is never one
// it left behind, so there is nothing legitimate to tolerate. On Windows
// (enforced=false) ownership is governed by ACLs and this check is skipped.
func (w *NPMRCWriter) checkOwner(f *os.File, rt *resolvedTarget) error {
	if w.secureHome != nil {
		if err := w.secureHome.VerifyOwner(f, rt.base); err != nil {
			return fmt.Errorf("npmrc: %w", err)
		}
		return nil
	}
	uid, _, enforced, err := w.owners.ownerUIDGID(f)
	if err != nil {
		return fmt.Errorf("npmrc: read owner: %w", err)
	}
	if !enforced {
		return nil
	}
	if uid == uint32(w.uid) { // #nosec G115 -- w.uid is strconv.Atoi of a POSIX uid (os/user), always non-negative and within uint32
		return nil
	}
	return fmt.Errorf("npmrc: leaf %q owned by uid %d, not target user: %w", rt.base, uid, ErrTargetUnusable)
}

// Read returns the managed block body (canonicalized) and whether it is
// present. It satisfies the Writer interface; the reconciler uses Converged
// (not this) for the real idempotency decision.
func (w *NPMRCWriter) Read() (string, bool, error) {
	rt, err := w.resolveLeaf()
	if err != nil {
		return "", false, err
	}
	defer rt.close()

	data, existed, _, err := w.readCurrent(rt)
	if err != nil {
		return "", false, err
	}
	if !existed {
		return "", false, nil
	}
	body, present := extractManagedBody(string(data))
	return body, present, nil
}

// ---------------------------------------------------------------------------
// Write / Clear (the §3 rewrite and clear algorithms)
// ---------------------------------------------------------------------------

// Write applies the rewrite transform for the given rendered block body and
// returns the block body read back from disk. The op is transactional: it
// snapshots the pre-state first, and any failure after the rename self-restores
// before returning. On success the snapshot is retained for a later
// RestoreSnapshot.
func (w *NPMRCWriter) Write(value string) (string, error) {
	rt, err := w.resolveLeaf()
	if err != nil {
		return "", err
	}
	defer rt.close()

	cur, existed, mode, err := w.readCurrent(rt)
	if err != nil {
		return "", err
	}
	if !existed {
		mode = npmrcFileMode
	}

	next, err := w.rewriteContent(cur, value)
	if err != nil {
		return "", err
	}

	snap := &pendingSnapshot{existed: existed, data: cur, mode: mode, leaf: rt.rel}
	if existed {
		// Preserve the pre-rewrite file before overwriting it. Best-effort:
		// backup failure must not block enforcement.
		if err := w.backup(rt, cur); err != nil {
			w.log("npmrc: backup of %q failed: %v", rt.base, err)
		}
	}
	out, err := w.commit(rt, next, npmrcFileMode)
	if err != nil {
		if out.renamed {
			// New bytes landed but their identity could not be confirmed. Revert to
			// the pre-state so an unverified write is never left behind; if that
			// revert also fails, disk is indeterminate (ErrWriteUnverified).
			return "", w.afterFailedRollback(rt, snap, err, "commit verification")
		}
		return "", err
	}
	snap.committed = out.committed

	body, err := w.readbackBody(rt)
	if err != nil {
		// The write landed but readback failed — undo it so disk is not left in an
		// unverified state (and flag an indeterminate disk if the undo fails too).
		return "", w.afterFailedRollback(rt, snap, err, "readback")
	}
	w.pending = snap
	return body, nil
}

// Clear removes the managed block and restores the user's commented-out
// `registry=` lines. It carries the same transactional and metadata guarantees
// as Write and never deletes the file. The returned bool reports whether the
// file actually changed; the two no-op paths below return false.
func (w *NPMRCWriter) Clear() (bool, error) {
	rt, err := w.resolveLeaf()
	if err != nil {
		return false, err
	}
	defer rt.close()
	if w.ownedLeaf != "" && rt.rel != w.ownedLeaf {
		return false, fmt.Errorf("npmrc: resolved target changed from %q to %q: %w", w.ownedLeaf, rt.rel, ErrTargetUnusable)
	}

	cur, existed, mode, err := w.readCurrent(rt)
	if err != nil {
		return false, err
	}
	if !existed {
		// Nothing to clear; leave the (absent) file alone. A backup from an earlier
		// cycle can still hold a managed block, and with the live file gone this is
		// the only path that ever reaches it — so retry the purge here.
		w.purgeBackups(rt)
		return false, nil
	}

	next, err := w.clearContent(cur)
	if err != nil {
		return false, err
	}
	if bytes.Equal(next, cur) {
		// No managed block and no prefixed lines — a no-op that performs no write at
		// all. Nothing of ours is live, so a backup beside the leaf is residue: either
		// an earlier purge that could not unlink it, or a block someone removed by
		// hand. Retry the purge; the clear itself stays a no-op.
		w.purgeBackups(rt)
		return false, nil
	}
	if w.ownedCreated && len(next) == 0 {
		if enforcePOSIXMetadata && mode.Perm() != npmrcFileMode {
			return false, fmt.Errorf("npmrc: created target metadata changed: %w", ErrTargetUnusable)
		}
		if secure, err := w.metadataSecure(rt); err != nil || !secure {
			if err == nil {
				err = ErrTargetUnusable
			}
			return false, fmt.Errorf("npmrc: created target metadata changed: %w", err)
		}
		info, err := rt.child.Lstat(rt.base)
		if err != nil {
			return false, fmt.Errorf("npmrc: inspect created target before remove: %w", err)
		}
		if err := rt.child.Remove(rt.base); err != nil {
			return false, fmt.Errorf("npmrc: remove created target: %w", err)
		}
		w.pending = &pendingSnapshot{existed: true, data: cur, mode: mode, leaf: rt.rel, committed: info, removed: true}
		w.purgeBackups(rt)
		w.syncDir(rt)
		return true, nil
	}

	snap := &pendingSnapshot{existed: true, data: cur, mode: mode, leaf: rt.rel}
	if err := w.backup(rt, cur); err != nil {
		w.log("npmrc: backup of %q failed: %v", rt.base, err)
	}
	out, err := w.commit(rt, next, npmrcFileMode)
	if err != nil {
		if out.renamed {
			// The cleared bytes landed but unverified — revert to the pre-clear state
			// rather than leave an unverified file; a failed revert leaves disk
			// indeterminate (ErrWriteUnverified). The backup stays as a recovery aid.
			return false, w.afterFailedRollback(rt, snap, err, "clear commit verification")
		}
		return false, err
	}
	snap.committed = out.committed
	w.pending = snap
	// The clear succeeded, so every backup beside the leaf is now stale — and the
	// one taken moments ago holds the very token this clear exists to revoke.
	// Removing the managed block while leaving a readable copy of it in a sibling
	// would defeat offboarding, so drop our own backups here. Rollback is
	// unaffected: RestoreSnapshot reverts from snap's in-memory bytes.
	w.purgeBackups(rt)
	return true, nil
}

// RestoreSnapshot reverts the last successful Write/Clear. It re-resolves the
// chain and refuses to write if the leaf now differs from the snapshot's — either
// by relative path (the user re-pointed .npmrc) or by identity (the parent or
// leaf inode was swapped under an unchanged path) — surfacing that as an error the
// reconciler maps to verification_failed. The snapshot is CONSUMED: a restore is
// attempted at most once, so a second call cannot re-run against a stale leaf.
// Calling it with no pending snapshot is an error.
func (w *NPMRCWriter) RestoreSnapshot() error {
	if w.pending == nil {
		return errors.New("npmrc: no snapshot to restore")
	}
	snap := w.pending
	w.pending = nil

	var rt *resolvedTarget
	var err error
	if snap.removed {
		rt, err = w.pin(snap.leaf, false, false)
	} else {
		rt, err = w.resolveLeaf()
	}
	if err != nil {
		return err
	}
	defer rt.close()
	if rt.rel != snap.leaf {
		return fmt.Errorf("npmrc: chain moved from %q to %q; refusing to restore: %w", snap.leaf, rt.rel, ErrTargetUnusable)
	}
	if snap.removed {
		if _, err := rt.child.Lstat(rt.base); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = ErrTargetUnusable
			}
			return fmt.Errorf("npmrc: removed target changed before restore: %w", err)
		}
	} else if err := w.verifyCommitted(rt, snap); err != nil {
		return err
	}
	return w.restoreFrom(rt, snap)
}

// verifyCommitted confirms the leaf on disk is still the exact file this writer
// committed (SameFile against the snapshot's recorded identity) before a restore
// touches it. A relative path can be unchanged while the parent directory or the
// leaf has been swapped underneath it; reverting into that would write stale bytes
// into someone else's file. An identity mismatch wraps ErrTargetUnusable.
func (w *NPMRCWriter) verifyCommitted(rt *resolvedTarget, snap *pendingSnapshot) error {
	if snap.committed == nil {
		return nil
	}
	li, err := rt.child.Lstat(rt.base)
	if errors.Is(err, os.ErrNotExist) {
		if !snap.existed {
			// We had created the file and it is already gone — the pre-state is
			// "absent", so there is nothing to revert.
			return nil
		}
		return fmt.Errorf("npmrc: committed leaf %q vanished before restore: %w", rt.base, ErrTargetUnusable)
	}
	if err != nil {
		return fmt.Errorf("npmrc: lstat leaf before restore: %w", err)
	}
	if li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() || !os.SameFile(li, snap.committed) {
		return fmt.Errorf("npmrc: leaf %q changed since it was written; refusing to restore: %w", rt.base, ErrTargetUnusable)
	}
	return nil
}

// restoreFrom writes a snapshot's bytes/existence/mode at an already-resolved
// target. Ownership is not snapshotted: on restore, as on write, the file is
// chowned to the target user (the file should be target-user-owned, and an
// arbitrary prior owner cannot be expressed portably anyway).
func (w *NPMRCWriter) restoreFrom(rt *resolvedTarget, snap *pendingSnapshot) error {
	if !snap.existed {
		// The pre-state was "no file": remove what we created.
		if err := rt.child.Remove(rt.base); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("npmrc: restore-remove %q: %w", rt.base, err)
		}
		return nil
	}
	_, err := w.commit(rt, snap.data, snap.mode)
	return err
}

// afterFailedRollback runs the pre-state restore after a post-rename failure and
// returns the error to surface. If the restore itself fails, on-disk state is
// indeterminate — new bytes landed and could not be reverted — so the returned
// error wraps ErrWriteUnverified (the reconciler reports verification_failed). If
// the restore succeeds, disk is back to the pre-state and the original cause is
// surfaced unchanged (a clean write_failed).
func (w *NPMRCWriter) afterFailedRollback(rt *resolvedTarget, snap *pendingSnapshot, cause error, stage string) error {
	if rerr := w.restoreFrom(rt, snap); rerr != nil {
		w.log("npmrc: restore after %s aborted: %v", stage, rerr)
		return fmt.Errorf("npmrc: %s failed and rollback could not be verified (%v): %w", stage, cause, ErrWriteUnverified)
	}
	return cause
}

// commitOutcome reports what a commit did to disk so a caller can react to a
// partial failure. renamed is true once the temp has been renamed into place —
// even if the post-rename identity re-check then failed, meaning new bytes are on
// disk but unverified. committed is the verified leaf identity on full success
// (nil on any error).
type commitOutcome struct {
	committed os.FileInfo
	renamed   bool
}

// commit writes data to a fresh O_CREATE|O_EXCL temp beside the leaf, sets mode
// and owner on the handle before the rename, renames it into place, then
// re-verifies identity through the pinned child. On Windows the rename is
// best-effort replace semantics rather than a POSIX atomic swap. The returned
// commitOutcome lets Write/Clear tell "failed before the rename, disk untouched"
// apart from "renamed then failed to verify, disk changed" so they can restore.
func (w *NPMRCWriter) commit(rt *resolvedTarget, data []byte, mode os.FileMode) (commitOutcome, error) {
	tmp, tmpName, err := w.createExclusive(rt, rt.base+".dmg-tmp-", "")
	if err != nil {
		return commitOutcome{}, err
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = rt.child.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return commitOutcome{}, fmt.Errorf("npmrc: write temp: %w", err)
	}
	if err := w.applyMetadata(tmp, mode); err != nil {
		_ = tmp.Close()
		return commitOutcome{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return commitOutcome{}, fmt.Errorf("npmrc: fsync temp: %w", err)
	}
	tmpInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return commitOutcome{}, fmt.Errorf("npmrc: stat temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return commitOutcome{}, fmt.Errorf("npmrc: close temp: %w", err)
	}

	if err := rt.child.Rename(tmpName, rt.base); err != nil {
		return commitOutcome{}, fmt.Errorf("npmrc: rename into place: %w", err)
	}
	cleanupTmp = false // the temp name no longer exists after a successful rename

	// Re-verify the just-written leaf is the file we renamed. From here the rename
	// has landed, so a failure reports renamed=true: the caller must restore, not
	// assume disk is untouched.
	li, err := rt.child.Lstat(rt.base)
	if err != nil {
		return commitOutcome{renamed: true}, fmt.Errorf("npmrc: re-lstat after rename: %w", err)
	}
	if li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() || !os.SameFile(li, tmpInfo) {
		return commitOutcome{renamed: true}, fmt.Errorf("npmrc: leaf identity changed across rename: %w", ErrTargetUnusable)
	}
	if secure, err := w.metadataSecure(rt); err != nil || !secure {
		if err == nil {
			err = ErrTargetUnusable
		}
		return commitOutcome{renamed: true}, fmt.Errorf("npmrc: committed metadata verification: %w", err)
	}
	w.syncDir(rt)
	return commitOutcome{committed: li, renamed: true}, nil
}

// createExclusive opens a uniquely named file beside the leaf with
// O_CREATE|O_EXCL — the one open mode os.Root never resolves through a symlink,
// which is what makes a pre-planted file at the name harmless. The random middle
// keeps the name unpredictable; prefix and suffix let callers distinguish temp
// files (`.dmg-tmp-<rand>`) from committed backups (`.dmg-<rand>.bak`).
func (w *NPMRCWriter) createExclusive(rt *resolvedTarget, prefix, suffix string) (*os.File, string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		mid, err := randomSuffix()
		if err != nil {
			return nil, "", fmt.Errorf("npmrc: random suffix: %w", err)
		}
		name := prefix + mid + suffix
		f, err := rt.child.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, npmrcFileMode)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("npmrc: create %q: %w", name, err)
		}
		return f, name, nil
	}
	return nil, "", errors.New("npmrc: could not create a unique temp file")
}

// applyMetadata sets mode and owner on an open handle. Both are POSIX-only:
// Windows inherits ACLs and asserts no POSIX mode, so this is a no-op there.
func (w *NPMRCWriter) applyMetadata(f *os.File, mode os.FileMode) error {
	if w.secureHome != nil {
		if err := w.secureHome.ApplyMetadata(f, mode, false); err != nil {
			return fmt.Errorf("npmrc: apply secure metadata: %w", err)
		}
		if err := w.secureHome.VerifyOwner(f, filepath.Base(f.Name())); err != nil {
			return fmt.Errorf("npmrc: verify secure owner: %w", err)
		}
		secure, err := w.secureHome.MetadataSecure(f, mode)
		if err != nil {
			return fmt.Errorf("npmrc: verify secure metadata: %w", err)
		}
		if !secure {
			return fmt.Errorf("npmrc: insecure metadata after apply: %w", ErrTargetUnusable)
		}
		return nil
	}
	if !enforcePOSIXMetadata {
		return nil
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("npmrc: fchmod: %w", err)
	}
	if err := chownHandle(f, w.uid, w.gid); err != nil {
		return fmt.Errorf("npmrc: fchown: %w", err)
	}
	return nil
}

func (w *NPMRCWriter) metadataSecure(rt *resolvedTarget) (bool, error) {
	if w.secureHome == nil {
		return true, nil
	}
	file, err := rt.child.OpenFile(rt.base, os.O_RDONLY|nonblockOpenFlag(), 0)
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	current, err := rt.child.Lstat(rt.base)
	if err != nil || current.Mode()&fs.ModeSymlink != 0 || !os.SameFile(info, current) {
		return false, fmt.Errorf("npmrc: leaf changed during metadata check: %w", ErrTargetUnusable)
	}
	if err := w.secureHome.VerifyOwner(file, rt.base); err != nil {
		return false, err
	}
	return w.secureHome.MetadataSecure(file, npmrcFileMode)
}

// syncDir best-effort fsyncs the resolved parent directory so the rename is
// durable. A failure here never fails the write.
func (w *NPMRCWriter) syncDir(rt *resolvedTarget) {
	d, err := rt.child.Open(".")
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// readbackBody re-reads the leaf and extracts the managed block body.
func (w *NPMRCWriter) readbackBody(rt *resolvedTarget) (string, error) {
	data, existed, _, err := w.readCurrent(rt)
	if err != nil {
		return "", err
	}
	if !existed {
		return "", nil
	}
	body, _ := extractManagedBody(string(data))
	return body, nil
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

// backup copies the pre-rewrite bytes into a uniquely named, 0600,
// target-user-owned sibling and prunes the set to the newest npmrcMaxBackups.
// The first backup is the pre-policy file (no token); every later one is
// token-bearing, so it carries the same 0600/ownership as the live file. The
// prune is best-effort — a transient extra backup is the same exposure class as
// the file itself and is not worth failing enforcement over.
func (w *NPMRCWriter) backup(rt *resolvedTarget, data []byte) error {
	f, name, err := w.createExclusive(rt, rt.base+".dmg-", ".bak")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = rt.child.Remove(name)
		return fmt.Errorf("npmrc: write backup: %w", err)
	}
	if err := w.applyMetadata(f, npmrcFileMode); err != nil {
		_ = f.Close()
		_ = rt.child.Remove(name)
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("npmrc: close backup: %w", err)
	}
	w.rotateBackups(rt)
	return nil
}

// rotateBackups prunes backups beside the leaf down to the newest npmrcMaxBackups,
// matching basenames only. Committed backups are "<base>.dmg-<rand>.bak"; in-flight
// temp files ("<base>.dmg-tmp-<rand>") carry no ".bak" suffix and are excluded.
//
// The directory is read in bounded batches and pruning happens as candidates are
// seen, so a home stuffed with millions of pattern-matching entries cannot force
// the whole listing into memory: at most one batch plus npmrcMaxBackups names are
// ever held. Only already-returned entries are removed mid-iteration (the current
// candidate or one kept from an earlier batch), which is safe for directory
// enumeration.
func (w *NPMRCWriter) rotateBackups(rt *resolvedTarget) {
	d, err := rt.child.Open(".")
	if err != nil {
		w.log("npmrc: backup rotation open dir failed: %v", err)
		return
	}
	defer d.Close()

	prefix := rt.base + ".dmg-"
	tmpPrefix := rt.base + ".dmg-tmp-"

	type backupFile struct {
		name  string
		mtime int64
	}
	kept := make([]backupFile, 0, npmrcMaxBackups) // ascending mtime; kept[0] is oldest
	remove := func(name string) {
		if err := rt.child.Remove(name); err != nil {
			w.log("npmrc: prune backup %q failed: %v", name, err)
		}
	}
	insert := func(bf backupFile) {
		i := sort.Search(len(kept), func(i int) bool { return kept[i].mtime > bf.mtime })
		kept = append(kept, backupFile{})
		copy(kept[i+1:], kept[i:])
		kept[i] = bf
	}

	for {
		entries, rerr := d.ReadDir(256)
		for _, e := range entries {
			name := e.Name()
			if name == "" || strings.ContainsRune(name, filepath.Separator) {
				continue
			}
			if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".bak") {
				continue
			}
			if strings.HasPrefix(name, tmpPrefix) {
				continue
			}
			li, lerr := rt.child.Lstat(name)
			if lerr != nil || !li.Mode().IsRegular() {
				continue
			}
			bf := backupFile{name: name, mtime: li.ModTime().UnixNano()}
			if len(kept) < npmrcMaxBackups {
				insert(bf)
				continue
			}
			if bf.mtime <= kept[0].mtime {
				remove(bf.name) // older than everything kept
				continue
			}
			remove(kept[0].name) // evict the oldest kept, then keep this newer one
			copy(kept, kept[1:])
			kept = kept[:len(kept)-1]
			insert(bf)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			w.log("npmrc: backup rotation readdir failed: %v", rerr)
			break
		}
	}
}

// purgeBackups removes every committed backup beside the leaf. It runs on every
// Clear that leaves nothing of ours live: the managed block is gone from the live
// file, so a sibling still holding a copy of it would keep the revoked token
// readable and defeat offboarding. Only files WE created are touched — the
// "<base>.dmg-<rand>.bak" shape rotateBackups maintains — and in-flight temp files
// are left to their own owners.
//
// Failures are logged, never returned, for two reasons. By the time we get here the
// revocation itself has already happened, so reporting a failed unlink as a failed
// Clear would call a completed revocation failed; and because the reconciler then
// re-clears a file that has no block left, every later pass would take the no-op
// path and fail again — a permanent synthetic failure over a sibling file. The no-op
// paths call this instead, so an unlink that lost a race with a reader (a mapped or
// open .bak on Windows) is retried on the next unassignment cycle.
func (w *NPMRCWriter) purgeBackups(rt *resolvedTarget) {
	d, err := rt.child.Open(".")
	if err != nil {
		w.log("npmrc: backup purge open dir failed: %v", err)
		return
	}
	defer d.Close()

	prefix := rt.base + ".dmg-"
	tmpPrefix := rt.base + ".dmg-tmp-"
	for {
		entries, rerr := d.ReadDir(256)
		for _, e := range entries {
			name := e.Name()
			if name == "" || strings.ContainsRune(name, filepath.Separator) {
				continue
			}
			if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".bak") {
				continue
			}
			if strings.HasPrefix(name, tmpPrefix) {
				continue
			}
			li, lerr := rt.child.Lstat(name)
			if lerr != nil || !li.Mode().IsRegular() {
				continue
			}
			if err := rt.child.Remove(name); err != nil {
				w.log("npmrc: purge backup %q failed: %v", name, err)
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				w.log("npmrc: backup purge readdir failed: %v", rerr)
			}
			break
		}
	}
}

func randomSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// parseNPMDesired parses a rendered body into the one form shared by rewrite,
// convergence, MDM verification, and observation. It accepts exactly what
// RenderNPMRCBlock produces: an optional leading StepSecurity pair followed by
// the byte-sorted settings, or the sorted settings alone. The pair is
// recognized by the two-line shape RenderNPMRCBlock emits, a bare `registry=`
// line immediately followed by a `//…:_authToken=` line, not by the bare
// `registry` key alone: a settings-only body may carry `registry` as an
// ordinary setting, but never in that position, because byte order sorts every
// `//`-scoped key before it.
func parseNPMDesired(body string) (npmDesired, bool) {
	if strings.HasSuffix(body, "\n") {
		return npmDesired{}, false
	}
	lines := strings.Split(body, "\n")
	values := make(map[string]string, len(lines))
	entries := make([]npmSetting, 0, len(lines))
	for _, line := range lines {
		// Compare the desired body using the same semantics npm applies when it
		// reads the rendered bytes, notably doubled backslashes.
		key, value, ok := activeKV(line)
		if !ok || key == "" {
			return npmDesired{}, false
		}
		if _, duplicate := values[key]; duplicate {
			return npmDesired{}, false
		}
		values[key] = value
		entries = append(entries, npmSetting{key: key, value: value})
	}
	desired := npmDesired{body: body, settings: entries, values: values}
	if len(entries) >= 2 && isStepSecurityPair(entries[0], entries[1]) {
		desired.registry = entries[0].value
		desired.tokenKey = entries[1].key
		desired.tokenValue = entries[1].value
		desired.settings = entries[2:]
	}
	return desired, true
}

// isStepSecurityPair reports whether two leading rendered lines have the shape
// of the StepSecurity registry and device-token pair. Only the shape is judged,
// not the values: an observed MDM body with a drifted registry or a shared
// tenant token must still parse so its settings can be compared.
func isStepSecurityPair(registry, token npmSetting) bool {
	return registry.key == "registry" && registry.value != "" &&
		strings.HasPrefix(token.key, "//") && strings.HasSuffix(token.key, ":_authToken") && token.value != ""
}

// ---------------------------------------------------------------------------
// Content transforms (rewrite / clear) and the INI classifier
// ---------------------------------------------------------------------------

// rewriteContent produces the new file bytes from the current bytes and the
// rendered block body: strip any existing managed block, fail closed on an INI
// section header, comment out active bare `registry=` lines when the
// StepSecurity registry is desired, and append a fresh block at the very bottom
// on its own line. Preserves all other bytes exactly.
func (w *NPMRCWriter) rewriteContent(current []byte, body string) ([]byte, error) {
	desired, ok := parseNPMDesired(body)
	if !ok {
		return nil, fmt.Errorf("npmrc: expected value is not a rendered npm policy: %w", ErrTargetUnusable)
	}
	rest, bom := stripBOM(current)
	if hasLoneCR(string(rest)) {
		return nil, fmt.Errorf("npmrc: file contains a bare CR npm would treat as a line break; cannot safely transform: %w", ErrTargetUnusable)
	}
	lines := strings.Split(string(rest), "\n")

	lines, strippedToEOF := stripManagedBlock(lines)
	if strippedToEOF {
		w.log("npmrc: managed block had no END marker; stripped to EOF and rewriting")
	}
	if countMarker(lines, npmrcMDMMarker) != 0 || countMarker(lines, npmrcMDMBeginMarker) != 0 || countMarker(lines, npmrcMDMEndMarker) != 0 {
		return nil, fmt.Errorf("npmrc: file contains an mdm-managed block; cannot safely append: %w", ErrTargetUnusable)
	}
	if containsSection(lines) {
		// An INI section header scopes every following key to section.key, which
		// npm ignores — our appended block would be inert while a line-based
		// check reported it applied. There is no way to close a section, so the
		// only safe outcome is to refuse.
		return nil, fmt.Errorf("npmrc: file contains an INI [section] header; cannot safely append: %w", ErrTargetUnusable)
	}
	if hasCoercibleQuotedKey(lines) {
		return nil, fmt.Errorf("npmrc: file has a quoted key npm would coerce from non-string JSON; cannot safely transform: %w", ErrTargetUnusable)
	}
	if hasArrayAppendOverride(lines, desired) {
		// npm folds `registry[]=` and our block's `registry=` into one array, so the
		// block would be present and last-wins yet npm would not resolve to the
		// tenant registry alone. Commenting the array line out is not enough (npm
		// arrays are order-independent), so refuse the transform.
		return nil, fmt.Errorf("npmrc: file uses npm array-append syntax on a managed key; cannot safely transform: %w", ErrTargetUnusable)
	}
	if desired.stepSecurity() {
		lines = commentBareRegistry(lines)
	} else {
		// A settings-only policy treats `registry` as an ordinary last-wins
		// setting, so a bare registry line the StepSecurity shape had previously
		// commented out is handed back to the user before the new block lands.
		lines = unprefixDMG(lines)
	}

	base := strings.Join(lines, "\n")
	var buf bytes.Buffer
	buf.Write(bom)
	buf.WriteString(base)
	if len(base) > 0 && !strings.HasSuffix(base, "\n") {
		// Start the block on a fresh line, but never squash a pre-existing
		// trailing newline (blank lines are content and are preserved).
		buf.WriteByte('\n')
	}
	buf.WriteString(npmrcBeginMarker)
	buf.WriteByte('\n')
	buf.WriteString(body)
	buf.WriteByte('\n')
	buf.WriteString(npmrcEndMarker)
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// clearContent removes the managed block and un-comments only our own
// `# [stepsecurity-dmg] ` lines. It never touches the MDM script's
// `# [stepsecurity] ` lines and never deletes the file. The one permitted byte
// deviation from "restore the world" is that a missing original final newline
// is not restored — the remainder keeps the newline enforce added before the
// block.
//
// It fails closed on a bare CR for a reason specific to clearing: a CR-delimited
// file collapses to a single line under the '\n' split, so no marker line matches
// and the block is not FOUND — the transform would return the input unchanged,
// Clear would report the nothing-to-do success, and the reconciler would drop
// ownership state while the token stayed on disk. Refusing keeps the failure
// visible and the ownership record intact, so a later run can retry.
func (w *NPMRCWriter) clearContent(current []byte) ([]byte, error) {
	rest, bom := stripBOM(current)
	if hasLoneCR(string(rest)) {
		return nil, fmt.Errorf("npmrc: file contains a bare CR npm treats as a line break; the managed block cannot be located to remove it: %w", ErrTargetUnusable)
	}
	lines := strings.Split(string(rest), "\n")
	lines, _ = stripManagedBlock(lines)
	lines = unprefixDMG(lines)
	var buf bytes.Buffer
	buf.Write(bom)
	buf.WriteString(strings.Join(lines, "\n"))
	return buf.Bytes(), nil
}

// stripBOM splits a leading UTF-8 BOM off the content. The BOM is removed for
// parsing (an INI key on the first line is matched correctly, a JSON document
// starts on a value) and re-prepended on rewrite so the bytes are preserved.
// Used by both the ~/.npmrc block writer and the settings.json writer.
func stripBOM(b []byte) (rest, bom []byte) {
	const bomSeq = "\ufeff"
	if bytes.HasPrefix(b, []byte(bomSeq)) {
		return b[len(bomSeq):], []byte(bomSeq)
	}
	return b, nil
}

// stripManagedBlock removes EVERY managed block (each BEGIN marker through its
// matching END, inclusive), not just the first. A BEGIN with no matching END
// anywhere after it is a truncated block and is stripped to EOF, reported via the
// returned flag. Removing all blocks is what makes offboarding revoke every
// token: a duplicated block — a user copy, or a partial prior write — must never
// survive a clear still carrying a live token, and must never make a rewrite
// oscillate forever between one block and two.
func stripManagedBlock(lines []string) ([]string, bool) {
	out := make([]string, 0, len(lines))
	strippedToEOF := false
	for i := 0; i < len(lines); {
		if !isMarkerLine(lines[i], npmrcBeginMarker) {
			out = append(out, lines[i])
			i++
			continue
		}
		end := -1
		for j := i + 1; j < len(lines); j++ {
			if isMarkerLine(lines[j], npmrcEndMarker) {
				end = j
				break
			}
		}
		if end < 0 {
			// Truncated block: no END exists past this BEGIN. Drop it to EOF so no
			// partial token lingers; bytes past a genuine truncation are not
			// recoverable structure.
			strippedToEOF = true
			break
		}
		i = end + 1
	}
	return out, strippedToEOF
}

// isMarkerLine matches a marker tolerantly of surrounding whitespace and a
// trailing CR, so a marker survives being read back from a CRLF file.
func isMarkerLine(line, marker string) bool {
	return strings.TrimSpace(line) == marker
}

// containsSection reports whether any line is an INI section header.
func containsSection(lines []string) bool {
	for _, l := range lines {
		if isSectionLine(l) {
			return true
		}
	}
	return false
}

// hasLoneCR reports whether s contains a bare carriage return — a '\r' not
// immediately followed by '\n'. npm's INI parser splits logical lines on '\r\n',
// '\n', AND a lone '\r', so a bare CR begins a new line for npm that our
// '\n'-only split does not see. That split mismatch is exploitable: `[global]\r`
// is a section header to npm (scoping, and thus nullifying, our appended block)
// but one opaque line to us, and `k=v\rregistry=evil` hides an overriding
// registry from us while npm honors it. We cannot safely transform such a file,
// so the enforce/convergence/probe paths treat a bare CR the way they treat an
// INI section: fail closed. A CRLF ('\r\n') file is NOT a lone CR and still
// round-trips through the '\n' split with its trailing '\r' preserved.
func hasLoneCR(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' && (i+1 >= len(s) || s[i+1] != '\n') {
			return true
		}
	}
	return false
}

// hasCoercibleQuotedKey reports whether any active line's key is a single-quoted
// token whose inner text npm's unsafe() JSON-parses to a NON-string value. npm
// strips the single quotes, JSON-parses the bare inner, and then coerces the
// result to a string when it is used as a config key — a single-element array
// like `'["registry"]'` becomes the JS array ["registry"], which coerces to the
// key `registry`, forging an override. Replicating JS's String() coercion for
// every shape (arrays join, objects → "[object Object]", numbers, bools) is
// fragile, and our own keys are never quoted, so we fail closed on any such line
// the same way we do on an INI section or a bare CR. (A double-quoted token is
// itself a JSON string literal, so it always decodes to a string — jsonDecodeString
// already handles it — and is not coercible-non-string.)
func hasCoercibleQuotedKey(lines []string) bool {
	for _, l := range lines {
		if isCommentLine(l) || isSectionLine(l) {
			continue
		}
		i := strings.IndexByte(l, '=')
		if i < 0 {
			continue
		}
		if quotedNonStringInner(strings.TrimSpace(l[:i])) {
			return true
		}
	}
	return false
}

// hasArrayAppendOverride reports whether any active line uses npm's `key[]=`
// array-append form on a key this writer's precedence model treats as a scalar.
// npm's ini reader turns `registry[]=…` into an ARRAY and then folds the plain
// `registry=` assignment into that same array, so BOTH orders leave the effective
// registry a comma-joined list containing the injected value while a last-wins
// scalar scan still sees the block's own `registry=` as the winner — i.e. we would
// report converged (or observe a clean registry_url) on a file where npm no longer
// resolves to the tenant registry alone. Verified against npm 10.9.7:
//
//	registry=<ours> + registry[]=<theirs> → "<ours>,<theirs>"
//	registry[]=<theirs> + registry=<ours> → "<theirs>,<ours>"
//
// Only keys in the parsed desired body are judged, so an unrelated array config
// (`omit[]=dev`) remains untouched while arrays for the registry, either token,
// or any optional setting fail closed.
//
// The `[]` suffix is tested AFTER npmUnsafe, matching npm's own order (it unquotes
// before checking for `[]`), which is what catches the quoted `"registry[]"=…` form;
// `registry [] = …` is NOT flagged because npm stores that under the distinct key
// "registry " and it overrides nothing.
func hasArrayAppendOverride(lines []string, desired npmDesired) bool {
	for _, l := range lines {
		key, _, ok := activeKV(l)
		if !ok {
			continue
		}
		base, isAppend := strings.CutSuffix(key, "[]")
		if !isAppend {
			continue
		}
		if _, managed := desired.values[base]; managed {
			return true
		}
	}
	return false
}

// quotedNonStringInner reports whether s is a single-quoted token whose bare inner
// is valid JSON that is NOT a string (array, object, number, bool, null) — the
// shape npm coerces to a string key. A parse failure (e.g. the bare word in
// `'registry'`) or a JSON string is not coercible-non-string and is left to the
// normal npmUnsafe path.
func quotedNonStringInner(s string) bool {
	if len(s) < 2 || s[0] != '\'' || s[len(s)-1] != '\'' {
		return false
	}
	var v any
	if err := json.Unmarshal([]byte(s[1:len(s)-1]), &v); err != nil {
		return false
	}
	_, isStr := v.(string)
	return !isStr
}

// commentBareRegistry prefixes every active bare `registry=` line with the DMG
// prefix, preserving the original (including any trailing CR) after the prefix.
// Scoped `@scope:registry=` lines, token lines, cooldown keys, env-ref lines,
// and every comment are left untouched.
func commentBareRegistry(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if key, _, ok := activeKV(l); ok && key == "registry" {
			out[i] = npmrcDMGPrefix + l
			continue
		}
		out[i] = l
	}
	return out
}

// unprefixDMG restores lines the writer previously commented out, removing only
// an exact leading DMG prefix.
func unprefixDMG(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if strings.HasPrefix(l, npmrcDMGPrefix) {
			out[i] = l[len(npmrcDMGPrefix):]
			continue
		}
		out[i] = l
	}
	return out
}

// isCommentLine reports whether a line is an npm INI comment (first non-space
// rune is '#' or ';') or blank.
func isCommentLine(line string) bool {
	t := strings.TrimLeft(line, " \t")
	if t == "" {
		return true
	}
	return t[0] == '#' || t[0] == ';'
}

// isSectionLine reports whether a line is an INI section header `[...]`.
func isSectionLine(line string) bool {
	t := strings.TrimSpace(line)
	return len(t) >= 2 && t[0] == '[' && t[len(t)-1] == ']'
}

// activeKV parses an active (uncommented, non-section) key=value line the way
// npm's INI parser does: split on the FIRST '=', then run BOTH sides through
// npmUnsafe — npm's own key/value normalization (trim, unquote a fully quoted
// token, or strip an unescaped inline ';'/'#' comment). ok is false for comments,
// sections, and lines with no '=' or an empty key. This one classifier backs
// every key-matching path (comment-out, clear, probe precedence, convergence);
// parsing keys exactly as npm does is what keeps a disguised override like
// `registry#x=evil` or `"registry"=evil` — both of which npm reads as the key
// `registry` — from slipping past the precedence checks as an unrecognized key,
// and a spaced form like `registry = https://evil/` from being mistaken for inert.
func activeKV(line string) (key, value string, ok bool) {
	if isCommentLine(line) || isSectionLine(line) {
		return "", "", false
	}
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	key = npmUnsafe(line[:i])
	if key == "" {
		return "", "", false
	}
	value = npmUnsafe(line[i+1:])
	return key, value, true
}

// npmUnsafe mirrors the npm `ini` package's unsafe(): the normalization npm
// applies to BOTH the key and the value of every line before storing it. A fully
// quoted token is unquoted (one layer); otherwise everything from the first
// UNESCAPED ';' or '#' is dropped as an inline comment and '\;', '\#', '\\'
// escapes are resolved (any other '\x' is kept verbatim). Our classifier must
// match npm here or it fails to recognize a disguised override: npm reads
// `registry#x=evil` as key `registry` and `"registry"=evil` as key `registry`, so
// a naive first-'=' split keeping `registry#x` / `"registry"` would let a later
// poisoned line defeat last-wins while Converged/ProbeExpected still reported
// compliant. Rendered policy settings may contain backslashes, so
// parseNPMDesired runs them through this same normalization before comparison.
func npmUnsafe(s string) string {
	s = strings.TrimSpace(s)
	if inner, ok := unquoteININToken(s); ok {
		return inner
	}
	var b strings.Builder
	b.Grow(len(s))
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			if c == '\\' || c == ';' || c == '#' {
				b.WriteByte(c)
			} else {
				b.WriteByte('\\')
				b.WriteByte(c)
			}
			esc = false
		case c == ';' || c == '#':
			return strings.TrimSpace(b.String())
		case c == '\\':
			esc = true
		default:
			b.WriteByte(c)
		}
	}
	if esc {
		b.WriteByte('\\')
	}
	return strings.TrimSpace(b.String())
}

// unquoteININToken mirrors npm ini unsafe()'s quoted branch, which JSON-parses a
// quoted token rather than merely stripping the quotes. A double-quoted token is
// JSON-decoded whole, so string escapes resolve — `"registry"` decodes to
// `registry`, an active override we must recognize — and falls back to the
// ORIGINAL quoted string when it is not a valid JSON string (npm keeps the quoted
// form on a JSON.parse failure). A single-quoted token has its quotes stripped
// and the inside JSON-decoded only if that inside is itself a valid JSON string,
// else kept verbatim. ok is false when s is not fully quoted, so the caller falls
// through to inline-comment handling. Merely trimming the quotes (the previous
// behavior) would read `"registry"` as the key `registry` and miss the
// override npm honors as `registry`.
func unquoteININToken(s string) (string, bool) {
	if len(s) < 2 {
		return "", false
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		if v, ok := jsonDecodeString(s); ok {
			return v, true
		}
		return s, true // npm keeps the quoted form when JSON.parse fails
	}
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		inner := s[1 : len(s)-1]
		if v, ok := jsonDecodeString(inner); ok {
			return v, true
		}
		return inner, true
	}
	return "", false
}

// jsonDecodeString reports whether s is a valid JSON string literal and, if so,
// its decoded value — the string half of npm's JSON.parse(). A non-string JSON
// value (number, object, bool) or a parse error yields ok=false.
func jsonDecodeString(s string) (string, bool) {
	var v string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", false
	}
	return v, true
}

// extractManagedBody returns the canonical body between our markers (the two
// content lines, '\n'-joined, no markers) and whether a well-formed block is
// present. A BEGIN with no END yields present=false.
func extractManagedBody(content string) (string, bool) {
	rest, _ := stripBOM([]byte(content))
	lines := strings.Split(string(rest), "\n")
	begin := -1
	for i, l := range lines {
		if isMarkerLine(l, npmrcBeginMarker) {
			begin = i
			break
		}
	}
	if begin < 0 {
		return "", false
	}
	end := -1
	for i := begin + 1; i < len(lines); i++ {
		if isMarkerLine(lines[i], npmrcEndMarker) {
			end = i
			break
		}
	}
	if end < 0 {
		return "", false
	}
	body := make([]string, 0, end-begin-1)
	for _, l := range lines[begin+1 : end] {
		body = append(body, strings.TrimRight(l, "\r"))
	}
	return strings.Join(body, "\n"), true
}

// ---------------------------------------------------------------------------
// Convergence
// ---------------------------------------------------------------------------

// Converged reports whether the file already reflects the desired block with no
// further work needed. It is stronger than block-body equality: the block must
// be present with body == expected, effective (nothing active overrides its
// managed scalar values, END marker intact, no displaced duplicate), and
// carry sane metadata (0600, target-user-owned on POSIX). A `registry=` line
// appended below an unchanged block (e.g. `aws codeartifact login`) leaves the
// body equal but defeats precedence — so body equality alone would report
// converged forever without ever re-running the transform.
func (w *NPMRCWriter) Converged(expected string) (bool, error) {
	desired, ok := parseNPMDesired(expected)
	if !ok {
		return false, fmt.Errorf("npmrc: expected value is not a rendered npm policy: %w", ErrTargetUnusable)
	}
	rt, err := w.resolveLeaf()
	if err != nil {
		return false, err
	}
	defer rt.close()

	data, existed, mode, err := w.readCurrent(rt)
	if err != nil {
		return false, err
	}
	if !existed {
		return false, nil
	}

	rest, _ := stripBOM(data)
	if hasLoneCR(string(rest)) {
		// A bare CR is a line break to npm but not to our '\n' split, so a section or
		// overriding line could hide behind it — the block would look present and
		// effective to us yet be scoped-out or overridden for npm. Fail closed, the
		// same refusal the rewrite path makes.
		return false, fmt.Errorf("npmrc: file contains a bare CR npm treats as a line break; managed block cannot be verified: %w", ErrTargetUnusable)
	}
	lines := strings.Split(string(rest), "\n")
	if containsSection(lines) {
		// An INI [section] header scopes our registry/token keys to section.key,
		// which npm ignores for the global registry: the block would be present and
		// body-equal yet inert, so reporting it converged would loop on a false
		// 'compliant'. Fail closed — the same refusal the rewrite path makes — so
		// enforce classifies it write_failed rather than silently accepting it.
		return false, fmt.Errorf("npmrc: file contains an INI [section] header; managed block cannot be effective: %w", ErrTargetUnusable)
	}
	if hasCoercibleQuotedKey(lines) {
		// A single-quoted key npm coerces from non-string JSON (e.g. '["registry"]')
		// could override our registry/token invisibly to a line-based check. Fail
		// closed, the same refusal the rewrite path makes.
		return false, fmt.Errorf("npmrc: file has a quoted key npm would coerce from non-string JSON; managed block cannot be verified: %w", ErrTargetUnusable)
	}
	if hasArrayAppendOverride(lines, desired) {
		// npm folds an array-append line into the same key as the block's scalar
		// assignment, so last-wins would report converged while npm resolves to a
		// list containing someone else's registry. Fail closed, as the rewrite path
		// does.
		return false, fmt.Errorf("npmrc: file uses npm array-append syntax on a managed key; managed block cannot be verified: %w", ErrTargetUnusable)
	}

	body, present := extractManagedBody(string(data))
	if !present || body != expected {
		return false, nil
	}

	if countMarker(lines, npmrcBeginMarker) != 1 || countMarker(lines, npmrcEndMarker) != 1 {
		// A duplicate or displaced block: converge by rewriting.
		return false, nil
	}
	if !blockIsLastEffective(lines, expected) {
		return false, nil
	}

	if enforcePOSIXMetadata && mode.Perm() != npmrcFileMode {
		return false, nil
	}
	if w.secureHome != nil {
		return w.metadataSecure(rt)
	}
	// Ownership is not re-checked here: readCurrent already required the resolved
	// leaf to be owned by the target user, from the same identity-verified handle
	// it read the content through. A second open to re-read the owner would race
	// the very content check it is meant to corroborate.
	return true, nil
}

// blockIsLastEffective reports whether the block's registry, token, and optional
// settings are the last-wins scalar values for the file.
func blockIsLastEffective(lines []string, expected string) bool {
	desired, ok := parseNPMDesired(expected)
	if !ok {
		return false
	}
	return desiredValuesEffective(lines, desired)
}

func countMarker(lines []string, marker string) int {
	n := 0
	for _, l := range lines {
		if isMarkerLine(l, marker) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// MDM probe
// ---------------------------------------------------------------------------

// ProbeExpected reports whether the MDM lane has actually achieved the current
// desired state for this device — not merely that an MDM marker exists. Because
// ~/.npmrc is user-writable (unlike the privileged VS Code policy locations),
// trusting a marker alone would let a user pin permanent mdm_managed while
// pointing npm anywhere. Managed requires all of: the MDM marker outside our
// block, the MDM block body matching the expected marker format, every managed
// scalar effective (last-wins), and sane metadata (0600, target-user-owned on
// POSIX).
func (w *NPMRCWriter) ProbeExpected(expected string) (bool, string) {
	rt, err := w.resolveLeaf()
	if err != nil {
		return false, ""
	}
	defer rt.close()

	data, existed, mode, err := w.readCurrent(rt)
	if err != nil || !existed {
		return false, ""
	}

	managed, detail := probeNPMRCContent(string(data), expected)
	if !managed {
		return false, ""
	}
	if enforcePOSIXMetadata && mode.Perm() != npmrcFileMode {
		return false, ""
	}
	if w.secureHome != nil {
		secure, err := w.metadataSecure(rt)
		if err != nil || !secure {
			return false, ""
		}
	}
	// Ownership is already enforced by readCurrent's checkOwner on the same
	// identity-verified handle; re-opening to re-read the owner would race the
	// content probe above.
	return true, detail
}

// probeNPMRCContent is the pure content logic behind ProbeExpected. It takes the
// whole file and the expected rendered body and reports whether the MDM lane
// owns an effective, current block.
func probeNPMRCContent(content, expected string) (bool, string) {
	desired, ok := parseNPMDesired(expected)
	if !ok {
		return false, ""
	}
	rest, _ := stripBOM([]byte(content))
	if hasLoneCR(string(rest)) {
		// A bare CR hides a section/override from our '\n' split; a marker plus
		// matching lines is then not proof the MDM lane governs npm. Fail closed.
		return false, ""
	}
	lines := strings.Split(string(rest), "\n")

	if containsSection(lines) {
		// A section scopes every following key to section.key; npm then ignores the
		// MDM block's registry/token for the global registry, so a marker plus
		// matching lines under a section is NOT proof the MDM lane governs npm. Fail
		// closed (not managed) — enforce then refuses the sectioned file too.
		return false, ""
	}
	if hasCoercibleQuotedKey(lines) {
		// A single-quoted key npm coerces from non-string JSON could override the
		// registry/token below the MDM block invisibly to the precedence loop. A
		// marker plus matching lines is then not proof; fail closed (not managed).
		return false, ""
	}
	if hasArrayAppendOverride(lines, desired) {
		// npm folds an array-append line into the MDM block's own key, so a marker
		// plus matching lines is not proof the MDM lane governs npm. Fail closed.
		return false, ""
	}

	markers, inDMG, err := scanNPMMDMMarkers(lines)
	if err != nil {
		return false, ""
	}
	if len(desired.settings) == 0 {
		if len(markers.fixed) != 1 || len(markers.begins) != 0 || len(markers.ends) != 0 ||
			!fixedMDMBlockMatches(lines, inDMG, markers.fixed[0], desired) {
			return false, ""
		}
	} else {
		body, valid := boundedMDMBody(lines, inDMG, markers)
		if len(markers.fixed) != 0 || !valid || body != desired.body {
			return false, ""
		}
	}
	if !desiredValuesEffective(lines, desired) {
		return false, ""
	}
	return true, "mdm-managed npmrc block present and effective"
}

type npmMDMMarkers struct {
	fixed  []int
	begins []int
	ends   []int
}

func scanNPMMDMMarkers(lines []string) (npmMDMMarkers, []bool, error) {
	inDMG, err := dmgBlockLines(lines)
	if err != nil {
		return npmMDMMarkers{}, nil, err
	}
	var markers npmMDMMarkers
	for i, line := range lines {
		if inDMG[i] {
			continue
		}
		switch {
		case isMarkerLine(line, npmrcMDMMarker):
			markers.fixed = append(markers.fixed, i)
		case isMarkerLine(line, npmrcMDMBeginMarker):
			markers.begins = append(markers.begins, i)
		case isMarkerLine(line, npmrcMDMEndMarker):
			markers.ends = append(markers.ends, i)
		}
	}
	return markers, inDMG, nil
}

func fixedMDMBlockMatches(lines []string, inDMG []bool, marker int, desired npmDesired) bool {
	found := make(map[string]bool, 2)
	for i := marker + 1; i < len(lines); i++ {
		if inDMG[i] || strings.TrimSpace(lines[i]) == "" || isSectionLine(lines[i]) {
			break
		}
		key, value, ok := activeKV(lines[i])
		if ok && desired.values[key] == value {
			found[key] = true
		}
	}
	return found["registry"] && found[desired.tokenKey]
}

func boundedMDMBody(lines []string, inDMG []bool, markers npmMDMMarkers) (string, bool) {
	if len(markers.begins) != 1 || len(markers.ends) != 1 || markers.ends[0] <= markers.begins[0] {
		return "", false
	}
	begin, end := markers.begins[0], markers.ends[0]
	body := make([]string, 0, end-begin-1)
	for i := begin + 1; i < end; i++ {
		if inDMG[i] {
			return "", false
		}
		body = append(body, strings.TrimRight(lines[i], "\r"))
	}
	return strings.Join(body, "\n"), true
}

func desiredValuesEffective(lines []string, desired npmDesired) bool {
	last := make(map[string]string, len(desired.values))
	for _, line := range lines {
		key, value, ok := activeKV(line)
		if !ok {
			continue
		}
		if _, managed := desired.values[key]; managed {
			last[key] = value
		}
	}
	for key, value := range desired.values {
		if last[key] != value {
			return false
		}
	}
	return true
}

// managedBlockBounds returns the [begin, end] line indices of our block, or
// (len, -1) when absent (so the "i >= begin && i <= end" exclusion is empty).
func managedBlockBounds(lines []string) (int, int) {
	begin := -1
	for i, l := range lines {
		if isMarkerLine(l, npmrcBeginMarker) {
			begin = i
			break
		}
	}
	if begin < 0 {
		return len(lines), -1
	}
	for i := begin + 1; i < len(lines); i++ {
		if isMarkerLine(lines[i], npmrcEndMarker) {
			return begin, i
		}
	}
	return begin, len(lines) - 1
}

// ProbeContentNPM is the MDM verify-only reader. It reports whether a
// StepSecurity MDM-managed block is present in ~/.npmrc and, if so, the effective
// (last-wins) configuration as the base three-key observed bag plus aggregate
// settings_status when settings are desired. It NEVER writes, patches, or
// clears — in MDM mode the agent owns nothing on this file — and it never
// touches the ownership state store.
//
// expected is the rendered desired block. Only its tenant key (the api_key before
// `::dev:<serial>`) is used, to decide auth_token_status here on the device; no
// token, hash, or fingerprint is ever returned or logged.
//
// The three outcomes are deliberately distinct:
//
//   - genuinely absent file, or present with no MDM marker → (false, nil, nil) →
//     policy_not_applied. Nothing is managing this file.
//   - unreadable file — permission failure, a leaf that became a symlink or
//     changed across the open, a non-regular leaf, an ownership mismatch, the size
//     cap — or a construct we cannot reason about → error → verification_failed.
//     We could not establish the effective config, so we must not report the clean
//     policy_not_applied.
//   - MDM marker present and the file parses → (true, bag, nil) → mdm_managed.
//
// Like the base-only MDM path, this reports the observed configuration even when
// metadata is loose. Metadata is outside the observed wire contract; ownership
// remains enforced by readCurrent.
func (w *NPMRCWriter) ProbeContentNPM(expected string) (bool, map[string]json.RawMessage, error) {
	rt, err := w.resolveLeaf()
	if err != nil {
		return false, nil, err
	}
	defer rt.close()

	data, existed, mode, err := w.readCurrent(rt)
	if err != nil {
		return false, nil, err
	}
	if !existed {
		return false, nil, nil
	}
	present, observed, err := probeNPMRCObserved(string(data), expected)
	if err != nil || !present {
		return present, observed, err
	}
	if enforcePOSIXMetadata && mode.Perm() != npmrcFileMode {
		w.log("npmrc: mdm-managed file mode is %#o, not %#o (token may be readable by other local users)", mode.Perm(), npmrcFileMode)
	}
	return present, observed, nil
}

// probeNPMRCObserved is the pure content logic behind ProbeContentNPM. It shares
// the parse guards and the last-wins precedence scan with probeNPMRCContent, but
// returns the observed registry plus secret-free auth and settings verdicts.
func probeNPMRCObserved(content, expected string) (bool, map[string]json.RawMessage, error) {
	// The desired registry is deliberately unused: the backend compares
	// registry_url structurally. Only the token key (which _authToken line belongs
	// to the tenant registry) and its value (the tenant key) are needed here.
	desired, ok := parseNPMDesired(expected)
	if !ok {
		return false, nil, errors.New("npmrc: expected value is not a rendered npm policy")
	}

	rest, _ := stripBOM([]byte(content))
	// Fail closed on the same constructs the DMG probe rejects. Each one hides a
	// section or an override from the '\n'-split precedence scan below, so the
	// values we would report are not provably the effective ones. An honest
	// verification_failed beats a confident wrong observation.
	if hasLoneCR(string(rest)) {
		return false, nil, fmt.Errorf("npmrc: file contains a bare CR line break: %w", ErrTargetUnusable)
	}
	lines := strings.Split(string(rest), "\n")
	if containsSection(lines) {
		return false, nil, fmt.Errorf("npmrc: file contains an INI section header: %w", ErrTargetUnusable)
	}
	if hasCoercibleQuotedKey(lines) {
		return false, nil, fmt.Errorf("npmrc: file contains a coercible quoted key: %w", ErrTargetUnusable)
	}
	if hasArrayAppendOverride(lines, desired) {
		// The registry we would report is not the one npm resolves: it folds the
		// array-append line into the same key. Reporting the scalar last-wins value
		// would be a confident wrong observation.
		return false, nil, fmt.Errorf("npmrc: file uses npm array-append syntax on a managed key: %w", ErrTargetUnusable)
	}

	// Presence = an MDM marker OUTSIDE every DMG-owned block, so a marker planted
	// inside one of our own blocks cannot pass as MDM management.
	markers, inDMGBlock, err := scanNPMMDMMarkers(lines)
	if err != nil {
		return false, nil, err
	}
	present := len(markers.fixed) > 0
	if len(desired.settings) > 0 {
		present = present || len(markers.begins) > 0
	}
	if !present {
		return false, nil, nil
	}

	settingsStatus := ""
	if len(desired.settings) > 0 {
		settingsStatus = observedSettingsStatus(lines, inDMGBlock, markers, desired)
	}
	if !desired.stepSecurity() {
		// A settings-only policy has no StepSecurity registry or credential axis to
		// report; the aggregate settings verdict is the whole observation.
		return npmObservedBag("", "", settingsStatus)
	}

	// Effective precedence over the WHOLE file: npm takes the LAST active
	// assignment, so a line below the MDM block wins. Report what npm would
	// actually use — an override surfaces as drift at the backend, which is the
	// correct outcome, not something to hide.
	lastReg, lastRegOK := "", false
	lastTok, lastTokOK := "", false
	for _, l := range lines {
		key, val, ok := activeKV(l)
		if !ok {
			continue
		}
		switch key {
		case "registry":
			lastReg, lastRegOK = val, true
		case desired.tokenKey:
			// The tenant registry's _authToken key. A block pointing at a DIFFERENT
			// registry carries a different token key, so its token does not count as
			// this policy's credential — it reports absent, alongside the registry drift.
			lastTok, lastTokOK = val, true
		}
	}
	if !lastRegOK {
		// A managed marker with no effective registry line is not a credible read,
		// and the backend requires registry_url to compare anything at all.
		return false, nil, errors.New("npmrc: mdm marker present but no effective registry line")
	}
	if err := transmittableRegistryURL(lastReg); err != nil {
		return false, nil, err
	}

	status := authTokenAbsent
	if lastTokOK {
		// Tenant-key PREFIX comparison on both sides: an admin-pushed shared token
		// carrying no ::dev:<serial> suffix is still the tenant's key, so it reads
		// match. The serial is device-specific and deliberately not part of the
		// verdict.
		status = authTokenMismatch
		if tenantKeyPrefix(lastTok) == tenantKeyPrefix(desired.tokenValue) {
			status = authTokenMatch
		}
	}

	return npmObservedBag(lastReg, status, settingsStatus)
}

// observedSettingsStatus reduces the desired settings to one secret-free
// verdict: absent when no desired settings key has an active assignment, match
// when exactly one bounded MDM block carries precisely the desired settings and
// every one of them is the last-effective value, mismatch for any other readable
// state (partial, wrong, overridden, duplicated, or a fixed-marker block).
func observedSettingsStatus(lines []string, inDMG []bool, markers npmMDMMarkers, desired npmDesired) string {
	last := make(map[string]string, len(desired.settings))
	for _, line := range lines {
		key, value, ok := activeKV(line)
		if !ok || desired.stepSecurityKey(key) {
			continue
		}
		if _, managed := desired.values[key]; managed {
			last[key] = value
		}
	}
	if len(last) == 0 {
		return settingsAbsent
	}
	body, valid := boundedMDMBody(lines, inDMG, markers)
	if len(markers.fixed) != 0 || !valid || !boundedSettingsMatch(body, desired) {
		return settingsMismatch
	}
	for _, setting := range desired.settings {
		if last[setting.key] != setting.value {
			return settingsMismatch
		}
	}
	return settingsMatch
}

// boundedSettingsMatch compares only the settings entries of a bounded MDM body,
// so registry or token drift in a combined block is reported on its own axes
// rather than as a settings mismatch. The block must still be the desired SHAPE:
// a stale combined block left behind after a policy moved to settings-only keeps
// StepSecurity as the effective default registry, and must not read as match.
func boundedSettingsMatch(body string, desired npmDesired) bool {
	observed, ok := parseNPMDesired(body)
	if !ok || observed.stepSecurity() != desired.stepSecurity() || len(observed.settings) != len(desired.settings) {
		return false
	}
	for i, setting := range desired.settings {
		if observed.settings[i] != setting {
			return false
		}
	}
	return true
}

// dmgBlockLines marks every line that falls inside a DMG-owned block, so the MDM
// marker search can exclude all of them. managedBlockBounds only locates the
// FIRST block, so a second BEGIN/END pair would leave its interior unexcluded and
// a marker planted there would read as MDM presence — refuse that file instead.
// The writer never produces two blocks, so this is a tampered/hand-edited file.
func dmgBlockLines(lines []string) ([]bool, error) {
	if countMarker(lines, npmrcBeginMarker) > 1 || countMarker(lines, npmrcEndMarker) > 1 {
		return nil, fmt.Errorf("npmrc: more than one dmg-managed block: %w", ErrTargetUnusable)
	}
	in := make([]bool, len(lines))
	begin, end := managedBlockBounds(lines)
	for i := begin; i <= end && i < len(lines); i++ {
		in[i] = true
	}
	return in, nil
}

// transmittableRegistryURL rejects an effective registry_url that must not leave
// the device. It is deliberately a SUBSET of validateRegistryURL's rules: the
// value is read off a user-writable file, so credential-bearing or
// parser-ambiguous forms (userinfo, a query, a fragment, control bytes) and
// oversize values are refused before transmission — a token smuggled into the URL
// must never reach the backend. The shape rules validateRegistryURL also enforces
// (host grammar, no port, an exact /javascript path) are NOT applied: a merely
// wrong registry is the drift the backend exists to detect, and erroring on it
// would destroy that signal.
//
// The SCHEME is likewise not judged beyond http/https: a device resolving to a
// plaintext http mirror is the most security-relevant drift an admin can have, so
// it must travel as evidence and surface as a registry_url diff rather than be
// discarded as malformed. validateRegistryURL stays https-only for the POLICY
// side, where we compose the URL and a non-https value is our own bug; here the
// URL is someone else's input, so it is data to report. What still fails is a
// value that is not a credible registry read at all — another scheme, or no host.
func transmittableRegistryURL(raw string) error {
	if len(raw) > npmrcMaxRegistryURLBytes {
		return fmt.Errorf("npmrc: effective registry_url exceeds %d bytes", npmrcMaxRegistryURLBytes)
	}
	if hasControlBytes(raw) {
		return errors.New("npmrc: effective registry_url contains control characters")
	}
	if strings.ContainsAny(raw, "#?") {
		return errors.New("npmrc: effective registry_url contains '#' or '?'")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("npmrc: effective registry_url is not a valid URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("npmrc: effective registry_url is not an http(s) URL")
	}
	if u.Host == "" {
		return errors.New("npmrc: effective registry_url has no host")
	}
	if u.User != nil {
		return errors.New("npmrc: effective registry_url contains userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("npmrc: effective registry_url contains a query")
	}
	if u.Fragment != "" {
		return errors.New("npmrc: effective registry_url contains a fragment")
	}
	return nil
}

// tenantKeyPrefix returns the tenant api_key portion of a device token —
// everything before the "::dev:<serial>" suffix. A token with no suffix is
// already the bare tenant key and returns unchanged.
func tenantKeyPrefix(token string) string {
	return strings.SplitN(token, "::dev:", 2)[0]
}

// npmObservedBag builds the observed bag for the desired shape: ecosystem always,
// registry_url and auth_token_status when the StepSecurity registry is desired
// (authStatus non-empty), and settings_status when settings are desired
// (non-empty). Nothing derived from a token or setting beyond its aggregate
// verdict is included.
func npmObservedBag(registryURL, authStatus, settingsStatus string) (bool, map[string]json.RawMessage, error) {
	observed := make(map[string]json.RawMessage, 4)
	put := func(key, value string) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("npmrc: encode observed %s: %w", key, err)
		}
		observed[key] = raw
		return nil
	}
	if err := put(observedKeyEcosystem, "npm"); err != nil {
		return false, nil, err
	}
	if authStatus != "" {
		if err := put(observedKeyRegistryURL, registryURL); err != nil {
			return false, nil, err
		}
		if err := put(observedKeyAuthTokenStatus, authStatus); err != nil {
			return false, nil, err
		}
	}
	if settingsStatus != "" {
		if err := put(observedKeySettingsStatus, settingsStatus); err != nil {
			return false, nil, err
		}
	}
	return true, observed, nil
}

// npmCompliantObserved is the observed bag a converged DMG-enforced file reports
// for a policy with settings: every desired axis reads match. A StepSecurity-only
// policy reports no bag, preserving its existing wire shape.
func npmCompliantObserved(rendered string) (map[string]json.RawMessage, error) {
	desired, ok := parseNPMDesired(rendered)
	if !ok || len(desired.settings) == 0 {
		return nil, nil
	}
	authStatus := ""
	if desired.stepSecurity() {
		authStatus = authTokenMatch
	}
	_, observed, err := npmObservedBag(desired.registry, authStatus, settingsMatch)
	return observed, err
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// npmPolicy is the run-config policy payload for the npm ecosystem. The
// StepSecurity fields stay raw so an explicit null is distinguishable from an
// absent member: registry_url and auth are a pair that is either both present
// (StepSecurity-backed) or both absent (settings-only).
type npmPolicy struct {
	Ecosystem   string          `json:"ecosystem"`
	RegistryURL json.RawMessage `json:"registry_url"`
	Auth        json.RawMessage `json:"auth"`
	Settings    json.RawMessage `json:"settings"`
}

type npmAuth struct {
	Scheme string `json:"scheme"`
	APIKey string `json:"api_key"`
}

type npmSetting struct {
	key   string
	value string
}

// npmDesired is the one parsed form shared by rewrite, convergence, MDM
// verification, and observation. registry, tokenKey, and tokenValue describe
// the leading StepSecurity pair and are empty for a settings-only policy;
// settings holds the policy settings in byte-sorted key order (a settings-only
// `registry` is one of them); values maps every managed scalar key, StepSecurity
// pair included, to its desired value.
type npmDesired struct {
	body       string
	registry   string
	tokenKey   string
	tokenValue string
	settings   []npmSetting
	values     map[string]string
}

// stepSecurity reports whether the desired body carries the StepSecurity
// registry and device-token pair.
func (d npmDesired) stepSecurity() bool { return d.tokenKey != "" }

// stepSecurityKey reports whether key is one of the two product-owned
// StepSecurity lines rather than a policy setting.
func (d npmDesired) stepSecurityKey(key string) bool {
	return d.stepSecurity() && (key == "registry" || key == d.tokenKey)
}

// RenderNPMRCBlock validates a policy and returns the content lines the writer
// wraps in its markers, with no markers or trailing newline: the StepSecurity
// registry/token pair when the policy carries one, followed by any settings in
// byte-sorted key order. It fully validates the policy (the HTTP layer only
// checks "is a JSON object"): the token line's host and path derive from
// registry_url, the composed device token is `<api_key>::dev:<serial>`, and a
// settings-only policy must declare a default or scoped registry. Any
// validation failure returns an error the reconciler reports as
// policy_not_applied; error messages never echo the key or the policy.
func RenderNPMRCBlock(policy json.RawMessage, serial string) (string, error) {
	if !utf8.Valid(policy) {
		return "", errors.New("npmrc: policy is not valid UTF-8")
	}
	var p npmPolicy
	decoder := json.NewDecoder(bytes.NewReader(policy))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return "", errors.New("npmrc: policy is not a well-formed npm policy object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("npmrc: policy has trailing data")
	}
	if err := rejectDuplicateJSONKeys(policy); err != nil {
		return "", errors.New("npmrc: policy contains duplicate JSON keys")
	}
	if p.Ecosystem != "npm" {
		return "", errors.New("npmrc: policy ecosystem is not npm")
	}

	var lines []string
	productTokenKey := ""
	switch {
	case len(p.RegistryURL) > 0 || len(p.Auth) > 0:
		var err error
		if lines, productTokenKey, err = renderStepSecurityPair(p, serial); err != nil {
			return "", err
		}
	case len(p.Settings) == 0:
		return "", errors.New("npmrc: policy has neither a StepSecurity registry nor settings")
	default:
		if err := validateDeviceSerial(serial); err != nil {
			return "", err
		}
	}

	settings, err := validateNPMSettings(p.Settings, productTokenKey)
	if err != nil {
		return "", err
	}
	for _, setting := range settings {
		lines = append(lines, setting.key+"="+setting.value)
	}
	body := strings.Join(lines, "\n")
	if len(body) > npmrcMaxRenderedBytes {
		return "", errors.New("npmrc: rendered block exceeds size limit")
	}
	if _, ok := parseNPMDesired(body); !ok {
		return "", errors.New("npmrc: policy settings are ambiguous after normalization")
	}
	return body, nil
}

// renderStepSecurityPair validates the StepSecurity registry_url/auth pair and
// returns its two rendered lines plus the derived token key the settings must
// not collide with.
func renderStepSecurityPair(p npmPolicy, serial string) (lines []string, tokenKey string, err error) {
	if len(p.RegistryURL) == 0 || len(p.Auth) == 0 {
		return nil, "", errors.New("npmrc: policy registry_url and auth must be present together")
	}
	var registryURL string
	if err := json.Unmarshal(p.RegistryURL, &registryURL); err != nil {
		return nil, "", errors.New("npmrc: policy registry_url is not a string")
	}
	var auth npmAuth
	authDecoder := json.NewDecoder(bytes.NewReader(p.Auth))
	authDecoder.DisallowUnknownFields()
	if err := authDecoder.Decode(&auth); err != nil {
		return nil, "", errors.New("npmrc: policy auth is not a well-formed object")
	}
	if auth.Scheme != "stepsecurity_device_token" {
		return nil, "", errors.New("npmrc: unsupported auth scheme")
	}

	key := auth.APIKey
	if key == "" {
		return nil, "", errors.New("npmrc: policy api_key is empty")
	}
	if len(key) > npmrcMaxKeyBytes {
		return nil, "", errors.New("npmrc: policy api_key too long")
	}
	if !isNPMSafe(key) {
		return nil, "", errors.New("npmrc: policy api_key contains unsupported characters")
	}
	if err := validateDeviceSerial(serial); err != nil {
		return nil, "", err
	}

	host, path, err := validateRegistryURL(registryURL)
	if err != nil {
		return nil, "", err
	}

	token := key + "::dev:" + serial
	// npm's _authToken key is `//host/path/:_authToken` with a trailing slash
	// before the colon.
	tokenKey = "//" + host + path + "/:_authToken"
	return []string{"registry=" + registryURL, tokenKey + "=" + token}, tokenKey, nil
}

func validateDeviceSerial(serial string) error {
	if serial == "" {
		return errors.New("npmrc: device serial is empty")
	}
	if len(serial) > npmrcMaxSerialBytes {
		return errors.New("npmrc: device serial too long")
	}
	if !isNPMSafe(serial) {
		return errors.New("npmrc: device serial contains unsupported characters")
	}
	return nil
}

// validateNPMSettings decodes and validates the optional settings map and
// returns it sorted by key. productTokenKey is the derived StepSecurity token
// key for a StepSecurity-backed policy and empty for a settings-only policy,
// which must instead declare a default `registry` or `@scope:registry`.
func validateNPMSettings(raw json.RawMessage, productTokenKey string) ([]npmSetting, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, errors.New("npmrc: policy settings must be a non-null object of strings")
	}
	settings := make(map[string]string, len(members))
	for key, rawValue := range members {
		var value string
		if bytes.Equal(bytes.TrimSpace(rawValue), []byte("null")) || json.Unmarshal(rawValue, &value) != nil {
			return nil, errors.New("npmrc: policy settings must be a non-null object of strings")
		}
		settings[key] = value
	}
	if len(settings) == 0 || len(settings) > npmrcMaxSettings {
		return nil, fmt.Errorf("npmrc: policy settings must contain 1 through %d entries", npmrcMaxSettings)
	}

	stepSecurity := productTokenKey != ""
	keys := make([]string, 0, len(settings))
	registryAuthKeys := make(map[string]struct{})
	for key, value := range settings {
		if err := validateNPMSettingKey(key); err != nil {
			return nil, err
		}
		if err := validateNPMSettingValue(value); err != nil {
			return nil, err
		}
		if key == productTokenKey {
			return nil, errors.New("npmrc: policy setting collides with the StepSecurity token key")
		}
		scope, scoped := npmScopedRegistryKey(key)
		if scoped || key == "registry" && !stepSecurity {
			authKey, canonical, err := canonicalNPMRegistry(value)
			if err != nil || canonical != value || scoped && scope == "" {
				return nil, errors.New("npmrc: policy contains a non-canonical registry setting")
			}
			if authKey == productTokenKey {
				// StepSecurity authentication is expressed only through the compiled
				// registry_url/auth pair, never as a managed setting.
				return nil, errors.New("npmrc: policy registry setting targets the StepSecurity registry")
			}
			registryAuthKeys[authKey] = struct{}{}
		}
		keys = append(keys, key)
	}
	if !stepSecurity && len(registryAuthKeys) == 0 {
		return nil, errors.New("npmrc: settings-only policy must declare a default or scoped registry")
	}

	for _, key := range keys {
		value := settings[key]
		if isReservedNPMSetting(key, !stepSecurity) {
			return nil, errors.New("npmrc: policy contains a reserved setting key")
		}
		credential, scoped := npmURLScopedCredential(key)
		if !scoped {
			continue
		}
		if !strings.EqualFold(credential, "_authToken") {
			return nil, errors.New("npmrc: policy contains an unsupported credential setting")
		}
		if _, ok := registryAuthKeys[key]; !ok || !isExactEnvReference(value) {
			return nil, errors.New("npmrc: policy scoped auth token is not canonical")
		}
	}

	sort.Strings(keys)
	result := make([]npmSetting, 0, len(keys))
	for _, key := range keys {
		result = append(result, npmSetting{key: key, value: settings[key]})
	}
	return result, nil
}

func validateNPMSettingKey(key string) error {
	if key == "" || strings.Trim(key, " \t") != key {
		return errors.New("npmrc: policy contains a non-canonical setting key")
	}
	if len(key) > npmrcMaxSettingKeyBytes || !utf8.ValidString(key) {
		return errors.New("npmrc: policy contains an invalid setting key")
	}
	for _, r := range key {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("=#;'\"[]", r) {
			return errors.New("npmrc: policy contains an unsafe setting key")
		}
	}
	return nil
}

func validateNPMSettingValue(value string) error {
	if strings.Trim(value, " \t") != value {
		return errors.New("npmrc: policy contains a non-canonical setting value")
	}
	if len(value) > npmrcMaxSettingValueBytes || !utf8.ValidString(value) {
		return errors.New("npmrc: policy contains an invalid setting value")
	}
	for _, r := range value {
		if unicode.IsControl(r) || strings.ContainsRune("#;'\"", r) {
			return errors.New("npmrc: policy contains an unsafe setting value")
		}
	}
	if !validEnvReferences(value) {
		return errors.New("npmrc: policy contains a malformed environment reference")
	}
	if u, err := url.Parse(value); err == nil && u.IsAbs() && u.User != nil {
		return errors.New("npmrc: policy setting URL contains userinfo")
	}
	return nil
}

func validEnvReferences(value string) bool {
	for start := 0; ; {
		i := strings.Index(value[start:], "${")
		if i < 0 {
			return true
		}
		i += start
		end := strings.IndexByte(value[i+2:], '}')
		if end < 0 {
			return false
		}
		end += i + 2
		if !validEnvName(value[i+2 : end]) {
			return false
		}
		start = end + 1
	}
}

func validEnvName(name string) bool {
	if name == "" || !isASCIIAlpha(name[0]) && name[0] != '_' {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isASCIIAlpha(name[i]) && (name[i] < '0' || name[i] > '9') && name[i] != '_' {
			return false
		}
	}
	return true
}

func isASCIIAlpha(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func isExactEnvReference(value string) bool {
	return len(value) >= 4 && strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") && validEnvName(value[2:len(value)-1])
}

// isReservedNPMSetting reports whether key is a product-owned or
// credential-bearing npm config name a policy may not manage. The exact
// lowercase `registry` is the third-party default registry of a settings-only
// policy and is released when allowDefaultRegistry is set; its case variants
// stay reserved so they cannot evade the registry rules.
func isReservedNPMSetting(key string, allowDefaultRegistry bool) bool {
	if strings.HasPrefix(key, "//") {
		return false
	}
	switch strings.ToLower(key) {
	case "registry":
		return !allowDefaultRegistry || key != "registry"
	case "_authtoken", "_auth", "_password", "username", "tokenhelper", "cert", "key":
		return true
	default:
		return false
	}
}

func npmScopedRegistryKey(key string) (string, bool) {
	const suffix = ":registry"
	if !strings.HasPrefix(key, "@") || len(key) < len(suffix) || !strings.EqualFold(key[len(key)-len(suffix):], suffix) {
		return "", false
	}
	if !strings.HasSuffix(key, suffix) {
		return "", true
	}
	scope := strings.TrimSuffix(strings.TrimPrefix(key, "@"), suffix)
	if scope == "" {
		return "", true
	}
	for i := 0; i < len(scope); i++ {
		c := scope[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("._~-", rune(c)) {
			continue
		}
		return "", true
	}
	return scope, true
}

func canonicalNPMRegistry(raw string) (authKey, canonical string, err error) {
	if hasControlBytes(raw) || strings.ContainsAny(raw, "#?") {
		return "", "", errors.New("unsafe registry URL")
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", "", errors.New("invalid registry URL")
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", "", errors.New("invalid registry port")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", "", errors.New("invalid registry port")
		}
	}
	host := strings.ToLower(u.Host)
	path := strings.TrimRight(u.EscapedPath(), "/") + "/"
	if path == "" {
		path = "/"
	}
	canonical = "https://" + host + path
	return "//" + host + path + ":_authToken", canonical, nil
}

func npmURLScopedCredential(key string) (string, bool) {
	if !strings.HasPrefix(key, "//") {
		return "", false
	}
	i := strings.LastIndexByte(key, ':')
	if i < 2 || i == len(key)-1 {
		return "", false
	}
	credential := key[i+1:]
	switch strings.ToLower(credential) {
	case "_authtoken", "_auth", "_password", "username", "tokenhelper", "cert", "key":
		return credential, true
	default:
		return "", false
	}
}

// validateRegistryURL requires an HTTPS URL with no userinfo, query, fragment,
// or port; a valid lowercase RFC 1123 host; and an exact `/javascript` path. It
// returns the host and path used to compose the token key.
func validateRegistryURL(raw string) (host, path string, err error) {
	if raw == "" {
		return "", "", errors.New("npmrc: policy registry_url is empty")
	}
	if hasControlBytes(raw) {
		return "", "", errors.New("npmrc: policy registry_url contains control characters")
	}
	// Reject '#' and '?' in the raw string. url.Parse turns a trailing bare '#'
	// into an empty Fragment (there is no ForceFragment to catch it the way
	// ForceQuery catches a bare '?'), so `.../javascript#` would otherwise slip
	// through the Fragment check below and land verbatim in the rendered
	// `registry=` line — where an npm INI parser could read '#' as a mid-value
	// comment and silently fall back to the default registry.
	if strings.ContainsAny(raw, "#?") {
		return "", "", errors.New("npmrc: policy registry_url must not contain '#' or '?'")
	}
	u, perr := url.Parse(raw)
	if perr != nil {
		return "", "", errors.New("npmrc: policy registry_url is not a valid URL")
	}
	if u.Scheme != "https" {
		return "", "", errors.New("npmrc: policy registry_url must be https")
	}
	if u.User != nil {
		return "", "", errors.New("npmrc: policy registry_url must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", "", errors.New("npmrc: policy registry_url must not contain a query")
	}
	if u.Fragment != "" {
		return "", "", errors.New("npmrc: policy registry_url must not contain a fragment")
	}
	if u.Port() != "" {
		return "", "", errors.New("npmrc: policy registry_url must not contain a port")
	}
	host = u.Hostname()
	if !isValidHost(host) {
		return "", "", errors.New("npmrc: policy registry_url host is not a valid hostname")
	}
	if u.EscapedPath() != "/javascript" {
		return "", "", errors.New("npmrc: policy registry_url path must be /javascript")
	}
	return host, "/javascript", nil
}

// isNPMSafe reports whether every byte is in the unquoted npm-INI-safe alphabet
// [A-Za-z0-9._:@/-]. Anything outside it — spaces, quotes, '#', ';', '=',
// '$', control bytes — is rejected rather than escaped; v1 defines no escaping.
func isNPMSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == ':' || c == '@' || c == '/' || c == '-':
		default:
			return false
		}
	}
	return true
}

func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// isValidHost validates a lowercase RFC 1123 hostname. The grammar is checked,
// not an allowlist — dedicated instances use custom domains, so no base domain
// can be pinned agent-side.
func isValidHost(host string) bool {
	if host == "" || len(host) > npmrcMaxHostBytes {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
