package devicepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

// CacheFilename is the basename of the enforcement state file — the ONE file
// holding every category's ownership record, keyed by category then target. It
// lives under ~/.stepsecurity/ alongside config.json and hooks-state.json, and is
// distinct from the AI-agent hook cache (a separate subsystem — no shared state).
const CacheFilename = "device-policy-state.json"

// CacheSchemaVersion is the on-disk version of the state file. Bump only on a
// breaking shape change.
const CacheSchemaVersion = 1

const (
	cacheFileMode      os.FileMode = 0o600
	cacheParentDirMode os.FileMode = 0o700
)

// AppliedStateFile is the on-disk shape: a schema-versioned wrapper keyed by
// category and then by target, so every category and target shares ONE file
// without forcing a future migration. This is the only state file the subsystem
// keeps — a category does not get its own, and writing or clearing one
// (category, target) preserves every other one.
//
//	{
//	  "schema_version": 1,
//	  "categories": {
//	    "ide_extension": {
//	      "targets": {
//	        "vscode": { "applied_hash": …, "written_settings": …, "fetched_at": … }
//	      }
//	    },
//	    "package_config": {
//	      "targets": {
//	        "npm": { "applied_hash": …, "written_settings": …, "fetched_at": … }
//	      }
//	    }
//	  }
//	}
type AppliedStateFile struct {
	SchemaVersion int                             `json:"schema_version"`
	Categories    map[string]AppliedCategoryState `json:"categories"`
}

// AppliedCategoryState wraps the per-target ownership records for one category.
// The category is the map key in AppliedStateFile; the target is the map key in
// Targets. An absent category key, an absent target key, or a nil Targets map
// all mean "the agent owns nothing on disk" for that category/target.
type AppliedCategoryState struct {
	Targets map[string]AppliedTargetState `json:"targets"`
}

// AppliedTargetState records the non-secret facts needed to verify and safely
// clear one target. WrittenSettings holds exact values only for non-secret
// settings; marker-owned credential lanes store fixed ownership markers plus
// the minimum path/creation/host metadata needed for restoration.
//
//   - AppliedHash is the backend's content hash, stored VERBATIM (never
//     recomputed). Compared against the freshly-fetched hash for idempotency.
//   - WrittenSettings records setting id to written value for ordinary settings,
//     or a fixed non-secret marker for credential-bearing managed blocks.
//
// A zero-value entry means "the agent owns nothing on disk" for that
// category/target.
//
// AppliedHash and WrittenSettings are persisted as one struct in one write, so a
// record whose AppliedHash equals the freshly-fetched hash always carries the
// complete ownership map for that policy. Convergence checks rely on that: a
// cycle that finds the target converged with an unchanged hash short-circuits
// without persisting, which is only safe because a matching hash cannot coexist
// with partial ownership. A record hand-edited to break that pairing is outside
// the supported inputs — the value-based clear would leave those keys in place.
type AppliedTargetState struct {
	AppliedHash     string            `json:"applied_hash"`
	WrittenSettings map[string]string `json:"written_settings,omitempty"`
	FileCreated     bool              `json:"file_created,omitempty"`
	ResolvedPath    string            `json:"resolved_path,omitempty"`
	ResolvedPaths   map[string]string `json:"resolved_paths,omitempty"`
	RegistryHost    string            `json:"registry_host,omitempty"`
	FetchedAt       time.Time         `json:"fetched_at"`
}

// cacheMu serializes the read-modify-write of the state file so two in-process
// category writers cannot lose each other's update. It sees only this process;
// withStateLock covers separate agent processes, and every read-modify-write
// takes both — cacheMu first, then the file lock, always in that order.
//
// The lock is NOT reentrant: helpers that already hold it use the unlocked
// readStateFile / persistStateFile, never the public ReadAppliedState /
// WriteAppliedState / ClearAppliedState.
var cacheMu sync.Mutex

// cachePathOverride lets tests redirect reads/writes to a tempdir. Production
// leaves it empty. Same pattern as state.cachePathOverride.
var cachePathOverride string
var cacheStateFile *secureuserfile.File
var cacheLockFile *secureuserfile.File

// cacheWarnf receives state failures that ReadAppliedState swallows, so a cycle
// that silently reads "owns nothing" still leaves a trace. cacheLastWarn keeps
// the several per-cycle readers from repeating one line.
var cacheWarnf func(format string, args ...any)
var cacheLastWarn string

type targetUserExecutor struct {
	executor.Executor
	user *user.User
}

func (e targetUserExecutor) LoggedInUser() (*user.User, error) {
	u := *e.user
	return &u, nil
}

// ConfigureCacheTarget pins Windows state to the same active target user used
// by package writers. Other platforms retain their existing process-user path.
// warnf receives redacted state failures that reads would otherwise swallow.
func ConfigureCacheTarget(exec executor.Executor, warnf func(string, ...any)) (executor.Executor, func(), error) {
	if exec == nil || exec.GOOS() != model.PlatformWindows {
		return exec, func() {}, nil
	}
	home, err := secureuserfile.OpenUserHome(exec)
	if err != nil {
		return nil, nil, err
	}
	stateRelative := filepath.Join(".stepsecurity", CacheFilename)
	stateFile, err := home.Open(stateRelative, ".dmg-state-", secureuserfile.MaxBytes)
	if err != nil {
		_ = home.Close()
		return nil, nil, err
	}
	if err := stateFile.RequireResolvedPath(stateRelative); err != nil {
		_ = home.Close()
		return nil, nil, err
	}
	lockRelative := stateRelative + stateLockSuffix
	lockFile, err := home.Open(lockRelative, ".dmg-lock-", secureuserfile.MaxBytes)
	if err != nil {
		_ = home.Close()
		return nil, nil, err
	}
	if err := lockFile.RequireResolvedPath(lockRelative); err != nil {
		_ = home.Close()
		return nil, nil, err
	}
	target := targetUserExecutor{Executor: exec, user: home.User()}
	cacheMu.Lock()
	previousPath, previousStateFile, previousLockFile := cachePathOverride, cacheStateFile, cacheLockFile
	previousWarnf, previousLastWarn := cacheWarnf, cacheLastWarn
	cachePathOverride = filepath.Join(home.Path(), ".stepsecurity", CacheFilename)
	cacheStateFile = stateFile
	cacheLockFile = lockFile
	cacheWarnf, cacheLastWarn = warnf, ""
	cacheMu.Unlock()
	return target, func() {
		cacheMu.Lock()
		cachePathOverride = previousPath
		cacheStateFile, cacheLockFile = previousStateFile, previousLockFile
		cacheWarnf, cacheLastWarn = previousWarnf, previousLastWarn
		cacheMu.Unlock()
		_ = home.Close()
	}, nil
}

// SetCachePathForTest redirects CachePath() to the given absolute path and
// returns a restore function. Test-only.
func SetCachePathForTest(p string) (restore func()) {
	prev := cachePathOverride
	cachePathOverride = p
	return func() { cachePathOverride = prev }
}

// CachePath returns the absolute state-file path, honoring the test override.
// Empty string means the home directory could not be resolved.
func CachePath() string {
	if cachePathOverride != "" {
		return cachePathOverride
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".stepsecurity", CacheFilename)
}

// readStatus classifies a state file for the read-modify-write callers.
type readStatus int

const (
	// stateReadable: the file parsed and its schema is this build's or older.
	stateReadable readStatus = iota
	// stateAbsentOrCorrupt: missing, or read but not a JSON object. Safe to
	// recreate from scratch — nothing interpretable is there to lose. The two stay
	// one status because both callers treat them identically: a write recreates,
	// and a clear's removeStateFile already takes an absent file as success.
	stateAbsentOrCorrupt
	// stateUnreadable: the file is THERE but its bytes could not be obtained (no
	// read permission, an I/O error, a directory at the path, an unresolvable
	// home). Distinct from corrupt precisely because the content is unknown, not
	// known-worthless: it may hold live ownership records for other categories, so
	// a write must not replace it and a clear must not remove it — on POSIX an
	// unreadable file is still unlinkable through a writable parent. Both surface
	// the read error instead.
	stateUnreadable
	// stateFuture: a cleanly-parsed file from a NEWER agent (schema_version
	// beyond this build). Must NOT be overwritten — its category metadata can't
	// be interpreted, and clobbering it would strand a newer agent's ownership.
	stateFuture
)

// peekSchemaVersion extracts schema_version without committing to the full
// shape. ok=false when b is not a JSON object (corrupt); a JSON object with no
// schema_version field yields (0, true). This is what separates a "future"
// file (parseable object, high version → refuse) from a "corrupt" one (not an
// object → recreate).
func peekSchemaVersion(b []byte) (version int, ok bool) {
	var probe struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return 0, false
	}
	return probe.SchemaVersion, true
}

// readStateFile loads and classifies the state file. UNLOCKED: callers that
// also write hold cacheMu and call this (never the public ReadAppliedState),
// because cacheMu is not reentrant. On stateReadable, Categories is non-nil.
//
// The returned error is non-nil only for stateUnreadable, and is what a mutating
// caller returns instead of touching a file whose content it could not see.
func readStateFile() (AppliedStateFile, readStatus, error) {
	path := CachePath()
	if path == "" {
		return AppliedStateFile{}, stateUnreadable, errNoHomeDir
	}
	var b []byte
	if cacheStateFile != nil {
		parentPresent, err := cacheStateFile.ParentPresent()
		if err != nil {
			return AppliedStateFile{}, stateUnreadable, err
		}
		if !parentPresent {
			return AppliedStateFile{}, stateAbsentOrCorrupt, nil
		}
		var existed bool
		b, existed, _, err = cacheStateFile.Read()
		if err != nil {
			return AppliedStateFile{}, stateUnreadable, err
		}
		if !existed {
			return AppliedStateFile{}, stateAbsentOrCorrupt, nil
		}
		secure, err := cacheStateFile.MetadataSecure(cacheFileMode)
		if err != nil || !secure {
			if err == nil {
				err = fmt.Errorf("%w: %w", errInsecureStateMetadata, secureuserfile.ErrTargetUnusable)
			}
			return AppliedStateFile{}, stateUnreadable, err
		}
	} else {
		var err error
		// #nosec G304 -- CachePath is a test override or the fixed user-home state path.
		b, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return AppliedStateFile{}, stateAbsentOrCorrupt, nil
		}
		if err != nil {
			return AppliedStateFile{}, stateUnreadable, fmt.Errorf("devicepolicy: read %s: %w", path, err)
		}
	}
	ver, ok := peekSchemaVersion(b)
	if !ok {
		// Not a JSON object — corrupt. Safe to recreate.
		return AppliedStateFile{}, stateAbsentOrCorrupt, nil
	}
	// Refuse a file from a newer agent. A schema beyond what this build knows
	// may reuse fields with changed meaning; the reader falls back to "owns
	// nothing" and the writer refuses to clobber it.
	if ver > CacheSchemaVersion {
		return AppliedStateFile{}, stateFuture, nil
	}
	var f AppliedStateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return AppliedStateFile{}, stateAbsentOrCorrupt, nil
	}
	// A 0 version predates the field (or was hand-written); persistStateFile
	// always stamps it, so a genuine file from this agent is never 0. Two older
	// shapes parse here as "owns nothing" (one harmless re-apply, by design, NOT
	// migrated): a legacy single-object file (no "categories" key → empty map),
	// and a pre-target category-keyed file (categories.<cat> has no "targets" key
	// → nil Targets map → no target record).
	if f.SchemaVersion == 0 {
		f.SchemaVersion = CacheSchemaVersion
	}
	if f.Categories == nil {
		f.Categories = map[string]AppliedCategoryState{}
	}
	return f, stateReadable, nil
}

// prepareStateFile restores the strict permission boundary on a state file left
// with a broader DACL by an older agent (1.15/1.16 inherited their parent's), so
// its records stay readable instead of being refused. Permissions only: bytes,
// owner and every category's records are preserved, and a wrong owner is still
// refused before anything changes. Absent state is left absent. UNLOCKED: callers
// hold cacheMu and the state lock, so no peer can rewrite the file mid-repair.
func prepareStateFile() error {
	if cacheStateFile == nil {
		return nil
	}
	present, err := cacheStateFile.ParentPresent()
	if err != nil || !present {
		return err
	}
	if err := cacheStateFile.RepairMetadata(cacheFileMode); err != nil {
		return fmt.Errorf("devicepolicy: repair state permissions: %w", err)
	}
	return nil
}

// readPreparedStateFile is readStateFile after prepareStateFile, for callers
// holding both locks. A failed repair is stateUnreadable, so mutators refuse.
func readPreparedStateFile() (AppliedStateFile, readStatus, error) {
	if err := prepareStateFile(); err != nil {
		return AppliedStateFile{}, stateUnreadable, err
	}
	return readStateFile()
}

// ReadAppliedState returns the agent's recorded ownership for one
// (category, target): (state, true) when a record exists, else (zero, false).
// An empty target defaults to vscode. It never surfaces an error — a
// missing/corrupt/unreadable file, or one written by a newer agent
// (schema_version beyond this build's CacheSchemaVersion), simply means "no
// recorded ownership". The reconciler treats that as owning nothing: safe,
// because it then refuses to clear a value it has no record of writing and
// re-applies the policy. Only the MUTATING accessors distinguish unreadable from
// absent, because only they can destroy what they could not read.
//
// A plain read takes no file lock: it modifies nothing, and every write lands by
// atomic rename, so a reader sees one complete generation of the file or another —
// never a half-written one. Only state an older agent left with broader
// permissions takes the cross-process lock, to repair it before reading again;
// absent state never does, so a read creates nothing. A swallowed unreadable
// state is reported once per target through cacheWarnf, redacted.
func ReadAppliedState(category, target string) (AppliedTargetState, bool) {
	s, ok, err := readAppliedStateChecked(category, target)
	if err != nil {
		cacheMu.Lock()
		warnStateRead(err)
		cacheMu.Unlock()
	}
	return s, ok
}

// readAppliedStateChecked is ReadAppliedState without the warning, returning the
// error of an unreadable Windows target store (including a failed legacy
// permission repair) for a caller that must not treat it as owning nothing.
// Absent, corrupt and future-schema state return a nil error, as does any read
// on other platforms, whose behavior is unchanged.
func readAppliedStateChecked(category, target string) (AppliedTargetState, bool, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if target == "" {
		target = TargetVSCode
	}
	f, status, err := readStateFile()
	if errors.Is(err, errInsecureStateMetadata) {
		// A busy lock leaves the first read's stateUnreadable in place.
		err = withStateLock(func() error {
			var rerr error
			f, status, rerr = readPreparedStateFile()
			return rerr
		})
	}
	if status == stateUnreadable && cacheStateFile != nil {
		return AppliedTargetState{}, false, err
	}
	if status != stateReadable {
		return AppliedTargetState{}, false, nil
	}
	cat, ok := f.Categories[category]
	if !ok {
		return AppliedTargetState{}, false, nil
	}
	s, ok := cat.Targets[target]
	return s, ok, nil
}

// warnStateRead reports a swallowed read failure. Callers hold cacheMu.
func warnStateRead(err error) {
	if cacheWarnf == nil || err == nil {
		return
	}
	msg := redact.String(err.Error())
	if msg == cacheLastWarn {
		return
	}
	cacheLastWarn = msg
	cacheWarnf("devicepolicy: read applied state: %s", msg)
}

// WriteAppliedState records ownership for one (category, target), PRESERVING
// every other category AND every sibling target already in the file
// (read-modify-write), then atomically replaces the file (temp + sync + rename).
// An empty target defaults to vscode. It REFUSES to overwrite a file written by
// a newer agent (errFutureSchema) rather than clobber metadata it cannot
// interpret, and likewise refuses (returning the read error) when the file is
// present but unreadable — recreating it there would silently drop live sibling
// records whose content was never seen. A missing or corrupt file IS recreated:
// neither holds anything a read could have recovered.
//
// The whole read-modify-write runs under cacheMu and the cross-process file lock,
// so a concurrent write for a different category — an npm reconcile in one process
// against an IDE reconcile in another — cannot drop this one's record, or have its
// own dropped. That holds unconditionally: a lock that cannot be taken fails the
// write (errStateLockBusy and friends) instead of proceeding unlocked.
func WriteAppliedState(category, target string, s AppliedTargetState) error {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if target == "" {
		target = TargetVSCode
	}
	return withStateLock(func() error {
		f, status, rerr := readPreparedStateFile()
		switch status {
		case stateUnreadable:
			return rerr
		case stateFuture:
			return errFutureSchema
		case stateAbsentOrCorrupt:
			f = AppliedStateFile{Categories: map[string]AppliedCategoryState{}}
		}
		if f.Categories == nil {
			f.Categories = map[string]AppliedCategoryState{}
		}
		cat := f.Categories[category]
		if cat.Targets == nil {
			cat.Targets = map[string]AppliedTargetState{}
		}
		cat.Targets[target] = s
		f.Categories[category] = cat
		return persistStateFile(f)
	})
}

// ProbeAppliedStateWritable verifies that the shared state store can be read,
// locked, and atomically replaced without committing an ownership record.
func ProbeAppliedStateWritable() error {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	return withStateLock(func() error {
		_, status, err := readPreparedStateFile()
		switch status {
		case stateUnreadable:
			return err
		case stateFuture:
			return errFutureSchema
		}
		if cacheStateFile != nil {
			return cacheStateFile.ProbeWritable(cacheFileMode)
		}
		path := CachePath()
		if path == "" {
			return errNoHomeDir
		}
		parent := filepath.Dir(path)
		if err := ensureCacheParent(parent); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(parent, "."+CacheFilename+".probe-*")
		if err != nil {
			return err
		}
		name := tmp.Name()
		if err := tmp.Chmod(cacheFileMode); err != nil {
			_ = tmp.Close()
			_ = os.Remove(name)
			return err
		}
		if err := tmp.Close(); err != nil {
			_ = os.Remove(name)
			return err
		}
		return os.Remove(name)
	})
}

// ClearAppliedState drops one (category, target) ownership record, PRESERVING
// every other category AND every sibling target, then atomically rewrites the
// file. An empty target defaults to vscode. When the cleared target was the
// category's last, the now-empty category is dropped too. Same future-schema
// refusal and same cacheMu + cross-process locking as WriteAppliedState. An
// already-absent category/target is a no-op (nothing recorded to drop).
//
// A CORRUPT file is removed rather than left in place. Its bytes can still hold a
// token-bearing written_settings entry (the ~/.npmrc block records the device's
// auth token), and a clear is an unassignment or offboarding — reporting it done
// while those bytes survive on disk is what removal prevents. Nothing
// interpretable is lost: an unparseable file already reads as "owns nothing" for
// every category, so no sibling record could have been recovered from it. An
// absent file is left alone (there is nothing to remove).
//
// An UNREADABLE file is neither removed nor rewritten — the read error is
// returned. On POSIX a file with no read permission is still unlinkable through a
// writable parent, so removing it here would destroy sibling categories' live
// ownership records sight unseen; a surfaced error keeps the operation honest and
// leaves the file for the next cycle (or an admin) to deal with.
func ClearAppliedState(category, target string) error {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if target == "" {
		target = TargetVSCode
	}
	return withStateLock(func() error {
		f, status, rerr := readPreparedStateFile()
		switch status {
		case stateUnreadable:
			return rerr
		case stateFuture:
			return errFutureSchema
		case stateAbsentOrCorrupt:
			return removeStateFile()
		}
		cat, ok := f.Categories[category]
		if !ok {
			return nil
		}
		if _, ok := cat.Targets[target]; !ok {
			return nil
		}
		delete(cat.Targets, target)
		if len(cat.Targets) == 0 {
			delete(f.Categories, category)
		} else {
			f.Categories[category] = cat
		}
		if len(f.Categories) == 0 {
			return removeStateFile()
		}
		return persistStateFile(f)
	})
}

// removeStateFile unlinks the state file, treating an already-absent one as
// success — which is what makes it safe for the shared absent-or-corrupt status:
// absent stays a no-op, corrupt gets cleaned up. UNLOCKED: callers hold cacheMu
// and the file lock. A symlink at the path is unlinked itself, not followed, so it
// cannot redirect the delete.
func removeStateFile() error {
	if cacheStateFile != nil {
		parentPresent, err := cacheStateFile.ParentPresent()
		if err != nil || !parentPresent {
			return err
		}
		if err := cacheStateFile.Remove(); err != nil {
			return err
		}
		return cacheStateFile.PurgeBackups()
	}
	path := CachePath()
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// persistStateFile stamps the current schema version and atomically writes the
// file, creating the parent dir with 0o700 and the file with 0o600. UNLOCKED —
// callers hold cacheMu.
func persistStateFile(f AppliedStateFile) error {
	f.SchemaVersion = CacheSchemaVersion
	if f.Categories == nil {
		f.Categories = map[string]AppliedCategoryState{}
	}
	path := CachePath()
	if path == "" {
		return errNoHomeDir
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if cacheStateFile != nil {
		if err := cacheStateFile.EnsureParent(); err != nil {
			return err
		}
		if err := cacheStateFile.Commit(data, cacheFileMode); err != nil {
			return err
		}
		_ = cacheStateFile.PurgeBackups()
		return nil
	}

	parent := filepath.Dir(path)
	if err := ensureCacheParent(parent); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(parent, "."+CacheFilename+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	err = tmp.Chmod(cacheFileMode)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func ensureCacheParent(path string) error {
	if err := os.MkdirAll(path, cacheParentDirMode); err != nil {
		return err
	}
	return os.Chmod(path, cacheParentDirMode)
}

type cacheError string

func (e cacheError) Error() string { return string(e) }

const (
	errNoHomeDir    = cacheError("devicepolicy: cannot resolve home directory")
	errFutureSchema = cacheError("devicepolicy: refusing to overwrite a newer-schema state file")
	// errInsecureStateMetadata: the state file's permissions are broader than the
	// strict contract, as an older agent left them; the locked paths repair it.
	errInsecureStateMetadata = cacheError("devicepolicy: insecure cache metadata")
	// errStateLockBusy: a peer agent process held the state lock for the whole wait
	// budget. The read-modify-write is abandoned rather than run unlocked — see
	// withStateLock for why that trade is deliberate.
	errStateLockBusy = cacheError("devicepolicy: another process holds the enforcement-state lock")
)
