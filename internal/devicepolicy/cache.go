package devicepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CacheFilename is the basename of the enforcement state file. It lives under
// ~/.stepsecurity/ alongside config.json and hooks-state.json, and is distinct
// from the AI-agent hook cache (this is a separate subsystem — no shared state).
const CacheFilename = "device-policy-state.json"

// CacheSchemaVersion is the on-disk version of the state file. Bump only on a
// breaking shape change.
const CacheSchemaVersion = 1

const (
	cacheFileMode      os.FileMode = 0o600
	cacheParentDirMode os.FileMode = 0o700
)

// AppliedStateFile is the on-disk shape: a schema-versioned wrapper keyed by
// category and then by target, so multiple categories and IDE targets share one
// file without forcing a future migration. Exactly one pair
// (ide_extension/vscode) is populated today.
//
//	{
//	  "schema_version": 1,
//	  "categories": {
//	    "ide_extension": {
//	      "targets": {
//	        "vscode": { "applied_hash": …, "written_settings": …, "fetched_at": … }
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

// AppliedTargetState records what the agent last wrote to the user-scope
// settings for one (category, target). Value-based ownership drives both drift
// and clear: a key is converged or removed only while its on-disk value still
// equals what the agent recorded writing (a differing value — e.g. the user's
// own — is left untouched).
//
//   - AppliedHash is the backend's content hash, stored VERBATIM (never
//     recomputed). Compared against the freshly-fetched hash for idempotency.
//   - WrittenSettings holds ownership for the managed multi-key path: setting id
//     → the exact compacted value the agent wrote, for every managed key (the VS
//     Code allowlist and the gallery service URL). A key absent from the map is
//     one the agent does not own.
//   - WrittenValue holds ownership for the single-key path (the npm writer, which
//     owns one opaque value). The managed multi-key path does not use it.
//
// A zero-value entry means "the agent owns nothing on disk" for that
// category/target.
type AppliedTargetState struct {
	AppliedHash     string            `json:"applied_hash"`
	WrittenValue    string            `json:"written_value,omitempty"`
	WrittenSettings map[string]string `json:"written_settings,omitempty"`
	FetchedAt       time.Time         `json:"fetched_at"`
}

// cacheMu serializes the read-modify-write of the shared state file so two
// in-process category writers cannot lose each other's update. It does NOT make
// the file safe across separate agent PROCESSES — that still relies on
// atomic-rename last-writer-wins, and a cross-process lock (flock/LockFileEx)
// would be needed before categories are reconciled concurrently or multiple
// agents run against more than one category.
//
// The lock is NOT reentrant: helpers that already hold it use the unlocked
// readStateFile / persistStateFile, never the public ReadAppliedState /
// WriteAppliedState / ClearAppliedState.
var cacheMu sync.Mutex

// cachePathOverride lets tests redirect reads/writes to a tempdir. Production
// leaves it empty. Same pattern as state.cachePathOverride.
var cachePathOverride string

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
	// stateAbsentOrCorrupt: missing, unreadable, or not a JSON object. Safe to
	// recreate from scratch.
	stateAbsentOrCorrupt
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
func readStateFile() (AppliedStateFile, readStatus) {
	path := CachePath()
	if path == "" {
		return AppliedStateFile{}, stateAbsentOrCorrupt
	}
	// #nosec G304 -- path is CachePath(): a test override or os.UserHomeDir()
	// joined with the package constant CacheFilename. Never external input.
	b, err := os.ReadFile(path)
	if err != nil {
		return AppliedStateFile{}, stateAbsentOrCorrupt
	}
	ver, ok := peekSchemaVersion(b)
	if !ok {
		// Not a JSON object — corrupt. Safe to recreate.
		return AppliedStateFile{}, stateAbsentOrCorrupt
	}
	// Refuse a file from a newer agent. A schema beyond what this build knows
	// may reuse fields with changed meaning; the reader falls back to "owns
	// nothing" and the writer refuses to clobber it.
	if ver > CacheSchemaVersion {
		return AppliedStateFile{}, stateFuture
	}
	var f AppliedStateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return AppliedStateFile{}, stateAbsentOrCorrupt
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
	return f, stateReadable
}

// ReadAppliedState returns the agent's recorded ownership for one
// (category, target): (state, true) when a record exists, else (zero, false).
// An empty target defaults to vscode. It never surfaces an error — a
// missing/corrupt file, or one written by a newer agent (schema_version beyond
// this build's CacheSchemaVersion), simply means "no recorded ownership". The
// reconciler treats that as owning nothing: safe, because it then refuses to
// clear a value it has no record of writing and re-applies the policy.
func ReadAppliedState(category, target string) (AppliedTargetState, bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if target == "" {
		target = TargetVSCode
	}
	f, status := readStateFile()
	if status != stateReadable {
		return AppliedTargetState{}, false
	}
	cat, ok := f.Categories[category]
	if !ok {
		return AppliedTargetState{}, false
	}
	s, ok := cat.Targets[target]
	return s, ok
}

// WriteAppliedState records ownership for one (category, target), PRESERVING
// every other category AND every sibling target already in the file
// (read-modify-write), then atomically replaces the file (temp + sync + rename).
// An empty target defaults to vscode. It REFUSES to overwrite a file written by
// a newer agent (errFutureSchema) rather than clobber metadata it cannot
// interpret. A missing or corrupt file is recreated.
func WriteAppliedState(category, target string, s AppliedTargetState) error {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if target == "" {
		target = TargetVSCode
	}
	f, status := readStateFile()
	switch status {
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
}

// ClearAppliedState drops one (category, target) ownership record, PRESERVING
// every other category AND every sibling target, then atomically rewrites the
// file. An empty target defaults to vscode. When the cleared target was the
// category's last, the now-empty category is dropped too. Same future-schema
// refusal as WriteAppliedState. A missing or corrupt file — or an already-absent
// category/target — is a no-op (nothing recorded to drop).
func ClearAppliedState(category, target string) error {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if target == "" {
		target = TargetVSCode
	}
	f, status := readStateFile()
	switch status {
	case stateFuture:
		return errFutureSchema
	case stateAbsentOrCorrupt:
		return nil
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
	return persistStateFile(f)
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

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, cacheParentDirMode); err != nil {
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
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, cacheFileMode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

type cacheError string

func (e cacheError) Error() string { return string(e) }

const (
	errNoHomeDir    = cacheError("devicepolicy: cannot resolve home directory")
	errFutureSchema = cacheError("devicepolicy: refusing to overwrite a newer-schema state file")
)
