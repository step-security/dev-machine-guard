package devicepolicy

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
)

// StateStore is the ownership store the reconciler reads and writes through. It
// abstracts WHERE a category's applied-state records live so a category can keep
// its records in its own file instead of the shared device-policy-state.json.
// The three methods mirror the package-level ReadAppliedState /
// WriteAppliedState / ClearAppliedState the shared IDE path still calls directly.
//
// The npm category always uses one of these; the IDE category leaves it nil and
// keeps the shared store, byte-for-byte unchanged.
type StateStore interface {
	Read(category, target string) (AppliedTargetState, bool)
	Write(category, target string, s AppliedTargetState) error
	Drop(category, target string) error
}

// packageConfigStateBasename is the state-file basename for the package_config
// category. It is DELIBERATELY separate from CacheFilename (the shared IDE
// state): neither store takes a cross-process lock, so the only thing that keeps
// a package reconcile in one process from silently dropping a concurrent IDE
// reconcile's record in another (or vice versa) is that they never share a file.
// Separate files make that lost update structurally impossible.
const packageConfigStateBasename = "package-config-state"

// NewStateStoreFor builds the package_config ownership store for a resolved
// target user. It is bound to the identity handed in — the writer's
// TargetUser(), resolved exactly once — never a second independent lookup, so a
// console-user switch between two resolutions cannot file one user's state under
// another's record.
//
// Placement:
//   - user mode (the process IS the target user; the common case, and every
//     Windows case) → <home>/.stepsecurity/package-config-state.json (0600).
//   - root mode (a POSIX daemon running as uid 0) → a machine-owned directory
//     (/Library/Application Support/StepSecurity on macOS, /var/lib/stepsecurity
//     on Linux; 0700 root) with ONE record file per target uid
//     (package-config-state-<uid>.json). The shared store's ~/.stepsecurity is
//     unsafe under root here: the LaunchDaemon bakes the install-time console
//     user's HOME into its plist, so os.UserHomeDir() resolves into a
//     user-controlled tree and stays pinned to that user even after someone else
//     logs in. Per-uid files also keep one console user's ~/.npmrc state from
//     conflating with another's across cycles (false drift / wrong ownership).
func NewStateStoreFor(u *user.User) StateStore {
	if dir, uid, ok := rootMachineStateDir(u); ok {
		return &fileStateStore{
			dir:  dir,
			path: filepath.Join(dir, packageConfigStateBasename+"-"+uid+".json"),
		}
	}
	home := ""
	if u != nil {
		home = u.HomeDir
	}
	dir := filepath.Join(home, ".stepsecurity")
	return &fileStateStore{
		dir:  dir,
		path: filepath.Join(dir, packageConfigStateBasename+".json"),
	}
}

// rootMachineStateDir returns the machine-owned state directory and the target
// user's uid string when the process is a POSIX root daemon with a usable
// per-user identity. ok=false — meaning user-mode placement — when the process
// is not root (Geteuid is -1 on Windows, so it never is there), the OS has no
// defined machine path, or the uid is unresolvable.
func rootMachineStateDir(u *user.User) (dir, uid string, ok bool) {
	if os.Geteuid() != 0 || u == nil {
		return "", "", false
	}
	if _, err := strconv.Atoi(u.Uid); err != nil {
		return "", "", false
	}
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/StepSecurity", u.Uid, true
	case "linux":
		return "/var/lib/stepsecurity", u.Uid, true
	default:
		return "", "", false
	}
}

// fileStateStore is a StateStore backed by one JSON file at a fixed path. It
// carries the same schema-versioned category→target→record shape and the same
// atomic-replace (temp + fsync + rename) + future-schema-refusal discipline as
// the shared cache.go store — only the path differs, and the file belongs to
// this category alone. A process-local mutex serializes its read-modify-write
// within a process; across processes there is no lock — the atomic temp+rename
// keeps the file from tearing, and a concurrent overlap is eventually consistent
// (identical records while the policy is stable; a transient stale record only
// during a policy transition, reconverged on the next cycle).
type fileStateStore struct {
	dir  string
	path string
	mu   sync.Mutex
}

func (s *fileStateStore) Read(category, target string) (AppliedTargetState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, status := s.load()
	if status != stateReadable {
		return AppliedTargetState{}, false
	}
	cat, ok := f.Categories[category]
	if !ok {
		return AppliedTargetState{}, false
	}
	st, ok := cat.Targets[target]
	return st, ok
}

func (s *fileStateStore) Write(category, target string, st AppliedTargetState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, status := s.load()
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
	cat.Targets[target] = st
	f.Categories[category] = cat
	return s.persist(f)
}

func (s *fileStateStore) Drop(category, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, status := s.load()
	switch status {
	case stateFuture:
		return errFutureSchema
	case stateAbsentOrCorrupt:
		// Absent → nothing to drop. Corrupt (present but unparseable) → the bytes on
		// disk can still carry a token-bearing WrittenValue; a Drop that left the file
		// in place would strand that credential after offboarding. Remove it so no
		// stale record — readable or not — survives the clear.
		return s.removeIfPresent()
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
	return s.persist(f)
}

// removeIfPresent deletes this store's file, treating an already-absent file as
// success. It underpins Drop's corrupt-file cleanup: a corrupt state file is
// removed rather than left to strand a token-bearing record on disk. A symlink at
// the path is unlinked (not its target), so it cannot redirect the delete.
func (s *fileStateStore) removeIfPresent() error {
	if s.path == "" {
		return nil
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// load reads and classifies this store's file. UNLOCKED: callers hold s.mu. It
// is the path-parameterized twin of cache.go's readStateFile and reuses the same
// schema-version classification (corrupt → recreate, newer → refuse).
func (s *fileStateStore) load() (AppliedStateFile, readStatus) {
	if s.path == "" {
		return AppliedStateFile{}, stateAbsentOrCorrupt
	}
	// #nosec G304 -- s.path is built from the resolved target user's home or a
	// fixed machine directory plus package constants, never external input.
	b, err := os.ReadFile(s.path)
	if err != nil {
		return AppliedStateFile{}, stateAbsentOrCorrupt
	}
	ver, ok := peekSchemaVersion(b)
	if !ok {
		return AppliedStateFile{}, stateAbsentOrCorrupt
	}
	if ver > CacheSchemaVersion {
		return AppliedStateFile{}, stateFuture
	}
	var f AppliedStateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return AppliedStateFile{}, stateAbsentOrCorrupt
	}
	if f.SchemaVersion == 0 {
		f.SchemaVersion = CacheSchemaVersion
	}
	if f.Categories == nil {
		f.Categories = map[string]AppliedCategoryState{}
	}
	return f, stateReadable
}

// persist stamps the schema version and atomically replaces the file, creating
// the parent dir 0700 and the file 0600. UNLOCKED: callers hold s.mu. The
// path-parameterized twin of cache.go's persistStateFile. On POSIX root the dir
// and file land root-owned (machine state); in user mode they are the target
// user's own — either way not group/other-accessible.
func (s *fileStateStore) persist(f AppliedStateFile) error {
	f.SchemaVersion = CacheSchemaVersion
	if f.Categories == nil {
		f.Categories = map[string]AppliedCategoryState{}
	}
	if s.path == "" || s.dir == "" {
		return errNoHomeDir
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := os.MkdirAll(s.dir, cacheParentDirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "."+packageConfigStateBasename+".tmp-*")
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
	return os.Rename(tmpPath, s.path)
}
