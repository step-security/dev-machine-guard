package state

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// CacheFilename is the basename of the cache file. Lives under
// ~/.stepsecurity/ alongside config.json and ai-agent-hook-errors.jsonl.
const CacheFilename = "hooks-state.json"

const (
	cacheFileMode      os.FileMode = 0o600
	cacheParentDirMode os.FileMode = 0o700
)

// cachePathOverride lets tests redirect reads/writes to a tempdir.
// Production leaves it empty. Mutating from outside this package is
// a test-only concern; same pattern as cli.errorLogPathOverride.
var cachePathOverride string

// SetCachePathForTest redirects CachePath() to the given absolute path
// and returns a restore function. Test-only; production code never
// calls this. Living on the package surface (rather than as a
// build-tagged file) keeps cross-package tests in hook/* and main_test
// able to drive the override without an internal-import trick.
func SetCachePathForTest(p string) (restore func()) {
	prev := cachePathOverride
	cachePathOverride = p
	return func() { cachePathOverride = prev }
}

// CachePath returns the absolute cache path, honoring the test
// override when set.
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

// Read returns (state, true) on a successful parse. Any I/O or parse
// error returns (Default(), false) — Read never surfaces an error
// because the hot path must remain fail-open.
func Read() (State, bool) {
	path := CachePath()
	if path == "" {
		return Default(), false
	}
	// #nosec G304 -- path is CachePath(): either a test override set by
	// SetCachePathForTest, or os.UserHomeDir() joined with the package
	// constant CacheFilename. Never derived from external input.
	b, err := os.ReadFile(path)
	if err != nil {
		return Default(), false
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return Default(), false
	}
	if s.SchemaVersion == 0 {
		// Forward-compat tolerance: missing schema_version reads as the
		// current version. A future breaking change would gate on a
		// specific value here.
		s.SchemaVersion = SchemaVersion
	}
	return s, true
}

// Write atomically replaces the cache file. No backups are kept — the
// cache is rewritten on every reconcile tick, and orphaned backups
// would accumulate trash. Parent dir is created with 0o700.
func Write(s State) error {
	path := CachePath()
	if path == "" {
		return errNoHomeDir
	}
	data, err := json.MarshalIndent(s, "", "  ")
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

const errNoHomeDir = cacheError("state: cannot resolve home directory")
