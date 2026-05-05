// Package atomicfile writes files using a temp-file + rename discipline so
// readers never observe a half-written state.
//
// Atomic-write order: create temp in target dir → write → fsync → close →
// chmod → rename. Any existing file at the target is copied to a sibling
// backup (`<path>.dmg-<UTC stamp>.bak`) before the rename.
//
// Ownership is intentionally NOT this package's concern. Under root
// install, the caller (the install handler) chowns the result to the
// console user — WriteResult exposes every path we wrote or created so
// the caller has the full set without having to walk the filesystem.
//
// The `Restore`, `RestoreOptions`, `RestoreResult`, and `ListBackups`
// operations are omitted — `hooks restore` is not in scope.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// BackupPrefix is the literal between the original path and the timestamp
// on backup files. BackupExt is the trailing extension. Together they
// produce: `<path>.dmg-<UTC stamp>.bak`. The `.bak` ending is the
// conventional backup marker most editors and gitignore templates already
// recognize; the `dmg-` token identifies the file as ours.
const (
	BackupPrefix = ".dmg-"
	BackupExt    = ".bak"
)

// BackupStampLayout is the time.Format layout used in backup filenames.
// UTC is mandatory so backups sort chronologically across timezones.
const BackupStampLayout = "20060102T150405"

// MaxBackups caps per-target backup retention. After TakeBackup creates
// a new backup, older DMG-owned backups for the same target are deleted
// so at most MaxBackups remain (newest by mtime). Both the current
// `<path>.dmg-<stamp>.bak` form and the legacy `<path>.dmg-backup.<stamp>`
// form count toward the same cap so the rotation gradually cleans up
// files left from before the rename.
const MaxBackups = 3

// WriteResult reports every path WriteAtomic touched. The install handler
// uses CreatedDirs + Path + BackupPath to chown new files under root.
type WriteResult struct {
	Path        string   // the target file we wrote
	BackupPath  string   // "" when no pre-existing file was backed up
	CreatedDirs []string // every parent dir we mkdir'd (deepest last); empty if all parents existed
}

// PickMode returns the existing file's permission bits, or fallback if the
// file does not exist. Used so reinstalls preserve a user-tightened mode
// instead of clobbering with the default.
func PickMode(path string, fallback os.FileMode) os.FileMode {
	info, err := os.Stat(path)
	if err != nil {
		return fallback.Perm()
	}
	return info.Mode().Perm()
}

// TakeBackup copies the existing file at path to a sibling
// `<path>.dmg-<stamp>.bak`. Returns "" with nil error if the source
// does not exist (the common first-install case).
func TakeBackup(path string, now time.Time) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("atomicfile: %s is a directory, not a file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backupPath := path + BackupPrefix + now.UTC().Format(BackupStampLayout) + BackupExt
	if err := os.WriteFile(backupPath, data, info.Mode().Perm()); err != nil {
		return "", err
	}
	pruneBackups(path, MaxBackups)
	return backupPath, nil
}

// pruneBackups deletes older DMG-owned backups for path so at most keep
// remain (newest by mtime). Both the current `.dmg-*.bak` form and the
// legacy `.dmg-backup.*` form go in the same pool — the cap holds across
// the rename so legacy files don't linger forever.
//
// Best-effort: stat/remove errors are swallowed. Rotation must not fail
// the surrounding write — at worst a few extra backups stick around.
func pruneBackups(path string, keep int) {
	pool := []string{}
	for _, pattern := range []string{path + BackupPrefix + "*" + BackupExt, path + ".dmg-backup.*"} {
		m, _ := filepath.Glob(pattern)
		pool = append(pool, m...)
	}
	if len(pool) <= keep {
		return
	}
	type entry struct {
		name  string
		mtime time.Time
	}
	entries := make([]entry, 0, len(pool))
	for _, p := range pool {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		entries = append(entries, entry{p, info.ModTime()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].mtime.After(entries[j].mtime) })
	for i := keep; i < len(entries); i++ {
		_ = os.Remove(entries[i].name)
	}
}

// WriteAtomic writes data to path atomically. Parent directories are
// created (and reported) as needed; any existing file is backed up first.
//
// The temp file lives in the target directory (same filesystem) so the
// final rename is atomic on POSIX.
func WriteAtomic(path string, data []byte, mode os.FileMode) (WriteResult, error) {
	result := WriteResult{Path: path}

	backup, err := TakeBackup(path, time.Now())
	if err != nil {
		return result, fmt.Errorf("atomicfile: backup: %w", err)
	}
	result.BackupPath = backup

	parent := filepath.Dir(path)
	created, err := mkdirAllTracking(parent, 0o755)
	if err != nil {
		return result, fmt.Errorf("atomicfile: mkdir parents: %w", err)
	}
	result.CreatedDirs = created

	tmp, err := os.CreateTemp(parent, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return result, fmt.Errorf("atomicfile: create temp: %w", err)
	}
	tmpPath := tmp.Name()

	// Best-effort cleanup if anything below fails. Ignored on the success
	// path because rename consumes the temp.
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return result, fmt.Errorf("atomicfile: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return result, fmt.Errorf("atomicfile: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return result, fmt.Errorf("atomicfile: close temp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode.Perm()); err != nil {
		return result, fmt.Errorf("atomicfile: chmod temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return result, fmt.Errorf("atomicfile: rename: %w", err)
	}

	return result, nil
}

// InstallBytes is a thin alias used at install sites to make intent clear:
// "install these bytes at this path." Implementation is identical to
// WriteAtomic.
func InstallBytes(path string, data []byte, mode os.FileMode) (WriteResult, error) {
	return WriteAtomic(path, data, mode)
}

// mkdirAllTracking creates path (and any missing ancestors) with the given
// perm, returning only the directories it actually created — existing
// dirs are excluded. Order is shallowest-first so chown can apply parent
// before child without TOCTOU concerns.
func mkdirAllTracking(path string, perm os.FileMode) ([]string, error) {
	var toCreate []string
	cur := filepath.Clean(path)

	for {
		info, err := os.Stat(cur)
		switch {
		case err == nil && info.IsDir():
			// Reached an existing dir — stop walking up.
			goto create
		case err == nil:
			return nil, fmt.Errorf("atomicfile: %s exists but is not a directory", cur)
		case !os.IsNotExist(err):
			return nil, err
		}

		toCreate = append([]string{cur}, toCreate...)
		parent := filepath.Dir(cur)
		if parent == cur {
			// Hit filesystem root with no existing ancestor.
			return nil, fmt.Errorf("atomicfile: cannot create %s: no existing ancestor", path)
		}
		cur = parent
	}

create:
	for _, d := range toCreate {
		if err := os.Mkdir(d, perm.Perm()); err != nil && !os.IsExist(err) {
			return toCreate, err
		}
	}
	return toCreate, nil
}
