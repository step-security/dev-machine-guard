package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

// Resolve returns the absolute, fully symlink-resolved path of the
// running DMG binary. The result is what `hooks install` writes into
// agent settings as the hook command prefix.
//
// Symlinks are evaluated so the recorded path is canonical — Homebrew,
// for example, installs binaries under `/opt/homebrew/Cellar/...` and
// links `/opt/homebrew/bin/<name>` to them. Recording the Cellar path
// means a `brew upgrade` that swaps the symlink target still leaves a
// valid hook command (until the Cellar path itself is removed).
//
// On Windows, EvalSymlinks resolves directory junctions and reparse
// points the same way it resolves Unix symlinks.
func Resolve() (string, error) {
	raw, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("selfpath: os.Executable: %w", err)
	}
	return resolveFrom(raw)
}

// resolveFrom is the testable core of Resolve. It expects an absolute or
// relative path and returns the absolute, symlink-resolved canonical form.
//
// If symlink evaluation fails (broken link, permissions), the call fails
// rather than falling back to the unresolved path — recording an
// unresolved path defeats the canonicalization the install relies on.
func resolveFrom(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("selfpath: EvalSymlinks(%s): %w", path, err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("selfpath: Abs(%s): %w", resolved, err)
	}
	return abs, nil
}
