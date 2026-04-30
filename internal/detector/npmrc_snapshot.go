package detector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// CurrentNPMRCSnapshotVersion is the schema version we write today. Bump
// this whenever the on-disk shape changes incompatibly. Loaders should
// treat any other version as "no prior snapshot" — better to start fresh
// than to mis-diff old data.
const CurrentNPMRCSnapshotVersion = 1

// npmrcStateDir returns the directory we persist the snapshot in. We mirror
// the convention used by internal/config (~/.stepsecurity/) and put state
// under a dedicated `state/` subdir so config and state stay separate
// concerns.
func npmrcStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Fallback: emit into the temp dir so save/load doesn't crash, even
		// in environments without a home (some launchd / systemd contexts).
		// The diff will work for the lifetime of that tempdir; that's fine
		// for the contexts we care about.
		return filepath.Join(os.TempDir(), "stepsecurity-state")
	}
	return filepath.Join(home, ".stepsecurity", "state")
}

// NPMRCSnapshotFilePath is the absolute path to the snapshot file. Exposed
// so tests and the verbose pretty view can reference it.
func NPMRCSnapshotFilePath() string {
	return filepath.Join(npmrcStateDir(), "npmrc.json")
}

// BuildNPMRCSnapshot extracts a digest snapshot from a fresh audit. It's
// pure — no I/O, no time-dependent fields except the timestamp which the
// caller can override via the audit's existing data.
func BuildNPMRCSnapshot(audit *model.NPMRCAudit, takenAtUnix int64, hostname string) model.NPMRCSnapshot {
	files := make([]model.NPMRCFileSnapshot, 0, len(audit.Files))
	for _, f := range audit.Files {
		entries := make([]model.NPMRCEntryDigest, 0, len(f.Entries))
		for _, e := range f.Entries {
			entries = append(entries, model.NPMRCEntryDigest{
				Key:         e.Key,
				ValueSHA256: e.ValueSHA256,
				IsAuth:      e.IsAuth,
				IsArray:     e.IsArray,
			})
		}
		files = append(files, model.NPMRCFileSnapshot{
			Path:        f.Path,
			Scope:       f.Scope,
			Exists:      f.Exists,
			SHA256:      f.SHA256,
			SizeBytes:   f.SizeBytes,
			ModTimeUnix: f.ModTimeUnix,
			Mode:        f.Mode,
			OwnerName:   f.OwnerName,
			GroupName:   f.GroupName,
			Entries:     entries,
		})
	}

	envs := make([]model.NPMRCEnvVarSnapshot, 0, len(audit.Env))
	for _, e := range audit.Env {
		envs = append(envs, model.NPMRCEnvVarSnapshot{
			Name:        e.Name,
			Set:         e.Set,
			ValueSHA256: e.ValueSHA256,
		})
	}

	return model.NPMRCSnapshot{
		SnapshotVersion: CurrentNPMRCSnapshotVersion,
		AgentVersion:    buildinfo.Version,
		TakenAt:         takenAtUnix,
		Hostname:        hostname,
		Files:           files,
		Env:             envs,
	}
}

// LoadNPMRCSnapshot reads the previous snapshot from disk. Returns nil if:
//   - the file does not exist (first run)
//   - the file is corrupt / unparseable (treat as first run; better than crashing)
//   - the schema version doesn't match (treat as first run; old data is
//     not safe to diff against)
//
// Callers should NOT treat a nil return as an error condition; the diff
// layer will produce a FirstRun=true diff and the next save establishes
// the new baseline.
func LoadNPMRCSnapshot() (*model.NPMRCSnapshot, error) {
	data, err := os.ReadFile(NPMRCSnapshotFilePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var snap model.NPMRCSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		// Corrupt — log via returned error and let the caller decide. The
		// scanner ignores the error and continues with a FirstRun diff.
		return nil, fmt.Errorf("npmrc snapshot decode: %w", err)
	}
	if snap.SnapshotVersion != CurrentNPMRCSnapshotVersion {
		return nil, fmt.Errorf("npmrc snapshot version mismatch (got %d, want %d) — treating as first run",
			snap.SnapshotVersion, CurrentNPMRCSnapshotVersion)
	}
	return &snap, nil
}

// AttachDiff loads the previous snapshot, computes a diff against the
// current audit, enriches the diff with attribution, then writes the
// current state as the new baseline. It's the single entry point the
// scanner / telemetry / npmrc-only paths call to wire change tracking
// into an audit run.
//
// All errors are non-fatal: we want change tracking to be best-effort, not
// a reason for a scan to fail. Callers can still log returned errors but
// shouldn't propagate them.
func AttachDiff(ctx context.Context, exec executor.Executor, audit *model.NPMRCAudit, scanTimeUnix int64, hostname string) error {
	if audit == nil {
		return nil
	}
	prev, loadErr := LoadNPMRCSnapshot()
	// loadErr != nil is OK — we just treat as first run.
	diff := DiffNPMRC(prev, audit, scanTimeUnix)
	if diff != nil && len(diff.ModifiedFiles) > 0 {
		EnrichAttribution(ctx, exec, diff, scanTimeUnix)
	}
	audit.Diff = diff

	// Save current as the new baseline. Build snapshot from the audit AS
	// IT IS (post-diff is fine — Diff is metadata, not part of the
	// snapshot). If save fails, the diff against next run will be a
	// false-positive "first run" — annoying but not a security issue.
	curSnap := BuildNPMRCSnapshot(audit, scanTimeUnix, hostname)
	saveErr := SaveNPMRCSnapshot(&curSnap)

	if loadErr != nil {
		return fmt.Errorf("loading previous snapshot: %w", loadErr)
	}
	return saveErr
}

// SaveNPMRCSnapshot writes the snapshot atomically: write to a temp file in
// the same directory, then rename. This way an interrupted run never leaves
// a partial snapshot that the next run would mis-diff against. Mode 0600
// because the snapshot includes file paths, env-var names, and SHA-256
// fingerprints of secrets — nothing sensitive in plaintext, but still
// owner-only is the right default.
func SaveNPMRCSnapshot(snap *model.NPMRCSnapshot) error {
	dir := npmrcStateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}
	finalPath := NPMRCSnapshotFilePath()

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling snapshot: %w", err)
	}

	// Write to a sibling temp file then rename. os.Rename is atomic on
	// POSIX and on NTFS for same-volume moves.
	tmp, err := os.CreateTemp(dir, ".npmrc-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp snapshot: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// Best-effort cleanup if rename never happened.
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp snapshot: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp snapshot: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("renaming snapshot: %w", err)
	}
	return nil
}
