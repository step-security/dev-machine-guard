// Package heartbeat writes a small last-run.json "I started" breadcrumb to
// the install dir at the very top of a telemetry run — before the
// enterprise-config gate and before the singleton lock is acquired.
//
// Why this exists, separate from agent.error.log and scan-state.json: those
// only appear once a run gets far enough to log a line or finish an upload.
// Several failure modes never reach that point — a process killed mid-startup
// (e.g. the Windows GUI-launcher teardown), a run that fails the enterprise
// gate, a lock it can never acquire. The heartbeat captures "this binary
// started at time T, pid P, triggered by X" independent of any of that, so a
// stale file means "the agent isn't being invoked at all" (scheduler not
// firing — battery policy, missing task) while a fresh file alongside missing
// server-side telemetry means "the agent runs but dies/fails before upload."
//
// The write is durable against the abrupt termination it is meant to record:
// marshal to a temp sibling, fsync, then atomically rename over last-run.json
// (same pattern as internal/state). A kill at any point leaves either the
// previous heartbeat or the new one — never a truncated file.
package heartbeat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
)

// SchemaVersion is the on-disk format version for last-run.json. Bump when
// the Record shape changes incompatibly; readers treat a mismatch as "no
// usable heartbeat" rather than failing.
const SchemaVersion = 1

// Filename is the basename written into the install dir. Exported so callers
// and diagnostics can reference it without duplicating the literal.
const Filename = "last-run.json"

// Record is the last-run.json envelope: a point-in-time stamp that a run
// began. It deliberately carries only start-of-run facts — outcome lives in
// scan-state.json (LastSuccessfulExecutionID) and agent.error.log.
type Record struct {
	SchemaVersion    int       `json:"schema_version"`
	WrittenAt        time.Time `json:"written_at"`
	PID              int       `json:"pid"`
	AgentVersion     string    `json:"agent_version"`
	Command          string    `json:"command"`           // subcommand that started the run, e.g. "send-telemetry"
	InvocationMethod string    `json:"invocation_method"` // scheduler footprint vs manual; see telemetry.DetectInvocationMethod
	OS               string    `json:"os"`
}

// Write stamps last-run.json at path with this run's start metadata. An empty
// path is a no-op returning nil — callers pass paths.HeartbeatFile(), which is
// "" when the install dir is disabled (--install-dir=""), and treat the
// heartbeat as off in that case. Best-effort: callers should log a write error
// at debug/warn and continue, never fail the run on it.
func Write(path, command, invocationMethod string) error {
	if path == "" {
		return nil
	}
	rec := Record{
		SchemaVersion:    SchemaVersion,
		WrittenAt:        time.Now().UTC(),
		PID:              os.Getpid(),
		AgentVersion:     buildinfo.Version,
		Command:          command,
		InvocationMethod: invocationMethod,
		OS:               runtime.GOOS,
	}
	return writeRecord(path, rec)
}

// Load reads last-run.json. A missing file, parse error, or schema mismatch
// returns (nil, err) with err nil for the missing/mismatch cases (expected
// fall-throughs) so callers can treat a nil record as "no usable heartbeat"
// without distinguishing causes. Exposed for diagnostics and any future
// fleet-view that folds the last-run summary into the telemetry payload.
func Load(path string) (*Record, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.SchemaVersion != SchemaVersion {
		return nil, nil
	}
	return &r, nil
}

// writeRecord persists rec to path atomically: temp sibling, fsync, rename.
// Mirrors internal/state.Save, including the Windows pre-remove (os.Rename
// there fails when the destination already exists).
func writeRecord(path string, rec Record) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".last-run-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	_ = os.Remove(path)
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
