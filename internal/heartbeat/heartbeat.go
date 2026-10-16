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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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

// Record is the last-run.json envelope. The top-level fields are a
// point-in-time stamp that a run began — start-of-run facts only; the scan
// outcome lives in scan-state.json (LastSuccessfulExecutionID) and
// agent.error.log. RunGate is the run gate's small cache, folded into this
// same file rather than a sibling run-gate-state.json: it is the same "last
// run" kind of data written to the same install dir, and is consulted only on
// the offline fallback path.
type Record struct {
	SchemaVersion    int       `json:"schema_version"`
	WrittenAt        time.Time `json:"written_at"`
	PID              int       `json:"pid"`
	AgentVersion     string    `json:"agent_version"`
	Command          string    `json:"command"`           // subcommand that started the run, e.g. "send-telemetry"
	InvocationMethod string    `json:"invocation_method"` // scheduler footprint vs manual; see telemetry.DetectInvocationMethod
	OS               string    `json:"os"`
	RunGate          *RunGate  `json:"run_gate,omitempty"`
}

// RunGate is the run gate's cached memory: the resolved device id (so skipped
// wakeups never re-probe the serial), the last completed full run (stamped
// after upload), and the last directive's gating fields. Nil until the first
// successful check-in. Everything here is advisory — a missing, corrupt, or
// future-schema file only costs one serial probe and one fail-open run, never
// a wrong skip. Fields mirror the wire directive; see internal/rungate.
type RunGate struct {
	DeviceID                 string `json:"device_id,omitempty"`
	LastFullRunAt            int64  `json:"last_full_run_at,omitempty"` // unix sec; stamped on upload success
	GatingEnabled            bool   `json:"gating_enabled,omitempty"`
	EffectiveIntervalMinutes int    `json:"effective_interval_minutes,omitempty"`
	DirectiveFetchedAt       int64  `json:"directive_fetched_at,omitempty"` // unix sec of the last successful check-in
}

// mu serializes the read-modify-write writers (Write for the breadcrumb,
// UpdateRunGate for the gate cache). Within a single run they execute
// sequentially on the main goroutine; the mutex is cheap insurance for any
// future concurrent caller. Cross-process safety is atomic-rename
// last-writer-wins, same as internal/state.
var mu sync.Mutex

// Write stamps last-run.json at path with this run's start metadata. An empty
// path is a no-op returning nil — callers pass paths.HeartbeatFile(), which is
// "" when the install dir is disabled (--install-dir=""), and treat the
// heartbeat as off in that case. Best-effort: callers should log a write error
// at debug/warn and continue, never fail the run on it.
//
// It read-modify-writes so the RunGate cache survives: the heartbeat is
// stamped at the very top of every run, before the gate reads that cache on
// the offline path, so a blind overwrite here would erase it every wakeup.
func Write(path, command, invocationMethod string) error {
	if path == "" {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	rec := loadForUpdate(path)
	rec.SchemaVersion = SchemaVersion
	rec.WrittenAt = time.Now().UTC()
	rec.PID = os.Getpid()
	rec.AgentVersion = buildinfo.Version
	rec.Command = command
	rec.InvocationMethod = invocationMethod
	rec.OS = runtime.GOOS
	return writeRecord(path, rec)
}

// UpdateRunGate applies a read-modify-write to the RunGate cache in the file
// at path, preserving the breadcrumb fields and any RunGate fields the apply
// func leaves untouched. internal/rungate uses it to stamp the last full run
// and record each check-in. Best-effort by contract: on failure the next
// gated invocation simply re-probes / re-checks. Empty path errors so the
// caller can log it.
func UpdateRunGate(path string, apply func(*RunGate)) error {
	if path == "" {
		return errors.New("heartbeat: no path for run-gate state")
	}
	mu.Lock()
	defer mu.Unlock()
	rec := loadForUpdate(path)
	rec.SchemaVersion = SchemaVersion
	if rec.RunGate == nil {
		rec.RunGate = &RunGate{}
	}
	apply(rec.RunGate)
	return writeRecord(path, rec)
}

// loadForUpdate returns the record at path for a read-modify-write, or a zero
// Record when the file is absent, unreadable, corrupt, or a schema mismatch —
// all treated as "start fresh". The breadcrumb must always write, and the gate
// cache is fail-open-safe, so (unlike a versioned config) a newer-schema file
// is overwritten rather than preserved; only a rare downgrade hits that, and
// it costs at most one fail-open run. UNLOCKED — callers hold mu.
func loadForUpdate(path string) Record {
	rec, err := Load(path)
	if err != nil || rec == nil {
		return Record{}
	}
	return *rec
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
