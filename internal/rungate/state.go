package rungate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/paths"
)

// StateSchemaVersion is the on-disk version of run-gate-state.json. Bump only
// on a breaking shape change.
const StateSchemaVersion = 1

const (
	stateFileMode      os.FileMode = 0o600
	stateParentDirMode os.FileMode = 0o700
)

// State is the gate's on-disk memory: the cached device id (so skipped
// wakeups never re-probe the serial), the last successful full run (stamped
// after the telemetry upload), and the last directive's gating fields (the
// offline fallback gate). Everything here is advisory — a missing or corrupt
// file only costs one probe and one fail-open run, never a wrong skip.
type State struct {
	SchemaVersion            int    `json:"schema_version"`
	DeviceID                 string `json:"device_id,omitempty"`
	LastFullRunAt            int64  `json:"last_full_run_at,omitempty"` // unix sec; stamped on upload success
	GatingEnabled            bool   `json:"gating_enabled,omitempty"`
	EffectiveIntervalMinutes int    `json:"effective_interval_minutes,omitempty"`
	DirectiveFetchedAt       int64  `json:"directive_fetched_at,omitempty"` // unix sec of the last successful check-in
}

type loadStatus int

const (
	loadOK loadStatus = iota
	loadAbsentOrCorrupt
	loadFutureSchema
)

var errFutureSchema = errors.New("rungate: refusing to overwrite a newer-schema state file")

// stateMu serializes in-process read-modify-writes (the gate at run start and
// the stamp after upload live in one sequential process today; the mutex is
// cheap insurance against future concurrent callers). Cross-process safety
// relies on atomic-rename last-writer-wins, same as the devicepolicy cache.
var stateMu sync.Mutex

// statePathOverride lets tests redirect reads/writes to a tempdir.
var statePathOverride string

// SetStatePathForTest redirects the state file to the given absolute path and
// returns a restore function. Test-only.
func SetStatePathForTest(p string) (restore func()) {
	prev := statePathOverride
	statePathOverride = p
	return func() { statePathOverride = prev }
}

func statePath() string {
	if statePathOverride != "" {
		return statePathOverride
	}
	return paths.RunGateStateFile()
}

// loadState reads and classifies the state file. A parseable file stamped by
// a NEWER agent is loadFutureSchema: readers treat it as "no usable state"
// and writers refuse to clobber it (its fields may have changed meaning).
func loadState(path string) (State, loadStatus) {
	if path == "" {
		return State{}, loadAbsentOrCorrupt
	}
	// #nosec G304 -- path is RunGateStateFile() or a test override, never
	// external input.
	b, err := os.ReadFile(path)
	if err != nil {
		return State{}, loadAbsentOrCorrupt
	}
	var probe struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return State{}, loadAbsentOrCorrupt
	}
	if probe.SchemaVersion > StateSchemaVersion {
		return State{}, loadFutureSchema
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, loadAbsentOrCorrupt
	}
	return st, loadOK
}

// saveState stamps the schema version and atomically replaces the file
// (temp + sync + rename, 0600 under a 0700 dir). UNLOCKED — callers hold
// stateMu.
func saveState(path string, st State) error {
	if path == "" {
		return errors.New("rungate: no home directory for state file")
	}
	st.SchemaVersion = StateSchemaVersion
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, stateParentDirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(parent, "."+filepath.Base(path)+".tmp-*")
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
	if err := os.Chmod(tmpPath, stateFileMode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// mutateState is the shared read-modify-write: load (recreating on
// absent/corrupt, refusing on future schema), apply, save.
func mutateState(apply func(*State)) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	path := statePath()
	st, status := loadState(path)
	if status == loadFutureSchema {
		return errFutureSchema
	}
	if status == loadAbsentOrCorrupt {
		st = State{}
	}
	apply(&st)
	return saveState(path, st)
}

// StampLastFullRun records a completed full run (called from telemetry.Run
// right after the upload succeeds). Best-effort by contract: on failure the
// next gated invocation simply runs again.
func StampLastFullRun(now time.Time) error {
	return mutateState(func(st *State) {
		st.LastFullRunAt = now.Unix()
	})
}

// recordCheckin persists the freshly-resolved device id and the directive's
// gating fields after a successful check-in, preserving LastFullRunAt. The
// interval — never the skip itself — is what the offline fallback replays, so
// a stale cache can only delay a scan by one interval, not suppress it.
func recordCheckin(deviceID string, d Directive, fetchedAt time.Time) error {
	return mutateState(func(st *State) {
		st.DeviceID = deviceID
		st.GatingEnabled = d.GatingEnabled
		st.EffectiveIntervalMinutes = d.EffectiveIntervalMinutes
		st.DirectiveFetchedAt = fetchedAt.Unix()
	})
}

// readState returns the current state for the gate's decision inputs.
// ok=false covers absent, corrupt, and future-schema files alike — all mean
// "no usable local state" (fail open).
func readState() (State, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	st, status := loadState(statePath())
	return st, status == loadOK
}
