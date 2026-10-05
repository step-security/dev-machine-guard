package rungate

import (
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
	"github.com/step-security/dev-machine-guard/internal/paths"
)

// The run gate's cached memory lives inside last-run.json (heartbeat.RunGate),
// not a separate file: it is the same "last run" kind of data, written to the
// same install dir, and is read only on the offline fallback path. state.go is
// the thin adapter between the gate's decision logic and that shared storage.

// statePathOverride lets tests redirect reads/writes to a tempdir.
var statePathOverride string

// SetStatePathForTest redirects the gate's state file to the given absolute
// path and returns a restore function. Test-only.
func SetStatePathForTest(p string) (restore func()) {
	prev := statePathOverride
	statePathOverride = p
	return func() { statePathOverride = prev }
}

// statePath resolves last-run.json (the shared heartbeat + gate-cache file),
// or "" when the install dir is disabled — callers fail open on "".
func statePath() string {
	if statePathOverride != "" {
		return statePathOverride
	}
	return paths.HeartbeatFile()
}

// StampLastFullRun records a completed full run (called from telemetry.Run
// right after the upload succeeds). Best-effort by contract: on failure the
// next gated invocation simply runs again.
func StampLastFullRun(now time.Time) error {
	return heartbeat.UpdateRunGate(statePath(), func(rg *heartbeat.RunGate) {
		rg.LastFullRunAt = now.Unix()
	})
}

// recordCheckin persists the freshly-resolved device id and the directive's
// gating fields after a successful check-in, preserving LastFullRunAt. The
// interval — never the skip itself — is what the offline fallback replays, so
// a stale cache can only delay a scan by one interval, not suppress it.
func recordCheckin(deviceID string, d Directive, fetchedAt time.Time) error {
	return heartbeat.UpdateRunGate(statePath(), func(rg *heartbeat.RunGate) {
		if rg.DeviceID != "" && rg.DeviceID != deviceID {
			rg.LastFullRunAt = 0
		}
		rg.ConfiguredDeviceID = strings.TrimSpace(config.DeviceID)
		rg.DeviceID = deviceID
		rg.GatingEnabled = d.GatingEnabled
		rg.EffectiveIntervalMinutes = d.EffectiveIntervalMinutes
		rg.DirectiveFetchedAt = fetchedAt.Unix()
	})
}

// readState returns the gate's cached fields for the decision inputs.
// ok=false covers absent, corrupt, future-schema, and never-checked-in files
// alike — all mean "no usable local state" (fail open).
func readState() (heartbeat.RunGate, bool) {
	rec, err := heartbeat.Load(statePath())
	if err != nil || rec == nil || rec.RunGate == nil {
		return heartbeat.RunGate{}, false
	}
	return *rec.RunGate, true
}
