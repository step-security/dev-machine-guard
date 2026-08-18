package telemetry

import (
	"sync"
	"time"
)

// PhaseCompletion records a single analysis phase that ran to completion.
// The list of these forms phases_completed in the run-status payload.
type PhaseCompletion struct {
	Name       string `json:"name"`
	FinishedAt int64  `json:"finished_at"`
	DurationMs int64  `json:"duration_ms"`
	// SleptMs is how long the system was suspended while this phase ran:
	// the wall-clock elapsed minus the monotonic elapsed (macOS/Linux
	// monotonic clocks halt during sleep; Windows QPC usually keeps ticking,
	// so this under-reports there). DurationMs stays monotonic — actual work
	// time — so a phase that spanned a laptop nap reports both honestly.
	SleptMs int64 `json:"slept_ms,omitempty"`
}

// RunStatusInfo is the structured progress snapshot sent on each phase
// boundary and on every heartbeat tick. The same struct is embedded on the
// final telemetry Payload so a stored telemetry record is self-describing
// without joining to the run-status table.
//
// In-flight sub-progress (set via PhaseTracker.UpdateDetail) is folded into
// CurrentPhase as "<phase> (<detail>)" rather than carried in a separate
// field, so older backends that don't know about phase-detail still surface
// the string verbatim. Completed phases keep their base name only.
type RunStatusInfo struct {
	PhasesCompleted []PhaseCompletion `json:"phases_completed,omitempty"`
	CurrentPhase    string            `json:"current_phase,omitempty"`
	ElapsedMs       int64             `json:"elapsed_ms"`
	// LogTailGzipBase64 is an optional snapshot of the most recent
	// captureTailBytes bytes of the agent's stderr stream, gzip-compressed
	// and base64-encoded. Attached on a throttle (logTailHeartbeatInterval)
	// so the wire cost stays bounded even when phase boundaries fire
	// rapidly. Backend handlers must tolerate this field being absent on
	// any given snapshot.
	LogTailGzipBase64 string `json:"log_tail_gzip_b64,omitempty"`
	// SleptMs is the run-level counterpart of PhaseCompletion.SleptMs,
	// measured from run start so it also covers sleep that lands between
	// phases. Report-only: ElapsedMs stays monotonic.
	SleptMs int64 `json:"slept_ms,omitempty"`
}

// minReportedSleep is the smallest wall-vs-monotonic divergence reported as
// system sleep. NTP steps/slews and scheduler jitter can move the wall clock
// a few seconds relative to the monotonic clock; a genuine sleep is minutes.
const minReportedSleep = 60 * time.Second

// sleptDuration returns how long the system was suspended during an
// interval, given the interval measured on the wall clock and on the
// monotonic clock. Divergence below minReportedSleep — including the
// degenerate equal-inputs case, which is what a clock source without a
// monotonic reading (time.Unix-constructed test clocks) produces — reports
// zero. Never negative.
func sleptDuration(wallElapsed, monoElapsed time.Duration) time.Duration {
	d := wallElapsed - monoElapsed
	if d < minReportedSleep {
		return 0
	}
	return d
}

// PhaseTracker accumulates phase lifecycle events for a single telemetry
// run. The heartbeat goroutine and the main scan goroutine both touch it
// concurrently — Snapshot returns a defensive copy so the caller never
// observes a torn slice while a phase is appended.
type PhaseTracker struct {
	mu                 sync.Mutex
	startedAt          time.Time
	phaseStartedAt     time.Time
	currentPhase       string
	currentPhaseDetail string
	completed          []PhaseCompletion
	now                func() time.Time // overridable for tests
}

// NewPhaseTracker constructs a tracker anchored at the current time.
func NewPhaseTracker() *PhaseTracker {
	return newPhaseTrackerWithClock(time.Now)
}

func newPhaseTrackerWithClock(now func() time.Time) *PhaseTracker {
	return &PhaseTracker{
		startedAt: now(),
		now:       now,
	}
}

// Start records the beginning of a new phase. Calling Start while another
// phase is already in flight implicitly finishes the previous one — this
// keeps call sites tidy when phases run back-to-back without a Finish in
// between. Detail from the previous phase is cleared so it never leaks
// into the new one.
func (t *PhaseTracker) Start(phase string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.currentPhase != "" {
		t.finishLocked()
	}
	t.currentPhase = phase
	t.currentPhaseDetail = ""
	t.phaseStartedAt = t.now()
}

// Finish records completion of the current phase and returns it. The bool
// is false when nothing was in flight — safe to defer and to call in
// statement position.
func (t *PhaseTracker) Finish() (PhaseCompletion, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.finishLocked()
}

func (t *PhaseTracker) finishLocked() (PhaseCompletion, bool) {
	if t.currentPhase == "" {
		return PhaseCompletion{}, false
	}
	finishedAt := t.now()
	// Sub prefers the monotonic readings when both stamps carry one (actual
	// work time — halts during system sleep); Round(0) strips them, so the
	// second Sub is pure wall clock. The difference is time spent asleep.
	mono := finishedAt.Sub(t.phaseStartedAt)
	wall := finishedAt.Round(0).Sub(t.phaseStartedAt.Round(0))
	pc := PhaseCompletion{
		Name:       t.currentPhase,
		FinishedAt: finishedAt.Unix(),
		DurationMs: mono.Milliseconds(),
		SleptMs:    sleptDuration(wall, mono).Milliseconds(),
	}
	t.completed = append(t.completed, pc)
	t.currentPhase = ""
	t.currentPhaseDetail = ""
	return pc, true
}

// UpdateDetail sets a free-form sub-progress string for the current
// phase ("project 12 of 47", "scanning pip3", ...). No-op when no phase
// is in flight — keeps call sites tidy when a scanner reports progress
// from inside a goroutine that may outlive its enclosing Start/Finish.
func (t *PhaseTracker) UpdateDetail(detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.currentPhase == "" {
		return
	}
	t.currentPhaseDetail = detail
}

// Snapshot returns a copy of the tracker state safe for marshalling on
// another goroutine. The returned slice is independent of the tracker's
// internal buffer.
//
// When the in-flight phase has a detail set, it's folded into CurrentPhase
// as "<phase> (<detail>)" so the wire format stays flat — older backends
// without a dedicated detail field still render the progress verbatim.
// PhasesCompleted entries keep their base name; detail is per-tick state,
// not a permanent label.
func (t *PhaseTracker) Snapshot() RunStatusInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	current := t.currentPhase
	// Defense in depth: 5 of 10 RocketMortgage heartbeat rows showed
	// current_phase = "null" (literal string). The agent-side code path
	// here writes "" between phases and omitempty omits empty strings
	// from the JSON payload, so the literal should be unreachable — but
	// guard against any future regression that re-introduces it, keeping
	// the wire contract explicit (current_phase is never the string "null").
	if current == "null" {
		current = ""
	}
	if current != "" && t.currentPhaseDetail != "" {
		current = current + " (" + t.currentPhaseDetail + ")"
	}

	now := t.now()
	out := RunStatusInfo{
		CurrentPhase: current,
		ElapsedMs:    now.Sub(t.startedAt).Milliseconds(),
		// Run-level sleep, measured from run start so it also covers sleep
		// landing between phases (per-phase SleptMs can't see those gaps).
		SleptMs: sleptDuration(now.Round(0).Sub(t.startedAt.Round(0)), now.Sub(t.startedAt)).Milliseconds(),
	}
	if len(t.completed) > 0 {
		out.PhasesCompleted = make([]PhaseCompletion, len(t.completed))
		copy(out.PhasesCompleted, t.completed)
	}
	return out
}
