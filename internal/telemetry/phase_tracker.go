package telemetry

import (
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/awakeclock"
	"github.com/step-security/dev-machine-guard/internal/procusage"
)

// PhaseCompletion records a single analysis phase that ran to completion.
// The list of these forms phases_completed in the run-status payload.
type PhaseCompletion struct {
	Name       string `json:"name"`
	FinishedAt int64  `json:"finished_at"`
	DurationMs int64  `json:"duration_ms"`
	// CPUMs is CPU consumed during the phase (self plus subprocesses
	// where the platform attributes them), so an expensive phase is
	// distinguishable from a merely slow one. There is no memory
	// equivalent: peak RSS is a lifetime high-water mark and cannot be
	// differenced across phase boundaries.
	CPUMs int64 `json:"cpu_ms,omitempty"`
	// SleptMs is how long the system was suspended while this phase ran:
	// wall-clock elapsed minus awake elapsed (internal/awakeclock: the
	// monotonic clock on macOS and Linux, QueryUnbiasedInterruptTime on
	// Windows). DurationMs is awake time, the actual work, so a phase that
	// spanned a laptop nap reports both honestly.
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
	// phases. ElapsedMs is awake time; the two add up to wall-clock time.
	SleptMs int64 `json:"slept_ms,omitempty"`
}

// minReportedSleep is the smallest wall-vs-awake divergence reported as
// system sleep. NTP steps and slews move the wall clock a few seconds
// relative to the awake clock; a genuine sleep is minutes.
const minReportedSleep = 60 * time.Second

// sleptDuration returns how long the system was suspended during an
// interval, given the interval measured on the wall clock and on the awake
// clock. Divergence below minReportedSleep, including the equal-inputs case
// a single test clock produces, reports zero. Never negative.
func sleptDuration(wallElapsed, awakeElapsed time.Duration) time.Duration {
	d := wallElapsed - awakeElapsed
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
	startedAwake       time.Duration
	phaseStartedAt     time.Time
	phaseStartedAwake  time.Duration
	phaseStartedCPUMs  int64
	currentPhase       string
	currentPhaseDetail string
	completed          []PhaseCompletion
	now                func() time.Time     // wall clock; overridable for tests
	awake              func() time.Duration // awake clock; nil derives it from now (tests)
	cpuMs              func() int64         // overridable for tests
}

// NewPhaseTracker constructs a tracker anchored at the current time.
func NewPhaseTracker() *PhaseTracker {
	return newPhaseTrackerWithClocks(awakeclock.System.Wall, awakeclock.System.Awake)
}

// newPhaseTrackerWithClock drives both readings from one clock, so wall and
// awake time never diverge and every phase reports zero sleep.
func newPhaseTrackerWithClock(now func() time.Time) *PhaseTracker {
	return newPhaseTrackerWithClocks(now, nil)
}

func newPhaseTrackerWithClocks(now func() time.Time, awake func() time.Duration) *PhaseTracker {
	t := &PhaseTracker{now: now, awake: awake, cpuMs: procusage.CPUMillis}
	t.startedAt = now()
	if awake != nil {
		t.startedAwake = awake()
	}
	return t
}

// readClocks takes one wall reading and the matching awake reading. With no
// awake source the awake time is derived from the same wall stamp, so the
// single-clock tests see identical deltas and no sleep.
func (t *PhaseTracker) readClocks() (time.Time, time.Duration) {
	now := t.now()
	if t.awake == nil {
		return now, now.Sub(t.startedAt)
	}
	return now, t.awake()
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
	t.phaseStartedAt, t.phaseStartedAwake = t.readClocks()
	t.phaseStartedCPUMs = t.cpuMs()
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
	finishedAt, finishedAwake := t.readClocks()
	// CPU counters are monotonic, but clamp anyway: a swapped-in reader
	// or a failed getrusage returning 0 must not emit a negative cost.
	cpuDelta := t.cpuMs() - t.phaseStartedCPUMs
	if cpuDelta < 0 {
		cpuDelta = 0
	}
	// Work time is awake time. Round(0) strips any monotonic reading from
	// the stamps so the second difference is pure wall clock; the gap
	// between the two is time spent asleep.
	work := finishedAwake - t.phaseStartedAwake
	if work < 0 {
		work = 0
	}
	wall := finishedAt.Round(0).Sub(t.phaseStartedAt.Round(0))
	pc := PhaseCompletion{
		Name:       t.currentPhase,
		FinishedAt: finishedAt.Unix(),
		DurationMs: work.Milliseconds(),
		CPUMs:      cpuDelta,
		SleptMs:    sleptDuration(wall, work).Milliseconds(),
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

	now, awakeNow := t.readClocks()
	elapsed := awakeNow - t.startedAwake
	if elapsed < 0 {
		elapsed = 0
	}
	out := RunStatusInfo{
		CurrentPhase: current,
		ElapsedMs:    elapsed.Milliseconds(),
		// Run-level sleep, measured from run start so it also covers sleep
		// landing between phases (per-phase SleptMs can't see those gaps).
		SleptMs: sleptDuration(now.Round(0).Sub(t.startedAt.Round(0)), elapsed).Milliseconds(),
	}
	if len(t.completed) > 0 {
		out.PhasesCompleted = make([]PhaseCompletion, len(t.completed))
		copy(out.PhasesCompleted, t.completed)
	}
	return out
}
