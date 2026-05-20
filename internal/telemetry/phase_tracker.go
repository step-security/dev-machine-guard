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
}

// RunStatusInfo is the structured progress snapshot sent on each phase
// boundary and on every heartbeat tick. The same struct is embedded on the
// final telemetry Payload so a stored telemetry record is self-describing
// without joining to the run-status table.
type RunStatusInfo struct {
	PhasesCompleted []PhaseCompletion `json:"phases_completed,omitempty"`
	CurrentPhase    string            `json:"current_phase,omitempty"`
	ElapsedMs       int64             `json:"elapsed_ms"`
}

// PhaseTracker accumulates phase lifecycle events for a single telemetry
// run. The heartbeat goroutine and the main scan goroutine both touch it
// concurrently — Snapshot returns a defensive copy so the caller never
// observes a torn slice while a phase is appended.
type PhaseTracker struct {
	mu             sync.Mutex
	startedAt      time.Time
	phaseStartedAt time.Time
	currentPhase   string
	completed      []PhaseCompletion
	now            func() time.Time // overridable for tests
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
// between.
func (t *PhaseTracker) Start(phase string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.currentPhase != "" {
		t.finishLocked()
	}
	t.currentPhase = phase
	t.phaseStartedAt = t.now()
}

// Finish records completion of the current phase. No-op when nothing is
// in flight — safe to defer.
func (t *PhaseTracker) Finish() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finishLocked()
}

func (t *PhaseTracker) finishLocked() {
	if t.currentPhase == "" {
		return
	}
	finishedAt := t.now()
	t.completed = append(t.completed, PhaseCompletion{
		Name:       t.currentPhase,
		FinishedAt: finishedAt.Unix(),
		DurationMs: finishedAt.Sub(t.phaseStartedAt).Milliseconds(),
	})
	t.currentPhase = ""
}

// Snapshot returns a copy of the tracker state safe for marshalling on
// another goroutine. The returned slice is independent of the tracker's
// internal buffer.
func (t *PhaseTracker) Snapshot() RunStatusInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := RunStatusInfo{
		CurrentPhase: t.currentPhase,
		ElapsedMs:    t.now().Sub(t.startedAt).Milliseconds(),
	}
	if len(t.completed) > 0 {
		out.PhasesCompleted = make([]PhaseCompletion, len(t.completed))
		copy(out.PhasesCompleted, t.completed)
	}
	return out
}
