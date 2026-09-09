package telemetry

import (
	"sync"
	"testing"
	"time"
)

// fakeClock returns deterministic, monotonically advancing timestamps so
// duration math in the tracker is checkable without sleeping.
type fakeClock struct {
	mu   sync.Mutex
	cur  time.Time
	step time.Duration
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.cur
	f.cur = f.cur.Add(f.step)
	return t
}

func TestPhaseTracker_StartFinishRecordsCompletion(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	pt := newPhaseTrackerWithClock(clk.now)

	pt.Start("device_info") // t=0
	pt.Finish()             // t=1

	snap := pt.Snapshot() // t=2 — advances clock for elapsed_ms
	if len(snap.PhasesCompleted) != 1 {
		t.Fatalf("phases_completed = %d, want 1", len(snap.PhasesCompleted))
	}
	got := snap.PhasesCompleted[0]
	if got.Name != "device_info" {
		t.Errorf("name = %q, want device_info", got.Name)
	}
	if got.DurationMs != 1000 {
		t.Errorf("duration_ms = %d, want 1000", got.DurationMs)
	}
	if snap.CurrentPhase != "" {
		t.Errorf("current_phase = %q, want empty after Finish", snap.CurrentPhase)
	}
}

func TestPhaseTracker_StartImplicitlyFinishesPrevious(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	pt := newPhaseTrackerWithClock(clk.now)

	pt.Start("ide_scan")       // t=0
	pt.Start("extension_scan") // t=1 — implicit finish of ide_scan
	pt.Finish()                // t=2

	snap := pt.Snapshot()
	if len(snap.PhasesCompleted) != 2 {
		t.Fatalf("phases_completed = %d, want 2", len(snap.PhasesCompleted))
	}
	if snap.PhasesCompleted[0].Name != "ide_scan" || snap.PhasesCompleted[1].Name != "extension_scan" {
		t.Errorf("unexpected order: %+v", snap.PhasesCompleted)
	}
}

func TestPhaseTracker_SnapshotIncludesInFlightPhase(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	pt := newPhaseTrackerWithClock(clk.now)

	pt.Start("brew_scan") // t=0

	snap := pt.Snapshot() // t=1 — snapshot mid-phase
	if snap.CurrentPhase != "brew_scan" {
		t.Errorf("current_phase = %q, want brew_scan", snap.CurrentPhase)
	}
	if len(snap.PhasesCompleted) != 0 {
		t.Errorf("phases_completed = %d, want 0 while phase still running", len(snap.PhasesCompleted))
	}
	if snap.ElapsedMs < 1000 {
		t.Errorf("elapsed_ms = %d, want ≥ 1000", snap.ElapsedMs)
	}
}

func TestPhaseTracker_FinishNoOpWithoutStart(t *testing.T) {
	pt := NewPhaseTracker()
	pt.Finish() // no panic
	if got := pt.Snapshot(); len(got.PhasesCompleted) != 0 || got.CurrentPhase != "" {
		t.Errorf("after Finish-without-Start: %+v, want zero state", got)
	}
}

// Defensive: 5 of 10 RocketMortgage heartbeat rows surfaced the literal
// string "null" in current_phase. The agent-side code shouldn't ever
// produce that — Start writes a real phase name and Finish writes "" —
// but Snapshot now sanitizes it explicitly so the wire contract is
// "current_phase is never the literal string 'null'" regardless of any
// future regression.
func TestPhaseTracker_SnapshotSanitizesLiteralNullCurrentPhase(t *testing.T) {
	pt := NewPhaseTracker()
	pt.currentPhase = "null" // bypass the public API to inject the bad state directly

	snap := pt.Snapshot()
	if snap.CurrentPhase != "" {
		t.Errorf("current_phase = %q, want empty string (sanitized)", snap.CurrentPhase)
	}
}

func TestPhaseTracker_SnapshotIsDefensiveCopy(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	pt := newPhaseTrackerWithClock(clk.now)

	pt.Start("a")
	pt.Finish()
	snap := pt.Snapshot()

	// Mutating the snapshot must not affect the tracker's internal state.
	if len(snap.PhasesCompleted) > 0 {
		snap.PhasesCompleted[0].Name = "tampered"
	}

	again := pt.Snapshot()
	if again.PhasesCompleted[0].Name != "a" {
		t.Errorf("internal phase name was tampered via snapshot: got %q",
			again.PhasesCompleted[0].Name)
	}
}

func TestPhaseTracker_UpdateDetailFoldsIntoCurrentPhase(t *testing.T) {
	pt := NewPhaseTracker()

	// Detail before Start is a no-op — keeps callers from leaking stale
	// per-phase strings into the next phase.
	pt.UpdateDetail("dropped")
	if got := pt.Snapshot(); got.CurrentPhase != "" {
		t.Errorf("detail before Start should be ignored, got %q", got.CurrentPhase)
	}

	pt.Start("brew_scan")
	if got := pt.Snapshot(); got.CurrentPhase != "brew_scan" {
		t.Errorf("no detail yet: current_phase = %q, want %q", got.CurrentPhase, "brew_scan")
	}

	pt.UpdateDetail("fetching formulae")
	if got := pt.Snapshot(); got.CurrentPhase != "brew_scan (fetching formulae)" {
		t.Errorf("with detail: current_phase = %q, want %q",
			got.CurrentPhase, "brew_scan (fetching formulae)")
	}

	pt.UpdateDetail("fetching casks")
	if got := pt.Snapshot(); got.CurrentPhase != "brew_scan (fetching casks)" {
		t.Errorf("detail should overwrite, got %q", got.CurrentPhase)
	}
}

func TestPhaseTracker_StartClearsPreviousDetail(t *testing.T) {
	pt := NewPhaseTracker()

	pt.Start("a")
	pt.UpdateDetail("a-detail")
	pt.Start("b") // implicit finish of a; detail must reset
	if got := pt.Snapshot(); got.CurrentPhase != "b" {
		t.Errorf("detail should reset on next phase, got current_phase = %q", got.CurrentPhase)
	}
}

func TestPhaseTracker_FinishClearsDetail(t *testing.T) {
	pt := NewPhaseTracker()

	pt.Start("a")
	pt.UpdateDetail("in-flight")
	pt.Finish()
	if got := pt.Snapshot(); got.CurrentPhase != "" {
		t.Errorf("detail should clear on Finish, got current_phase = %q", got.CurrentPhase)
	}
}

// Completed phases keep their base name only — detail is per-tick state,
// not a permanent label baked into history.
func TestPhaseTracker_CompletedPhasesKeepBaseName(t *testing.T) {
	pt := NewPhaseTracker()

	pt.Start("node_scan")
	pt.UpdateDetail("project 5 of 10")
	pt.Finish()

	snap := pt.Snapshot()
	if len(snap.PhasesCompleted) != 1 {
		t.Fatalf("phases_completed = %d, want 1", len(snap.PhasesCompleted))
	}
	if snap.PhasesCompleted[0].Name != "node_scan" {
		t.Errorf("completed name = %q, want bare %q without detail",
			snap.PhasesCompleted[0].Name, "node_scan")
	}
}

func TestPhaseTracker_ConcurrentReadDuringWrite(t *testing.T) {
	// Race detector must report clean. Spawn a writer that flips phases and
	// a reader (mimicking the heartbeat goroutine) that snapshots repeatedly.
	pt := NewPhaseTracker()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 1000 {
			pt.Start("phase")
			pt.Finish()
		}
		close(stop)
	}()

	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = pt.Snapshot()
			}
		}
	}()

	wg.Wait()
}

// fakeCPU returns a monotonically advancing CPU total so per-phase
// deltas are checkable without burning real cycles.
type fakeCPU struct {
	mu   sync.Mutex
	cur  int64
	step int64
}

func (f *fakeCPU) millis() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.cur
	f.cur += f.step
	return v
}

func TestPhaseTracker_RecordsPerPhaseCPU(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	cpu := &fakeCPU{step: 100}
	pt := newPhaseTrackerWithClock(clk.now)
	pt.cpuMs = cpu.millis

	pt.Start("ide_scan")       // cpu reads 0
	pt.Start("extension_scan") // implicit finish reads 100; new phase starts at 200
	pt.Finish()                // reads 300

	snap := pt.Snapshot()
	if len(snap.PhasesCompleted) != 2 {
		t.Fatalf("phases_completed = %d, want 2", len(snap.PhasesCompleted))
	}
	for _, p := range snap.PhasesCompleted {
		if p.CPUMs != 100 {
			t.Errorf("%s cpu_ms = %d, want 100", p.Name, p.CPUMs)
		}
	}
}

// TestPhaseTracker_CPUNeverNegative covers a failed getrusage returning
// zero mid-run, which would otherwise emit a negative phase cost.
func TestPhaseTracker_CPUNeverNegative(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	readings := []int64{500, 0}
	i := 0
	pt := newPhaseTrackerWithClock(clk.now)
	pt.cpuMs = func() int64 {
		v := readings[i]
		if i < len(readings)-1 {
			i++
		}
		return v
	}

	pt.Start("ide_scan")
	pt.Finish()

	snap := pt.Snapshot()
	if got := snap.PhasesCompleted[0].CPUMs; got != 0 {
		t.Errorf("cpu_ms = %d, want 0 (clamped)", got)
	}
}
