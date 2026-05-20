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
