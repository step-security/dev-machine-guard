package telemetry

import (
	"testing"
	"time"
)

func TestSleptDuration(t *testing.T) {
	tests := []struct {
		name string
		wall time.Duration
		mono time.Duration
		want time.Duration
	}{
		{name: "equal inputs (no monotonic reading)", wall: 5 * time.Minute, mono: 5 * time.Minute, want: 0},
		{name: "divergence below threshold (NTP step)", wall: 5*time.Minute + 59*time.Second, mono: 5 * time.Minute, want: 0},
		{name: "divergence exactly at threshold", wall: 6 * time.Minute, mono: 5 * time.Minute, want: 60 * time.Second},
		{name: "incident shape: 53m wall vs 7m work", wall: 53 * time.Minute, mono: 7 * time.Minute, want: 46 * time.Minute},
		{name: "negative divergence clamps to zero", wall: 4 * time.Minute, mono: 5 * time.Minute, want: 0},
		{name: "zero interval", wall: 0, mono: 0, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sleptDuration(tc.wall, tc.mono); got != tc.want {
				t.Errorf("sleptDuration(%v, %v) = %v, want %v", tc.wall, tc.mono, got, tc.want)
			}
		})
	}
}

// The fakeClock produces time.Unix-constructed stamps with no monotonic
// reading, so wall and monotonic elapsed are identical — the tracker must
// report zero sleep everywhere. This is the degradation contract for any
// environment where the two clocks cannot diverge.
func TestPhaseTracker_NoMonotonicReadingReportsZeroSleep(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: 2 * time.Minute}
	pt := newPhaseTrackerWithClock(clk.now)

	pt.Start("malicious_file_scan") // t=0
	pc, finished := pt.Finish()     // t=2m
	if !finished {
		t.Fatal("Finish() finished = false, want true")
	}
	if pc.SleptMs != 0 {
		t.Errorf("phase slept_ms = %d, want 0 without monotonic divergence", pc.SleptMs)
	}

	snap := pt.Snapshot() // t=4m
	if snap.SleptMs != 0 {
		t.Errorf("run slept_ms = %d, want 0 without monotonic divergence", snap.SleptMs)
	}
	if len(snap.PhasesCompleted) != 1 || snap.PhasesCompleted[0].SleptMs != 0 {
		t.Errorf("phases_completed = %+v, want one entry with slept_ms 0", snap.PhasesCompleted)
	}
}

func TestPhaseTracker_FinishReturnValues(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	pt := newPhaseTrackerWithClock(clk.now)

	if pc, finished := pt.Finish(); finished || pc.Name != "" {
		t.Errorf("Finish() with nothing in flight = (%+v, %v), want zero value and false", pc, finished)
	}

	pt.Start("ide_scan")
	pc, finished := pt.Finish()
	if !finished {
		t.Fatal("Finish() finished = false, want true")
	}
	if pc.Name != "ide_scan" || pc.DurationMs != 1000 {
		t.Errorf("Finish() completion = %+v, want ide_scan with duration_ms 1000", pc)
	}
}
