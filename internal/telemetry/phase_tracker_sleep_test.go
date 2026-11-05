package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSleptDuration(t *testing.T) {
	tests := []struct {
		name  string
		wall  time.Duration
		awake time.Duration
		want  time.Duration
	}{
		{name: "equal inputs (single clock)", wall: 5 * time.Minute, awake: 5 * time.Minute, want: 0},
		{name: "divergence below threshold (NTP step)", wall: 5*time.Minute + 59*time.Second, awake: 5 * time.Minute, want: 0},
		{name: "divergence exactly at threshold", wall: 6 * time.Minute, awake: 5 * time.Minute, want: 60 * time.Second},
		{name: "incident shape: 53m wall vs 7m work", wall: 53 * time.Minute, awake: 7 * time.Minute, want: 46 * time.Minute},
		{name: "negative divergence clamps to zero", wall: 4 * time.Minute, awake: 5 * time.Minute, want: 0},
		{name: "zero interval", wall: 0, awake: 0, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sleptDuration(tc.wall, tc.awake); got != tc.want {
				t.Errorf("sleptDuration(%v, %v) = %v, want %v", tc.wall, tc.awake, got, tc.want)
			}
		})
	}
}

// A single fake clock drives both readings, so wall and awake elapsed are
// identical and the tracker must report zero sleep everywhere. This is the
// contract every existing fake-clock test relies on.
func TestPhaseTracker_SingleClockReportsZeroSleep(t *testing.T) {
	clk := &fakeClock{cur: time.Unix(1_700_000_000, 0), step: 2 * time.Minute}
	pt := newPhaseTrackerWithClock(clk.now)

	pt.Start("malicious_file_scan")
	pc, finished := pt.Finish()
	if !finished {
		t.Fatal("Finish() finished = false, want true")
	}
	if pc.SleptMs != 0 || pc.DurationMs != (2*time.Minute).Milliseconds() {
		t.Errorf("phase = %+v, want slept_ms 0 and duration_ms %d", pc, (2 * time.Minute).Milliseconds())
	}

	snap := pt.Snapshot()
	if snap.SleptMs != 0 {
		t.Errorf("run slept_ms = %d, want 0 with a single clock", snap.SleptMs)
	}
	if len(snap.PhasesCompleted) != 1 || snap.PhasesCompleted[0].SleptMs != 0 {
		t.Errorf("phases_completed = %+v, want one entry with slept_ms 0", snap.PhasesCompleted)
	}
}

// Separate wall and awake clocks: a phase that spans a sleep reports its
// awake time as the duration and the gap as sleep; a sleep between phases
// shows up only at run level; elapsed and slept add up to wall time.
func TestPhaseTracker_SleepSpanningRun(t *testing.T) {
	wall := time.Unix(1_700_000_000, 0)
	awake := time.Duration(0)
	pt := newPhaseTrackerWithClocks(func() time.Time { return wall }, func() time.Duration { return awake })

	// Seven minutes of work while the lid was closed for 46 more.
	pt.Start("ide_scan")
	wall = wall.Add(53 * time.Minute)
	awake += 7 * time.Minute
	pc, finished := pt.Finish()
	if !finished {
		t.Fatal("Finish() finished = false, want true")
	}
	if got, want := pc.DurationMs, (7 * time.Minute).Milliseconds(); got != want {
		t.Errorf("duration_ms = %d, want %d (awake time only)", got, want)
	}
	if got, want := pc.SleptMs, (46 * time.Minute).Milliseconds(); got != want {
		t.Errorf("phase slept_ms = %d, want %d", got, want)
	}

	// Ten minutes asleep between phases, then a short phase with no sleep.
	wall = wall.Add(10 * time.Minute)
	pt.Start("mcp_scan")
	wall = wall.Add(time.Minute)
	awake += time.Minute
	pc, _ = pt.Finish()
	if pc.SleptMs != 0 || pc.DurationMs != time.Minute.Milliseconds() {
		t.Errorf("second phase = %+v, want no sleep and duration_ms %d", pc, time.Minute.Milliseconds())
	}

	snap := pt.Snapshot()
	if got, want := snap.ElapsedMs, (8 * time.Minute).Milliseconds(); got != want {
		t.Errorf("elapsed_ms = %d, want %d (awake time)", got, want)
	}
	if got, want := snap.SleptMs, (56 * time.Minute).Milliseconds(); got != want {
		t.Errorf("run slept_ms = %d, want %d (46m in a phase plus 10m between phases)", got, want)
	}
	if snap.ElapsedMs+snap.SleptMs != (64 * time.Minute).Milliseconds() {
		t.Errorf("elapsed + slept = %d, want the 64m wall-clock span", snap.ElapsedMs+snap.SleptMs)
	}
}

// Wall stamps are differenced without their monotonic reading: with it, Sub
// would use the monotonic clock, which stops during a sleep, and hide the
// gap. A fabricated stamp cannot carry a diverging monotonic reading, so the
// normalization is asserted directly on the helper both calculations use.
func TestWallStamp_StripsMonotonicReading(t *testing.T) {
	now := time.Now()
	if !strings.Contains(now.String(), " m=") {
		t.Skip("time.Now() carries no monotonic reading on this platform")
	}
	stamp := wallStamp(now)
	if strings.Contains(stamp.String(), " m=") {
		t.Fatalf("wallStamp kept the monotonic reading: %s", stamp)
	}
	if !stamp.Equal(now) {
		t.Fatalf("wallStamp changed the wall time: %s vs %s", stamp, now)
	}
	if wallStamp(now.Add(time.Hour)).Sub(stamp) != time.Hour {
		t.Fatal("stripped stamps must difference on wall time")
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

// slept_ms is omitted at zero (older backends and the common case) and
// present when sleep was observed, at both levels.
func TestRunStatusInfo_SleptMsJSONShape(t *testing.T) {
	quiet, _ := json.Marshal(RunStatusInfo{ElapsedMs: 1000, PhasesCompleted: []PhaseCompletion{{Name: "ide_scan", DurationMs: 10}}})
	if strings.Contains(string(quiet), "slept_ms") {
		t.Errorf("zero sleep must omit slept_ms: %s", quiet)
	}
	slept, _ := json.Marshal(RunStatusInfo{ElapsedMs: 1000, SleptMs: 5000, PhasesCompleted: []PhaseCompletion{{Name: "ide_scan", DurationMs: 10, SleptMs: 4000}}})
	for _, want := range []string{`"slept_ms":5000`, `"slept_ms":4000`} {
		if !strings.Contains(string(slept), want) {
			t.Errorf("payload missing %s: %s", want, slept)
		}
	}
}
