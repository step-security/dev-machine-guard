package procusage

import (
	"math"
	"strings"
	"testing"
	"time"
)

// stubUsage swaps the platform hook for the duration of the test.
func stubUsage(t *testing.T, ru rusage) {
	t.Helper()
	prev := readUsageFn
	readUsageFn = func() rusage { return ru }
	t.Cleanup(func() { readUsageFn = prev })
}

func TestCaptureMapsPlatformCounters(t *testing.T) {
	stubUsage(t, rusage{
		userMs:             1200,
		sysMs:              300,
		childUserMs:        5000,
		childSysMs:         800,
		peakRSSBytes:       48 << 20,
		maxChildRSSBytes:   112 << 20,
		childrenAttributed: true,
	})

	got := Capture(10 * time.Second)

	if got.WallMs != 10_000 {
		t.Errorf("wall_ms = %d, want 10000", got.WallMs)
	}
	if got.SelfCPUMs() != 1500 {
		t.Errorf("self cpu = %d, want 1500", got.SelfCPUMs())
	}
	if got.ChildCPUMs() != 5800 {
		t.Errorf("child cpu = %d, want 5800", got.ChildCPUMs())
	}
	if got.TotalCPUMs() != 7300 {
		t.Errorf("total cpu = %d, want 7300", got.TotalCPUMs())
	}
	if got.PeakRSSBytes != 48<<20 {
		t.Errorf("peak_rss = %d, want %d", got.PeakRSSBytes, 48<<20)
	}
	if !got.ChildrenAttributed {
		t.Error("children_attributed = false, want true")
	}
	// Filled from the live Go runtime, not the stub — assert only that
	// they were populated.
	if got.Goroutines <= 0 {
		t.Errorf("goroutines = %d, want > 0", got.Goroutines)
	}
	if got.GoSysBytes == 0 {
		t.Error("go_sys_bytes = 0, want > 0")
	}
}

func TestCoresBusy(t *testing.T) {
	tests := []struct {
		name   string
		sample Sample
		want   float64
	}{
		{
			name:   "half a core",
			sample: Sample{WallMs: 1000, CPUUserMs: 500, LogicalCores: 12},
			want:   0.5,
		},
		{
			name:   "parallel work exceeds one core",
			sample: Sample{WallMs: 1000, CPUUserMs: 1000, CPUChildUserMs: 3000, LogicalCores: 12},
			want:   4,
		},
		{
			name:   "unknown wall time yields zero, not a divide by zero",
			sample: Sample{WallMs: 0, CPUUserMs: 500, LogicalCores: 12},
			want:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sample.CoresBusy(); got != tt.want {
				t.Errorf("CoresBusy() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCPUPercentIsShareOfWholeMachine pins the distinction that prompted
// the change: one core saturated on a 12-core box is 8% of the machine,
// not 100%.
func TestCPUPercentIsShareOfWholeMachine(t *testing.T) {
	tests := []struct {
		name   string
		sample Sample
		want   float64
	}{
		{
			name:   "one core of twelve",
			sample: Sample{WallMs: 1000, CPUUserMs: 1000, LogicalCores: 12},
			want:   100.0 / 12,
		},
		{
			name:   "every core saturated is 100, never more",
			sample: Sample{WallMs: 1000, CPUUserMs: 12000, LogicalCores: 12},
			want:   100,
		},
		{
			name:   "single-core machine matches cores-busy",
			sample: Sample{WallMs: 1000, CPUUserMs: 500, LogicalCores: 1},
			want:   50,
		},
		{
			name:   "unknown core count yields zero, not a divide by zero",
			sample: Sample{WallMs: 1000, CPUUserMs: 500},
			want:   0,
		},
		{
			name:   "unknown wall time yields zero",
			sample: Sample{WallMs: 0, CPUUserMs: 500, LogicalCores: 12},
			want:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tolerance, not equality: the division order here differs
			// from the implementation's, so exact float match is luck.
			if got := tt.sample.CPUPercent(); math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("CPUPercent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCPUMillisSumsSelfAndChildren(t *testing.T) {
	stubUsage(t, rusage{userMs: 10, sysMs: 20, childUserMs: 30, childSysMs: 40})
	if got := CPUMillis(); got != 100 {
		t.Errorf("CPUMillis() = %d, want 100", got)
	}
}

func TestStringFlagsUnattributedChildren(t *testing.T) {
	attributed := Sample{WallMs: 1000, CPUUserMs: 500, CPUChildUserMs: 200, ChildrenAttributed: true}
	if s := attributed.String(); !strings.Contains(s, "children 200ms") {
		t.Errorf("String() = %q, want child CPU reported", s)
	}

	// The Windows shape: silence here would read as "no subprocesses ran".
	unattributed := Sample{WallMs: 1000, CPUUserMs: 500}
	if s := unattributed.String(); !strings.Contains(s, "not attributed") {
		t.Errorf("String() = %q, want the attribution gap called out", s)
	}
}

// TestReadUsageLive exercises the real syscalls. The stubbed tests above
// would pass just as well against a hook wired up wrong, so burn some
// measurable CPU and assert the counters actually move.
func TestReadUsageLive(t *testing.T) {
	before := CPUMillis()

	deadline := time.Now().Add(150 * time.Millisecond)
	x := 0
	for time.Now().Before(deadline) {
		x++
	}
	_ = x

	got := Capture(200 * time.Millisecond)
	if got.TotalCPUMs() < before {
		t.Errorf("cpu went backwards: %d then %d", before, got.TotalCPUMs())
	}
	if got.TotalCPUMs() == 0 {
		t.Error("total cpu = 0 after a busy loop, platform hook likely misread")
	}
	if got.PeakRSSBytes == 0 {
		t.Error("peak_rss = 0, platform hook likely misread")
	}
}
