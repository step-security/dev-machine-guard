// Package procusage reports what a run cost this process in CPU and
// memory. Best-effort throughout: every reading degrades to zero rather
// than erroring, so nothing here can abort a scan.
//
// This is the one place that reads OS resource counters directly instead
// of going through executor.Executor (AGENTS.md §2.1). The counters are
// in-process syscalls against our own PID, not spawned commands, so
// there is nothing for executor.Mock to intercept; tests swap the
// readUsage hook below instead.
package procusage

import (
	"fmt"
	"runtime"
	"time"
)

// Sample is one resource reading for a completed run.
//
// Child CPU is counted on Unix — executor.Run reaps subprocesses
// in-process, so getrusage attributes them to us — but not on Windows,
// which has no getrusage equivalent. ChildrenAttributed records which,
// so a Windows sample is never read as a Unix run that spawned nothing.
type Sample struct {
	WallMs         int64 `json:"wall_ms"`
	CPUUserMs      int64 `json:"cpu_user_ms"`
	CPUSysMs       int64 `json:"cpu_sys_ms"`
	CPUChildUserMs int64 `json:"cpu_child_user_ms,omitempty"`
	CPUChildSysMs  int64 `json:"cpu_child_sys_ms,omitempty"`

	PeakRSSBytes uint64 `json:"peak_rss_bytes"`
	// MaxChildRSSBytes is the peak RSS of the single largest child, not a
	// sum over children — that is all getrusage(RUSAGE_CHILDREN) reports.
	MaxChildRSSBytes uint64 `json:"max_child_rss_bytes,omitempty"`

	// Go runtime accounting, not RSS: these read well below PeakRSSBytes
	// and are here to separate "our heap grew" from "a child was fat".
	GoHeapBytes uint64 `json:"go_heap_bytes"`
	GoSysBytes  uint64 `json:"go_sys_bytes"`
	Goroutines  int    `json:"goroutines"`
	NumGC       uint32 `json:"num_gc"`

	// LogicalCores is what CPU time has to be divided by to mean
	// anything. Recorded per sample because the history is compared
	// across machines with different core counts.
	LogicalCores int `json:"logical_cores,omitempty"`

	// Deliberately not omitempty: false is the meaningful value.
	ChildrenAttributed bool `json:"children_attributed"`
}

// rusage is the platform-independent shape the per-OS hook fills in.
type rusage struct {
	userMs             int64
	sysMs              int64
	childUserMs        int64
	childSysMs         int64
	peakRSSBytes       uint64
	maxChildRSSBytes   uint64
	childrenAttributed bool
}

// readUsageFn is the platform hook, swapped by tests.
var readUsageFn = readUsage

// Capture takes a reading for a run that spanned wall.
func Capture(wall time.Duration) Sample {
	ru := readUsageFn()

	// ReadMemStats stops the world (~65us measured). Tolerable because
	// Capture runs once per run; phase boundaries call CPUMillis, which
	// deliberately skips this.
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	return Sample{
		WallMs:             wall.Milliseconds(),
		CPUUserMs:          ru.userMs,
		CPUSysMs:           ru.sysMs,
		CPUChildUserMs:     ru.childUserMs,
		CPUChildSysMs:      ru.childSysMs,
		PeakRSSBytes:       ru.peakRSSBytes,
		MaxChildRSSBytes:   ru.maxChildRSSBytes,
		GoHeapBytes:        ms.HeapAlloc,
		GoSysBytes:         ms.Sys,
		Goroutines:         runtime.NumGoroutine(),
		NumGC:              ms.NumGC,
		LogicalCores:       runtime.NumCPU(),
		ChildrenAttributed: ru.childrenAttributed,
	}
}

// CPUMillis is total CPU consumed so far, self plus children where they
// are attributed. Monotonic, so callers can difference it across phase
// boundaries — unlike peak RSS, which is a lifetime high-water mark and
// cannot be differenced.
func CPUMillis() int64 {
	ru := readUsageFn()
	return ru.userMs + ru.sysMs + ru.childUserMs + ru.childSysMs
}

// SelfCPUMs is CPU attributed to this process alone.
func (s Sample) SelfCPUMs() int64 { return s.CPUUserMs + s.CPUSysMs }

// ChildCPUMs is CPU attributed to reaped subprocesses; always 0 where
// ChildrenAttributed is false.
func (s Sample) ChildCPUMs() int64 { return s.CPUChildUserMs + s.CPUChildSysMs }

// TotalCPUMs is all CPU this run is known to have consumed.
func (s Sample) TotalCPUMs() int64 { return s.SelfCPUMs() + s.ChildCPUMs() }

// CoresBusy is total CPU over wall time: the average number of cores the
// run kept busy. 1.0 means one core saturated for the whole run; above
// 1.0 means genuine parallelism. Zero when wall time is unknown.
//
// Not expressed as a percentage on purpose — "96% of wall" reads as
// "used 96% of the CPU" when it actually meant 0.96 of one core, which
// on a 12-core box is 8% of the machine. Use CPUPercent for that.
func (s Sample) CoresBusy() float64 {
	if s.WallMs <= 0 {
		return 0
	}
	return float64(s.TotalCPUMs()) / float64(s.WallMs)
}

// CPUPercent is the share of the whole machine's CPU capacity the run
// consumed: CPU time over (wall time x cores). This is the "how much of
// the box did we eat" number, and it cannot exceed 100. Zero when wall
// time or the core count is unknown.
func (s Sample) CPUPercent() float64 {
	if s.WallMs <= 0 || s.LogicalCores <= 0 {
		return 0
	}
	return float64(s.TotalCPUMs()) / (float64(s.WallMs) * float64(s.LogicalCores)) * 100
}

// String renders the one-line summary logged at info.
func (s Sample) String() string {
	children := fmt.Sprintf("children %s", ms(s.ChildCPUMs()))
	if !s.ChildrenAttributed {
		children = "children not attributed on this platform"
	}
	out := fmt.Sprintf("wall=%s cpu=%s (self %s + %s) cpu_pct=%.1f%% of %d cores (%.2f cores busy) peak_rss=%s",
		ms(s.WallMs), ms(s.TotalCPUMs()), ms(s.SelfCPUMs()), children,
		s.CPUPercent(), s.LogicalCores, s.CoresBusy(), mib(s.PeakRSSBytes))
	if s.MaxChildRSSBytes > 0 {
		out += fmt.Sprintf(" max_child_rss=%s", mib(s.MaxChildRSSBytes))
	}
	return out + fmt.Sprintf(" go_heap=%s go_sys=%s goroutines=%d gc=%d",
		mib(s.GoHeapBytes), mib(s.GoSysBytes), s.Goroutines, s.NumGC)
}

func ms(v int64) string { return (time.Duration(v) * time.Millisecond).String() }

func mib(b uint64) string { return fmt.Sprintf("%.1fMB", float64(b)/(1<<20)) }
