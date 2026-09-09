package procusage

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/progress"
)

// BenchmarkCapture covers the once-per-run reading. Includes
// runtime.ReadMemStats, which stops the world — the reason this is
// called once per run and never in a loop.
func BenchmarkCapture(b *testing.B) {
	for b.Loop() {
		_ = Capture(time.Second)
	}
}

// BenchmarkCPUMillis covers the per-phase-boundary reading: two
// getrusage calls, no ReadMemStats. PhaseTracker calls this twice per
// phase, so ~28 times on a 14-phase enterprise run.
func BenchmarkCPUMillis(b *testing.B) {
	for b.Loop() {
		_ = CPUMillis()
	}
}

// BenchmarkAppendHistoryAtCap is the expensive part: at the cap this
// reads and rewrites ~250KB once per run.
func BenchmarkAppendHistoryAtCap(b *testing.B) {
	path := filepath.Join(b.TempDir(), "run-metrics.jsonl")
	for i := range maxHistoryRecords {
		if err := AppendHistory(path, enterpriseRecord(fmt.Sprintf("seed-%04d", i))); err != nil {
			b.Fatalf("seed: %v", err)
		}
	}
	rec := enterpriseRecord("bench")
	b.ResetTimer()
	for b.Loop() {
		if err := AppendHistory(path, rec); err != nil {
			b.Fatalf("AppendHistory: %v", err)
		}
	}
}

// BenchmarkReport is the whole per-run cost: capture, format, log, and
// the history append.
func BenchmarkReport(b *testing.B) {
	b.Setenv("STEPSECURITY_HOME", b.TempDir())
	log := progress.NewNoop()
	phases := enterpriseRecord("x").Phases
	for b.Loop() {
		Report(log, 54*time.Second, Meta{Command: "send-telemetry"}, phases)
	}
}
