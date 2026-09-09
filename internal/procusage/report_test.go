package procusage

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// captureStderr collects what fn writes to stderr. progress.Logger
// writes there directly, so this is the only way to assert on level.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	_ = w.Close()
	os.Stderr = orig
	out := <-done
	_ = r.Close()
	return out
}

func stubbedReport(t *testing.T, level progress.Level, phases []Phase) string {
	t.Helper()
	t.Setenv(paths.HomeEnvVar, t.TempDir())
	stubUsage(t, rusage{
		userMs: 1000, sysMs: 500,
		childUserMs: 4000, childSysMs: 500,
		peakRSSBytes: 20 << 20, childrenAttributed: true,
	})
	return captureStderr(t, func() {
		Report(progress.NewLogger(level), 5*time.Second,
			Meta{Command: "send-telemetry", ExecutionID: "exec-1"}, phases)
	})
}

// TestReportEmitsAtInfo is the regression guard that matters: the
// enterprise ExecutionLogs payload carries only what the run wrote to
// stderr at the configured level, and installs run at log_level=info. A
// debug-level line would be missing from every log we can download.
func TestReportEmitsAtInfo(t *testing.T) {
	out := stubbedReport(t, progress.LevelInfo, nil)

	if !strings.Contains(out, "resource usage:") {
		t.Fatalf("info-level output = %q, want a resource usage line", out)
	}
	for _, want := range []string{"wall=5s", "cpu=6s", "peak_rss=20.0MB"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestReportEmitsPhaseCPUAtInfo(t *testing.T) {
	out := stubbedReport(t, progress.LevelInfo, []Phase{
		{Name: "ide_scan", DurationMs: 400, CPUMs: 120},
		{Name: "credentials_scan", DurationMs: 900, CPUMs: 5000},
	})

	if !strings.Contains(out, "phase cpu:") {
		t.Fatalf("output = %q, want a phase cpu line", out)
	}
	// Costliest first, so the line points at what to optimise.
	idxExpensive := strings.Index(out, "credentials_scan")
	idxCheap := strings.Index(out, "ide_scan=")
	if idxExpensive == -1 || idxCheap == -1 || idxExpensive > idxCheap {
		t.Errorf("phases not ranked by cost: %s", out)
	}
}

func TestReportSilentBelowInfo(t *testing.T) {
	if out := stubbedReport(t, progress.LevelWarn, nil); strings.Contains(out, "resource usage") {
		t.Errorf("warn-level output = %q, want no resource usage line", out)
	}
}

func TestReportWritesHistory(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.HomeEnvVar, home)
	stubUsage(t, rusage{userMs: 10, peakRSSBytes: 1 << 20})

	_ = captureStderr(t, func() {
		Report(progress.NewNoop(), time.Second, Meta{Command: "install"}, nil)
	})

	got, err := LoadHistory(filepath.Join(home, "run-metrics.jsonl"))
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("records = %d, want 1", len(got))
	}
	if got[0].Command != "install" {
		t.Errorf("command = %q, want install", got[0].Command)
	}
}

// TestReportNamesTheDefaultDispatch covers the community path, where cli
// leaves Command empty.
func TestReportNamesTheDefaultDispatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.HomeEnvVar, home)
	stubUsage(t, rusage{userMs: 10})

	_ = captureStderr(t, func() {
		Report(progress.NewNoop(), time.Second, Meta{}, nil)
	})

	got, err := LoadHistory(filepath.Join(home, "run-metrics.jsonl"))
	if err != nil || len(got) != 1 {
		t.Fatalf("LoadHistory = %v, %v", got, err)
	}
	if got[0].Command != "scan" {
		t.Errorf("command = %q, want scan", got[0].Command)
	}
}
