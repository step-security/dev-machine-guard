package telemetry

import (
	"testing"
)

// Verifies the wiring contract telemetry.Run() relies on: a ProgressHook
// closure that calls tracker.UpdateDetail surfaces the detail through the
// next Snapshot's CurrentPhase field (folded as "<phase> (<detail>)").
// Keeps the scanner / tracker integration honest even when the real
// scanner tests live in package detector.
func TestProgressHook_PlumbsDetailIntoSnapshot(t *testing.T) {
	tracker := NewPhaseTracker()
	tracker.Start("node_scan")

	// Simulate the closure telemetry.Run() installs on NodeScanner.ProgressHook.
	hook := func(detail string) { tracker.UpdateDetail(detail) }

	hook("project 1 of 47")
	if got := tracker.Snapshot().CurrentPhase; got != "node_scan (project 1 of 47)" {
		t.Fatalf("after hook: current_phase = %q, want %q", got, "node_scan (project 1 of 47)")
	}

	hook("project 47 of 47")
	if got := tracker.Snapshot().CurrentPhase; got != "node_scan (project 47 of 47)" {
		t.Fatalf("after second hook call: current_phase = %q", got)
	}

	tracker.Finish()
	if got := tracker.Snapshot().CurrentPhase; got != "" {
		t.Fatalf("after Finish: current_phase = %q, want empty", got)
	}
}
