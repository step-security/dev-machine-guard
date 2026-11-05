package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLog(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "update.log")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAdoptSeedOutcomeLastRun(t *testing.T) {
	p := writeLog(t,
		"2026-11-01T10:00:00Z bootstrap: adopt-seed: copied seed 1.17.0 into C:\\pf\\versions\\1.17.0",
		"2026-11-04T21:20:01Z bootstrap: adopt-seed: MSI helper: refreshed",
		"2026-11-04T21:20:02Z bootstrap: adopt-seed: copying seed 1.18.1: rename a b: Access is denied. (held by X.exe pid 1)",
		"2026-11-04T21:20:02Z bootstrap: adopt-seed: versions\\1.18.1 unusable (incomplete); state left unchanged",
		"2026-11-04T21:20:05Z bootstrap: adopt-seed --commit: done",
		"2026-11-04T21:21:00Z bootstrap: updater 1.18.1 exited 1",
	)
	got := adoptSeedOutcome(p)
	want := "adopt-seed: MSI helper: refreshed | adopt-seed: copying seed 1.18.1: rename a b: Access is denied. (held by X.exe pid 1) | adopt-seed: versions\\1.18.1 unusable (incomplete); state left unchanged"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestWithAdoptSeedOutcome(t *testing.T) {
	p := writeLog(t, "2026-11-04T21:20:02Z bootstrap: adopt-seed: update lock not taken (timeout); the updater converges on its next tick")
	if got := withAdoptSeedOutcome("state_missing", p); got != "state_missing; adopt-seed: update lock not taken (timeout); the updater converges on its next tick" {
		t.Fatalf("got %q", got)
	}
	// Only state_* reasons: current_missing is not adopt-seed's doing.
	if got := withAdoptSeedOutcome("current_missing", p); got != "current_missing" {
		t.Fatalf("got %q", got)
	}
	if got := withAdoptSeedOutcome("state_missing", filepath.Join(t.TempDir(), "absent.log")); got != "state_missing" {
		t.Fatalf("got %q", got)
	}
	if got := withAdoptSeedOutcome("state_missing", writeLog(t, "2026-11-04T21:21:00Z bootstrap: updater 1.18.1 exited 1")); got != "state_missing" {
		t.Fatalf("got %q", got)
	}
}

func TestAdoptSeedOutcomeReadsOnlyTheTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "update.log")
	old := "2026-11-01T10:00:00Z bootstrap: adopt-seed: old run\n"
	pad := strings.Repeat("2026-11-02T10:00:00Z self-update: filler line\n", (adoptSeedTailBytes/40)+10)
	recent := "2026-11-04T21:20:02Z bootstrap: adopt-seed: recent run\n"
	if err := os.WriteFile(p, []byte(old+pad+recent), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := adoptSeedOutcome(p); got != "adopt-seed: recent run" {
		t.Fatalf("got %q", got)
	}
}
