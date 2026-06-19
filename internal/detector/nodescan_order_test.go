package detector

import (
	"reflect"
	"testing"
	"time"
)

func TestOrderScanProjects_NilMapFallsBackToMtimeDesc(t *testing.T) {
	in := []projectEntry{
		{dir: "/old", modTime: 100},
		{dir: "/new", modTime: 300},
		{dir: "/mid", modTime: 200},
	}
	got := orderScanProjects(in, nil)
	want := []projectEntry{
		{dir: "/new", modTime: 300},
		{dir: "/mid", modTime: 200},
		{dir: "/old", modTime: 100},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nil map: got %v, want %v", got, want)
	}
}

func TestOrderScanProjects_EmptyMapFallsBackToMtimeDesc(t *testing.T) {
	in := []projectEntry{
		{dir: "/a", modTime: 100},
		{dir: "/b", modTime: 200},
	}
	got := orderScanProjects(in, map[string]time.Time{})
	want := []projectEntry{
		{dir: "/b", modTime: 200},
		{dir: "/a", modTime: 100},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("empty map: got %v, want %v", got, want)
	}
}

func TestOrderScanProjects_UnknownFirstByMtime_KnownAfterByStaleness(t *testing.T) {
	verified := func(year int) time.Time {
		return time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	known := map[string]time.Time{
		"/known-fresh": verified(2026),
		"/known-stale": verified(2024),
		"/known-mid":   verified(2025),
	}
	in := []projectEntry{
		{dir: "/known-mid", modTime: 100},
		{dir: "/unknown-new", modTime: 500},
		{dir: "/known-fresh", modTime: 600},
		{dir: "/unknown-old", modTime: 200},
		{dir: "/known-stale", modTime: 300},
	}

	got := orderScanProjects(in, known)
	wantOrder := []string{
		"/unknown-new", // unknown, mtime 500 (highest)
		"/unknown-old", // unknown, mtime 200
		"/known-stale", // known, verified 2024 (oldest)
		"/known-mid",   // known, verified 2025
		"/known-fresh", // known, verified 2026 (newest)
	}
	for i, want := range wantOrder {
		if got[i].dir != want {
			t.Errorf("position %d: got %q, want %q (full order: %v)", i, got[i].dir, want, got)
		}
	}
}

func TestOrderScanProjects_AllKnown(t *testing.T) {
	verified := func(year int) time.Time {
		return time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	known := map[string]time.Time{
		"/a": verified(2025),
		"/b": verified(2024),
	}
	in := []projectEntry{
		{dir: "/a", modTime: 100},
		{dir: "/b", modTime: 200},
	}
	got := orderScanProjects(in, known)
	if got[0].dir != "/b" || got[1].dir != "/a" {
		t.Errorf("expected stalest-first ordering, got %v", got)
	}
}

func TestOrderScanProjects_AllUnknown(t *testing.T) {
	in := []projectEntry{
		{dir: "/a", modTime: 100},
		{dir: "/b", modTime: 200},
	}
	got := orderScanProjects(in, map[string]time.Time{"/other": time.Now()})
	if got[0].dir != "/b" || got[1].dir != "/a" {
		t.Errorf("expected mtime-desc for all-unknown, got %v", got)
	}
}
