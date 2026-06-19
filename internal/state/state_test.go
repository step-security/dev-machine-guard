package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

const runningAgentVersion = "1.6.0"

func tempStatePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "scan-state.json")
}

// freshScan simulates one project's scan record.
func freshScan(path, hash string) ScanRecord {
	return ScanRecord{Path: path, Hash: hash, PackageManager: "npm", PMVersion: "10.2.0", ExitCode: 0}
}

func sortedEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func TestLoad_MissingFileReturnsEmpty(t *testing.T) {
	s, err := Load(tempStatePath(t), runningAgentVersion)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if s == nil || s.SchemaVersion != SchemaVersion {
		t.Errorf("expected fresh state with version %d, got %+v", SchemaVersion, s)
	}
	if len(s.NPMProjects)+len(s.PythonProjects)+len(s.NPMGlobal)+len(s.PythonGlobal) != 0 {
		t.Errorf("expected empty maps on miss")
	}
}

func TestLoad_CorruptReturnsEmpty(t *testing.T) {
	path := tempStatePath(t)
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path, runningAgentVersion)
	if err == nil {
		t.Error("expected parse error to surface")
	}
	if s == nil || len(s.NPMProjects) != 0 {
		t.Errorf("expected empty fallback state on corrupt file, got %+v", s)
	}
}

func TestLoad_WrongSchemaVersionReturnsEmpty(t *testing.T) {
	path := tempStatePath(t)
	body, _ := json.Marshal(map[string]any{
		"schema_version": 999,
		"npm_projects":   map[string]any{"/x": map[string]any{"scan_output_hash": "sha256:xx"}},
	})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path, runningAgentVersion)
	if err != nil {
		t.Fatalf("schema mismatch should not error: %v", err)
	}
	if len(s.NPMProjects) != 0 {
		t.Errorf("expected empty state on schema mismatch")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	path := tempStatePath(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	orig := New(runningAgentVersion)
	orig.NPMProjects["/svc"] = ProjectEntry{
		ScanOutputHash:          "sha256:abc",
		LastUploadedExecutionID: "exec-1",
		LastUploadedAt:          now,
		LastVerifiedAt:          now,
		FirstSeenAt:             now,
		PackageManager:          "npm",
		PMVersion:               "10.2.0",
	}
	orig.LastFullSyncAt = now
	orig.LastSuccessfulExecutionID = "exec-1"

	if err := orig.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := Load(path, runningAgentVersion)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, ok := loaded.NPMProjects["/svc"]
	if !ok {
		t.Fatal("missing /svc after reload")
	}
	if got.ScanOutputHash != "sha256:abc" || !got.LastUploadedAt.Equal(now) {
		t.Errorf("entry roundtrip lost data: %+v", got)
	}
	if !loaded.LastFullSyncAt.Equal(now) || loaded.LastSuccessfulExecutionID != "exec-1" {
		t.Errorf("envelope fields lost: %+v", loaded)
	}
}

// Reconcile cases ---------------------------------------------------------

func TestReconcile_FirstRunEverythingUnknown(t *testing.T) {
	s := New(runningAgentVersion)
	unknown, known, removed := s.Reconcile(EcosystemNPM, []string{"/a", "/b"})
	if !sortedEq(unknown, []string{"/a", "/b"}) {
		t.Errorf("unknown=%v", unknown)
	}
	if len(known) != 0 || len(removed) != 0 {
		t.Errorf("known=%v removed=%v", known, removed)
	}
}

func TestReconcile_RemovedDetected(t *testing.T) {
	s := New(runningAgentVersion)
	s.NPMProjects["/a"] = ProjectEntry{ScanOutputHash: "sha256:1"}
	s.NPMProjects["/b"] = ProjectEntry{ScanOutputHash: "sha256:2"}

	_, _, removed := s.Reconcile(EcosystemNPM, []string{"/a"})
	if !sortedEq(removed, []string{"/b"}) {
		t.Errorf("expected /b removed, got %v", removed)
	}
}

func TestReconcile_KnownSortedByStaleness(t *testing.T) {
	s := New(runningAgentVersion)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mid := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	new := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	s.NPMProjects["/recent"] = ProjectEntry{LastVerifiedAt: new}
	s.NPMProjects["/oldest"] = ProjectEntry{LastVerifiedAt: old}
	s.NPMProjects["/middle"] = ProjectEntry{LastVerifiedAt: mid}

	_, known, _ := s.Reconcile(EcosystemNPM, []string{"/recent", "/oldest", "/middle"})
	if known[0] != "/oldest" || known[1] != "/middle" || known[2] != "/recent" {
		t.Errorf("expected oldest-first ordering, got %v", known)
	}
}

// Partition cases ---------------------------------------------------------

func TestPartition_NewProjectIsChanged(t *testing.T) {
	s := New(runningAgentVersion)
	changed, unchanged := s.Partition(EcosystemNPM, []ScanRecord{freshScan("/a", "sha256:x")}, false)
	if !sortedEq(changed, []string{"/a"}) || len(unchanged) != 0 {
		t.Errorf("changed=%v unchanged=%v", changed, unchanged)
	}
}

func TestPartition_MatchingHashIsUnchanged(t *testing.T) {
	s := New(runningAgentVersion)
	s.NPMProjects["/a"] = ProjectEntry{ScanOutputHash: "sha256:x"}

	changed, unchanged := s.Partition(EcosystemNPM, []ScanRecord{freshScan("/a", "sha256:x")}, false)
	if len(changed) != 0 || !sortedEq(unchanged, []string{"/a"}) {
		t.Errorf("changed=%v unchanged=%v", changed, unchanged)
	}
}

func TestPartition_HashDiffIsChanged(t *testing.T) {
	s := New(runningAgentVersion)
	s.NPMProjects["/a"] = ProjectEntry{ScanOutputHash: "sha256:old"}

	changed, unchanged := s.Partition(EcosystemNPM, []ScanRecord{freshScan("/a", "sha256:new")}, false)
	if !sortedEq(changed, []string{"/a"}) || len(unchanged) != 0 {
		t.Errorf("changed=%v unchanged=%v", changed, unchanged)
	}
}

func TestPartition_FullSyncForcesChanged(t *testing.T) {
	s := New(runningAgentVersion)
	s.NPMProjects["/a"] = ProjectEntry{ScanOutputHash: "sha256:x"}

	changed, unchanged := s.Partition(EcosystemNPM, []ScanRecord{freshScan("/a", "sha256:x")}, true)
	if !sortedEq(changed, []string{"/a"}) || len(unchanged) != 0 {
		t.Errorf("full sync should force changed; got changed=%v unchanged=%v", changed, unchanged)
	}
}

func TestPartition_FailedScanIsChanged(t *testing.T) {
	s := New(runningAgentVersion)
	s.NPMProjects["/a"] = ProjectEntry{ScanOutputHash: "sha256:x"}
	rec := freshScan("/a", "sha256:x")
	rec.ExitCode = 1

	changed, unchanged := s.Partition(EcosystemNPM, []ScanRecord{rec}, false)
	if !sortedEq(changed, []string{"/a"}) || len(unchanged) != 0 {
		t.Errorf("failed scan must not collapse to unchanged; changed=%v unchanged=%v", changed, unchanged)
	}
}

// Full-sync rules ---------------------------------------------------------

func TestIsFullSyncDue_FirstEverRun(t *testing.T) {
	s := New(runningAgentVersion)
	if !s.IsFullSyncDue(time.Now(), runningAgentVersion, DefaultFullSyncHorizon) {
		t.Error("first run (zero LastFullSyncAt) should force full sync")
	}
}

func TestIsFullSyncDue_AgentVersionChange(t *testing.T) {
	s := New(runningAgentVersion)
	s.LastFullSyncAt = time.Now()
	if !s.IsFullSyncDue(time.Now(), "1.7.0", DefaultFullSyncHorizon) {
		t.Error("agent version drift should force full sync")
	}
}

func TestIsFullSyncDue_HorizonElapsed(t *testing.T) {
	s := New(runningAgentVersion)
	now := time.Now()
	s.LastFullSyncAt = now.Add(-8 * 24 * time.Hour)
	if !s.IsFullSyncDue(now, runningAgentVersion, DefaultFullSyncHorizon) {
		t.Error("8 days > 7-day horizon should force full sync")
	}
}

func TestIsFullSyncDue_RecentNotDue(t *testing.T) {
	s := New(runningAgentVersion)
	now := time.Now()
	s.LastFullSyncAt = now.Add(-time.Hour)
	if s.IsFullSyncDue(now, runningAgentVersion, DefaultFullSyncHorizon) {
		t.Error("recent full sync should not force another")
	}
}

// Removal-pending lifecycle ----------------------------------------------

func TestMarkRemovedPending_DedupsAcrossCalls(t *testing.T) {
	s := New(runningAgentVersion)
	now := time.Now()
	s.MarkRemovedPending(EcosystemNPM, []string{"/a", "/b"}, now)
	s.MarkRemovedPending(EcosystemNPM, []string{"/a", "/c"}, now)
	if len(s.RemovedPendingAck) != 3 {
		t.Errorf("expected dedup to yield 3 entries, got %d: %+v", len(s.RemovedPendingAck), s.RemovedPendingAck)
	}
}

func TestPendingRemovalsFor_FiltersByEcosystem(t *testing.T) {
	s := New(runningAgentVersion)
	now := time.Now()
	s.MarkRemovedPending(EcosystemNPM, []string{"/a"}, now)
	s.MarkRemovedPending(EcosystemPython, []string{"/p"}, now)

	if got := s.PendingRemovalsFor(EcosystemNPM); len(got) != 1 || got[0].Path != "/a" {
		t.Errorf("npm filter: %+v", got)
	}
	if got := s.PendingRemovalsFor(EcosystemPython); len(got) != 1 || got[0].Path != "/p" {
		t.Errorf("python filter: %+v", got)
	}
}

func TestAckRemovals_DropsExactMatches(t *testing.T) {
	s := New(runningAgentVersion)
	now := time.Now()
	s.MarkRemovedPending(EcosystemNPM, []string{"/a", "/b"}, now)
	s.MarkRemovedPending(EcosystemPython, []string{"/a"}, now) // same path, different ecosystem

	s.AckRemovals([]PendingRemoval{{Ecosystem: EcosystemNPM, Path: "/a"}})
	if len(s.RemovedPendingAck) != 2 {
		t.Errorf("expected 2 remaining after one ack, got %d: %+v", len(s.RemovedPendingAck), s.RemovedPendingAck)
	}
	for _, e := range s.RemovedPendingAck {
		if e.Ecosystem == EcosystemNPM && e.Path == "/a" {
			t.Error("acked entry still present")
		}
	}
}

// Commit semantics --------------------------------------------------------

func TestCommitAfterUpload_NewProjectStored(t *testing.T) {
	s := New(runningAgentVersion)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.CommitAfterUpload(now, "exec-1", runningAgentVersion,
		[]ScanRecord{freshScan("/a", "sha256:x")}, nil, nil, nil, false)

	e := s.NPMProjects["/a"]
	if e.ScanOutputHash != "sha256:x" || e.LastUploadedExecutionID != "exec-1" || !e.FirstSeenAt.Equal(now) {
		t.Errorf("commit lost data: %+v", e)
	}
}

func TestCommitAfterUpload_PreservesFirstSeen(t *testing.T) {
	s := New(runningAgentVersion)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	s.NPMProjects["/a"] = ProjectEntry{
		ScanOutputHash: "sha256:old",
		FirstSeenAt:    t0,
	}
	s.CommitAfterUpload(t1, "exec-2", runningAgentVersion,
		[]ScanRecord{freshScan("/a", "sha256:new")}, nil, nil, nil, false)

	if !s.NPMProjects["/a"].FirstSeenAt.Equal(t0) {
		t.Errorf("FirstSeenAt should not move on update, got %v", s.NPMProjects["/a"].FirstSeenAt)
	}
}

func TestCommitAfterUpload_SkipsFailedScans(t *testing.T) {
	s := New(runningAgentVersion)
	s.NPMProjects["/a"] = ProjectEntry{ScanOutputHash: "sha256:old"}

	bad := freshScan("/a", "sha256:doesnt-matter")
	bad.ExitCode = 1
	s.CommitAfterUpload(time.Now(), "exec-2", runningAgentVersion,
		[]ScanRecord{bad}, nil, nil, nil, false)

	if s.NPMProjects["/a"].ScanOutputHash != "sha256:old" {
		t.Errorf("failed scan must not overwrite cached hash; got %s", s.NPMProjects["/a"].ScanOutputHash)
	}
}

func TestCommitAfterUpload_RefreshesFullSyncTimestamp(t *testing.T) {
	s := New(runningAgentVersion)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.CommitAfterUpload(now, "exec-1", runningAgentVersion, nil, nil, nil, nil, true)
	if !s.LastFullSyncAt.Equal(now) {
		t.Errorf("full sync flag should refresh LastFullSyncAt, got %v", s.LastFullSyncAt)
	}
}

func TestBumpVerified_OnlyTouchesVerifiedAt(t *testing.T) {
	s := New(runningAgentVersion)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	s.NPMProjects["/a"] = ProjectEntry{
		ScanOutputHash: "sha256:x", LastUploadedAt: t0, LastVerifiedAt: t0, FirstSeenAt: t0,
	}
	s.BumpVerified(EcosystemNPM, []string{"/a"}, t1)

	got := s.NPMProjects["/a"]
	if !got.LastVerifiedAt.Equal(t1) {
		t.Errorf("LastVerifiedAt: got %v want %v", got.LastVerifiedAt, t1)
	}
	if !got.LastUploadedAt.Equal(t0) {
		t.Errorf("LastUploadedAt must not move on bump-verify; got %v", got.LastUploadedAt)
	}
}

// Cap-dropped projects ----------------------------------------------------

func TestPartition_CapDroppedEntriesUntouched(t *testing.T) {
	// State has A, B, C. Discovery returns A, B, C. Scanner runs A and B
	// only (cap). The state entry for C must be preserved without appearing
	// in any payload bucket — Partition only sees A and B.
	s := New(runningAgentVersion)
	s.NPMProjects["/a"] = ProjectEntry{ScanOutputHash: "sha256:x"}
	s.NPMProjects["/b"] = ProjectEntry{ScanOutputHash: "sha256:y"}
	s.NPMProjects["/c"] = ProjectEntry{ScanOutputHash: "sha256:z"}

	scanned := []ScanRecord{freshScan("/a", "sha256:x"), freshScan("/b", "sha256:y")}
	changed, unchanged := s.Partition(EcosystemNPM, scanned, false)
	if len(changed) != 0 {
		t.Errorf("expected no changes; got %v", changed)
	}
	if !sortedEq(unchanged, []string{"/a", "/b"}) {
		t.Errorf("expected /a /b unchanged; got %v", unchanged)
	}
	if _, ok := s.NPMProjects["/c"]; !ok {
		t.Error("/c must remain in state when cap dropped it")
	}
}

// Cross-ecosystem isolation ----------------------------------------------

func TestPartition_SamePathDifferentEcosystems(t *testing.T) {
	s := New(runningAgentVersion)
	s.NPMProjects["/proj"] = ProjectEntry{ScanOutputHash: "sha256:npm"}

	// Python scanner sees the same path as a different project (e.g. a
	// monorepo with both a package.json and a pyproject.toml). The Python
	// bucket must treat it as unknown.
	changed, unchanged := s.Partition(EcosystemPython, []ScanRecord{freshScan("/proj", "sha256:py")}, false)
	if !sortedEq(changed, []string{"/proj"}) || len(unchanged) != 0 {
		t.Errorf("ecosystem isolation broken: changed=%v unchanged=%v", changed, unchanged)
	}
}

// Globals -----------------------------------------------------------------

func TestPartitionGlobals_NewPMIsChanged(t *testing.T) {
	s := New(runningAgentVersion)
	changed, unchanged := s.PartitionGlobals(EcosystemNPM,
		[]GlobalRecord{{PM: "npm", Hash: "sha256:x"}}, false)
	if !sortedEq(changed, []string{"npm"}) || len(unchanged) != 0 {
		t.Errorf("changed=%v unchanged=%v", changed, unchanged)
	}
}

func TestPartitionGlobals_MatchIsUnchanged(t *testing.T) {
	s := New(runningAgentVersion)
	s.NPMGlobal["yarn"] = GlobalEntry{ScanOutputHash: "sha256:y"}
	changed, unchanged := s.PartitionGlobals(EcosystemNPM,
		[]GlobalRecord{{PM: "yarn", Hash: "sha256:y"}}, false)
	if len(changed) != 0 || !sortedEq(unchanged, []string{"yarn"}) {
		t.Errorf("changed=%v unchanged=%v", changed, unchanged)
	}
}
