package telemetry

import (
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/state"
)

var timeFixture = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func tempStateFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "scan-state.json")
}

func nodeResult(path, pm, stdout string) model.NodeScanResult {
	return model.NodeScanResult{
		ProjectPath:     path,
		PackageManager:  pm,
		PMVersion:       "10.2.0",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		ExitCode:        0,
	}
}

func nodeGlobal(pm, stdout string, exit int) model.NodeScanResult {
	return model.NodeScanResult{
		PackageManager:  pm,
		PMVersion:       "10.2.0",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		ExitCode:        exit,
	}
}

// runDelta drives buildDeltaSnapshot + commitDeltaSnapshot for the given
// inputs and returns the snapshot (post-mutation, pre-commit) plus the
// reloaded state from disk after commit.
func runDelta(
	t *testing.T, s *state.State, statePath, execID string,
	npm []model.NodeScanResult, npmDisc []string,
	py []model.ProjectInfo, pyDisc []string,
	npmG []model.NodeScanResult, pyG []model.PythonScanResult,
	fullSync bool,
) (*deltaSnapshot, *state.State) {
	t.Helper()
	snap := buildDeltaSnapshot(s, fullSync, npm, npmDisc, py, pyDisc, npmG, pyG)
	if err := commitDeltaSnapshot(s, snap, statePath, execID, buildinfo.Version); err != nil {
		t.Fatalf("commit: %v", err)
	}
	reloaded, err := state.Load(statePath, buildinfo.Version)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return snap, reloaded
}

func TestDelta_FirstRunPopulatesStateAndShipsAllAsChanged(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	npm := []model.NodeScanResult{
		nodeResult("/svc-api", "npm", `{"deps":{"x":"1.0"}}`),
		nodeResult("/svc-web", "npm", `{"deps":{"y":"2.0"}}`),
	}

	snap, reloaded := runDelta(t, s, path, "exec-1", npm, []string{"/svc-api", "/svc-web"}, nil, nil, nil, nil, false)

	if len(snap.npmChanged) != 2 {
		t.Errorf("expected 2 changed, got %d", len(snap.npmChanged))
	}
	if len(snap.npmUnchanged) != 0 {
		t.Errorf("expected 0 unchanged on first run, got %d", len(snap.npmUnchanged))
	}
	if len(reloaded.NPMProjects) != 2 {
		t.Errorf("expected 2 npm state entries after commit, got %d", len(reloaded.NPMProjects))
	}
	if reloaded.LastSuccessfulExecutionID != "exec-1" {
		t.Errorf("execution_id not stamped: %s", reloaded.LastSuccessfulExecutionID)
	}
}

func TestDelta_SecondRunWithSameHashesShipsUnchangedRefs(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	npm := []model.NodeScanResult{nodeResult("/svc", "npm", `{"deps":{"x":"1.0"}}`)}

	runDelta(t, s, path, "exec-1", npm, []string{"/svc"}, nil, nil, nil, nil, false)

	s2, _ := state.Load(path, buildinfo.Version)
	snap, _ := runDelta(t, s2, path, "exec-2", npm, []string{"/svc"}, nil, nil, nil, nil, false)

	if len(snap.npmChanged) != 0 {
		t.Errorf("expected 0 changed bodies on identical re-run, got %d", len(snap.npmChanged))
	}
	if len(snap.npmUnchanged) != 1 || snap.npmUnchanged[0].Path != "/svc" {
		t.Errorf("expected /svc as unchanged ref, got %+v", snap.npmUnchanged)
	}
	if snap.npmUnchanged[0].LastUploadedExecutionID != "exec-1" {
		t.Errorf("expected ref to carry prior exec id, got %s", snap.npmUnchanged[0].LastUploadedExecutionID)
	}
	if snap.npmUnchanged[0].ScanOutputHash == "" {
		t.Errorf("expected ref to carry hash")
	}
}

func TestDelta_HashDiffShipsAsChanged(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	runDelta(t, s, path, "exec-1",
		[]model.NodeScanResult{nodeResult("/svc", "npm", `{"deps":{"x":"1.0"}}`)},
		[]string{"/svc"}, nil, nil, nil, nil, false)

	s2, _ := state.Load(path, buildinfo.Version)
	snap, _ := runDelta(t, s2, path, "exec-2",
		[]model.NodeScanResult{nodeResult("/svc", "npm", `{"deps":{"x":"2.0"}}`)},
		[]string{"/svc"}, nil, nil, nil, nil, false)

	if len(snap.npmChanged) != 1 {
		t.Errorf("expected /svc in changed (version bump), got %+v", snap.npmChanged)
	}
	if len(snap.npmUnchanged) != 0 {
		t.Errorf("expected 0 unchanged, got %+v", snap.npmUnchanged)
	}
}

func TestDelta_RemovedProjectShipsAsRemovedRef(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	runDelta(t, s, path, "exec-1",
		[]model.NodeScanResult{
			nodeResult("/a", "npm", `{"x":1}`),
			nodeResult("/b", "npm", `{"y":2}`),
		}, []string{"/a", "/b"}, nil, nil, nil, nil, false)

	s2, _ := state.Load(path, buildinfo.Version)
	snap, reloaded := runDelta(t, s2, path, "exec-2",
		[]model.NodeScanResult{nodeResult("/a", "npm", `{"x":1}`)},
		[]string{"/a"}, nil, nil, nil, nil, false)

	if len(snap.npmRemoved) != 1 || snap.npmRemoved[0].Path != "/b" {
		t.Errorf("expected /b in removed refs, got %+v", snap.npmRemoved)
	}
	if snap.npmRemoved[0].LastUploadedExecutionID != "exec-1" {
		t.Errorf("expected ref to carry prior exec id, got %s", snap.npmRemoved[0].LastUploadedExecutionID)
	}
	// After commit, /b is gone from both the main map AND pending_ack.
	if _, ok := reloaded.NPMProjects["/b"]; ok {
		t.Errorf("/b should be dropped from main map after ack")
	}
	if len(reloaded.PendingRemovalsFor(state.EcosystemNPM)) != 0 {
		t.Errorf("pending_ack should be empty after ack, got %+v", reloaded.PendingRemovalsFor(state.EcosystemNPM))
	}
}

func TestDelta_CapDroppedProjectIsNotMarkedRemoved(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	runDelta(t, s, path, "exec-1",
		[]model.NodeScanResult{
			nodeResult("/a", "npm", `{"x":1}`),
			nodeResult("/b", "npm", `{"y":2}`),
		}, []string{"/a", "/b"}, nil, nil, nil, nil, false)

	// Second run: /b is still on disk (in discovered) but didn't get scanned
	// (cap dropped it). MUST NOT be marked removed.
	s2, _ := state.Load(path, buildinfo.Version)
	snap, reloaded := runDelta(t, s2, path, "exec-2",
		[]model.NodeScanResult{nodeResult("/a", "npm", `{"x":1}`)},
		[]string{"/a", "/b"}, nil, nil, nil, nil, false)

	if len(snap.npmRemoved) != 0 {
		t.Errorf("cap-dropped project must not appear in removed refs: %+v", snap.npmRemoved)
	}
	if _, ok := reloaded.NPMProjects["/b"]; !ok {
		t.Errorf("cap-dropped project entry should be preserved in state")
	}
}

func TestDelta_ReappearedProjectIsFilteredFromRemovedRefs(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	// Run 1: /a + /b → state.
	runDelta(t, s, path, "exec-1",
		[]model.NodeScanResult{
			nodeResult("/a", "npm", `{"x":1}`),
			nodeResult("/b", "npm", `{"y":2}`),
		}, []string{"/a", "/b"}, nil, nil, nil, nil, false)

	// Run 2: /b gone — but commitDeltaSnapshot's Save fails on next run by
	// loading from a fresh path so the pending_ack persists (simulating an
	// upload that ack'd /b on disk but a follow-up run that re-discovers it).
	s2, _ := state.Load(path, buildinfo.Version)
	// Manually leave /b in state's pending_ack (post-MarkRemoved state) so we
	// can test the filter on the next call.
	s2.MarkRemovedPending(state.EcosystemNPM, []string{"/b"}, timeFixture)
	// Now /b reappears with the same content.
	snap := buildDeltaSnapshot(s2, false,
		[]model.NodeScanResult{
			nodeResult("/a", "npm", `{"x":1}`),
			nodeResult("/b", "npm", `{"y":2}`),
		}, []string{"/a", "/b"}, nil, nil, nil, nil)

	if len(snap.npmRemoved) != 0 {
		t.Errorf("re-discovered project must be filtered from removed refs: %+v", snap.npmRemoved)
	}
}

func TestDelta_FailedScanDoesNotOverwriteHash(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	runDelta(t, s, path, "exec-1",
		[]model.NodeScanResult{nodeResult("/svc", "npm", `{"x":1}`)},
		[]string{"/svc"}, nil, nil, nil, nil, false)

	good, _ := state.Load(path, buildinfo.Version)
	goodHash := good.NPMProjects["/svc"].ScanOutputHash

	s2, _ := state.Load(path, buildinfo.Version)
	bad := []model.NodeScanResult{{
		ProjectPath:     "/svc",
		PackageManager:  "npm",
		RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(`{"x":2}`)),
		ExitCode:        1,
	}}
	_, reloaded := runDelta(t, s2, path, "exec-2", bad, []string{"/svc"}, nil, nil, nil, nil, false)

	if reloaded.NPMProjects["/svc"].ScanOutputHash != goodHash {
		t.Errorf("failed scan must not overwrite prior hash: got %s want %s",
			reloaded.NPMProjects["/svc"].ScanOutputHash, goodHash)
	}
}

func TestDelta_PythonRoundTrip(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	py := []model.ProjectInfo{
		{Path: "/proj/.venv", PackageManager: "pip", Packages: []model.PackageDetail{{Name: "django", Version: "5.0"}}},
	}
	snap, reloaded := runDelta(t, s, path, "exec-1", nil, nil, py, []string{"/proj/.venv"}, nil, nil, false)

	if len(snap.pyChanged) != 1 {
		t.Errorf("expected 1 python changed, got %+v", snap.pyChanged)
	}
	if len(reloaded.PythonProjects) != 1 {
		t.Fatalf("expected 1 python entry, got %d", len(reloaded.PythonProjects))
	}
}

func TestDelta_GlobalsAreTracked(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	globals := []model.NodeScanResult{
		nodeGlobal("npm", `{"dependencies":{"tsc":"5.0"}}`, 0),
		nodeGlobal("yarn", `{"dependencies":{"create-react-app":"5.0"}}`, 0),
	}
	snap, reloaded := runDelta(t, s, path, "exec-1", nil, nil, nil, nil, globals, nil, false)

	if len(snap.npmGlobalsChanged) != 2 {
		t.Errorf("first run: expected 2 globals as changed, got %+v", snap.npmGlobalsChanged)
	}
	if len(reloaded.NPMGlobal) != 2 {
		t.Errorf("expected 2 global entries after commit, got %d", len(reloaded.NPMGlobal))
	}

	// Second run with identical globals: ships as unchanged refs, no bodies.
	s2, _ := state.Load(path, buildinfo.Version)
	snap2, _ := runDelta(t, s2, path, "exec-2", nil, nil, nil, nil, globals, nil, false)
	if len(snap2.npmGlobalsChanged) != 0 {
		t.Errorf("second run: expected 0 changed globals, got %+v", snap2.npmGlobalsChanged)
	}
	if len(snap2.npmGlobalsUnchanged) != 2 {
		t.Errorf("second run: expected 2 unchanged-ref globals, got %+v", snap2.npmGlobalsUnchanged)
	}
}

func TestDelta_FullSyncForcesAllChanged(t *testing.T) {
	path := tempStateFile(t)
	s := state.New(buildinfo.Version)
	npm := []model.NodeScanResult{nodeResult("/svc", "npm", `{"x":1}`)}
	runDelta(t, s, path, "exec-1", npm, []string{"/svc"}, nil, nil, nil, nil, false)

	s2, _ := state.Load(path, buildinfo.Version)
	snap, reloaded := runDelta(t, s2, path, "exec-2", npm, []string{"/svc"}, nil, nil, nil, nil, true)

	if len(snap.npmChanged) != 1 {
		t.Errorf("full sync should force changed even on identical hashes, got %+v", snap.npmChanged)
	}
	if len(snap.npmUnchanged) != 0 {
		t.Errorf("full sync should produce no unchanged refs, got %+v", snap.npmUnchanged)
	}
	if reloaded.LastFullSyncAt.IsZero() {
		t.Errorf("full-sync timestamp not refreshed")
	}
}

func TestDelta_NilStateReturnsNilSnapshot(t *testing.T) {
	snap := buildDeltaSnapshot(nil, false,
		[]model.NodeScanResult{nodeResult("/svc", "npm", `{"x":1}`)},
		[]string{"/svc"}, nil, nil, nil, nil)
	if snap != nil {
		t.Errorf("nil state should produce nil snapshot, got %+v", snap)
	}
}
