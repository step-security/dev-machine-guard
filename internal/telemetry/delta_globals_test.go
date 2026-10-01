package telemetry

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/state"
)

func npmGlobalRoot(path string, pkgs ...model.NodePackage) model.NodeScanResult {
	return model.NodeScanResult{
		ProjectPath:      path,
		WorkingDirectory: path,
		PackageManager:   "npm",
		Packages:         pkgs,
		PackagesCount:    len(pkgs),
	}
}

// Several roots must reduce to one record whose hash covers all of them —
// keeping the last root's hash would hide a change in any other.
func TestGlobalRecordsFromNode_FoldsRootsPerPM(t *testing.T) {
	chalk := model.NodePackage{Name: "chalk", Version: "5.6.1"}
	ts := model.NodePackage{Name: "typescript", Version: "5.4.0"}

	base := []model.NodeScanResult{
		npmGlobalRoot("/n/v20/lib/node_modules", chalk),
		npmGlobalRoot("/n/v22/lib/node_modules", ts),
	}
	recs := globalRecordsFromNode(base)
	if len(recs) != 1 || recs[0].PM != "npm" {
		t.Fatalf("want a single npm record, got %+v", recs)
	}

	// A change in the FIRST root must move the hash.
	changedFirst := []model.NodeScanResult{
		npmGlobalRoot("/n/v20/lib/node_modules", model.NodePackage{Name: "chalk", Version: "5.6.2"}),
		npmGlobalRoot("/n/v22/lib/node_modules", ts),
	}
	if h := globalRecordsFromNode(changedFirst)[0].Hash; h == recs[0].Hash {
		t.Error("hash unchanged after the first root's packages changed")
	}

	// Otherwise every run re-uploads globals.
	if h := globalRecordsFromNode(base)[0].Hash; h != recs[0].Hash {
		t.Errorf("hash is not stable across runs: %q vs %q", h, recs[0].Hash)
	}

	// ProjectPath is what the dashboard shows, so a moved root is a change.
	moved := []model.NodeScanResult{
		npmGlobalRoot("/n/v20/lib/node_modules", chalk),
		npmGlobalRoot("/opt/homebrew/lib/node_modules", ts),
	}
	if h := globalRecordsFromNode(moved)[0].Hash; h == recs[0].Hash {
		t.Error("hash unchanged after a root moved to a different prefix")
	}
}

// A failing root must not be masked by a healthy one folded in after it.
func TestGlobalRecordsFromNode_FailedRootMarksPMChanged(t *testing.T) {
	bad := npmGlobalRoot("/n/v20/lib/node_modules")
	bad.ExitCode = 1
	recs := globalRecordsFromNode([]model.NodeScanResult{
		bad,
		npmGlobalRoot("/n/v22/lib/node_modules", model.NodePackage{Name: "chalk", Version: "5.6.1"}),
	})
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].ExitCode == 0 {
		t.Error("folded record reports success despite a failed root")
	}
}

// The backend keys the unchanged ref by PM, so several roots yield one ref.
func TestSplitNodeGlobals_OneUnchangedRefPerPM(t *testing.T) {
	results := []model.NodeScanResult{
		npmGlobalRoot("/n/v20/lib/node_modules", model.NodePackage{Name: "chalk", Version: "5.6.1"}),
		npmGlobalRoot("/n/v22/lib/node_modules", model.NodePackage{Name: "typescript", Version: "5.4.0"}),
	}
	recs := globalRecordsFromNode(results)
	prior := map[string]state.GlobalEntry{
		"npm": {ScanOutputHash: recs[0].Hash, LastUploadedExecutionID: "exec-1", LastVerifiedAt: time.Now()},
	}

	changed, unchanged := splitNodeGlobals(prior, results, recs, nil, []string{"npm"})
	if len(changed) != 0 {
		t.Errorf("want no changed results, got %d", len(changed))
	}
	if len(unchanged) != 1 {
		t.Fatalf("want 1 unchanged ref for npm, got %d: %+v", len(unchanged), unchanged)
	}
	if unchanged[0].ScanOutputHash != recs[0].Hash {
		t.Errorf("ref hash = %q, want the folded per-PM hash %q", unchanged[0].ScanOutputHash, recs[0].Hash)
	}

	// When the PM is changed, every root ships.
	changed, unchanged = splitNodeGlobals(prior, results, recs, []string{"npm"}, nil)
	if len(changed) != 2 {
		t.Errorf("want both roots in the changed set, got %d", len(changed))
	}
	if len(unchanged) != 0 {
		t.Errorf("want no unchanged refs, got %d", len(unchanged))
	}
}

func TestPythonGlobals_PartialUploadRecovery(t *testing.T) {
	complete := []model.PythonScanResult{{PackageManager: "pip", RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(`[{"name":"widgets","version":"1"},{"name":"gizmo","version":"1"}]`))}}
	partial := []model.PythonScanResult{{PackageManager: "pip", Partial: true, RawStdoutBase64: base64.StdEncoding.EncodeToString([]byte(`[{"name":"widgets","version":"1"}]`))}}
	now := time.Now()
	saved := state.New("test")
	saved.CommitAfterUpload(now, "exec-complete", "test", nil, nil, nil, globalRecordsFromPython(complete), true)
	snap := buildDeltaSnapshot(saved, false, false, true, nil, nil, nil, nil, nil, partial)
	if len(snap.pyGlobalsChanged) != 1 || len(snap.pyGlobalsUnchanged) != 0 {
		t.Fatalf("partial package body not sent: %+v", snap)
	}
	wire, err := json.Marshal(snap.pyGlobalsChanged)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "partial") || snap.pyGlobalsChanged[0].ExitCode != 0 {
		t.Fatalf("unexpected partial wire result: %s", wire)
	}
	// Without a successful upload, the existing baseline still owns the inventory.
	if saved.PythonGlobal["pip"].LastUploadedExecutionID != "exec-complete" {
		t.Fatal("building a snapshot advanced the upload baseline")
	}
	saved.CommitAfterUpload(now.Add(time.Minute), "exec-partial", "test", snap.npmRecords, snap.pyRecords, snap.npmGlobalRecords, snap.pyGlobalRecords, false)
	if got := saved.PythonGlobal["pip"].LastUploadedExecutionID; got != "exec-partial" {
		t.Errorf("partial upload predecessor = %q, want exec-partial", got)
	}
	repeated := buildDeltaSnapshot(saved, false, false, true, nil, nil, nil, nil, nil, partial)
	if len(repeated.pyGlobalsChanged) != 0 || len(repeated.pyGlobalsUnchanged) != 1 || repeated.pyGlobalsUnchanged[0].LastUploadedExecutionID != "exec-partial" {
		t.Errorf("identical partial scan must reference its uploaded body: %+v", repeated)
	}
	recovered := buildDeltaSnapshot(saved, false, false, true, nil, nil, nil, nil, nil, complete)
	if len(recovered.pyGlobalsChanged) != 1 || len(recovered.pyGlobalsUnchanged) != 0 {
		t.Fatalf("readable recovery must upload A+B, not the old reference: %+v", recovered)
	}
	saved.CommitAfterUpload(now.Add(2*time.Minute), "exec-recovered", "test", recovered.npmRecords, recovered.pyRecords, recovered.npmGlobalRecords, recovered.pyGlobalRecords, false)
	unchanged := buildDeltaSnapshot(saved, false, false, true, nil, nil, nil, nil, nil, complete)
	if len(unchanged.pyGlobalsChanged) != 0 || len(unchanged.pyGlobalsUnchanged) != 1 || unchanged.pyGlobalsUnchanged[0].LastUploadedExecutionID != "exec-recovered" {
		t.Fatalf("recovered baseline not reusable: %+v", unchanged)
	}
	// Actual failed scans still send an error and leave the successful cache intact.
	failed := []model.PythonScanResult{{PackageManager: "pip", Partial: true, ExitCode: 1, Error: "protected roots"}}
	failure := buildDeltaSnapshot(saved, false, false, true, nil, nil, nil, nil, nil, failed)
	if len(failure.pyGlobalsChanged) != 1 || len(failure.pyGlobalsUnchanged) != 0 {
		t.Fatalf("failure not reported: %+v", failure)
	}
	saved.CommitAfterUpload(now.Add(3*time.Minute), "exec-failed", "test", nil, nil, nil, failure.pyGlobalRecords, false)
	if saved.PythonGlobal["pip"].LastUploadedExecutionID != "exec-recovered" {
		t.Fatal("failed scan replaced the successful baseline")
	}
	full := buildDeltaSnapshot(saved, true, false, true, nil, nil, nil, nil, nil, complete)
	if len(full.pyGlobalsChanged) != 1 || len(full.pyGlobalsUnchanged) != 0 {
		t.Fatal("full sync must send the package body")
	}
}

func TestNodeGlobals_FailedScanRecovery(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "all-refused", true: "mixed-roots"}[mixed], func(t *testing.T) {
			complete := []model.NodeScanResult{
				npmGlobalRoot("/n/v20/lib/node_modules", model.NodePackage{Name: "widgets", Version: "1"}),
				npmGlobalRoot("/n/v22/lib/node_modules", model.NodePackage{Name: "gizmo", Version: "1"}),
			}
			partial := []model.NodeScanResult{{PackageManager: "npm", ExitCode: 1, Error: "global package roots include protected paths"}}
			if mixed {
				partial = append(partial, complete[0])
			}
			saved := state.New("test")
			now := time.Now()
			saved.CommitAfterUpload(now, "exec-complete", "test", nil, nil, globalRecordsFromNode(complete), nil, true)
			snapshot := buildDeltaSnapshot(saved, false, true, false, nil, nil, nil, nil, partial, nil)
			if len(snapshot.npmGlobalsChanged) != len(partial) || len(snapshot.npmGlobalsUnchanged) != 0 {
				t.Fatalf("failed global bodies not sent: %+v", snapshot)
			}
			statePath := filepath.Join(t.TempDir(), "scan-state.json")
			if err := commitDeltaSnapshot(saved, snapshot, statePath, "exec-partial", "test"); err != nil {
				t.Fatal(err)
			}
			restored, err := state.Load(statePath, "test")
			if err != nil {
				t.Fatal(err)
			}
			recovered := buildDeltaSnapshot(restored, false, true, false, nil, nil, nil, nil, complete, nil)
			if len(recovered.npmGlobalsChanged) != len(complete) || len(recovered.npmGlobalsUnchanged) != 0 {
				t.Fatalf("recovery must upload each readable root after a failed global body, not reuse the old manager-wide reference: %+v", recovered)
			}
			if err := commitDeltaSnapshot(restored, recovered, statePath, "exec-recovered", "test"); err != nil {
				t.Fatal(err)
			}
			unchanged := buildDeltaSnapshot(restored, false, true, false, nil, nil, nil, nil, complete, nil)
			if len(unchanged.npmGlobalsChanged) != 0 || len(unchanged.npmGlobalsUnchanged) != 1 || unchanged.npmGlobalsUnchanged[0].LastUploadedExecutionID != "exec-recovered" {
				t.Fatalf("complete recovered roots must become reusable: %+v", unchanged)
			}
		})
	}
}
