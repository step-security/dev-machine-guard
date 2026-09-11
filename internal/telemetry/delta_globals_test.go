package telemetry

import (
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
