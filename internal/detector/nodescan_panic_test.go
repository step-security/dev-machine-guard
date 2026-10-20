package detector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestScanProjects_WorkerPanicIsPerProject(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"good", "bad"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("STEPSEC_NODE_SCAN_CACHE", filepath.Join(t.TempDir(), "cache.json"))
	t.Setenv("STEPSEC_NODE_SCAN_CACHE_BYPASS", "1")

	exec := executor.NewReal()
	s := NewNodeScanner(exec, progress.NewNoop(), "").WithDiskScan(NewNodeDistDetector(exec))
	s.scanOverride = func(_ context.Context, dir, pm string) (model.NodeScanResult, bool) {
		if filepath.Base(dir) == "bad" {
			panic("malformed lockfile")
		}
		return model.NodeScanResult{ProjectPath: dir, PackageManager: pm}, true
	}

	results, _ := s.ScanProjects(context.Background(), []string{root}, nil)
	byName := map[string]model.NodeScanResult{}
	for _, r := range results {
		byName[filepath.Base(r.ProjectPath)] = r
	}
	if r, ok := byName["good"]; !ok || r.ExitCode != 0 {
		t.Errorf("good project: got %+v, ok=%v", r, ok)
	}
	if r, ok := byName["bad"]; !ok || r.ExitCode == 0 || r.Error == "" {
		t.Errorf("bad project should be a failed result, got %+v, ok=%v", r, ok)
	}
}
