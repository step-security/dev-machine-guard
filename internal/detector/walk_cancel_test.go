package detector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// cancelTree builds n project dirs, each with a package.json, a venv with
// dist-info metadata, a node_modules package and an mcp.json, so every walker
// would find something if it ignored ctx.
func cancelTree(t *testing.T, n int) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"package.json":                         `{"name":"p"}`,
		"mcp.json":                             `{}`,
		"node_modules/dep/package.json":        `{"name":"dep","version":"1.0.0"}`,
		".venv/pyvenv.cfg":                     "home = /usr\n",
		".venv/lib/python3.12/site-packages/x": "",
		".venv/lib/python3.12/site-packages/flask-3.0.0.dist-info/METADATA": "Name: Flask\nVersion: 3.0.0\n",
	}
	for i := range n {
		for rel, body := range files {
			p := filepath.Join(root, fmt.Sprintf("p%03d", i), rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestWalksStopOnCancelledContext(t *testing.T) {
	root := cancelTree(t, 200)
	exec := executor.NewReal()
	ctx := cancelledCtx()
	t.Setenv("STEPSEC_NODE_SCAN_CACHE", filepath.Join(t.TempDir(), "cache.json"))
	t.Setenv("STEPSEC_NODE_SCAN_CACHE_BYPASS", "1")

	start := time.Now()

	scanner := NewNodeScanner(exec, progress.NewNoop(), "").WithDiskScan(NewNodeDistDetector(exec))
	if res, disc := scanner.ScanProjects(ctx, []string{root}, nil); len(res) != 0 || len(disc) != 0 {
		t.Errorf("node ScanProjects: got %d results, %d discovered; want 0", len(res), len(disc))
	}
	if pkgs := NewNodeDistDetector(exec).ScanGlobalModules(ctx, root); len(pkgs) != 0 {
		t.Errorf("node ScanGlobalModules: got %d packages, want 0", len(pkgs))
	}

	py := NewPythonProjectDetector(exec).WithDiskScan(NewPythonDistDetector(exec))
	if projects, disc := py.ListProjects(ctx, []string{root}, nil); len(projects) != 0 || len(disc) != 0 {
		t.Errorf("python ListProjects: got %d projects, %d discovered; want 0", len(projects), len(disc))
	}
	// A cancelled walk is partial, so ScanRoots reports failure (nil).
	if pkgs := NewPythonDistDetector(exec).ScanRoots(ctx, []string{root}); pkgs != nil {
		t.Errorf("python ScanRoots: got %v, want nil", pkgs)
	}

	if specs := (&MCPDetector{}).discoverWalkedMCPConfigs(ctx, []string{root}, ""); len(specs) != 0 {
		t.Errorf("mcp walk: got %d specs, want 0", len(specs))
	}

	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("cancelled walks took %v", d)
	}
}
