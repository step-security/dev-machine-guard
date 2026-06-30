package detector

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// ScanGlobalModules marks immediate children of the global root as direct
// (globally-installed) and anything below a nested node_modules as transitive.
func TestScanGlobalModules(t *testing.T) {
	// Real global roots end in "node_modules"; the package-path rule keys on
	// that segment, so the fixture must too.
	root := filepath.Join(t.TempDir(), "lib", "node_modules")
	mustWrite(t, filepath.Join(root, "typescript", "package.json"), `{"name":"typescript","version":"5.4.0"}`)
	mustWrite(t, filepath.Join(root, "@scope", "cli", "package.json"), `{"name":"@scope/cli","version":"1.0.0"}`)
	mustWrite(t, filepath.Join(root, "typescript", "node_modules", "dep", "package.json"), `{"name":"dep","version":"2.0.0"}`)

	got := newDistDetector().ScanGlobalModules(root)
	assertPkgs(t, got, "typescript@5.4.0+direct", "@scope/cli@1.0.0+direct", "dep@2.0.0")
}

// An explicit npm prefix override is resolved to <prefix>/lib/node_modules.
func TestNodeGlobalRoots_PrefixOverride(t *testing.T) {
	prefix := t.TempDir()
	nm := filepath.Join(prefix, "lib", "node_modules")
	mustWrite(t, filepath.Join(nm, "typescript", "package.json"), `{"name":"typescript","version":"5.4.0"}`)
	t.Setenv("npm_config_prefix", prefix)

	found := false
	for _, r := range NodeGlobalRoots(executor.NewReal()) {
		if r.pm == "npm" && filepath.Clean(r.dir) == filepath.Clean(nm) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected npm global root %q from prefix override", nm)
	}
}

// Enterprise disk mode: ScanProjects emits structured packages with no raw
// output and no package-manager invocation.
func TestNodeScanner_DiskMode_Project(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, "app")
	mustWrite(t, filepath.Join(proj, "package.json"), `{"name":"app","dependencies":{"lodash":"^4"}}`)
	mustWrite(t, filepath.Join(proj, "package-lock.json"), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name":"app"},
	    "node_modules/lodash": {"version":"4.17.21"},
	    "node_modules/dep": {"version":"1.0.0"}
	  }
	}`)
	// Isolate the scan cache to a temp file and bypass it for a deterministic run.
	t.Setenv("STEPSEC_NODE_SCAN_CACHE", filepath.Join(t.TempDir(), "cache.json"))
	t.Setenv("STEPSEC_NODE_SCAN_CACHE_BYPASS", "1")

	exec := executor.NewReal()
	scanner := NewNodeScanner(exec, progress.NewNoop(), "").
		WithDiskScan(NewNodeDistDetector(exec))

	results, discovered := scanner.ScanProjects(context.Background(), []string{root}, nil)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	r := results[0]
	if r.RawStdoutBase64 != "" {
		t.Errorf("disk mode must not emit raw stdout, got %d bytes", len(r.RawStdoutBase64))
	}
	if r.PackagesCount != 2 || len(r.Packages) != 2 {
		t.Fatalf("want 2 packages, got count=%d slice=%v", r.PackagesCount, r.Packages)
	}
	assertPkgs(t, r.Packages, "lodash@4.17.21+direct", "dep@1.0.0")
	if len(discovered) != 1 {
		t.Errorf("want 1 discovered project, got %d", len(discovered))
	}
}
