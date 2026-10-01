//go:build darwin

package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

func TestMixedNVMGlobalRoots(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(home, ".nvm", "versions", "node")
	safe := filepath.Join(versions, "safe", "lib", "node_modules")
	protected := filepath.Join(home, "Documents", "node")
	for _, p := range []string{filepath.Join(safe, "widgets"), filepath.Join(versions, "bad"), protected} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(safe, "widgets", "package.json"), []byte(`{"name":"widgets","version":"1.0.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(versions, "bad", "lib")); err != nil {
		t.Fatal(err)
	}
	e := isolatedGlobalExecutor{protectedFixtureExecutor{Executor: executor.NewReal(), home: home}}
	s := tcc.New(home)
	guarded := tcc.GuardedFiles(e, s, maxLockfileSize, "pnpm", "Application Support/fnm")
	matches, globErr := guarded.Glob(filepath.Join(versions, "*", "lib", "node_modules"))
	t.Logf("guarded Glob: matches=%v err=%v", matches, globErr)
	if len(matches) != 1 || matches[0] != safe || globErr == nil {
		t.Fatalf("fixture did not produce safe match plus refusal: %v %v", matches, globErr)
	}
	results := NewNodeScanner(e, progress.NewNoop(), "").WithSkipper(s).WithDiskScan(NewNodeDistDetector(e).WithSkipper(s)).scanGlobalPackagesFromDisk()
	readable, incomplete := false, false
	for _, r := range results {
		t.Logf("manager=%s packages=%d exit=%d error=%q", r.PackageManager, r.PackagesCount, r.ExitCode, r.Error)
		if r.PackageManager == "npm" && r.ExitCode == 0 && len(r.Packages) == 1 && r.Packages[0].Name == "widgets" {
			readable = true
		}
		if r.PackageManager == "npm" && r.ExitCode != 0 {
			incomplete = true
		}
	}
	if !readable || !incomplete {
		t.Fatalf("readable=%v incomplete=%v, want both", readable, incomplete)
	}
}
