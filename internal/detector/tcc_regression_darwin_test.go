//go:build darwin

package detector

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/state"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

type isolatedGlobalExecutor struct{ protectedFixtureExecutor }

func (e isolatedGlobalExecutor) Getenv(key string) string {
	if key == "PNPM_HOME" {
		return filepath.Join(e.home, "Documents", "pnpm")
	}
	return e.protectedFixtureExecutor.Getenv(key)
}
func (e isolatedGlobalExecutor) DirExists(path string) bool {
	return strings.HasPrefix(path, e.home+string(filepath.Separator)) && e.Executor.DirExists(path)
}
func (e isolatedGlobalExecutor) Glob(pattern string) ([]string, error) {
	if !strings.HasPrefix(pattern, e.home+string(filepath.Separator)) {
		return nil, nil
	}
	return e.Executor.Glob(pattern)
}
func (e isolatedGlobalExecutor) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	e.Executor = e.Executor.GuardedFiles(roots, guard, max)
	return e
}

func TestProtectedPnpmKeepsSafeGlobalPackages(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{filepath.Join(home, ".npm-global", "lib", "node_modules"), filepath.Join(home, ".config", "yarn", "global", "node_modules")} {
		path := filepath.Join(root, "widgets", "package.json")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"name":"widgets","version":"1.0.0"}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	exec := isolatedGlobalExecutor{protectedFixtureExecutor{Executor: executor.NewReal(), home: home}}
	skipper := tcc.New(home)
	scanner := NewNodeScanner(exec, progress.NewNoop(), "").WithSkipper(skipper).WithDiskScan(NewNodeDistDetector(exec).WithSkipper(skipper))
	got := scanner.scanGlobalPackagesFromDisk()
	for _, pm := range []string{"npm", "yarn"} {
		found := false
		for _, result := range got {
			if result.PackageManager == pm && result.ExitCode == 0 && len(result.Packages) == 1 && result.Packages[0].Name == "widgets" {
				found = true
			}
		}
		if !found {
			t.Errorf("missing safe %s inventory: %+v", pm, got)
		}
	}
	refused := false
	for _, result := range got {
		if result.PackageManager == "pnpm" && result.ExitCode != 0 {
			refused = true
		}
	}
	if !refused {
		t.Error("missing pnpm incomplete result")
	}
}

func TestProtectedDiscoveryRetainsKnownProjects(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exec := protectedFixtureExecutor{Executor: executor.NewReal(), home: home}
	skipper := tcc.New(home)
	for _, family := range []string{"node", "python"} {
		t.Run(family, func(t *testing.T) {
			project := filepath.Join(home, "Documents", family)
			if family == "python" {
				project = filepath.Join(project, ".venv")
			}
			if err := os.MkdirAll(project, 0700); err != nil {
				t.Fatal(err)
			}
			known := map[string]time.Time{project: time.Unix(123, 0)}
			var discovered []string
			if family == "node" {
				_, discovered = NewNodeScanner(exec, progress.NewNoop(), "").WithSkipper(skipper).WithDiskScan(NewNodeDistDetector(exec).WithSkipper(skipper)).ScanProjects(context.Background(), []string{filepath.Join(home, "Documents")}, known)
			} else {
				_, discovered = NewPythonProjectDetector(exec).WithSkipper(skipper).WithDiskScan(NewPythonDistDetector(exec).WithSkipper(skipper)).ListProjects([]string{filepath.Join(home, "Documents")}, known)
			}
			if !slices.Contains(discovered, project) {
				t.Errorf("unobserved project lost from reconciliation: %v", discovered)
			}
		})
	}
}

func TestProtectedDiscoveryReconcilesReadableRemoval(t *testing.T) {
	for _, family := range []string{"node", "python"} {
		t.Run(family, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			safe := filepath.Join(home, "work", "safe")
			protected := filepath.Join(home, "Documents", "protected")
			removed := filepath.Join(home, "work", "removed")
			if family == "python" {
				safe = filepath.Join(safe, ".venv")
				protected = filepath.Join(protected, ".venv")
				removed = filepath.Join(removed, ".venv")
			}
			for _, path := range []string{safe, protected} {
				if family == "node" {
					mustWrite(t, filepath.Join(path, "package.json"), `{"name":"widgets"}`)
					mustWrite(t, filepath.Join(path, "node_modules", "widgets", "package.json"), `{"name":"widgets","version":"1.0.0"}`)
				} else {
					mustWrite(t, filepath.Join(path, "pyvenv.cfg"), "home = /example/python")
					mustWrite(t, filepath.Join(path, "lib", "python3.12", "site-packages", "widgets-1.0.0.dist-info", "METADATA"), "Name: widgets\nVersion: 1.0.0\n")
				}
			}
			exec := protectedFixtureExecutor{Executor: executor.NewReal(), home: home}
			known := map[string]time.Time{safe: time.Unix(123, 0), protected: time.Unix(123, 0), removed: time.Unix(123, 0)}
			scan := func(skipper *tcc.Skipper) []string {
				if family == "node" {
					_, found := NewNodeScanner(exec, progress.NewNoop(), "").WithSkipper(skipper).WithDiskScan(NewNodeDistDetector(exec).WithSkipper(skipper)).ScanProjects(context.Background(), []string{home}, known)
					return found
				}
				_, found := NewPythonProjectDetector(exec).WithSkipper(skipper).WithDiskScan(NewPythonDistDetector(exec).WithSkipper(skipper)).ListProjects([]string{home}, known)
				return found
			}
			ecosystem := state.EcosystemNPM
			saved := state.New("test")
			entries := saved.NPMProjects
			if family == "python" {
				ecosystem = state.EcosystemPython
				entries = saved.PythonProjects
			}
			for path := range known {
				entries[path] = state.ProjectEntry{LastVerifiedAt: known[path]}
			}
			_, _, deletions := saved.Reconcile(ecosystem, scan(tcc.New(home)))
			if len(deletions) != 1 || deletions[0] != removed {
				t.Fatalf("deletions=%v, want only readable missing project %s", deletions, removed)
			}
			recovered := scan(nil)
			if !slices.Contains(recovered, safe) || !slices.Contains(recovered, protected) {
				t.Fatalf("recovery lost projects: %v", recovered)
			}
			if err := os.RemoveAll(protected); err != nil {
				t.Fatal(err)
			}
			_, _, deletions = saved.Reconcile(ecosystem, scan(nil))
			if !slices.Contains(deletions, protected) {
				t.Fatalf("real uninstall not removed: %v", deletions)
			}
		})
	}
}
