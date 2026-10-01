//go:build darwin

package detector

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

func TestMixedPythonGlobalRoots(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(home, ".local", "lib", "python3.12", "site-packages")
	metadata := filepath.Join(safe, "widgets-1.0.0.dist-info", "METADATA")
	link := filepath.Join(home, ".local", "share", "pipx", "venvs")
	protected := filepath.Join(home, "Documents", "pipx")
	for _, path := range []string{filepath.Dir(metadata), filepath.Dir(link), protected} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(metadata, []byte("Name: widgets\nVersion: 1.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, link); err != nil {
		t.Fatal(err)
	}
	e := isolatedGlobalExecutor{protectedFixtureExecutor{Executor: executor.NewReal(), home: home}}
	s := tcc.New(home)
	control := NewPythonDistDetector(e).WithSkipper(s).ScanRoots([]string{safe})
	if len(control) != 1 || control[0].Name != "widgets" {
		t.Fatalf("safe control missing package: %+v", control)
	}
	guarded := tcc.GuardedFiles(e, s, maxMetadataFileSize, "Python")
	roots := GlobalPythonRoots(guarded, progress.NewNoop())
	t.Logf("roots=%v refusals=%d", roots, tcc.Refusals(guarded))
	if len(roots) != 1 || (roots[0] != safe && roots[0] != filepath.Dir(safe)) || tcc.Refusals(guarded) == 0 {
		t.Fatal("fixture must preserve safe root and refuse pipx redirect")
	}
	t.Run("enterprise", func(t *testing.T) {
		results := NewPythonScanner(e, progress.NewNoop()).ScanGlobalPackagesFromDisk(s)
		for _, r := range results {
			data, _ := base64.StdEncoding.DecodeString(r.RawStdoutBase64)
			t.Logf("exit=%d error=%q packages=%s", r.ExitCode, r.Error, data)
			if strings.Contains(string(data), "widgets") && r.Partial && r.ExitCode == 0 {
				return
			}
		}
		t.Fatal("protected pipx root swallowed ordinary Python package")
	})
	t.Run("community", func(t *testing.T) {
		dist := NewPythonDistDetector(e).WithSkipper(s)
		packages := dist.ScanGlobalPackages()
		if !dist.Incomplete() {
			t.Fatal("partial community scan reported complete")
		}
		for _, p := range packages {
			if p.Name == "widgets" {
				return
			}
		}
		t.Fatal("protected pipx root swallowed ordinary Python package")
	})
}

func TestPartialPythonMetadataRead(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".local", "lib", "python3.12", "site-packages")
	safe := filepath.Join(root, "widgets-1.0.0.dist-info", "METADATA")
	link := filepath.Join(root, "blocked-1.0.0.dist-info", "METADATA")
	target := filepath.Join(home, "Documents", "METADATA")
	for _, p := range []string{filepath.Dir(safe), filepath.Dir(link), filepath.Dir(target)} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(safe, []byte("Name: widgets\nVersion: 1.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	e := isolatedGlobalExecutor{protectedFixtureExecutor{Executor: executor.NewReal(), home: home}}
	dist := NewPythonDistDetector(e).WithSkipper(tcc.New(home))
	if packages := dist.scanRoots([]string{root}); len(packages) != 1 || !dist.Incomplete() {
		t.Fatalf("partial metadata packages=%v incomplete=%v", packages, dist.Incomplete())
	}
	if packages := dist.ScanRoots([]string{root}); packages != nil {
		t.Fatal("project inventory must not cache partial metadata as complete")
	}
}
