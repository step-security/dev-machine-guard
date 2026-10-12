package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// mustWriteMeta writes a metadata file to the real filesystem (so the walker
// finds it) and registers its content in the mock (so ReadFile returns it).
func mustWriteMeta(t *testing.T, mock *executor.Mock, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	mock.SetFile(path, []byte(content))
}

const sampleMetadata = `Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.

This is the long description that should never be parsed.
Version: 9.9.9 (this trailing header must be ignored)
`

func TestPythonDistDetector_ScanVenv_DistInfo(t *testing.T) {
	dir := t.TempDir()
	mock := executor.NewMock()
	sp := filepath.Join(dir, ".venv", "lib", "python3.11", "site-packages")

	mustWriteMeta(t, mock, filepath.Join(sp, "requests-2.31.0.dist-info", "METADATA"), sampleMetadata)
	mustWriteMeta(t, mock, filepath.Join(sp, "click-8.1.7.dist-info", "METADATA"),
		"Name: click\nVersion: 8.1.7\n\nbody")

	det := NewPythonDistDetector(mock)
	pkgs := det.ScanVenv(filepath.Join(dir, ".venv"))

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}
	// Sorted by name: click then requests.
	if pkgs[0].Name != "click" || pkgs[0].Version != "8.1.7" {
		t.Errorf("pkgs[0] = %+v, want click 8.1.7", pkgs[0])
	}
	if pkgs[1].Name != "requests" || pkgs[1].Version != "2.31.0" {
		t.Errorf("pkgs[1] = %+v, want requests 2.31.0", pkgs[1])
	}
}

// ScanVenv limits its walk to the venv's site-packages dirs, so metadata
// stashed elsewhere in the tree (e.g. under bin/) is not reported.
func TestPythonDistDetector_ScanVenv_ScopedToSitePackages(t *testing.T) {
	dir := t.TempDir()
	mock := executor.NewMock()
	venv := filepath.Join(dir, ".venv")
	sp := filepath.Join(venv, "lib", "python3.11", "site-packages")

	mustWriteMeta(t, mock, filepath.Join(sp, "requests-2.31.0.dist-info", "METADATA"), sampleMetadata)
	// A stray metadata file outside site-packages must be ignored.
	mustWriteMeta(t, mock, filepath.Join(venv, "bin", "stray-1.0.0.dist-info", "METADATA"),
		"Name: stray\nVersion: 1.0.0\n\nbody")

	pkgs := NewPythonDistDetector(mock).ScanVenv(venv)
	if len(pkgs) != 1 || pkgs[0].Name != "requests" {
		t.Fatalf("expected only requests from site-packages, got %+v", pkgs)
	}
}

func TestPythonDistDetector_EggInfoFallback(t *testing.T) {
	dir := t.TempDir()
	mock := executor.NewMock()
	sp := filepath.Join(dir, "lib", "python3.9", "site-packages")

	mustWriteMeta(t, mock, filepath.Join(sp, "legacy.egg-info", "PKG-INFO"),
		"Metadata-Version: 1.0\nName: legacy\nVersion: 0.1.0\n\nbody")

	pkgs := NewPythonDistDetector(mock).ScanRoots([]string{dir})
	if len(pkgs) != 1 || pkgs[0].Name != "legacy" || pkgs[0].Version != "0.1.0" {
		t.Fatalf("expected legacy 0.1.0, got %+v", pkgs)
	}
}

func TestPythonDistDetector_SkipsCachesAndNonDistInfo(t *testing.T) {
	dir := t.TempDir()
	mock := executor.NewMock()
	sp := filepath.Join(dir, "site-packages")

	// dist-info under __pycache__ must be skipped (dir is pruned).
	mustWriteMeta(t, mock, filepath.Join(sp, "__pycache__", "evil-1.0.dist-info", "METADATA"),
		"Name: evil\nVersion: 1.0\n\nx")
	// A METADATA file NOT inside a *.dist-info dir must be ignored.
	mustWriteMeta(t, mock, filepath.Join(sp, "notadist", "METADATA"),
		"Name: nope\nVersion: 1.0\n\nx")
	// A real package, to prove the walk still works.
	mustWriteMeta(t, mock, filepath.Join(sp, "good-2.0.dist-info", "METADATA"),
		"Name: good\nVersion: 2.0\n\nx")

	pkgs := NewPythonDistDetector(mock).ScanRoots([]string{dir})
	if len(pkgs) != 1 || pkgs[0].Name != "good" {
		t.Fatalf("expected only good, got %+v", pkgs)
	}
}

func TestPythonDistDetector_MalformedAndDedup(t *testing.T) {
	dir := t.TempDir()
	mock := executor.NewMock()
	sp := filepath.Join(dir, "site-packages")

	// Missing Version → skipped.
	mustWriteMeta(t, mock, filepath.Join(sp, "broken-0.dist-info", "METADATA"),
		"Name: broken\nSummary: no version\n\nx")
	// Same (name, version) twice → de-duplicated.
	mustWriteMeta(t, mock, filepath.Join(sp, "dup-1.0.dist-info", "METADATA"),
		"Name: dup\nVersion: 1.0\n\nx")
	mustWriteMeta(t, mock, filepath.Join(sp, "dup-1.0-py3.dist-info", "METADATA"),
		"Name: dup\nVersion: 1.0\n\nx")

	pkgs := NewPythonDistDetector(mock).ScanRoots([]string{dir})
	if len(pkgs) != 1 || pkgs[0].Name != "dup" {
		t.Fatalf("expected single dup, got %+v", pkgs)
	}
}

func TestPythonDistDetector_SizeCap(t *testing.T) {
	dir := t.TempDir()
	mock := executor.NewMock()
	sp := filepath.Join(dir, "site-packages")
	mustWriteMeta(t, mock, filepath.Join(sp, "big-1.0.dist-info", "METADATA"),
		"Name: big\nVersion: 1.0\n\nx")

	det := NewPythonDistDetector(mock)
	det.maxFileSize = 5 // smaller than the header → rejected
	if pkgs := det.ScanRoots([]string{dir}); len(pkgs) != 0 {
		t.Fatalf("expected size-cap to drop the package, got %+v", pkgs)
	}
}

func TestParseRFC822NameVersion(t *testing.T) {
	name, version := parseRFC822NameVersion([]byte(sampleMetadata))
	if name != "requests" || version != "2.31.0" {
		t.Fatalf("got name=%q version=%q, want requests/2.31.0 (must stop at blank line)", name, version)
	}
}

func TestIsDistInfoAndEggInfo(t *testing.T) {
	if !isDistInfoMetadata("/a/foo-1.0.dist-info/METADATA") {
		t.Error("expected dist-info METADATA to match")
	}
	if isDistInfoMetadata("/a/foo/METADATA") {
		t.Error("plain METADATA must not match")
	}
	if !isEggInfoPKGInfo("/a/foo.egg-info/PKG-INFO") {
		t.Error("expected egg-info PKG-INFO to match")
	}
	if isEggInfoPKGInfo("/a/foo/PKG-INFO") {
		t.Error("plain PKG-INFO must not match")
	}
}

// Disk-mode ListProjects: a venv's packages come from site-packages metadata,
// with no pip invocation — and it works for a --without-pip venv.
func TestPythonProjectDetector_DiskScan(t *testing.T) {
	dir := t.TempDir()
	mock := executor.NewMock()

	venv := filepath.Join(dir, "proj", ".venv")
	// pyvenv.cfg marks the venv (no bin/pip → exercises the --without-pip path).
	mustWriteMeta(t, mock, filepath.Join(venv, "pyvenv.cfg"), "home = /usr\n")
	sp := filepath.Join(venv, "lib", "python3.12", "site-packages")
	mustWriteMeta(t, mock, filepath.Join(sp, "flask-3.0.0.dist-info", "METADATA"),
		"Name: Flask\nVersion: 3.0.0\n\nx")

	dist := NewPythonDistDetector(mock)
	det := NewPythonProjectDetector(mock).WithDiskScan(dist)
	projects, _ := det.ListProjects([]string{dir}, nil)

	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d: %+v", len(projects), projects)
	}
	if got := projects[0].Packages; len(got) != 1 || got[0].Name != "Flask" || got[0].Version != "3.0.0" {
		t.Fatalf("expected Flask 3.0.0 from disk, got %+v", got)
	}
}

func TestPythonDistDetector_EmptyAndFailedWalks(t *testing.T) {
	root := t.TempDir()
	mock := executor.NewMock()
	populated := filepath.Join(root, "populated")
	mustWriteMeta(t, mock, filepath.Join(populated, "x.dist-info", "METADATA"), "Name: x\nVersion: 1\n")
	empty := t.TempDir()
	missing := filepath.Join(root, "missing")
	for _, tc := range []struct {
		name   string
		roots  []string
		failed bool
	}{
		{"empty", []string{empty}, false},
		{"missing", []string{missing}, true},
		{"partial", []string{populated, missing}, true},
		{"no roots", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NewPythonDistDetector(mock).ScanRoots(tc.roots)
			if (got == nil) != tc.failed || len(got) != 0 {
				t.Fatalf("packages=%v nil=%v, want failure=%v", got, got == nil, tc.failed)
			}
		})
	}
}

func TestPythonProjectDetector_NoPipIsUnscannedUnlessDiskInspected(t *testing.T) {
	for _, tc := range []struct {
		name            string
		disk, populated bool
		want            int
	}{
		{"legacy empty", false, false, -1},
		{"legacy populated", false, true, -1},
		{"disk empty", true, false, 0},
		{"disk populated", true, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			venv := filepath.Join(root, "venv")
			sp := filepath.Join(venv, "lib", "python3.13", "site-packages")
			if err := os.MkdirAll(sp, 0o755); err != nil {
				t.Fatal(err)
			}
			mock := executor.NewMock()
			mock.SetFile(filepath.Join(venv, "pyvenv.cfg"), []byte("home = /usr/bin"))
			if tc.populated {
				mustWriteMeta(t, mock, filepath.Join(sp, "x.dist-info", "METADATA"), "Name: x\nVersion: 1\n")
			}
			d := NewPythonProjectDetector(mock)
			if tc.disk {
				d.WithDiskScan(NewPythonDistDetector(mock))
			}
			projects, discovered := d.ListProjects([]string{root}, nil)
			if len(projects) != 1 || len(discovered) != 1 || discovered[0] != venv {
				t.Fatalf("projects=%v discovered=%v", projects, discovered)
			}
			pkgs := projects[0].Packages
			if tc.want < 0 {
				if pkgs != nil {
					t.Fatal("unscanned venv treated as empty")
				}
				return
			}
			if pkgs == nil || len(pkgs) != tc.want {
				t.Fatalf("packages=%v nil=%v, want %d", pkgs, pkgs == nil, tc.want)
			}
		})
	}
}

func TestPythonDistDetector_UnreadableWalkIsNotEmpty(t *testing.T) {
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })
	if _, err := os.ReadDir(blocked); err == nil {
		t.Skip("filesystem permits reading mode-000 directories")
	}
	for _, path := range []string{blocked, root} {
		if got := NewPythonDistDetector(executor.NewMock()).ScanRoots([]string{path}); got != nil {
			t.Fatalf("unreadable walk %s returned successful inventory: %v", path, got)
		}
	}
}
