//go:build windows

package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"golang.org/x/sys/windows"
)

// OFFLINE exercises the Windows enumeration and the actual project detector
// without requiring a signed-in OneDrive client on CI.
func TestNodeProjects_OneDriveAndOfflineFiles(t *testing.T) {
	home := t.TempDir()
	syncRoot := filepath.Join(home, "OneDrive - Example")
	for _, root := range []string{home, syncRoot} {
		for _, name := range []string{"local", "offline"} {
			project := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Join(project, "node_modules"), 0700); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(project, "package.json")
			if err := os.WriteFile(manifest, []byte(`{"dependencies":{"a":"1.0.0"}}`), 0600); err != nil {
				t.Fatal(err)
			}
			if name == "offline" {
				p, err := windows.UTF16PtrFromString(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_OFFLINE); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	include := true
	for _, root := range []string{home, syncRoot} {
		s := tcc.ForRun(home, &include, &include, root)
		projects := NewNodeProjectDetector(executor.NewReal()).WithSkipper(s).ListProjects([]string{root})
		if len(projects) != 1 || projects[0].Path != filepath.Join(root, "local") || len(projects[0].Packages) != 1 {
			t.Errorf("ListProjects(%q) = %+v, want just the local project and its dependency", root, projects)
		}
	}
}

func TestPythonProjects_OfflineVenvMarker(t *testing.T) {
	root := t.TempDir()
	venv := filepath.Join(root, ".venv")
	dist := filepath.Join(venv, "Lib", "site-packages", "local-1.0.dist-info")
	if err := os.MkdirAll(dist, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "METADATA"), []byte("Name: local\nVersion: 1.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(venv, "pyvenv.cfg")
	if err := os.WriteFile(marker, []byte("version = 3.12\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_OFFLINE); err != nil {
		t.Fatal(err)
	}

	ex := executor.NewReal()
	skipper := tcc.ForRun(root, nil, nil, root)
	d := NewPythonProjectDetector(ex).WithSkipper(skipper).WithDiskScan(NewPythonDistDetector(ex).WithSkipper(skipper))
	projects, _ := d.ListProjects(t.Context(), []string{root}, nil)
	if len(projects) != 1 || projects[0].Path != venv || len(projects[0].Packages) != 1 || projects[0].Packages[0].Name != "local" {
		t.Fatalf("offline pyvenv.cfg with local site-packages: got %+v, want venv with local package", projects)
	}
}
