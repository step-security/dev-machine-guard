//go:build windows

package runtimeinv

import (
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"golang.org/x/sys/windows"
)

// The executable stays available. Only its sibling metadata file or an
// intermediate directory becomes offline on the second pass.
func TestRuntimeOfflineMetadata(t *testing.T) {
	for _, tc := range []struct {
		runtime, metadata, contents, offline, version string
	}{
		{"java", "release", "JAVA_VERSION=17.0.1", "release", "17.0.1"},
		{"go", "VERSION", "go1.22.1", "VERSION", "1.22.1"},
		{"node", "include/node/node_version.h", nodeVersionH, "include", "18.20.4"},
		{"python", "include/patchlevel.h", "#define PY_VERSION \"3.12.4\"", "include/patchlevel.h", "3.12.4"},
		{"php", "include/php/main/php_version.h", "#define PHP_VERSION \"8.3.1\"", "include/php", "8.3.1"},
		{"ruby", "lib/ruby/3.3.0/x64/rbconfig.rb", `CONFIG["RUBY_PROGRAM_VERSION"] = "3.3.2"`, "lib/ruby/3.3.0", "3.3.2"},
		{"dotnet", "shared/Microsoft.NETCore.App/8.0.1/marker", "", "shared", "8.0.1"},
	} {
		t.Run(tc.runtime, func(t *testing.T) {
			f := newFixture(t)
			const root = "OneDrive - Example/v9.8.7/"
			f.file(root+tc.runtime+".exe", "", false)
			f.file(root+tc.metadata, tc.contents, false)
			s := NewScanner(executor.NewReal(), f.root).WithSkipper(tcc.ForRun(f.root, nil, nil, f.path(root)))
			s.rootsOverride = []walkRoot{{path: f.path(root)}}
			local, _, _ := s.Scan(t.Context())
			if len(local) != 1 || local[0].Version != tc.version {
				t.Fatalf("local version = %+v, want %s", local, tc.version)
			}

			p, err := windows.UTF16PtrFromString(filepath.Join(f.path(root), filepath.FromSlash(tc.offline)))
			if err != nil {
				t.Fatal(err)
			}
			attrs, err := windows.GetFileAttributes(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetFileAttributes(p, attrs|windows.FILE_ATTRIBUTE_OFFLINE); err != nil {
				t.Fatal(err)
			}
			offline, _, _ := s.Scan(t.Context())
			if tc.runtime == "dotnet" {
				if len(offline) != 0 {
					t.Errorf("listed .NET versions inside an offline directory: %+v", offline)
				}
			} else if len(offline) != 1 || offline[0].Version != "9.8.7" || offline[0].VersionSource != versionFromPath {
				t.Errorf("expected path fallback for offline version metadata, got %+v", offline)
			}
		})
	}
}
