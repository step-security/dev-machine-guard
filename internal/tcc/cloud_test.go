package tcc

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"syscall"
	"testing"
)

func TestOneDriveProjectWalk(t *testing.T) {
	home := t.TempDir()
	for _, pair := range [][2]string{{"OneDrive", "Redirected"}, {"OneDriveCommercial", "WorkSync"}, {"OneDriveConsumer", "PersonalSync"}} {
		t.Setenv(pair[0], filepath.Join(home, pair[1]))
	}
	dirs := []string{"OneDrive", "OneDrive - Example", "WorkSync", "PersonalSync", "Redirected", "OneDrive.backup", "code/OneDrive", "code/local"}
	for _, dir := range dirs {
		project := filepath.Join(home, filepath.FromSlash(dir), "project")
		if err := os.MkdirAll(project, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, "package.json"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		root string
		want []string
	}{
		{"default", home, []string{"OneDrive.backup/project", "code/OneDrive/project", "code/local/project"}},
		{"explicit sync root", filepath.Join(home, "WorkSync"), []string{"WorkSync/project"}},
		{"explicit synced project", filepath.Join(home, "OneDrive - Example", "project"), []string{"OneDrive - Example/project"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Skipper{cloud: newCloudRoots(home, []string{tc.root})}
			var got []string
			err := filepath.WalkDir(tc.root, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() && s.ShouldSkip(path, tc.root) {
					return fs.SkipDir
				}
				if entry.Name() == "package.json" {
					rel, err := filepath.Rel(home, filepath.Dir(path))
					if err != nil {
						return err
					}
					got = append(got, filepath.ToSlash(rel))
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("discovered %v, want %v", got, tc.want)
			}
			if !s.WithinProtected(filepath.Join(home, "oNeDrIvE", "sibling", "package.json")) {
				t.Error("direct access to an unselected sync subtree was allowed")
			}
		})
	}
}

func TestCloudPathChecksLinkTargets(t *testing.T) {
	home := t.TempDir()
	syncDir := filepath.Join(home, "OneDrive")
	for _, dir := range []string{syncDir, filepath.Join(home, "local")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ name, target string }{
		{"cloud-dir", syncDir},
		{"cloud-file", filepath.Join("cloud-dir", "package.json")},
		{"local-file", filepath.Join("local", "package.json")},
		{"loop", "loop"},
	} {
		makeCloudTestLink(t, link.target, filepath.Join(home, link.name))
	}
	for _, tc := range []struct {
		path                string
		allowSync, wantSkip bool
	}{
		{"cloud-file", false, true},
		{filepath.Join("cloud-dir", "package.json"), false, true},
		{"local-file", false, false},
		{"cloud-file", true, false},
		{"loop", true, true},
	} {
		var roots []string
		if tc.allowSync {
			roots = []string{syncDir}
		}
		s := &Skipper{cloud: newCloudRoots(home, roots)}
		if got := s.SkipCloudPath(filepath.Join(home, tc.path)); got != tc.wantSkip {
			t.Errorf("SkipCloudPath(%q) with explicit sync root %t = %t, want %t", tc.path, tc.allowSync, got, tc.wantSkip)
		}
	}
}

func makeCloudTestLink(t *testing.T, target, alias string) {
	t.Helper()
	if err := os.Symlink(target, alias); err != nil {
		const privilegeNotHeld = syscall.Errno(1314) // Windows ERROR_PRIVILEGE_NOT_HELD
		if runtime.GOOS == "windows" && (os.IsPermission(err) || errors.Is(err, privilegeNotHeld)) {
			t.Skipf("symlink creation requires permission: %v", err)
		}
		t.Fatal(err)
	}
}
