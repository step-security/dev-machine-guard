package schtasks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveAllExcept_KeepsRunningImageAndItsPath(t *testing.T) {
	root := t.TempDir()
	versions := filepath.Join(root, "versions")
	keep := filepath.Join(versions, "1.18.1", "stepsecurity-dev-machine-guard.exe")
	for _, f := range []string{
		keep,
		filepath.Join(versions, "1.18.1", "manifest.json"),
		filepath.Join(versions, "1.18.1", "stepsecurity-dev-machine-guard-task.exe"),
		filepath.Join(versions, "1.17.0", "stepsecurity-dev-machine-guard.exe"),
		filepath.Join(versions, "1.17.0", "sub", "nested.txt"),
	} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeAllExcept(versions, strings.ToUpper(keep)); err != nil {
		t.Fatalf("removeAllExcept: %v", err)
	}
	var left []string
	_ = filepath.WalkDir(versions, func(path string, d os.DirEntry, err error) error {
		if err == nil {
			rel, _ := filepath.Rel(root, path)
			left = append(left, filepath.ToSlash(rel))
		}
		return nil
	})
	want := []string{"versions", "versions/1.18.1", "versions/1.18.1/stepsecurity-dev-machine-guard.exe"}
	if strings.Join(left, ",") != strings.Join(want, ",") {
		t.Errorf("left = %v, want %v", left, want)
	}
}

func TestRemoveAllExcept_RemovesEverythingWhenKeepIsElsewhere(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(state, "msi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "msi", "bootstrap.exe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeAllExcept(state, filepath.Join(root, "seed", "agent.exe")); err != nil {
		t.Fatalf("removeAllExcept: %v", err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("state dir still exists (err=%v)", err)
	}
	if err := removeAllExcept(filepath.Join(root, "missing"), ""); err != nil {
		t.Errorf("missing dir: got %v, want nil", err)
	}
}

func TestIsWithin(t *testing.T) {
	sep := string(filepath.Separator)
	dir := filepath.Join("C:", "Program Files", "StepSecurity", "versions")
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"file under dir", filepath.Join(dir, "1.18.1", "agent.exe"), true},
		{"different case", strings.ToUpper(filepath.Join(dir, "1.18.1", "agent.exe")), true},
		{"the dir itself", dir, false},
		{"sibling with the same prefix", dir + "-old" + sep + "agent.exe", false},
		{"outside", filepath.Join("C:", "Program Files", "StepSecurity", "seed", "agent.exe"), false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWithin(tc.path, dir); got != tc.want {
				t.Errorf("isWithin(%q, %q) = %v, want %v", tc.path, dir, got, tc.want)
			}
		})
	}
}
