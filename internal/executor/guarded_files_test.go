package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuardedFilesRefusesRedirectsAndGlob(t *testing.T) {
	home := t.TempDir()
	home, _ = filepath.EvalSymlinks(home)
	safe, protected := filepath.Join(home, "safe"), filepath.Join(home, "protected")
	for _, dir := range []string{safe, protected} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(protected, "metadata.json"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(safe, "redirect")); err != nil {
		t.Skip(err)
	}
	guarded := NewReal().GuardedFiles([]string{home}, func(path string) string {
		if path == protected {
			return "tcc_protected"
		}
		return ""
	}, 1024)
	for _, path := range []string{filepath.Join(protected, "metadata.json"), filepath.Join(safe, "redirect", "metadata.json")} {
		if guarded.FileExists(path) {
			t.Errorf("FileExists accepted protected path %s", path)
		}
		if _, err := guarded.ReadFile(path); err == nil {
			t.Errorf("ReadFile accepted protected path %s", path)
		}
	}
	if guarded.DirExists(filepath.Join(safe, "redirect")) {
		t.Error("DirExists followed protected redirect")
	}
	if matches, err := guarded.Glob(filepath.Join(safe, "*", "*.json")); err == nil || len(matches) != 0 {
		t.Errorf("Glob = %v, %v, want refused traversal", matches, err)
	}
}

func TestGuardedFilesFilesystemRoot(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "metadata.json")
	if err := os.WriteFile(path, []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.VolumeName(path) + string(filepath.Separator)
	guarded := NewReal().GuardedFiles([]string{root}, nil, 1024)
	if data, err := guarded.ReadFile(path); err != nil || string(data) != "ordinary" {
		t.Fatalf("filesystem-root reader = %q, %v", data, err)
	}
}

func TestGuardedFilesRootListingAndGlob(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	guarded := NewReal().GuardedFiles([]string{root}, nil, 1024)
	if _, err := guarded.ReadDir(root); err != nil {
		t.Fatal(err)
	}
	if matches, err := guarded.Glob(filepath.Join(root, "*")); err != nil || len(matches) == 0 {
		t.Fatalf("root glob = %v, %v", matches, err)
	}
}
