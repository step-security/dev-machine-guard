//go:build !windows

package updatestate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureProtectedDirStub(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "versions")
	for i := 0; i < 2; i++ {
		if fixed, err := EnsureProtectedDir(dir); fixed || err != nil {
			t.Fatalf("EnsureProtectedDir = %v, %v", fixed, err)
		}
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("dir not created: %v", err)
	}
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "l")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{file, link} {
		if _, err := EnsureProtectedDir(p); err == nil {
			t.Errorf("EnsureProtectedDir(%s) accepted a non-directory", p)
		}
	}
}
