//go:build darwin

package tcc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestProtectionAliases(t *testing.T) {
	s := New("/Users/test-user")
	for _, path := range []string{"/Users/test-user/Library/Containers/x", "/SYSTEM/VOLUMES/DATA/Users/test-user/library/Containers/x", "/System/Volumes/Data/Users/test-user/Documents/x"} {
		if !s.WithinProtected(path) {
			t.Errorf("not protected: %s", path)
		}
	}
	if s.WithinProtected("/System/Volumes/DataBackup/Users/test-user/Library/x") {
		t.Error("matched unrelated DataBackup path")
	}
}

func TestLibraryExceptionsDoNotAllowBrowserSiblings(t *testing.T) {
	home := t.TempDir()
	ordinary := filepath.Join(home, "Library", "Application Support", "Google", "AndroidStudio2026.1", "plugins")
	chrome := filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	for _, path := range []string{ordinary, chrome} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	s := New(home)
	guarded := GuardedFiles(executor.NewReal(), s, 1024, "Application Support/Google/AndroidStudio*")
	if _, err := guarded.ReadDir(ordinary); err != nil {
		t.Fatal(err)
	}
	if len(s.Hits()) != 0 {
		t.Fatalf("ordinary Library read recorded skip: %v", s.Hits())
	}
	if _, err := guarded.ReadDir(chrome); err == nil {
		t.Fatal("Chrome sibling admitted")
	}
	if Refusals(guarded) == 0 {
		t.Fatal("refusal not recorded")
	}
}

func TestExplicitProtectedRootRequiresInclude(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Documents")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	guarded := GuardedFiles(executor.NewReal(), ForRun(home, new(false), nil), 1024)
	if guarded.DirExists(root) {
		t.Fatal("explicit root bypassed protection")
	}
	included := GuardedFiles(executor.NewReal(), ForRun(home, new(true), nil), 1024)
	if !included.DirExists(root) {
		t.Fatal("explicit include refused ordinary fixture")
	}
}
