package lock

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/paths"
)

func withScope(t *testing.T, s string) {
	t.Helper()
	prev := paths.UserScope()
	paths.SetUserScope(s)
	t.Cleanup(func() { paths.SetUserScope(prev) })
}

func TestLockPath_UnchangedWithoutScope(t *testing.T) {
	withScope(t, "")
	if got := filepath.Base(lockPath()); got != "stepsecurity-dev-machine-guard.lock" {
		t.Fatalf("lock file = %q", got)
	}
}

func TestLockPath_SuffixedByUserScope(t *testing.T) {
	withScope(t, "")
	shared := lockPath()
	withScope(t, "jdoe")
	scoped := lockPath()
	if filepath.Base(scoped) != "stepsecurity-dev-machine-guard-jdoe.lock" {
		t.Fatalf("scoped lock file = %q", filepath.Base(scoped))
	}
	// Same directory as the shared lock: only the name changes.
	if filepath.Dir(scoped) != filepath.Dir(shared) {
		t.Fatalf("scoped lock moved directories: %q vs %q", scoped, shared)
	}
	if strings.Contains(scoped, "users") {
		t.Fatalf("lock must not live in the per-user state dir: %q", scoped)
	}
}
