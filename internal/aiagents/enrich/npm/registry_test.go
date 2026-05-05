package npm

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func stubRun(t *testing.T, fn func(ctx context.Context, cwd, bin string, args ...string) (string, error)) {
	t.Helper()
	orig := runFunc
	runFunc = fn
	t.Cleanup(func() { runFunc = orig })
}

func TestResolveUnknownManagerReturnsNotOK(t *testing.T) {
	_, _, ok := Resolve(context.Background(), "cargo", "")
	if ok {
		t.Errorf("expected ok=false for unknown pm")
	}
}

func TestResolveNPMTrimsWhitespace(t *testing.T) {
	stubRun(t, func(_ context.Context, _, _ string, _ ...string) (string, error) {
		return "https://registry.npmjs.org/\n", nil
	})
	if !canLookPath("npm") {
		t.Skip("npm not on PATH; LookPath gate would block stub")
	}
	got, src, ok := Resolve(context.Background(), "npm", "")
	if !ok {
		t.Fatal("expected ok")
	}
	if got != "https://registry.npmjs.org/" {
		t.Errorf("registry: %q", got)
	}
	if src != SourceNPM {
		t.Errorf("source: %s", src)
	}
}

func TestResolveYarnDetectsBerry(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".yarnrc.yml"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isYarnBerry(dir) {
		t.Errorf("expected Berry detection in %s", dir)
	}
	if isYarnBerry(t.TempDir()) {
		t.Errorf("expected non-Berry in empty dir")
	}
}

func TestResolveTreatsUndefinedAsMissing(t *testing.T) {
	if !canLookPath("npm") {
		t.Skip("npm not on PATH")
	}
	stubRun(t, func(_ context.Context, _, _ string, _ ...string) (string, error) {
		return "undefined\n", nil
	})
	_, _, ok := Resolve(context.Background(), "npm", "")
	if ok {
		t.Errorf("expected ok=false on 'undefined'")
	}
}

func TestResolvePropagatesRunError(t *testing.T) {
	if !canLookPath("npm") {
		t.Skip("npm not on PATH")
	}
	stubRun(t, func(_ context.Context, _, _ string, _ ...string) (string, error) {
		return "", errors.New("boom")
	})
	_, _, ok := Resolve(context.Background(), "npm", "")
	if ok {
		t.Errorf("expected ok=false on run error")
	}
}

func canLookPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}
