package updatestate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLayoutPaths(t *testing.T) {
	l := Layout{InstallRoot: filepath.Join("root", "SS"), DataRoot: filepath.Join("data", "SS")}
	v := Version{1, 19, 0}
	j := filepath.Join
	for got, want := range map[string]string{
		l.VersionsDir(): j("root", "SS", "versions"),
		l.VersionDir(v): j("root", "SS", "versions", "1.19.0"),
		l.SeedDir(v):    j("root", "SS", "seed", "1.19.0"),
		l.StateDir():    j("root", "SS", "state"),
		l.StateFile():   j("root", "SS", "state", "state.json"),
		l.LockFile():    j("root", "SS", "state", "update.lock"),
		l.LogFile():     j("root", "SS", "state", "update.log"),
		l.RunsDir():     j("data", "SS", "runs"),
		l.RunFile(v):    j("data", "SS", "runs", "1.19.0.json"),
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestStagingDir(t *testing.T) {
	l := Layout{InstallRoot: t.TempDir()}
	v := Version{1, 2, 3}
	if _, err := l.StagingDir(v); err == nil {
		t.Fatal("StagingDir must fail when VersionsDir is missing")
	}
	if err := os.MkdirAll(l.VersionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	a, err := l.StagingDir(v)
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.StagingDir(v)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || filepath.Dir(a) != l.VersionsDir() || !strings.HasPrefix(filepath.Base(a), ".staging-1.2.3-") {
		t.Fatalf("staging dirs %q, %q", a, b)
	}
	for name, want := range map[string]bool{filepath.Base(a): true, ".trash-1.2.3-x": true, "1.2.3": false, "staging-1": false} {
		if IsSweepable(name) != want {
			t.Errorf("IsSweepable(%q) != %v", name, want)
		}
	}
}
