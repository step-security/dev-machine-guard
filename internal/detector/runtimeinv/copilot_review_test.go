package runtimeinv

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Regressions for the PR #261 review findings.

// A capped directory listing must mark its root truncated, not look complete.
func TestCappedListingMarksRootTruncated(t *testing.T) {
	m := executor.NewMock()
	m.SetGOOS("linux")
	ents := make([]os.DirEntry, 0, maxDirEntries+1)
	for i := 0; i <= maxDirEntries; i++ {
		ents = append(ents, executor.MockDirEntry("f", false))
	}
	m.SetDirEntries("/flat", ents)
	s := &Scanner{exec: m, goos: "linux", rootsOverride: []walkRoot{{"/flat", 1, nil, maxDirEntries * 2}}}
	_, truncated, roots := s.Scan(context.Background())
	if !truncated || len(roots) != 1 || roots[0] != "/flat" {
		t.Fatalf("truncated=%v roots=%v, want [/flat]", truncated, roots)
	}
}

// Co-installed interpreters in one prefix get their own headers' versions.
func TestSharedPrefixVersionsMatchABI(t *testing.T) {
	f := newFixture(t)
	f.file("usr/bin/python3.10", "\x7fELF", true)
	f.file("usr/bin/python3.12", "\x7fELF", true)
	f.file("usr/include/python3.10/patchlevel.h", `#define PY_VERSION "3.10.14"`, false)
	f.file("usr/include/python3.12/patchlevel.h", `#define PY_VERSION "3.12.3"`, false)
	f.file("usr/bin/ruby3.2", "\x7fELF", true)
	f.file("usr/bin/ruby3.3", "\x7fELF", true)
	f.file("usr/lib/ruby/3.2.0/x86_64-linux/rbconfig.rb", `CONFIG["RUBY_PROGRAM_VERSION"] = "3.2.4"`, false)
	f.file("usr/lib/ruby/3.3.0/x86_64-linux/rbconfig.rb", `CONFIG["RUBY_PROGRAM_VERSION"] = "3.3.1"`, false)
	out := f.scan("linux", "", walkRoot{f.path("usr/bin"), 0, nil, 0})
	got := map[string]string{}
	for _, r := range out {
		got[filepath.Base(r.ExecutablePath)] = r.Version
	}
	want := map[string]string{"python3.10": "3.10.14", "python3.12": "3.12.3", "ruby3.2": "3.2.4", "ruby3.3": "3.3.1"}
	for exe, v := range want {
		if got[exe] != v {
			t.Errorf("%s = %q, want %q (all: %v)", exe, got[exe], v, got)
		}
	}
}

// With no ABI in the name and several headers, don't guess one of them.
func TestAmbiguousSharedPrefixDoesNotGuess(t *testing.T) {
	f := newFixture(t)
	f.file("usr/bin/python3", "\x7fELF", true) // a copy, not a link
	f.file("usr/include/python3.10/patchlevel.h", `#define PY_VERSION "3.10.14"`, false)
	f.file("usr/include/python3.12/patchlevel.h", `#define PY_VERSION "3.12.3"`, false)
	out := f.scan("linux", "", walkRoot{f.path("usr/bin"), 0, nil, 0})
	if len(out) != 1 || out[0].Version == "3.10.14" || out[0].Version == "3.12.3" {
		t.Fatalf("ambiguous prefix picked a header: %+v", out)
	}
}

func TestPathVersionPrefersPreciseCompatibleDir(t *testing.T) {
	cases := []struct{ exe, root, want string }{
		{"/x/3.12.9/bin/python3.12", "/x/3.12.9", "3.12.9"}, // dir more precise, compatible
		{"/x/3.11.2/bin/python3.12", "/x/3.11.2", "3.12"},   // dir disagrees: trust the exe name
		{"/x/v18.20.8/bin/node", "/x/v18.20.8", "18.20.8"},  // no exe version
		{"/usr/bin/python3.13", "/usr", "3.13"},             // exe only
	}
	for _, c := range cases {
		r, ok := pathVersionStrategy(context.Background(), nil, c.exe, c.root)
		if !ok || r.version != c.want {
			t.Errorf("%s: got %q ok=%v, want %q", c.exe, r.version, ok, c.want)
		}
	}
}

func TestDetectVersionStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	sig := &signature{runtime: "x", versions: []versionStrategy{
		func(context.Context, executor.Executor, string, string) (versionResult, bool) {
			calls++
			return versionResult{}, false
		},
	}}
	if r := detectVersion(ctx, nil, sig, "/x", "/"); r.version != "unknown" || calls != 0 {
		t.Fatalf("got %+v after %d strategy calls", r, calls)
	}
}

func TestWindowsRootsIncludeUVPython(t *testing.T) {
	m := executor.NewMock()
	m.SetGOOS("windows")
	m.SetEnv("APPDATA", "/C/Users/dev/AppData/Roaming")
	s := &Scanner{exec: m, goos: "windows", home: "/C/Users/dev"}
	for _, r := range s.roots() {
		if r.path == filepath.Join("/C/Users/dev/AppData/Roaming", "uv", "python") {
			return
		}
	}
	t.Fatal("uv python root missing")
}
