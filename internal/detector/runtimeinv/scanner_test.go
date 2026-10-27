package runtimeinv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// fixture builds files under a temp root; exe=true makes them executable.
type fixture struct {
	t    *testing.T
	root string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir()) // macOS /var -> /private/var
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, root: root}
}

func (f *fixture) path(rel string) string { return filepath.Join(f.root, filepath.FromSlash(rel)) }

func (f *fixture) file(rel, content string, exe bool) string {
	f.t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	mode := os.FileMode(0o644)
	if exe {
		mode = 0o755
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) symlink(rel, target string) {
	f.t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) scan(goos, home string, roots ...walkRoot) []model.RuntimeInstall {
	f.t.Helper()
	s := &Scanner{exec: executor.NewReal(), goos: goos, home: home, rootsOverride: roots}
	out, truncated, _ := s.Scan(context.Background())
	if truncated {
		f.t.Fatal("unexpected truncation")
	}
	return out
}

func byRuntime(rs []model.RuntimeInstall, runtime string) []model.RuntimeInstall {
	var out []model.RuntimeInstall
	for _, r := range rs {
		if r.Runtime == runtime {
			out = append(out, r)
		}
	}
	return out
}

const nodeVersionH = `#ifndef SRC_NODE_VERSION_H_
#define SRC_NODE_VERSION_H_

#define NODE_MAJOR_VERSION 18
#define NODE_MINOR_VERSION 20
#define NODE_PATCH_VERSION 4
`

func TestScanUnixLayouts(t *testing.T) {
	f := newFixture(t)
	home := f.path("home/dev")

	// nvm with headers.
	f.file("home/dev/.nvm/versions/node/v18.20.4/bin/node", "", true)
	f.file("home/dev/.nvm/versions/node/v18.20.4/include/node/node_version.h", nodeVersionH, false)
	// nvm without headers -> path version.
	f.file("home/dev/.nvm/versions/node/v20.11.1/bin/node", "", true)
	// brew node reached via a /usr/local/bin symlink and the Cellar: one record.
	cellarNode := f.file("usr/local/Cellar/node/22.1.0/bin/node", "", true)
	f.symlink("usr/local/bin/node", cellarNode)
	// pyenv python: python3.12 real, python3 copy, python symlink -> one record.
	f.file("home/dev/.pyenv/versions/3.12.1/bin/python3.12", "", true)
	f.file("home/dev/.pyenv/versions/3.12.1/bin/python3", "", true)
	f.symlink("home/dev/.pyenv/versions/3.12.1/bin/python", "python3.12")
	f.file("home/dev/.pyenv/versions/3.12.1/include/python3.12/patchlevel.h", `#define PY_VERSION              "3.12.1"`, false)
	// python3.12-config is not an interpreter.
	f.file("home/dev/.pyenv/versions/3.12.1/bin/python3.12-config", "", true)
	// A virtualenv is skipped.
	f.file("home/dev/proj/.venv/pyvenv.cfg", "home = /usr/bin", false)
	f.file("home/dev/proj/.venv/bin/python3", "", true)
	// node_modules is skipped.
	f.file("home/dev/proj/node_modules/node/bin/node", "", true)
	// Non-executable file is ignored.
	f.file("home/dev/notes/node", "", false)
	// JDK with release file; JDK 8 style jre/bin/java is not double counted.
	f.file("opt/jdk-21.0.2/bin/java", "", true)
	f.file("opt/jdk-21.0.2/release", "JAVA_VERSION=\"21.0.2\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n", false)
	f.file("opt/jdk-21.0.2/jre/bin/java", "", true)
	// Go with VERSION.
	f.file("usr/local/go/bin/go", "", true)
	f.file("usr/local/go/VERSION", "go1.22.1\ntime 2024-02-29T18:18:00Z\n", false)
	// Ruby via rbenv with rbconfig.
	f.file("home/dev/.rbenv/versions/3.3.0/bin/ruby", "", true)
	f.file("home/dev/.rbenv/versions/3.3.0/lib/ruby/3.3.0/arm64-darwin23/rbconfig.rb", `  CONFIG["RUBY_PROGRAM_VERSION"] = "3.3.0"`, false)
	// PHP with headers.
	f.file("opt/php/bin/php", "", true)
	f.file("opt/php/include/php/main/php_version.h", `#define PHP_VERSION "8.3.1"`, false)
	// dotnet with two side-by-side runtimes.
	f.file("home/dev/.dotnet/dotnet", "", true)
	f.file("home/dev/.dotnet/shared/Microsoft.NETCore.App/8.0.4/x", "", false)
	f.file("home/dev/.dotnet/shared/Microsoft.NETCore.App/6.0.29/x", "", false)
	// Bundled node inside an app bundle.
	f.file("Applications/Foo.app/Contents/Resources/node", "", true)
	// bun with no version source.
	f.file("home/dev/.bun/bin/bun", "", true)

	out := f.scan("linux", home,
		walkRoot{home, 6, nil, 0},
		walkRoot{f.path("usr/local"), 5, nil, 0},
		walkRoot{f.path("opt"), 4, nil, 0},
		walkRoot{f.path("Applications"), 5, nil, 0},
	)

	nodes := byRuntime(out, "node")
	want := map[string]struct{ version, vsrc, source, scope, bundled string }{
		f.path("home/dev/.nvm/versions/node/v18.20.4/bin/node"): {"18.20.4", "file", "nvm", "user", ""},
		f.path("home/dev/.nvm/versions/node/v20.11.1/bin/node"): {"20.11.1", "path", "nvm", "user", ""},
		cellarNode: {"22.1.0", "path", "brew", "machine", ""},
		f.path("Applications/Foo.app/Contents/Resources/node"): {"unknown", "unknown", "bundled", "machine", "Foo"},
	}
	if len(nodes) != len(want) {
		t.Fatalf("node records = %d, want %d: %+v", len(nodes), len(want), nodes)
	}
	for _, n := range nodes {
		w, ok := want[n.ExecutablePath]
		if !ok {
			t.Errorf("unexpected node %s", n.ExecutablePath)
			continue
		}
		if n.Version != w.version || n.VersionSource != w.vsrc || n.Source != w.source || n.Scope != w.scope || n.BundledBy != w.bundled {
			t.Errorf("%s = %+v, want %+v", n.ExecutablePath, n, w)
		}
	}

	py := byRuntime(out, "python")
	if len(py) != 1 || py[0].Version != "3.12.1" || py[0].Source != "pyenv" {
		t.Errorf("python = %+v", py)
	}
	java := byRuntime(out, "java")
	if len(java) != 1 || java[0].Version != "21.0.2" || java[0].Vendor != "Eclipse Adoptium" {
		t.Errorf("java = %+v", java)
	}
	if g := byRuntime(out, "go"); len(g) != 1 || g[0].Version != "1.22.1" {
		t.Errorf("go = %+v", g)
	}
	if r := byRuntime(out, "ruby"); len(r) != 1 || r[0].Version != "3.3.0" || r[0].Source != "rbenv" {
		t.Errorf("ruby = %+v", r)
	}
	if p := byRuntime(out, "php"); len(p) != 1 || p[0].Version != "8.3.1" {
		t.Errorf("php = %+v", p)
	}
	if d := byRuntime(out, "dotnet"); len(d) != 2 || d[0].Version != "6.0.29" || d[1].Version != "8.0.4" {
		t.Errorf("dotnet = %+v", d)
	}
	if b := byRuntime(out, "bun"); len(b) != 1 || b[0].Version != "unknown" || b[0].Source != "manual" {
		t.Errorf("bun = %+v", b)
	}
}

func TestScanWindowsLayouts(t *testing.T) {
	f := newFixture(t)
	home := f.path("Users/dev")
	orig := peVersion
	t.Cleanup(func() { peVersion = orig })
	peVersion = func(p string) string {
		if filepath.Base(filepath.Dir(p)) == "xampp-php" {
			return ""
		}
		switch filepath.Base(p) {
		case "node.exe":
			return "18.20.4.0"
		case "php.exe":
			return "8.2.12"
		}
		return ""
	}

	f.file("Users/dev/AppData/Roaming/nvm/v18.20.4/node.exe", "", false)
	f.file("Users/dev/AppData/Roaming/nvm/v16.0.0/notes.txt", "", false)
	f.file("Users/dev/scoop/apps/php/8.2.12/php.exe", "", false)
	f.file("Users/dev/scoop/apps/php/8.2.12/php-cgi.exe", "", false)
	f.file("Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Microsoft/VisualStudio/NodeJs/node.exe", "", false)
	// php.exe without a PE version under a versioned dir -> path version.
	f.file("wamp64/bin/php/php7.4.33/xampp-php/php.exe", "", false)
	// A non-.exe named node is ignored on Windows.
	f.file("Users/dev/tools/node", "", true)

	out := f.scan("windows", home,
		walkRoot{f.path("Users/dev/AppData/Roaming/nvm"), 2, nil, 0},
		walkRoot{home, 5, []string{"appdata"}, 0},
		walkRoot{f.path("Program Files"), 9, nil, 0},
		walkRoot{f.path("wamp64"), 5, nil, 0},
	)

	nodes := byRuntime(out, "node")
	if len(nodes) != 2 {
		t.Fatalf("nodes = %+v", nodes)
	}
	for _, n := range nodes {
		switch {
		case n.BundledBy == "Visual Studio":
			if n.Source != "bundled" || n.Scope != "machine" {
				t.Errorf("vs node = %+v", n)
			}
		case n.Source == "nvm":
			if n.Version != "18.20.4" || n.VersionSource != "pe" || n.Scope != "user" {
				t.Errorf("nvm node = %+v", n)
			}
		default:
			t.Errorf("unexpected node %+v", n)
		}
	}
	php := byRuntime(out, "php")
	if len(php) != 2 {
		t.Fatalf("php = %+v", php)
	}
	for _, p := range php {
		switch p.Source {
		case "scoop":
			if p.Version != "8.2.12" || p.VersionSource != "pe" {
				t.Errorf("scoop php = %+v", p)
			}
		case "wamp":
			if p.Version != "7.4.33" || p.VersionSource != "path" {
				t.Errorf("wamp php = %+v", p)
			}
		default:
			t.Errorf("unexpected php %+v", p)
		}
	}
}

func TestScanDepthCapAndRevisit(t *testing.T) {
	f := newFixture(t)
	f.file("a/b/c/d/bin/node", "", true)
	if out := f.scan("linux", "", walkRoot{f.path("a"), 3, nil, 0}); len(out) != 0 {
		t.Fatalf("depth 3 should not reach a/b/c/d/bin: %+v", out)
	}
	// A shallow root first must not prevent a deeper root from reaching it.
	out := f.scan("linux", "", walkRoot{f.path("a"), 1, nil, 0}, walkRoot{f.path("a"), 4, nil, 0})
	if len(out) != 1 {
		t.Fatalf("deeper revisit missed node: %+v", out)
	}
}

func TestScanCancelledIsTruncated(t *testing.T) {
	f := newFixture(t)
	f.file("x/bin/node", "", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &Scanner{exec: executor.NewReal(), goos: "linux", rootsOverride: []walkRoot{{f.root, 3, nil, 0}}}
	_, truncated, roots := s.Scan(ctx)
	if !truncated || roots != nil {
		t.Fatalf("cancelled scan: truncated=%v roots=%v, want true and nil (whole scan partial)", truncated, roots)
	}
}

// A large deep subtree that exhausts the budget must not hide a shallow
// install in a later-sorting sibling (the walk is breadth-first).
func TestScanBudgetPrefersShallow(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 50; i++ {
		f.file(fmt.Sprintf("a/b/c/f%02d", i), "", false)
	}
	f.file("z/node", "", true)
	s := &Scanner{exec: executor.NewReal(), goos: "linux", rootsOverride: []walkRoot{{f.root, 5, nil, 20}}}
	out, truncated, roots := s.Scan(context.Background())
	if !truncated || len(roots) != 1 || roots[0] != f.root {
		t.Fatalf("budget truncation: truncated=%v roots=%v, want [%s]", truncated, roots, f.root)
	}
	if len(out) != 1 || out[0].ExecutablePath != f.path("z/node") {
		t.Fatalf("shallow node missed: %+v", out)
	}
}

// Only the root that exhausted its own budget is reported; a later root that
// completes is not, so the backend can replace installs outside it.
func TestScanTruncatedRootsListsOnlyExhaustedRoot(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 30; i++ {
		f.file(fmt.Sprintf("big/d/f%02d", i), "", false)
	}
	f.file("small/bin/node", "", true)
	s := &Scanner{exec: executor.NewReal(), goos: "linux", rootsOverride: []walkRoot{
		{f.path("big"), 3, nil, 10},
		{f.path("small"), 3, nil, 0},
	}}
	out, truncated, roots := s.Scan(context.Background())
	if !truncated || len(roots) != 1 || roots[0] != f.path("big") {
		t.Fatalf("truncated=%v roots=%v, want only %s", truncated, roots, f.path("big"))
	}
	if len(out) != 1 {
		t.Fatalf("node under the complete root missed: %+v", out)
	}
}
