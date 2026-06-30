package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// newDistDetector builds a detector backed by the real executor; the parser
// tests feed bytes directly, and the integration tests use real temp dirs.
func newDistDetector() *NodeDistDetector { return NewNodeDistDetector(executor.NewReal()) }

// pkgSet collapses a result to name@version[+direct] strings for order-free
// assertions.
func pkgSet(pkgs []model.NodePackage) map[string]bool {
	out := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		s := p.Name + "@" + p.Version
		if p.IsDirect {
			s += "+direct"
		}
		out[s] = true
	}
	return out
}

func assertPkgs(t *testing.T, got []model.NodePackage, want ...string) {
	t.Helper()
	set := pkgSet(got)
	if len(set) != len(want) {
		t.Fatalf("got %d packages %v, want %d %v", len(set), got, len(want), want)
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("missing %q in %v", w, got)
		}
	}
}

func TestParsePackageLock_V3(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21"},
	    "node_modules/@scope/util": {"version": "2.0.0"},
	    "node_modules/lodash/node_modules/nested-dep": {"version": "1.5.0"},
	    "node_modules/linkpkg": {"link": true},
	    "packages/ui": {"version": "0.0.0"}
	  }
	}`)
	direct := map[string]struct{}{"lodash": {}, "@scope/util": {}}
	got := newDistDetector().parsePackageLock(data, direct)
	// root/link/workspace skipped; nested-dep is hoisted to top-level but is
	// not a declared dep, so it is transitive.
	assertPkgs(t, got, "lodash@4.17.21+direct", "@scope/util@2.0.0+direct", "nested-dep@1.5.0")
}

func TestParsePackageLock_V1(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "lodash": {"version": "4.17.21"},
	    "chalk": {"version": "5.0.0", "dependencies": {"ansi": {"version": "6.0.0"}}}
	  }
	}`)
	direct := map[string]struct{}{"lodash": {}, "chalk": {}}
	got := newDistDetector().parsePackageLock(data, direct)
	assertPkgs(t, got, "lodash@4.17.21+direct", "chalk@5.0.0+direct", "ansi@6.0.0")
}

func TestParsePnpmLock_V9(t *testing.T) {
	data := []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.21
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-x}
  '@scope/util@2.0.0':
    resolution: {integrity: sha512-y}
  is-odd@1.0.0(react@18.0.0):
    resolution: {integrity: sha512-z}
snapshots:
  lodash@4.17.21: {}
`)
	got := newDistDetector().parsePnpmLock(data, map[string]struct{}{"lodash": {}})
	// peer suffix stripped on is-odd; snapshots block ignored; only lodash direct.
	assertPkgs(t, got, "lodash@4.17.21+direct", "@scope/util@2.0.0", "is-odd@1.0.0")
}

func TestParsePnpmLock_V6AndV5Keys(t *testing.T) {
	v6 := []byte("packages:\n  /foo@1.2.3:\n    resolution: {}\n  /@scope/bar@2.0.0(peer@1.0.0):\n    resolution: {}\n")
	assertPkgs(t, newDistDetector().parsePnpmLock(v6, nil), "foo@1.2.3", "@scope/bar@2.0.0")

	v5 := []byte("packages:\n  /foo/1.2.3:\n    resolution: {}\n  /@scope/bar/2.0.0:\n    resolution: {}\n")
	assertPkgs(t, newDistDetector().parsePnpmLock(v5, nil), "foo@1.2.3", "@scope/bar@2.0.0")
}

func TestParseYarnLock_ClassicAndBerry(t *testing.T) {
	classic := []byte(`# yarn lockfile v1
lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.example/lodash"

"@scope/util@^2.0.0", "@scope/util@^2.1.0":
  version "2.1.0"
`)
	assertPkgs(t, newDistDetector().parseYarnLock(classic, map[string]struct{}{"lodash": {}}),
		"lodash@4.17.21+direct", "@scope/util@2.1.0")

	berry := []byte(`__metadata:
  version: 6
"lodash@npm:^4.17.0":
  version: 4.17.21
"root@workspace:.":
  version: 0.0.0-use.local
`)
	// __metadata and the local workspace marker are skipped.
	assertPkgs(t, newDistDetector().parseYarnLock(berry, nil), "lodash@4.17.21")
}

func TestParseBunLock(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 1,
	  // installed packages
	  "packages": {
	    "lodash": ["lodash@4.17.21", {}, "sha512-x"],
	    "@scope/util": ["@scope/util@2.0.0", {}],
	    "legacy": {"version": "1.0.0"},
	  },
	}`)
	got := newDistDetector().parseBunLock(data, map[string]struct{}{"lodash": {}})
	assertPkgs(t, got, "lodash@4.17.21+direct", "@scope/util@2.0.0", "legacy@1.0.0")
}

func TestStripJSONC(t *testing.T) {
	in := []byte("{\n  // line\n  \"a\": \"http://x\", /* keep // inside string */\n  \"b\": [1, 2,],\n}")
	var v struct {
		A string `json:"a"`
		B []int  `json:"b"`
	}
	if err := json.Unmarshal(stripJSONC(in), &v); err != nil {
		t.Fatalf("stripped JSONC did not parse: %v", err)
	}
	if v.A != "http://x" || len(v.B) != 2 {
		t.Fatalf("got %+v, want a=http://x b=[1 2]", v)
	}
}

func TestParsePnpmPackageKey(t *testing.T) {
	cases := map[string][2]string{
		"foo@1.2.3":                   {"foo", "1.2.3"},
		"@scope/foo@1.2.3":            {"@scope/foo", "1.2.3"},
		"/foo@1.2.3":                  {"foo", "1.2.3"},
		"/@scope/foo@1.2.3(react@18)": {"@scope/foo", "1.2.3"},
		"/foo/1.2.3":                  {"foo", "1.2.3"},
		"/@scope/foo/1.2.3":           {"@scope/foo", "1.2.3"},
		"foo@1.2.3_react@18.0.0":      {"foo", "1.2.3"},
	}
	for in, want := range cases {
		n, v := parsePnpmPackageKey(in)
		if n != want[0] || v != want[1] {
			t.Errorf("parsePnpmPackageKey(%q) = (%q,%q), want (%q,%q)", in, n, v, want[0], want[1])
		}
	}
}

func TestIsNodeModulesPackagePath(t *testing.T) {
	yes := []string{
		"/p/node_modules/foo/package.json",
		"/p/node_modules/@scope/foo/package.json",
		"/p/node_modules/a/node_modules/b/package.json",
		"/p/node_modules/.pnpm/foo@1/node_modules/foo/package.json",
	}
	no := []string{
		"/p/package.json",                      // not under node_modules
		"/p/node_modules/foo/src/package.json", // nested fixture, not a pkg root
		"/p/node_modules/@scope/package.json",  // scope dir, no pkg
	}
	for _, p := range yes {
		if !isNodeModulesPackagePath(p) {
			t.Errorf("expected %q to be a package root", p)
		}
	}
	for _, p := range no {
		if isNodeModulesPackagePath(p) {
			t.Errorf("expected %q NOT to be a package root", p)
		}
	}
}

// ScanProject dispatches to the lockfile parser and de-duplicates.
func TestScanProject_LockfileDispatch(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{"name":"root","dependencies":{"lodash":"^4"}}`)
	mustWrite(t, filepath.Join(dir, "package-lock.json"), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name":"root"},
	    "node_modules/lodash": {"version":"4.17.21"},
	    "node_modules/dep": {"version":"1.0.0"}
	  }
	}`)
	got := newDistDetector().ScanProject(dir, "npm")
	assertPkgs(t, got, "lodash@4.17.21+direct", "dep@1.0.0")
}

// With no parseable lockfile, ScanProject falls back to node_modules.
func TestScanProject_NodeModulesFallback(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{"name":"root","dependencies":{"lodash":"^4"}}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "package.json"), `{"name":"lodash","version":"4.17.21"}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "@scope", "util", "package.json"), `{"name":"@scope/util","version":"2.0.0"}`)
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "node_modules", "tdep", "package.json"), `{"name":"tdep","version":"1.0.0"}`)
	// A nested fixture package.json that is NOT an installed package root:
	mustWrite(t, filepath.Join(dir, "node_modules", "lodash", "src", "package.json"), `{"name":"evil","version":"9.9.9"}`)

	got := newDistDetector().ScanProject(dir, "npm")
	assertPkgs(t, got, "lodash@4.17.21+direct", "@scope/util@2.0.0", "tdep@1.0.0")
}

func TestDedupSortPackages(t *testing.T) {
	in := []model.NodePackage{
		{Name: "b", Version: "1.0.0"},
		{Name: "a", Version: "2.0.0", IsDirect: true},
		{Name: "a", Version: "2.0.0"}, // dup of the direct one
		{Name: "a", Version: "1.0.0"}, // distinct version
		{Name: "", Version: "1.0.0"},  // dropped (no name)
	}
	got := dedupSortPackages(in)
	if len(got) != 3 {
		t.Fatalf("got %d, want 3: %v", len(got), got)
	}
	// sorted: a@1.0.0, a@2.0.0, b@1.0.0
	if got[0].Name != "a" || got[0].Version != "1.0.0" {
		t.Errorf("got[0]=%+v", got[0])
	}
	if got[1].Version != "2.0.0" || !got[1].IsDirect { // direct wins on merge
		t.Errorf("got[1]=%+v, want a@2.0.0 direct", got[1])
	}
	if got[2].Name != "b" {
		t.Errorf("got[2]=%+v", got[2])
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
