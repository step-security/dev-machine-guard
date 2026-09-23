package detector

import (
	"github.com/step-security/dev-machine-guard/internal/executor"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/tcc"
)

func writeFile(t *testing.T, root, rel string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(p)
}

func gotPathSet(specs []mcpConfigSpec) map[string]bool {
	m := make(map[string]bool, len(specs))
	for _, s := range specs {
		m[s.ConfigPath] = true
	}
	return m
}

// TestDiscoverWalkedMCPConfigs: recognizes mcp.json / .mcp.json anywhere in a
// walked tree, skips dependency/build dirs, and ignores non-config files.
func TestDiscoverWalkedMCPConfigs(t *testing.T) {
	root := t.TempDir()
	want1 := writeFile(t, root, "proj/.vscode/mcp.json")
	want2 := writeFile(t, root, "proj/agent-plugins/foo/.mcp.json")
	writeFile(t, root, "proj/node_modules/pkg/mcp.json") // excluded dir
	writeFile(t, root, "proj/dist/mcp.json")             // excluded dir
	writeFile(t, root, "proj/readme.txt")                // not a config

	d := NewMCPDetector(executor.NewReal()) // no skipper
	got := gotPathSet(d.discoverWalkedMCPConfigs([]string{root}, ""))

	if !got[want1] {
		t.Errorf("did not find %s", want1)
	}
	if !got[want2] {
		t.Errorf("did not find %s", want2)
	}
	for p := range got {
		if strings.Contains(p, "node_modules") || strings.Contains(p, string(filepath.Separator)+"dist"+string(filepath.Separator)) {
			t.Errorf("should have skipped excluded dir: %s", p)
		}
	}
	if len(got) != 2 {
		t.Errorf("expected 2 configs, got %d: %v", len(got), got)
	}
}

// TestMCPVendorForPath: the VS Code heuristic matches its real config shape
// and dotfile roots, but does NOT mislabel arbitrary project roots like ~/code.
func TestMCPVendorForPath(t *testing.T) {
	sep := string(filepath.Separator)
	cases := map[string]string{
		filepath.Join(sep+"Users", "x", "Library", "Application Support", "Code", "User", "mcp.json"):     "Microsoft",
		filepath.Join(sep+"Users", "x", ".vscode", "agent-plugins", "a", ".mcp.json"):                     "Microsoft",
		filepath.Join(sep+"Users", "x", "code", "myproj", ".mcp.json"):                                    "Discovered", // NOT Microsoft
		filepath.Join(sep+"Users", "x", ".cursor", "mcp.json"):                                            "Cursor",
		filepath.Join(sep+"Users", "x", "Library", "Application Support", "VSCodium", "User", "mcp.json"): "VSCodium",
	}
	for p, want := range cases {
		if got := mcpVendorForPath(p); got != want {
			t.Errorf("mcpVendorForPath(%q) = %q, want %q", p, got, want)
		}
	}
}

// TestMCPVendorForPath_OpenCode: the OpenCode case matches the basename, so it
// claims exactly the two files this detector knows and nothing else. A path
// test would be wrong in both directions — it would relabel an ordinary
// .mcp.json sitting inside a checkout of the tool itself.
func TestMCPVendorForPath_OpenCode(t *testing.T) {
	sep := string(filepath.Separator)
	cases := map[string]string{
		filepath.Join(sep+"Users", "x", ".config", "opencode", "opencode.json"):  "OpenCode",
		filepath.Join(sep+"Users", "x", ".config", "opencode", "opencode.jsonc"): "OpenCode",
		filepath.Join(sep+"Users", "x", "proj", "opencode.json"):                 "OpenCode",
		// The labeller folds case, but note it is not what decides whether a file
		// is walked at all: discoverWalkedMCPConfigs gates on a case-sensitive
		// mcpConfigBasenames lookup, so a project file actually named
		// OpenCode.JSONC is never offered to this function in the first place.
		// That predates OpenCode and holds for every basename; folding here just
		// means the label is right whenever a path does arrive spelled oddly.
		filepath.Join(sep+"Users", "x", "proj", "OpenCode.JSONC"): "OpenCode",
		// Ordering is load-bearing: the substring cases match on any ancestor
		// directory, so each of these would be claimed by a case below if the
		// basename case did not come first.
		filepath.Join(sep+"Users", "x", "dev", "cursor-tools", "opencode.json"):  "OpenCode", // else Cursor
		filepath.Join(sep+"Users", "x", "dev", "claude-tools", "opencode.jsonc"): "OpenCode", // else Anthropic
		filepath.Join(sep+"Users", "x", ".vscode", "opencode.json"):              "OpenCode", // else Microsoft
		// An unrelated config that merely lives inside an opencode checkout.
		filepath.Join(sep+"Users", "x", "src", "opencode", "example", ".mcp.json"): "Discovered",
		// A file whose name only starts with the prefix.
		filepath.Join(sep+"Users", "x", "proj", "opencode.json.bak"): "Discovered",
	}
	for p, want := range cases {
		if got := mcpVendorForPath(p); got != want {
			t.Errorf("mcpVendorForPath(%q) = %q, want %q", p, got, want)
		}
	}
}

// TestDiscoverWalkedMCPConfigs_OpenCode: a project-level OpenCode config in
// either spelling is found by the ordinary basename walk — no project-root
// logic and no new walk root — and is reported as discovered_mcp / OpenCode.
func TestDiscoverWalkedMCPConfigs_OpenCode(t *testing.T) {
	root := t.TempDir()
	wantJSON := writeFile(t, root, "proj-a/opencode.json")
	wantJSONC := writeFile(t, root, "proj-b/nested/opencode.jsonc")
	writeFile(t, root, "proj-c/node_modules/pkg/opencode.json") // excluded dir
	writeFile(t, root, "proj-d/opencode.json.bak")              // not a config

	d := NewMCPDetector(executor.NewReal()) // no skipper
	specs := d.discoverWalkedMCPConfigs([]string{root}, "")
	got := gotPathSet(specs)

	if !got[wantJSON] {
		t.Errorf("did not find %s", wantJSON)
	}
	if !got[wantJSONC] {
		t.Errorf("did not find %s", wantJSONC)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 configs, got %d: %v", len(got), got)
	}
	for _, s := range specs {
		if s.SourceName != "discovered_mcp" {
			t.Errorf("%s: source = %q, want discovered_mcp", s.ConfigPath, s.SourceName)
		}
		if s.Vendor != "OpenCode" {
			t.Errorf("%s: vendor = %q, want OpenCode", s.ConfigPath, s.Vendor)
		}
	}
}

// TestDiscoverWalkedMCPConfigs_TCCSkip: a config inside a TCC-protected subtree
// (~/Library) is never walked, while one outside it is found. macOS-only,
// since the TCC skipper is a no-op on other platforms.
func TestDiscoverWalkedMCPConfigs_TCCSkip(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("TCC skipper only protects paths on darwin")
	}
	home := t.TempDir()
	protected := writeFile(t, home, "Library/Application Support/App/mcp.json")
	allowed := writeFile(t, home, "proj/.mcp.json")

	d := NewMCPDetector(executor.NewReal()).WithSkipper(tcc.New(home))
	got := gotPathSet(d.discoverWalkedMCPConfigs([]string{home}, ""))

	if got[protected] {
		t.Errorf("TCC-protected config should have been skipped: %s", protected)
	}
	if !got[allowed] {
		t.Errorf("non-protected config should have been found: %s", allowed)
	}
}
