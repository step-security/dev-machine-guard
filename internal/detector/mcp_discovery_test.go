package detector

import (
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

	d := &MCPDetector{} // no skipper
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

	d := &MCPDetector{skipper: tcc.New(home)}
	got := gotPathSet(d.discoverWalkedMCPConfigs([]string{home}, ""))

	if got[protected] {
		t.Errorf("TCC-protected config should have been skipped: %s", protected)
	}
	if !got[allowed] {
		t.Errorf("non-protected config should have been found: %s", allowed)
	}
}
