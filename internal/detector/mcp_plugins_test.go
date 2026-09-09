package detector

import (
	"path/filepath"
	"testing"
)

func gotSpecMap(specs []mcpConfigSpec) map[string]mcpConfigSpec {
	m := make(map[string]mcpConfigSpec, len(specs))
	for _, s := range specs {
		m[s.ConfigPath] = s
	}
	return m
}

// TestDiscoverWalkedMCPConfigs_PluginPackages: marketplace catalog templates and
// files vendored inside a plugin payload are dropped; an installed plugin's own
// .mcp.json and ordinary configs are kept (issue #201).
func TestDiscoverWalkedMCPConfigs_PluginPackages(t *testing.T) {
	root := t.TempDir()

	// Claude catalog clone: one package per catalog entry, none installed.
	writeFile(t, root, ".claude/plugins/marketplaces/official/external_plugins/terraform/.claude-plugin/plugin.json")
	catalogClaude := writeFile(t, root, ".claude/plugins/marketplaces/official/external_plugins/terraform/.mcp.json")

	// Codex catalog clone.
	writeFile(t, root, ".codex/.tmp/plugins/plugins/linear/.codex-plugin/plugin.json")
	catalogCodex := writeFile(t, root, ".codex/.tmp/plugins/plugins/linear/.mcp.json")

	// Installed Claude plugin: its own .mcp.json is active, the opencode.json
	// vendored from the plugin's repo is not.
	writeFile(t, root, ".claude/plugins/cache/official/ponytail/1.0.0/.claude-plugin/plugin.json")
	installed := writeFile(t, root, ".claude/plugins/cache/official/ponytail/1.0.0/.mcp.json")
	vendored := writeFile(t, root, ".claude/plugins/cache/official/ponytail/1.0.0/opencode.json")

	// Ordinary project config, no plugin manifest anywhere above it.
	project := writeFile(t, root, "proj/.mcp.json")

	d := &MCPDetector{}
	got := gotSpecMap(d.discoverWalkedMCPConfigs([]string{root}, ""))

	for _, p := range []string{catalogClaude, catalogCodex, vendored} {
		if _, ok := got[p]; ok {
			t.Errorf("should not have reported %s", p)
		}
	}
	if s, ok := got[installed]; !ok {
		t.Errorf("did not find installed plugin config %s", installed)
	} else if s.SourceName != "claude_plugin" || s.Vendor != "Anthropic" {
		t.Errorf("installed plugin: got source=%q vendor=%q", s.SourceName, s.Vendor)
	}
	if s, ok := got[project]; !ok {
		t.Errorf("did not find project config %s", project)
	} else if s.SourceName != "discovered_mcp" {
		t.Errorf("project config: got source=%q, want discovered_mcp", s.SourceName)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 configs, got %d: %v", len(got), got)
	}
}

// TestDiscoverWalkedMCPConfigs_CodexInstalledPlugin: Codex installs under
// plugins/cache too, so its plugin .mcp.json is reported as codex_plugin.
func TestDiscoverWalkedMCPConfigs_CodexInstalledPlugin(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".codex/plugins/cache/openai-curated-remote/github/.codex-plugin/plugin.json")
	installed := writeFile(t, root, ".codex/plugins/cache/openai-curated-remote/github/.mcp.json")

	d := &MCPDetector{}
	got := gotSpecMap(d.discoverWalkedMCPConfigs([]string{root}, ""))

	s, ok := got[installed]
	if !ok {
		t.Fatalf("did not find %s: %v", installed, got)
	}
	if s.SourceName != "codex_plugin" || s.Vendor != "OpenAI" {
		t.Errorf("got source=%q vendor=%q", s.SourceName, s.Vendor)
	}
}

// TestPluginPackageRoot_NestedAndBounded: a config nested inside a package
// resolves to the package root; the search stops at the walk root.
func TestPluginPackageRoot_NestedAndBounded(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pkg/.claude-plugin/plugin.json")
	nested := writeFile(t, root, "pkg/config/deep/mcp.json")

	pluginRoot, manifest, ok := pluginPackageRoot(filepath.Dir(nested), root)
	if !ok {
		t.Fatal("expected to find package root")
	}
	if want := filepath.Join(root, "pkg"); pluginRoot != want {
		t.Errorf("pluginRoot = %q, want %q", pluginRoot, want)
	}
	if manifest.sourceName != "claude_plugin" {
		t.Errorf("manifest = %q, want claude_plugin", manifest.sourceName)
	}

	if _, _, ok := pluginPackageRoot(filepath.Join(root, "other"), root); ok {
		t.Error("expected no package root outside a plugin package")
	}
}
