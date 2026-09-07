package detector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// mcpPluginManifest describes one agent's plugin-package layout: the manifest
// directory that marks a package root, and how a config found there is
// reported.
type mcpPluginManifest struct {
	dir        string
	sourceName string
	vendor     string
}

var mcpPluginManifests = []mcpPluginManifest{
	{".claude-plugin", "claude_plugin", "Anthropic"},
	{".codex-plugin", "codex_plugin", "OpenAI"},
}

// pluginMCPBasename is the only MCP surface a plugin package declares. Any
// other MCP-shaped file inside a package is vendored from the plugin's own
// repo, not a config the host agent loads.
const pluginMCPBasename = ".mcp.json"

// maxPluginRootLookup bounds the upward search for a package root.
const maxPluginRootLookup = 8

// classifyWalkedMCPConfig decides what a walked hit is. Plugin marketplaces are
// clones of a catalog repo that ship one package — and one template .mcp.json —
// per catalog entry, none of which any agent loads (issue #201). So a
// plugin-scoped config counts only when it is the package's own .mcp.json and
// the package is installed.
func classifyWalkedMCPConfig(path, root string) (sourceName, vendor string, keep bool) {
	dir := filepath.Dir(path)
	pluginRoot, manifest, isPlugin := pluginPackageRoot(dir, root)
	if !isPlugin {
		return "discovered_mcp", mcpVendorForPath(path), true
	}
	if filepath.Base(path) != pluginMCPBasename || dir != pluginRoot {
		return "", "", false // vendored inside the plugin payload
	}
	if !isInstalledPluginPath(pluginRoot) {
		return "", "", false // marketplace catalog template
	}
	return manifest.sourceName, manifest.vendor, true
}

// pluginPackageRoot walks up from dir looking for a plugin manifest, stopping at
// the walk root.
func pluginPackageRoot(dir, root string) (string, mcpPluginManifest, bool) {
	cleanRoot := filepath.Clean(root)
	for i := 0; i < maxPluginRootLookup; i++ {
		for _, m := range mcpPluginManifests {
			if info, err := os.Stat(filepath.Join(dir, m.dir, "plugin.json")); err == nil && !info.IsDir() {
				return dir, m, true
			}
		}
		parent := filepath.Dir(dir)
		if dir == cleanRoot || parent == dir {
			break
		}
		dir = parent
	}
	return "", mcpPluginManifest{}, false
}

// isInstalledPluginPath reports whether a plugin package sits in an agent's
// installed-plugin tree (<agent dir>/plugins/cache/...). Both Claude Code and
// Codex install there and keep their catalog clones elsewhere
// (~/.claude/plugins/marketplaces, ~/.codex/.tmp/plugins), so the segment pair
// separates installed packages from catalog entries for either agent without a
// per-vendor path list.
func isInstalledPluginPath(pluginRoot string) bool {
	p := pluginRoot
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	sep := string(filepath.Separator)
	return strings.Contains(p, sep+"plugins"+sep+"cache"+sep)
}
