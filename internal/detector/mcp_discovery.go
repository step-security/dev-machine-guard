package detector

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// mcpConfigBasenames are the filenames recognized as MCP configs wherever they
// appear in a walked tree. Recognizing by basename (rather than only at
// hard-coded exact paths) is what lets discovery adapt to configs we didn't
// anticipate — e.g. a VS Code agent-plugin's .mcp.json. Parity with the
// filenames bumblebee recognizes.
var mcpConfigBasenames = map[string]bool{
	"mcp.json":                   true,
	".mcp.json":                  true,
	"mcp_config.json":            true,
	"mcp_settings.json":          true,
	"cline_mcp_settings.json":    true,
	"claude_desktop_config.json": true,
}

// mcpWalkExcludeDirs are directory names never descended during the MCP walk:
// dependency/cache/build trees that never hold user MCP configs, plus
// "extensions" (VS Code extension packages are inventoried by the extension
// detector and would make this walk needlessly expensive).
var mcpWalkExcludeDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".hg":          true,
	".svn":         true,
	".cache":       true,
	"__pycache__":  true,
	".tox":         true,
	".venv":        true,
	"venv":         true,
	"dist":         true,
	"build":        true,
	".next":        true,
	"target":       true,
	"extensions":   true,
}

// maxMCPWalkFiles caps files examined across the whole MCP walk — a cost
// backstop for pathological trees. MCP configs are shallow and few.
const maxMCPWalkFiles = 200000

// mcpDotfileRoots are per-user IDE state directories that live OUTSIDE
// ~/Library (so they are safe to walk under the TCC skipper) and can hold
// scattered mcp.json / .mcp.json files (plugins, per-workspace state, etc.).
func mcpDotfileRoots(homeDir string) []string {
	if homeDir == "" {
		return nil
	}
	return []string{
		filepath.Join(homeDir, ".vscode"),
		filepath.Join(homeDir, ".vscode-insiders"),
		filepath.Join(homeDir, ".vscode-server"),
		filepath.Join(homeDir, ".cursor"),
		filepath.Join(homeDir, ".windsurf"),
		filepath.Join(homeDir, ".vscodium"),
	}
}

// allConfigLocations gathers every MCP config location on the host, from three
// sources, deduplicated by resolved path:
//  1. known exact paths (mcpConfigDefinitions) — targeted reads, incl. paths
//     under ~/Library which the walk deliberately never enters;
//  2. project .mcp.json files registered in ~/.claude.json;
//  3. the bounded basename-recognizing walk (search dirs + IDE dotfile roots).
func (d *MCPDetector) allConfigLocations(homeDir string, searchDirs []string) []mcpConfigSpec {
	seen := make(map[string]bool)
	var out []mcpConfigSpec
	add := func(source, path, vendor string) {
		c := filepath.Clean(path)
		if c == "" || c == "." || seen[c] {
			return
		}
		seen[c] = true
		out = append(out, mcpConfigSpec{SourceName: source, ConfigPath: c, Vendor: vendor})
	}

	// (1) Known exact paths (includes ~/Library configs via targeted reads).
	for _, spec := range mcpConfigDefinitions {
		p := d.resolveConfigPath(spec, homeDir)
		if d.exec.FileExists(p) {
			add(spec.SourceName, p, spec.Vendor)
		}
	}
	// (2) Claude-registered project .mcp.json files.
	for _, s := range d.discoverProjectMCPConfigs(homeDir) {
		add(s.SourceName, s.ConfigPath, s.Vendor)
	}
	// (3) Bounded walk of search dirs + IDE dotfile roots.
	for _, s := range d.discoverWalkedMCPConfigs(searchDirs, homeDir) {
		add(s.SourceName, s.ConfigPath, s.Vendor)
	}
	return out
}

// discoverWalkedMCPConfigs walks the configured search dirs and the per-user
// IDE dotfile roots, recognizing MCP configs by basename. It never enters
// ~/Library (TCC skipper), skips dependency/cache/build dirs and directory
// symlinks, and is bounded by maxMCPWalkFiles.
func (d *MCPDetector) discoverWalkedMCPConfigs(searchDirs []string, homeDir string) []mcpConfigSpec {
	roots := make([]string, 0, len(searchDirs)+6)
	roots = append(roots, searchDirs...)
	roots = append(roots, mcpDotfileRoots(homeDir)...)

	var specs []mcpConfigSpec
	seen := make(map[string]bool)
	filesVisited := 0

	for _, root := range roots {
		if root == "" || filesVisited > maxMCPWalkFiles {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, ent fs.DirEntry, err error) error {
			if err != nil {
				// Unreadable dir: skip its subtree, continue elsewhere.
				if ent != nil && ent.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if ent.IsDir() {
				// TCC-protected subtree (Library, Documents, ...): never walk.
				if d.skipper != nil && d.skipper.ShouldSkip(path, root) {
					return fs.SkipDir
				}
				if mcpWalkExcludeDirs[ent.Name()] {
					return fs.SkipDir
				}
				// Do not follow directory symlinks (loop / cross-tree guard).
				if info, lerr := os.Lstat(path); lerr == nil && info.Mode()&os.ModeSymlink != 0 {
					return fs.SkipDir
				}
				return nil
			}
			filesVisited++
			if filesVisited > maxMCPWalkFiles {
				return fs.SkipAll
			}
			if mcpConfigBasenames[ent.Name()] {
				c := filepath.Clean(path)
				if !seen[c] {
					seen[c] = true
					specs = append(specs, mcpConfigSpec{
						SourceName: "discovered_mcp",
						ConfigPath: c,
						Vendor:     mcpVendorForPath(c),
					})
				}
			}
			return nil
		})
	}
	return specs
}

// mcpVendorForPath makes a best-effort vendor guess from a discovered config's
// path. Falls back to "Discovered" when nothing recognizable matches.
func mcpVendorForPath(p string) string {
	lp := strings.ToLower(p)
	switch {
	case strings.Contains(lp, "cursor"):
		return "Cursor"
	case strings.Contains(lp, "windsurf"), strings.Contains(lp, "codeium"):
		return "Codeium"
	case strings.Contains(lp, "vscodium"):
		return "VSCodium"
	case strings.Contains(lp, "claude"):
		return "Anthropic"
	case strings.Contains(lp, string(filepath.Separator)+".vscode"),
		strings.Contains(lp, string(filepath.Separator)+"code"+string(filepath.Separator)):
		return "Microsoft"
	default:
		return "Discovered"
	}
}
