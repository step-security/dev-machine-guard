// Package versionmeta resolves installed-tool versions from on-disk
// metadata — npm package manifests, version-encoded install layouts
// (<tool>/versions/<v>, Homebrew Cellar/Caskroom), and macOS app bundles —
// so detectors can avoid launching third-party binaries.
//
// Running `<tool> --version` is the detection path that popped macOS
// Gatekeeper "could not verify … free of malware" dialogs on customer
// machines: cursor-agent eagerly dlopens an un-notarized native addon
// (merkle-tree-napi.darwin-arm64.node) on any invocation. Metadata reads
// can't trigger that class of problem, so callers try FromBinary first and
// fall back to exec'ing the binary only when it returns "".
package versionmeta

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// FromBinary returns the version of the tool installed at binaryPath, derived
// purely from filesystem metadata, or "" when no trustworthy source exists.
// It never executes the target binary; the only subprocess it may spawn is
// Apple's own PlistBuddy (an OS utility) to read an app-bundle Info.plist.
//
// A "" result is not a failure — it means the caller should fall back to its
// existing version command. Sources are tried most- to least-authoritative:
//
//  1. npm package manifest: binary resolves into node_modules/<pkg>/, and the
//     manifest's package name matches the tool (rejects e.g. corepack's yarn
//     shim, whose manifest version would be corepack's, not yarn's).
//  2. <tool>/versions/<version>/ install layouts (cursor-agent, claude native
//     installer). The directory holding "versions" must match the tool name so
//     runtime-manager layouts (~/.pyenv/versions/3.12.1/bin/poetry) don't
//     misattribute the runtime's version to the tool.
//  3. Homebrew Cellar/Caskroom: physical containment in Cellar/<formula>/<v>/
//     means the formula owns the binary, so <v> is its version (npm-installed
//     binaries under a brew node live in node_modules and are claimed or
//     rejected by rule 1 before this can misfire).
//  4. macOS app bundle: CFBundleShortVersionString of the enclosing .app.
func FromBinary(ctx context.Context, exec executor.Executor, binaryPath string) string {
	if binaryPath == "" {
		return ""
	}
	base := toolBase(binaryPath)
	resolved, err := exec.EvalSymlinks(binaryPath)
	if err != nil || resolved == "" {
		resolved = binaryPath
	}

	if root := packageRoot(exec, resolved); root != "" {
		name, version := npmManifest(exec, root)
		if matchesTool(name, base) && IsVersionLike(version) {
			return version
		}
		// Inside a node_modules tree but the manifest doesn't claim this
		// tool: no path heuristic below can be trusted either (the path
		// encodes the runtime's version, not the tool's).
		return ""
	}
	if v := versionFromVersionsDir(resolved, base); v != "" {
		return v
	}
	if v := versionFromHomebrew(resolved); v != "" {
		return v
	}
	if exec.GOOS() == model.PlatformDarwin {
		if v := versionFromAppBundle(ctx, exec, resolved); v != "" {
			return v
		}
	}
	return ""
}

// NPMPackageName returns the full npm package name (e.g. "@github/copilot")
// that owns binaryPath, or "" when the binary doesn't resolve into an npm
// package. Lets detectors verify a tool's identity without executing it.
func NPMPackageName(exec executor.Executor, binaryPath string) string {
	resolved, err := exec.EvalSymlinks(binaryPath)
	if err != nil || resolved == "" {
		resolved = binaryPath
	}
	root := packageRoot(exec, resolved)
	if root == "" {
		return ""
	}
	name, _ := npmManifest(exec, root)
	return name
}

// packageRoot locates the npm package root for a resolved binary path via
// the node_modules tree (Unix symlink targets) or a Windows cmd-shim body.
func packageRoot(exec executor.Executor, resolved string) string {
	if root := NodeModulesPackageRoot(resolved); root != "" {
		return root
	}
	return NPMShimPackageRoot(exec, resolved)
}

// npmManifest reads name and version from the package.json at pkgRoot.
func npmManifest(exec executor.Executor, pkgRoot string) (name, version string) {
	sep := pathSeparator(pkgRoot)
	data, err := exec.ReadFile(pkgRoot + sep + "package.json")
	if err != nil {
		return "", ""
	}
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", ""
	}
	return manifest.Name, manifest.Version
}

// versionFromVersionsDir extracts <version> from <tool>/versions/<version>/…
// layouts. The segment before "versions" must match the tool name (see
// FromBinary rule 2).
func versionFromVersionsDir(resolved, base string) string {
	segments := splitPath(resolved)
	for i := 1; i < len(segments)-1; i++ {
		if segments[i] != "versions" {
			continue
		}
		if matchesTool(segments[i-1], base) && IsVersionLike(segments[i+1]) {
			return segments[i+1]
		}
	}
	return ""
}

// versionFromHomebrew extracts <version> from Cellar/<formula>/<version>/…
// or Caskroom/<token>/<version>/… paths, stripping Homebrew's _N revision
// suffix (3.12.8_1 → 3.12.8) so the result matches what the tool itself
// reports.
func versionFromHomebrew(resolved string) string {
	segments := splitPath(resolved)
	for i := 0; i < len(segments)-2; i++ {
		if segments[i] != "Cellar" && segments[i] != "Caskroom" {
			continue
		}
		v := stripHomebrewRevision(segments[i+2])
		if IsVersionLike(v) {
			return v
		}
	}
	return ""
}

// versionFromAppBundle reads CFBundleShortVersionString from the Info.plist
// of the .app bundle enclosing resolved. PlistBuddy is the established way to
// read (possibly binary) plists in this codebase; it is an Apple-signed OS
// utility, so executing it carries none of the third-party-binary risk this
// package exists to avoid.
func versionFromAppBundle(ctx context.Context, exec executor.Executor, resolved string) string {
	idx := strings.Index(resolved, ".app/")
	if idx < 0 {
		return ""
	}
	plist := resolved[:idx+4] + "/Contents/Info.plist"
	if !exec.FileExists(plist) {
		return ""
	}
	stdout, _, _, err := exec.RunWithTimeout(ctx, 10*time.Second, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", plist)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(stdout)
	if !IsVersionLike(v) {
		return ""
	}
	return v
}

// toolBase reduces a binary path to a comparable tool name: base name,
// Windows launcher extension stripped, lowercased.
func toolBase(binaryPath string) string {
	segments := splitPath(binaryPath)
	base := strings.ToLower(segments[len(segments)-1])
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		base = strings.TrimSuffix(base, ext)
	}
	return base
}

// matchesTool reports whether a package or directory name plausibly names the
// tool: exact match, or the tool name followed by a "-"/"@" boundary
// ("gemini" matches "gemini-cli"; "python3" does NOT match "python@3.12").
// Scoped npm names are compared by their final segment.
func matchesTool(name, base string) bool {
	if name == "" || base == "" {
		return false
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)
	return name == base || strings.HasPrefix(name, base+"-") || strings.HasPrefix(name, base+"@")
}

// IsVersionLike reports whether s looks like a version: optional "v", then a
// digit, at least one dot, and only [0-9A-Za-z.+_-] throughout. Rejects
// Caskroom "version,build" composites — callers fall back to exec for those.
func IsVersionLike(s string) bool {
	s = strings.TrimPrefix(s, "v")
	if s == "" || s[0] < '0' || s[0] > '9' || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r == '.', r == '-', r == '_', r == '+':
		default:
			return false
		}
	}
	return true
}

// stripHomebrewRevision drops a trailing _N bottle-revision suffix.
func stripHomebrewRevision(v string) string {
	i := strings.LastIndex(v, "_")
	if i <= 0 || i == len(v)-1 {
		return v
	}
	for _, r := range v[i+1:] {
		if r < '0' || r > '9' {
			return v
		}
	}
	return v[:i]
}

// splitPath splits a path on either separator style, dropping empty segments.
func splitPath(path string) []string {
	norm := strings.ReplaceAll(path, "\\", "/")
	parts := strings.Split(norm, "/")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NodeModulesPackageRoot walks up `path` looking for a `node_modules`
// directory; if found, returns the package root (one or two levels deeper
// depending on whether the package is scoped). Returns "" when the path
// isn't inside a node_modules tree.
//
// Separator-agnostic: handles both `/` and `\` paths regardless of the host
// OS. The returned path uses the same separator style as the input — Windows
// paths preserve backslashes, Unix paths preserve forward slashes.
//
// Examples:
//
//	/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe
//	  -> /usr/local/lib/node_modules/@anthropic-ai/claude-code
//	C:\Users\u\AppData\Roaming\npm\node_modules\@scope\name\cli.js
//	  -> C:\Users\u\AppData\Roaming\npm\node_modules\@scope\name
func NodeModulesPackageRoot(path string) string {
	sep := pathSeparator(path)
	norm := strings.ReplaceAll(path, "\\", "/")
	parts := strings.Split(norm, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "node_modules" {
			continue
		}
		if i+1 >= len(parts) {
			return ""
		}
		// Scoped package (`@scope/name`): take two segments past node_modules.
		if strings.HasPrefix(parts[i+1], "@") && i+2 < len(parts) {
			return strings.Join(parts[:i+3], sep)
		}
		return strings.Join(parts[:i+2], sep)
	}
	return ""
}

// NPMShimPackageRoot reads a Windows-style npm shim (`<bin>.cmd`,
// `<bin>.ps1`, `<bin>.bat`) and returns the install root of the package the
// shim invokes, by locating the first `node_modules\<...>` reference in the
// shim body. Returns "" when path isn't a shim, can't be read, or contains
// no node_modules reference.
//
// npm's Windows shim, generated by cmd-shim, looks like:
//
//	"%_prog%" "%dp0%\node_modules\@anthropic-ai\claude-code\cli.js" %*
//
// We extract the node_modules path, resolve it relative to the shim's own
// directory (cmd-shim's `%dp0%`), and feed the absolute path through
// NodeModulesPackageRoot.
func NPMShimPackageRoot(exec executor.Executor, path string) string {
	lower := strings.ToLower(path)
	if !strings.HasSuffix(lower, ".cmd") && !strings.HasSuffix(lower, ".ps1") && !strings.HasSuffix(lower, ".bat") {
		return ""
	}
	data, err := exec.ReadFile(path)
	if err != nil {
		return ""
	}
	content := string(data)
	idx := strings.Index(content, "node_modules")
	if idx < 0 {
		return ""
	}
	rest := content[idx:]
	if end := strings.IndexAny(rest, "\"' \t\r\n"); end > 0 {
		rest = rest[:end]
	}
	// Resolve relative to the shim's own directory, separator-agnostic so
	// the test path-parser works the same on a Windows host and a Mac host.
	sep := pathSeparator(path)
	shimDir := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			shimDir = path[:i]
			break
		}
	}
	rest = strings.TrimLeft(rest, "/\\")
	return NodeModulesPackageRoot(shimDir + sep + rest)
}

// pathSeparator picks the separator style of an input path. If both styles
// are present (rare), `/` wins because it's portable.
func pathSeparator(path string) string {
	if strings.Contains(path, "\\") && !strings.Contains(path, "/") {
		return "\\"
	}
	return "/"
}
