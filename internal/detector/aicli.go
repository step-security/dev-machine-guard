package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/execguard"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"github.com/step-security/dev-machine-guard/internal/versionmeta"
)

// cliResolution is what a ResolveFunc proves: the candidate it accepted, and
// the version carried by the manifest that proved it, when the accepting rule
// read one.
type cliResolution struct {
	// BinaryPath is the accepted candidate as found (what binary_path reports).
	BinaryPath string
	// StaticVersion is the version field of the manifest whose name the
	// accepting rule verified; "" when that rule read no manifest (path
	// anchors, winget identifiers, pacman ownership). Never filled from a
	// file the ladder did not prove.
	StaticVersion string
}

type cliToolSpec struct {
	Name        string
	Vendor      string
	Binaries    []string // binary names or paths (~ expanded at runtime)
	ConfigDirs  []string // config directory candidates (~ expanded)
	VersionFlag string   // flag to get version; defaults to "--version"
	VerifyFunc  func(ctx context.Context, exec executor.Executor, log *progress.Logger, binary string) bool

	// ResolveFunc, when set, owns candidate resolution for this spec: it walks
	// Binaries itself and returns the first candidate it can prove is this
	// tool, so a rejected candidate does not hide a valid later one — along
	// with the static version when the proving read carried one. skipper is
	// the scan's configured TCC skipper (nil when the customer opted
	// protected paths in); ladders route it through candidateGuard. Specs
	// that leave ResolveFunc nil resolve through findBinary exactly as before.
	//
	// It exists because binary names like `pi`, `droid` and `amp` all have
	// popular same-name collisions: findBinary returns the first candidate
	// that *exists* and a failing VerifyFunc skips to the next spec, so a
	// collider winning the PATH race hides a genuinely installed agent.
	ResolveFunc func(ctx context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool)

	// StaticVersionOnly suppresses the --version exec fallback in getVersion:
	// when no on-disk version source resolves, the tool reports "unknown"
	// rather than being launched. Specs that leave it false keep the existing
	// static-first, exec-last behavior.
	//
	// Set this only for a tool measured to make Gatekeeper refuse code it
	// loads at runtime, which a pre-flight execguard check cannot detect
	// because the code is extracted after launch. The value is per tool and
	// is not meant to be uniform across this table.
	StaticVersionOnly bool
}

var cliToolDefinitions = []cliToolSpec{
	{
		Name:       "claude-code",
		Vendor:     "Anthropic",
		Binaries:   []string{"claude", "~/.claude/local/claude", "~/.local/bin/claude"},
		ConfigDirs: []string{"~/.claude"},
	},
	{
		Name:       "codex",
		Vendor:     "OpenAI",
		Binaries:   []string{"codex"},
		ConfigDirs: []string{"~/.codex"},
	},
	{
		Name:       "gemini-cli",
		Vendor:     "Google",
		Binaries:   []string{"gemini"},
		ConfigDirs: []string{"~/.gemini"},
	},
	{
		Name:       "amazon-q-cli",
		Vendor:     "Amazon",
		Binaries:   []string{"kiro-cli", "kiro", "q"},
		ConfigDirs: []string{"~/.q", "~/.kiro", "~/.aws/q"},
		VerifyFunc: func(ctx context.Context, exec executor.Executor, log *progress.Logger, binary string) bool {
			if safe, reason := execguard.SafeToExec(ctx, exec, binary); !safe {
				log.Warn("skipping %s: %s — cannot verify identity", binary, reason)
				return false
			}
			log.Progress("exec fallback: running %s --version (amazon-q identity check)", binary)
			stdout, _, _, err := exec.RunWithTimeout(ctx, 10*time.Second, binary, "--version")
			if err != nil {
				return false
			}
			lower := strings.ToLower(stdout)
			return strings.Contains(lower, "amazon") || strings.Contains(lower, "kiro") || strings.Contains(lower, "q developer")
		},
	},
	{
		Name:   "github-copilot-cli",
		Vendor: "Microsoft",
		// `gh copilot` launches this same CLI, downloading it into gh's own data
		// directory when it isn't on PATH, so that install never lands on PATH.
		// Bare names stay first, so PATH hits keep resolving from the npm
		// manifest without exec'ing anything.
		Binaries: []string{
			"copilot", "gh-copilot",
			"~/.local/share/gh/copilot/copilot",
			"~/AppData/Local/GitHub CLI/copilot/copilot",
			"~/.local/bin/copilot",
			"~/AppData/Local/Microsoft/WinGet/Links/copilot.exe",
			"~/AppData/Roaming/npm/copilot.cmd",
			"~/.local/share/gh/extensions/gh-copilot/gh-copilot",
			"~/AppData/Local/GitHub CLI/extensions/gh-copilot/gh-copilot",
		},
		ConfigDirs: []string{"~/.config/github-copilot", "~/.copilot"},
		// Reject the VS Code Copilot Chat extension's shim, which lives on PATH
		// even when the real CLI isn't installed and replies to `--version` with
		// "GitHub Copilot CLI is not installed. Would you like to install it? (Y/n)".
		VerifyFunc: func(ctx context.Context, exec executor.Executor, log *progress.Logger, binary string) bool {
			// The real CLI is the @github/copilot npm package; confirming
			// identity from its manifest avoids exec'ing the binary at all.
			if versionmeta.NPMPackageName(exec, binary) == "@github/copilot" {
				return true
			}
			if safe, reason := execguard.SafeToExec(ctx, exec, binary); !safe {
				log.Warn("skipping %s: %s — cannot verify identity", binary, reason)
				return false
			}
			log.Progress("exec fallback: running %s --version (copilot identity check)", binary)
			stdout, _, exitCode, err := exec.RunWithTimeout(ctx, 10*time.Second, binary, "--version")
			if err != nil || exitCode != 0 {
				return false
			}
			lower := strings.ToLower(stdout)
			if strings.Contains(lower, "not installed") ||
				strings.Contains(lower, "would you like to install") {
				return false
			}
			return true
		},
	},
	{
		Name:       "microsoft-ai-shell",
		Vendor:     "Microsoft",
		Binaries:   []string{"aish", "ai"},
		ConfigDirs: []string{"~/.aish"},
	},
	{
		Name:       "aider",
		Vendor:     "OpenSource",
		Binaries:   []string{"aider"},
		ConfigDirs: []string{"~/.aider"},
	},
	{
		Name:        "opencode",
		Vendor:      "OpenSource",
		Binaries:    []string{"opencode", "~/.opencode/bin/opencode"},
		ConfigDirs:  []string{"~/.config/opencode"},
		VersionFlag: "-v",
	},
	{
		Name:       "cursor-agent",
		Vendor:     "Cursor",
		Binaries:   []string{"cursor-agent", "~/.local/bin/cursor-agent"},
		ConfigDirs: []string{"~/.cursor"},
	},
	{
		Name:   "pi",
		Vendor: "Earendil",
		// Bare name first (LookPath, full login-shell PATH), then the prefixes
		// an npm/bun global install can land in — see candidatePaths for the
		// rest of the prefix set. On Windows the Bun shim is a .exe (identity
		// via its .bunx pointer, rule 2b) and is NOT on PATH; the npm-prefix
		// entry must be the .cmd, never the extension-less sibling, which
		// exists as a #!/bin/sh shim and defeats NPMShimPackageRoot. The snap
		// entry is the payload inside the snap, not /snap/bin/pi — that one
		// resolves to the snapd wrapper and proves nothing.
		Binaries: []string{
			"pi", "~/.local/bin/pi", "~/.bun/bin/pi", "~/.bun/bin/pi.exe",
			"~/AppData/Roaming/npm/pi.cmd", "/snap/pi-coding-agent/current/bin/pi",
		},
		// The documented config root is ~/.pi/agent, not ~/.pi — which holds
		// only agent/. install_path already carries the install location.
		ConfigDirs:        []string{"~/.pi/agent"},
		ResolveFunc:       resolvePi,
		StaticVersionOnly: true,
	},
	{
		Name:        "factory",
		Vendor:      "Factory",
		Binaries:    []string{"droid", "~/.local/bin/droid", "~/bin/droid"},
		ConfigDirs:  []string{"~/.factory"},
		ResolveFunc: resolveFactory,
		// No StaticVersionOnly: droid is Developer-ID-signed and Gatekeeper
		// was measured allowing its exec without a prompt, so it keeps the
		// same static-first, exec-last behavior as every shipped spec. That
		// fallback is the curl channel's only version source.
	},
	{
		Name:   "amp",
		Vendor: "Sourcegraph",
		// Anchor FIRST: prefer the install root over an ambiguous PATH hit.
		// On a default install.sh machine both ~/.amp/bin/amp and the
		// ~/.local/bin/amp symlink exist and point at the same file; the
		// anchor is what binary_path must report.
		Binaries:          []string{"~/.amp/bin/amp", "amp"},
		ConfigDirs:        []string{"~/.config/amp"},
		ResolveFunc:       resolveAmp,
		StaticVersionOnly: true,
	},
}

// AICLIDetector detects AI CLI tools.
type AICLIDetector struct {
	exec    executor.Executor
	log     *progress.Logger
	skipper *tcc.Skipper
}

func NewAICLIDetector(exec executor.Executor) *AICLIDetector {
	return &AICLIDetector{exec: exec, log: progress.NewNoop()}
}

// WithLogger injects a logger (used to surface exec fallbacks when metadata
// version resolution misses). Chainable, mirrors configaudit's WithSkipper.
func (d *AICLIDetector) WithLogger(log *progress.Logger) *AICLIDetector {
	if log != nil {
		d.log = log
	}
	return d
}

// WithSkipper injects the scan's TCC skipper. Only the ResolveFunc ladders
// consult it: they resolve candidates the code did not spell (a PATH hit, a
// symlink target), which can land under a TCC-gated tree. nil — what the
// construction sites pass under --include-tcc-protected — means "allow
// everything", the same contract every walking detector honors.
func (d *AICLIDetector) WithSkipper(skipper *tcc.Skipper) *AICLIDetector {
	d.skipper = skipper
	return d
}

func (d *AICLIDetector) Detect(ctx context.Context) []model.AITool {
	homeDir := getHomeDir(d.exec)
	var results []model.AITool

	for _, spec := range cliToolDefinitions {
		var binaryPath, staticVersion string
		var found bool
		if spec.ResolveFunc != nil {
			var res cliResolution
			res, found = spec.ResolveFunc(ctx, d.exec, d.log, d.skipper, spec, homeDir)
			binaryPath, staticVersion = res.BinaryPath, res.StaticVersion
		} else {
			binaryPath, found = d.findBinary(ctx, spec, homeDir)
		}
		if !found {
			continue
		}

		// Verify if needed (e.g., amazon-q-cli)
		if spec.VerifyFunc != nil && !spec.VerifyFunc(ctx, d.exec, d.log, binaryPath) {
			continue
		}

		// A ladder that proved identity from a manifest already read that
		// manifest's version; getVersion only runs when it carried none.
		version := staticVersion
		if version == "" {
			version = d.getVersion(ctx, spec, binaryPath)
		}
		configDir := d.findConfigDir(spec, homeDir)
		installPath := resolveInstallPath(d.exec, binaryPath)

		results = append(results, model.AITool{
			Name:        spec.Name,
			Vendor:      spec.Vendor,
			Type:        "cli_tool",
			Version:     version,
			BinaryPath:  binaryPath,
			InstallPath: installPath,
			ConfigDir:   configDir,
		})
	}

	return results
}

// resolveInstallPath returns the on-disk install root for a CLI tool, given
// the binary path that was found via PATH or a home-relative lookup.
//
// Many AI CLIs (claude-code, codex, opencode) ship as npm packages whose
// binary is exposed as a tiny shim under /usr/local/bin/. The shim's symlink
// target lives inside `node_modules/<scope>/<package>/...` — that directory
// is what an investigator actually wants when they ask "where is claude
// installed?". When we detect that pattern, return the package root.
//
// If symlink resolution fails or the resolved path doesn't sit inside a
// node_modules tree, return the resolved real path (or the original path if
// resolution failed) so we still surface a meaningful install location
// instead of leaving the field empty.
func resolveInstallPath(exec executor.Executor, binaryPath string) string {
	if binaryPath == "" {
		return ""
	}
	resolved, err := exec.EvalSymlinks(binaryPath)
	if err != nil || resolved == "" {
		resolved = binaryPath
	}
	if pkgRoot := versionmeta.NodeModulesPackageRoot(resolved); pkgRoot != "" {
		return pkgRoot
	}
	// Windows: npm publishes a `.cmd` (and `.ps1`) shim instead of a symlink,
	// so the resolved path points at the shim itself, not the package. Parse
	// the shim to recover the node_modules package root.
	if pkgRoot := versionmeta.NPMShimPackageRoot(exec, resolved); pkgRoot != "" {
		return pkgRoot
	}
	return resolved
}

func (d *AICLIDetector) findBinary(ctx context.Context, spec cliToolSpec, homeDir string) (string, bool) {
	for _, bin := range spec.Binaries {
		expanded := expandTilde(bin, homeDir)
		if expanded != bin {
			// Path was expanded from tilde — it's a home-relative path, check if it exists
			if d.exec.FileExists(expanded) {
				return expanded, true
			}
			// On Windows, also try with .exe suffix
			if d.exec.GOOS() == model.PlatformWindows && !strings.HasSuffix(expanded, ".exe") {
				if d.exec.FileExists(expanded + ".exe") {
					return expanded + ".exe", true
				}
			}
			continue
		}
		// Search in PATH
		if path, err := d.exec.LookPath(expanded); err == nil {
			return path, true
		}
	}
	return "", false
}

func (d *AICLIDetector) getVersion(ctx context.Context, spec cliToolSpec, binaryPath string) string {
	// Static-first, exec-last (AGENTS.md §3.4): launching a third-party CLI
	// just for --version can pop a Gatekeeper "unverified software" dialog
	// when the tool ships unsigned native code (cursor-agent's merkle-tree
	// addon did exactly that on customer machines).
	if v := versionmeta.FromBinary(ctx, d.exec, binaryPath); v != "" {
		return v
	}
	if spec.StaticVersionOnly {
		// Disk-only spec: no static source resolved, and this tool is never
		// launched to ask. The path names the channel ("~/.amp/bin/amp" is the
		// installer, "/usr/bin/amp" is pacman), which is what a customer
		// asking "why is this version unknown" needs from --verbose.
		d.log.Debug("%s: no on-disk version source for %s; reporting version unknown (never launched)", spec.Name, binaryPath)
		return "unknown"
	}
	flag := "--version"
	if spec.VersionFlag != "" {
		flag = spec.VersionFlag
	}
	if safe, reason := execguard.SafeToExec(ctx, d.exec, binaryPath); !safe {
		d.log.Warn("skipping %s version probe: %s", binaryPath, reason)
		return "unknown"
	}
	d.log.Progress("exec fallback: running %s %s (no metadata version source)", binaryPath, flag)
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, binaryPath, flag)
	if err != nil {
		return "unknown"
	}
	return extractVersionFromOutput(stdout)
}

// extractVersionFromOutput finds the first line of `--version` output that
// contains a version-shaped token, then returns that token.
//
// Tools that talk to a daemon (ollama, lm-studio CLI) prepend warnings to
// their version output when the daemon isn't running, so we can't rely on the
// first line. Walking line-by-line and skipping lines without a version token
// keeps real version output ("codex-cli 0.118.0", "aider 0.86.2") working
// while making the detector robust against decorated output.
func extractVersionFromOutput(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if v := cleanVersionString(line); v != "unknown" {
			return v
		}
	}
	return "unknown"
}

// cleanVersionString strips a leading tool name prefix from version output.
// It finds the first token that looks like a version number (starts with a digit
// or "v" followed by a digit) and returns it, preserving any "v" prefix.
// e.g. "codex-cli 0.118.0" -> "0.118.0", "aider 0.86.2" -> "0.86.2", "v1.2.3" -> "v1.2.3"
func cleanVersionString(v string) string {
	parts := strings.Fields(v)
	for _, p := range parts {
		trimmed := strings.TrimLeft(p, "v")
		if len(trimmed) > 0 && trimmed[0] >= '0' && trimmed[0] <= '9' {
			return p
		}
	}
	return "unknown"
}

func (d *AICLIDetector) findConfigDir(spec cliToolSpec, homeDir string) string {
	for _, dir := range spec.ConfigDirs {
		expanded := expandTilde(dir, homeDir)
		if d.exec.DirExists(expanded) {
			return expanded
		}
	}
	return ""
}

func expandTilde(path, homeDir string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(homeDir, filepath.FromSlash(path[2:]))
	}
	return path
}

func getHomeDir(exec executor.Executor) string {
	if u, err := exec.LoggedInUser(); err == nil {
		return u.HomeDir
	}
	// No console user (issue #63) — fall back to the current user's home
	// before giving up to TempDir, otherwise file-path expansion in this
	// detector would lose any chance of hitting the right files.
	if u, err := exec.CurrentUser(); err == nil {
		return u.HomeDir
	}
	return os.TempDir()
}

// resolveEnvPath replaces %ENVVAR% patterns in Windows-style paths using the executor.
func resolveEnvPath(exec executor.Executor, path string) string {
	for strings.Contains(path, "%") {
		start := strings.Index(path, "%")
		end := strings.Index(path[start+1:], "%")
		if end < 0 {
			break
		}
		envName := path[start+1 : start+1+end]
		envVal := exec.Getenv(envName)
		path = path[:start] + envVal + path[start+2+end:]
	}
	return filepath.FromSlash(path)
}

// ---------------------------------------------------------------------------
// Shared helpers for the ResolveFunc ladders (pi, factory, amp).
//
// Every path manipulation below is separator-agnostic, and that is a
// correctness requirement rather than tidiness: these ladders run against a
// mocked exec.GOOS(), so backslash-shaped Windows fixtures are parsed on a
// darwin/linux CI host — where host filepath.Dir("C:\\Users\\u\\.bun\\bin\\pi.exe")
// is ".", and every sibling/join would silently collapse. versionmeta solves
// the same problem with its own private splitPath/pathSeparator; these are the
// local equivalents (§2.1 forbids widening versionmeta for this ticket).
// ---------------------------------------------------------------------------

// pathSep picks the separator style of path. Mirrors versionmeta's private
// pathSeparator: "/" wins when both styles appear, because it is portable.
func pathSep(path string) string {
	if strings.Contains(path, "\\") && !strings.Contains(path, "/") {
		return "\\"
	}
	return "/"
}

// pathDir returns everything before the last separator of either style, or ""
// when the path has none.
func pathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			if i == 0 {
				return path[:1] // the root itself
			}
			return path[:i]
		}
	}
	return ""
}

// pathBase returns the final segment of path, separator-agnostically.
func pathBase(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

// splitPathAny splits on either separator style, dropping empty segments — the
// local twin of versionmeta's unexported splitPath.
func splitPathAny(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
}

// joinPath appends parts to base using base's own separator style, so a
// Windows-shaped path stays Windows-shaped on a Unix host.
func joinPath(base string, parts ...string) string {
	sep := pathSep(base)
	var b strings.Builder
	b.WriteString(strings.TrimRight(base, "/\\"))
	for _, p := range parts {
		p = strings.Trim(p, "/\\")
		if p == "" {
			continue
		}
		b.WriteString(sep)
		b.WriteString(p)
	}
	return b.String()
}

// isDriveLetter reports whether c is an ASCII letter usable as a Windows drive.
func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isDrivePath reports whether p is a rooted local Windows drive path
// (`C:\...` or `C:/...`).
func isDrivePath(p string) bool {
	return len(p) >= 3 && isDriveLetter(p[0]) && p[1] == ':' && (p[2] == '/' || p[2] == '\\')
}

// isAbsPath reports whether p is absolute in either platform's spelling.
// filepath.IsAbs is host-keyed and answers false for every Windows-shaped
// fixture on a Unix CI host, which is exactly the case candidatePaths has to
// dispatch on correctly.
func isAbsPath(p string) bool {
	if p == "" {
		return false
	}
	if p[0] == '/' || p[0] == '\\' {
		return true
	}
	return isDrivePath(p)
}

// cleanPath is filepath.Clean without the host-OS separator assumption: it
// resolves "." and ".." segments and collapses repeats, preserving a leading
// root or drive prefix and re-joining with the input's own separator style.
func cleanPath(path string) string {
	if path == "" {
		return ""
	}
	sep := pathSep(path)
	norm := strings.ReplaceAll(path, "\\", "/")

	var prefix string
	switch {
	case len(norm) >= 2 && isDriveLetter(norm[0]) && norm[1] == ':':
		prefix = norm[:2]
		norm = norm[2:]
		if strings.HasPrefix(norm, "/") {
			prefix += sep
			norm = norm[1:]
		}
	case strings.HasPrefix(norm, "/"):
		prefix = sep
		norm = norm[1:]
	}

	var out []string
	for seg := range strings.SplitSeq(norm, "/") {
		switch seg {
		case "", ".":
			// nothing to add
		case "..":
			switch {
			case len(out) > 0 && out[len(out)-1] != "..":
				out = out[:len(out)-1]
			case prefix == "":
				out = append(out, "..")
			}
		default:
			out = append(out, seg)
		}
	}
	if cleaned := prefix + strings.Join(out, sep); cleaned != "" {
		return cleaned
	}
	return "."
}

// expandTildePath is expandTilde without the host-filepath dependency: the
// "~/" tail is re-joined with homeDir's separator style, so a "C:\Users\u"
// home yields "C:\Users\u\.bun\bin\pi.exe" on any host. Non-tilde paths —
// including the absolute snap candidate — come back verbatim.
func expandTildePath(path, homeDir string) string {
	if !strings.HasPrefix(path, "~/") || homeDir == "" {
		return path
	}
	return joinPath(homeDir, strings.Split(path[2:], "/")...)
}

// underPathStrict is the case-sensitive core of underPath: path is at or under
// dir, compared on a path boundary. Never a bare strings.HasPrefix, which
// would let ~/Documents.backup match ~/Documents.
func underPathStrict(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}
	p := strings.ReplaceAll(cleanPath(path), "\\", "/")
	d := strings.TrimRight(strings.ReplaceAll(cleanPath(dir), "\\", "/"), "/")
	if d == "" {
		return false
	}
	return p == d || strings.HasPrefix(p, d+"/")
}

// underPath reports whether path is at or under dir, case-insensitively on
// Windows (where the filesystem is).
func underPath(exec executor.Executor, path, dir string) bool {
	if exec.GOOS() == model.PlatformWindows {
		return underPathStrict(strings.ToLower(path), strings.ToLower(dir))
	}
	return underPathStrict(path, dir)
}

// underHomeDir reports whether resolved is at or under the home-relative path
// rel (e.g. "~/.amp/bin"), compared on a path boundary.
func underHomeDir(exec executor.Executor, homeDir, resolved, rel string) bool {
	return underPath(exec, resolved, expandTildePath(rel, homeDir))
}

// candidateGuard is the macOS TCC check as a value: built once per
// resolveVerified call from the skipper the detector was handed, then
// consulted before every stat of a candidate and on every EvalSymlinks result.
//
// It answers false outright off darwin, keyed on exec.GOOS() captured at
// construction rather than the host, so a mock-platform test behaves the same
// everywhere.
type candidateGuard struct {
	skipper *tcc.Skipper
	darwin  bool
	// exempt holds the darwin package-manager trees that live under ~/Library.
	// tcc coarse-skips ~/Library wholesale for walks; filtering candidates
	// through that unmodified would silently delete pnpm and fnm as macOS
	// channels for all three agents. The OS gates specific ~/Library subtrees
	// (Mail, Messages, Safari, Containers), not these — and shipped code
	// already stats the pnpm pair with no skipper at all
	// (resolveNodePMFromDefaults).
	exempt []string
}

func newCandidateGuard(exec executor.Executor, homeDir string, skipper *tcc.Skipper) candidateGuard {
	g := candidateGuard{skipper: skipper, darwin: exec.GOOS() == model.PlatformDarwin}
	if g.darwin && homeDir != "" {
		g.exempt = []string{
			// Covers both macOS pnpm shapes: ~/Library/pnpm/bin is under it.
			joinPath(homeDir, "Library", "pnpm"),
			joinPath(homeDir, "Library", "Application Support", "fnm"),
		}
	}
	return g
}

// protected reports whether path must not be touched. Order matters: the
// darwin gate, then the exemption — compared against the CLEANED candidate, so
// "~/Library/pnpm/../Mail/x" cannot ride it past the skipper — then the
// injected skipper, whose nil receiver answers false, which is
// --include-tcc-protected behaving as documented.
func (g candidateGuard) protected(path string) bool {
	if !g.darwin || path == "" {
		return false
	}
	cleaned := cleanPath(path)
	for _, ex := range g.exempt {
		if underPathStrict(cleaned, ex) {
			return false
		}
	}
	return g.skipper.WithinProtected(cleaned)
}

// aiCLIBinaryCandidateDirs is pmBinaryCandidateDirs plus the directories a
// global *agent* install can land in that a Node package-manager probe has no
// reason to know about.
//
// Reusing pmBinaryCandidateDirs is deliberate: it already carries the correct
// per-platform pnpm spellings, the ~/.npm-global prefix override, asdf, the
// two Linuxbrew prefixes and a version-sorted nvm glob — a hand-written list
// got several of those wrong. What it does not carry is the single most
// important directory here: ~/.local/bin, which is both Factory's and Amp's
// installer target.
//
// The install-tree globs matter for a second reason. Shim managers put a shim
// on PATH, not a package — ~/.volta/bin/<tool> is a symlink to volta-shim and
// ~/.asdf/shims/<tool> is a shell script, so EvalSymlinks ends nowhere near a
// node_modules and every ladder rule correctly rejects them. Probing the
// underlying install trees is what makes those managers detectable at all.
// Volta joins the npm package name verbatim, so a scoped package — which all
// three agents are — sits one level deeper than an unscoped one; hence both
// depths. On Windows volta's npm-managed images keep binaries at the image
// root rather than under bin.
func aiCLIBinaryCandidateDirs(exec executor.Executor, homeDir string) []string {
	goos := exec.GOOS()
	dirs := pmBinaryCandidateDirs(exec)

	// pmBinaryCandidateDirs joins with the HOST filepath, so a mocked-GOOS run
	// comes back with the host's separators (a windows fixture built on Linux
	// yields "C:\Users\u\AppData\Roaming/npm"). Normalize before anything
	// joins or boundary-compares against these.
	for i, d := range dirs {
		if goos == model.PlatformWindows {
			dirs[i] = strings.ReplaceAll(d, "/", "\\")
		} else {
			dirs[i] = strings.ReplaceAll(d, "\\", "/")
		}
	}
	if homeDir == "" {
		return dirs
	}

	home := func(parts ...string) string { return joinPath(homeDir, parts...) }
	switch goos {
	case model.PlatformDarwin, model.PlatformLinux:
		dirs = append(dirs,
			home(".local", "bin"), // Factory's AND Amp's installer target
			home(".yarn", "bin"),  // yarn global
			home("n", "bin"),      // n: n-install's default N_PREFIX
			home(".n", "bin"),     // n: the README's no-sudo N_PREFIX
		)
		// n keeps ONE shared prefix across node versions, so unlike nvm there
		// is no per-version directory to enumerate — the two dirs above are
		// all that manager needs. The rest are real install trees, globbed.
		dirs = append(dirs, globDirs(exec, home(".local", "share", "fnm", "node-versions", "*", "installation", "bin"))...)
		dirs = append(dirs, globDirs(exec, home(".local", "share", "mise", "installs", "node", "*", "bin"))...)
		dirs = append(dirs, globDirs(exec, home(".volta", "tools", "image", "packages", "*", "bin"))...)
		dirs = append(dirs, globDirs(exec, home(".volta", "tools", "image", "packages", "*", "*", "bin"))...)
		dirs = append(dirs, globDirs(exec, home(".asdf", "installs", "nodejs", "*", "bin"))...)
		if goos == model.PlatformDarwin {
			// fnm's macOS default base. The Linux spelling above is kept on
			// darwin too because XDG_DATA_HOME=~/.local/share is the one
			// common override; deriving the base from Getenv would regress
			// that (headless the variable reads empty) rather than fix it.
			dirs = append(dirs, globDirs(exec, home("Library", "Application Support", "fnm", "node-versions", "*", "installation", "bin"))...)
		}
	case model.PlatformWindows:
		dirs = append(dirs,
			home("bin"), // Factory's Windows installer target
			home("AppData", "Local", "Microsoft", "WinGet", "Links"), // winget portable
		)
		if localAppData := exec.Getenv("LOCALAPPDATA"); localAppData != "" {
			images := joinPath(localAppData, "Volta", "tools", "image", "packages")
			dirs = append(dirs, globDirs(exec, joinPath(images, "*"))...)
			dirs = append(dirs, globDirs(exec, joinPath(images, "*", "*"))...)
		}
	}
	return dirs
}

// globDirs expands one glob pattern, newest-looking first (descending lexical,
// the rule nvmNodeBinDirs already uses) and empty on any error.
func globDirs(exec executor.Executor, pattern string) []string {
	matches, err := exec.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	return matches
}

// candidatePaths returns every candidate that exists for one Binaries entry,
// instead of stopping at the first. Three modes, dispatched in this order:
//
//	tilde entry   -> expandTildePath + FileExists (plus the Windows .exe retry)
//	absolute path -> FileExists, verbatim, no expansion and no PATH lookup
//	bare name     -> LookPath, then pmDirs — the package-manager prefix dirs a
//	                 global install can land in, since PATH surfaces only one
//	                 of them and it may be an impostor
//
// The absolute branch is not optional. findBinary has only two modes and picks
// between them by testing whether expandTilde changed the string, so an
// absolute candidate like /snap/pi-coding-agent/current/bin/pi lands in its
// LookPath branch — which under UserAwareExecutor spawns a login shell per
// candidate, and under Mock reads m.paths while FileExists reads m.files.
//
// pmDirs is passed in rather than computed here: this runs once per Binaries
// entry (11 times per Detect across the three new specs) and building the set
// globs six version-manager trees.
//
// Every candidate passes the TCC guard before its first stat, so a PATH entry
// under ~/Documents is dropped — with a Debug line — before it is touched.
func candidatePaths(exec executor.Executor, log *progress.Logger, guard candidateGuard, bin, homeDir string, pmDirs []string) []string {
	var out []string
	blocked := func(path string) bool {
		if !guard.protected(path) {
			return false
		}
		log.Debug("skipping candidate %s: under a macOS TCC-protected path (--include-tcc-protected scans it)", path)
		return true
	}
	probe := func(path string) {
		if path == "" || blocked(path) {
			return
		}
		if exec.FileExists(path) {
			out = append(out, path)
		}
	}

	switch {
	case strings.HasPrefix(bin, "~/"):
		expanded := expandTildePath(bin, homeDir)
		probe(expanded)
		// Mirrors findBinary's Windows retry. Skipped when the candidate is
		// already spelled with an extension (pi.cmd, pi.exe), where appending
		// .exe could only ever name a file that does not exist.
		if exec.GOOS() == model.PlatformWindows && !strings.Contains(pathBase(expanded), ".") {
			probe(expanded + ".exe")
		}
	case isAbsPath(bin):
		probe(bin)
	default:
		// LookPath has already proven the file exists; re-stating that with
		// FileExists would add a syscall and, under Mock, consult a different
		// map than the one the fixture registered.
		if path, err := exec.LookPath(bin); err == nil && path != "" && !blocked(path) {
			out = append(out, path)
		}
		filenames := pmBinaryFilenames(exec, bin)
		for _, dir := range pmDirs {
			for _, name := range filenames {
				probe(joinPath(dir, name))
			}
		}
	}
	return out
}

// resolveVerified builds the package-manager prefix dirs ONCE, then walks
// candidatePaths for each spec.Binaries entry in order, returning the first
// candidate accept() proves is this tool — with the static version that proof
// carried, "" when it carried none — and skipping duplicates by resolved path.
//
// accept() receives the path as found (what binary_path reports, and what the
// npm helpers need to follow a symlink or a Windows .cmd shim) and its
// symlink-resolved form (what the path anchors and the Cellar/Caskroom and
// pacman rules reason about). The resolved form passes the TCC guard before
// accept() runs, so a symlink into a protected tree is rejected before any
// manifest read.
//
// BinaryPath is the candidate AS FOUND, not its target: that preserves today's
// binary_path semantics, and resolveInstallPath is what follows symlinks.
// Order inside Binaries is therefore part of each spec's contract — an anchor
// listed first wins over a PATH hit that resolves to the same file.
func resolveVerified(
	exec executor.Executor,
	log *progress.Logger,
	skipper *tcc.Skipper,
	spec cliToolSpec,
	homeDir string,
	accept func(found, resolved string) (staticVersion string, ok bool),
) (cliResolution, bool) {
	guard := newCandidateGuard(exec, homeDir, skipper)
	pmDirs := aiCLIBinaryCandidateDirs(exec, homeDir)
	seen := make(map[string]struct{})

	for _, bin := range spec.Binaries {
		for _, found := range candidatePaths(exec, log, guard, bin, homeDir, pmDirs) {
			resolved, err := exec.EvalSymlinks(found)
			if err != nil || resolved == "" {
				resolved = found
			}
			if _, dup := seen[resolved]; dup {
				continue
			}
			seen[resolved] = struct{}{}
			if guard.protected(resolved) {
				log.Debug("%s: rejecting %s — resolves to %s, under a macOS TCC-protected path", spec.Name, found, resolved)
				continue
			}
			if version, ok := accept(found, resolved); ok {
				return cliResolution{BinaryPath: found, StaticVersion: version}, true
			}
		}
	}
	return cliResolution{}, false
}

// npmIdentity reports whether the npm package owning this binary is one of
// names, and returns the version from the same manifest read. The observed
// name comes back either way so a reject path can log what it actually saw.
//
// It derives the package root from the paths resolveVerified already computed
// and guard-checked — NodeModulesPackageRoot(resolved) for the Unix symlink
// and Bun layouts (the node_modules segment lives only in the target; found is
// /opt/homebrew/bin/pi), NPMShimPackageRoot(exec, found) for the Windows .cmd
// shim. It must NOT call EvalSymlinks itself: versionmeta's entry points
// re-resolve internally, so copying that here would duplicate the syscall and
// re-resolve AFTER the TCC guard vetted resolved, reopening the symlink-swap
// window the guard closed.
//
// One ReadFile serves identity and version together, which is what
// cliResolution.StaticVersion is filled from on every npm-shaped channel. The
// version is returned only when the name has just passed the allowlist — no
// caller can obtain a version without the identity check in front of it.
func npmIdentity(exec executor.Executor, found, resolved string, names ...string) (name, version string, ok bool) {
	root := versionmeta.NodeModulesPackageRoot(resolved)
	if root == "" {
		root = versionmeta.NPMShimPackageRoot(exec, found)
	}
	if root == "" {
		return "", "", false
	}
	name, version = readNPMManifest(exec, root, 0)
	if name == "" {
		return "", "", false
	}
	if !slices.Contains(names, name) {
		return name, "", false
	}
	return name, version, true
}

// readNPMManifest reads name and version from pkgRoot/package.json. A local
// twin of versionmeta's unexported npmManifest, which is reachable only
// through packageRoot — and packageRoot returns "" for exactly the layouts the
// ladders need (a standalone tarball, a snap payload).
//
// maxBytes caps the read, 0 for uncapped. Callers that reach a package root the
// way versionmeta does pass 0 deliberately: that read already happens uncapped
// in versionmeta for every existing spec, so capping only this copy would move
// no attacker and would let the two disagree about the same file. Only
// siblingManifest, which has no versionmeta counterpart, passes a cap.
func readNPMManifest(exec executor.Executor, pkgRoot string, maxBytes int64) (name, version string) {
	path := joinPath(pkgRoot, "package.json")
	if maxBytes > 0 {
		if info, err := exec.Stat(path); err == nil && info.Size() > maxBytes {
			return "", ""
		}
	}
	data, err := exec.ReadFile(path)
	if err != nil || (maxBytes > 0 && int64(len(data)) > maxBytes) {
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

// siblingManifest reads <dir of resolved>/package.json and returns its name
// and version — the standalone tarball and the snap payload, where the binary
// has no node_modules ancestor. The Windows .zip extracts flat, so the same
// read works there. ("", "") on any failure.
//
// It cannot accept the npm collider by accident: that binary is
// .../node_modules/pi/bin/pi, whose sibling directory is bin/ and holds no
// manifest.
//
// This is the one manifest read with no versionmeta counterpart, so it is the
// one that must be capped. versionmeta reaches a manifest only through
// packageRoot, which demands a node_modules ancestor or a .cmd/.ps1/.bat shim;
// here the sole precondition is that a candidate resolved to this directory, so
// any directory holding a file named pi/droid/amp gets its package.json read —
// including a directory an attacker put on PATH. Bounded on the same
// Stat-then-verify shape as nodedist's readBounded.
func siblingManifest(exec executor.Executor, resolved string) (name, version string) {
	dir := pathDir(resolved)
	if dir == "" {
		return "", ""
	}
	return readNPMManifest(exec, dir, siblingManifestMaxBytes)
}

// bunxTarget reads the <name>.bunx sibling of a `~\.bun\bin\<name>.exe`
// candidate and returns the entry point it names — the Windows Bun shim, which
// no other rule can reach: the .exe is not inside node_modules and
// NPMShimPackageRoot accepts only .cmd/.ps1/.bat, and there is no sibling
// package.json.
//
// The pointer is attacker-shaped input — a few hundred bytes of text any
// process running as the user could rewrite. The failure that matters is not a
// wrong identity (the manifest gate stops that) but the READ itself: a target
// like \\server\share\x\package.json would make a scan open an SMB connection
// with credential negotiation. So the decoded string must be a clean absolute
// local drive path (anything beginning \\ — UNC, or the \\.\ and \\?\ device
// forms — is refused), free of NUL/CR/LF, and at or under
// ~\.bun\install\global\node_modules\ on a path boundary. An out-of-root
// pointer is dropped BEFORE any read of its target. "" on any failure.
//
// The read itself is size-capped, following readBounded's Stat-then-verify
// shape. This is the one new read that needs it: decodeUTF16LE allocates a
// uint16 slice AND a decoded string on top of the bytes, so peak memory is
// several times the file size, where a plain manifest read is one times. The
// pointer names a single path, so bunxMaxBytes is generous by two orders of
// magnitude and no real Bun install can trip it.
func bunxTarget(exec executor.Executor, exePath, homeDir string) string {
	if !strings.HasSuffix(strings.ToLower(exePath), ".exe") {
		return ""
	}
	bunxPath := exePath[:len(exePath)-len(".exe")] + ".bunx"
	if info, err := exec.Stat(bunxPath); err == nil && info.Size() > bunxMaxBytes {
		return ""
	}
	data, err := exec.ReadFile(bunxPath)
	if err != nil || int64(len(data)) > bunxMaxBytes {
		return ""
	}
	target := strings.Trim(decodeUTF16LE(data), "\x00 \t\r\n")
	if target == "" || strings.ContainsAny(target, "\x00\r\n") {
		return ""
	}
	// Refuse UNC and device paths before cleaning can normalize them away.
	if strings.HasPrefix(target, `\\`) || strings.HasPrefix(target, "//") {
		return ""
	}
	cleaned := cleanPath(target)
	if !isDrivePath(cleaned) {
		return ""
	}
	if !underPath(exec, cleaned, expandTildePath("~/.bun/install/global/node_modules", homeDir)) {
		return ""
	}
	return cleaned
}

// decodeUTF16LE decodes UTF-16LE bytes to a string, tolerating a BOM. Bun
// writes the .bunx pointer as UTF-16LE (measured on one file), so the UTF-8
// branches are defensive: a plain-UTF-8 pointer must not decode to garbage.
// The discriminator is the interleaved NUL bytes UTF-16LE ASCII text always
// has and UTF-8 text never does.
func decodeUTF16LE(data []byte) string {
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		data = data[2:] // UTF-16LE BOM
	case len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF:
		return string(data[3:]) // UTF-8 BOM
	case !bytes.ContainsRune(data, 0) && utf8.Valid(data):
		return string(data)
	}
	if len(data)%2 != 0 {
		return ""
	}
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, uint16(data[i])|uint16(data[i+1])<<8)
	}
	return string(utf16.Decode(units))
}

// brewRoot returns which Homebrew root — "Cellar" or "Caskroom" — encloses
// resolved, and the package-name segment immediately after it; ("", "") when
// neither is present.
//
// Both halves are needed: Factory's official channel is a CASK
// (Caskroom/droid) and its collider is a FORMULA (Cellar/droid), so a helper
// returning only the name would collapse the two. versionmeta's
// versionFromHomebrew reads the VERSION segment and treats the two roots
// identically, which is why this is local and not a change there.
func brewRoot(resolved string) (root, pkg string) {
	segments := splitPathAny(resolved)
	for i := 0; i < len(segments)-1; i++ {
		if segments[i] == "Cellar" || segments[i] == "Caskroom" {
			return segments[i], segments[i+1]
		}
	}
	return "", ""
}

// pacmanPackageOwns reports whether any installed package whose name is in
// pkgs lists relPath (e.g. "usr/bin/amp") in its %FILES% manifest. Fully
// static — no exec, no `pacman -Qo`. An unreadable DB yields no match, which
// falls through to reject: the correct direction.
//
// A Glob hit alone would not do: it proves a package is installed, which is
// not the statement "this package owns this path", and the glob is loose in
// both directions (ampcode-* also matches ampcode-bin-*; amp-* would match an
// unrelated amp-utils).
func pacmanPackageOwns(exec executor.Executor, pkgs []string, relPath string) bool {
	entries, err := exec.Glob("/var/lib/pacman/local/*-*")
	if err != nil {
		return false
	}
	for _, dir := range entries {
		if name := pacmanDirPackageName(pathBase(dir)); name == "" || !slices.Contains(pkgs, name) {
			continue
		}
		data, err := exec.ReadFile(joinPath(dir, "files"))
		if err != nil {
			continue
		}
		if filesManifestLists(string(data), relPath) {
			return true
		}
	}
	return false
}

// pacmanDirPackageName strips the trailing -<pkgver>-<pkgrel> from a pacman
// local-DB directory name, per libalpm's own
// "%s%s-%s/%s" (dbpath, name, version, filename) construction. An epoch lives
// inside the version and adds no dash segment, so dropping the last two
// segments is exact — and it is what makes names that themselves contain
// dashes parse correctly, which matters directly here: ampcode-bin and amp-bin
// are both real packages. Returns "" when there are fewer than two segments.
func pacmanDirPackageName(dir string) string {
	i := strings.LastIndex(dir, "-")
	if i < 0 {
		return ""
	}
	j := strings.LastIndex(dir[:i], "-")
	if j <= 0 {
		return ""
	}
	return dir[:j]
}

// filesManifestLists reports whether the %FILES% section of a pacman `files`
// manifest lists relPath as an exact line.
//
// Two format facts, read out of libalpm. Stored paths are root-relative with
// no leading slash (pacman joins them to the install root itself), so the
// match target is "usr/bin/amp" and never "/usr/bin/amp". And the section ends
// at the first BLANK line — reading to EOF would let a %BACKUP% entry for the
// same path satisfy the match, and a backup entry is not an ownership claim.
func filesManifestLists(manifest, relPath string) bool {
	inFiles := false
	for line := range strings.SplitSeq(manifest, "\n") {
		line = strings.TrimRight(line, "\r")
		if !inFiles {
			if strings.TrimSpace(line) == "%FILES%" {
				inFiles = true
			}
			continue
		}
		if line == "" {
			return false
		}
		if line == relPath {
			return true
		}
	}
	return false
}

// wingetPackage reports whether resolved sits inside winget's portable package
// directory for id — `WinGet\Packages\<Publisher>.<Name>_<source>`. The
// publisher-qualified identifier is exact and needs no exec; the source suffix
// after "_" is not pinned.
func wingetPackage(resolved, id string) bool {
	segments := splitPathAny(resolved)
	for i := 1; i < len(segments)-1; i++ {
		if !strings.EqualFold(segments[i], "Packages") || !strings.EqualFold(segments[i-1], "WinGet") {
			continue
		}
		pkg := strings.ToLower(segments[i+1])
		if pkg == strings.ToLower(id) || strings.HasPrefix(pkg, strings.ToLower(id)+"_") {
			return true
		}
	}
	return false
}

// fileAtLeast reports whether path is at least minBytes. Always a FLOOR, never
// an equality or a range: the same pinned Factory version served byte counts
// 64 KiB apart across two days, and the x64-baseline variant is a second,
// differently-sized artifact per version.
func fileAtLeast(exec executor.Executor, path string, minBytes int64) bool {
	info, err := exec.Stat(path)
	if err != nil || info == nil {
		return false
	}
	return info.Size() >= minBytes
}

// nonEmptyDir reports whether dir exists and holds at least one entry, without
// a ReadDir: these ladders never walk, and a one-level Glob is the targeted
// equivalent. Call it after the cheaper checks so the Glob rarely runs.
func nonEmptyDir(exec executor.Executor, dir string) bool {
	if !exec.DirExists(dir) {
		return false
	}
	matches, err := exec.Glob(joinPath(dir, "*"))
	return err == nil && len(matches) > 0
}

// ---------------------------------------------------------------------------
// The three identity ladders. Each is first-match-wins, static-only for
// identity, and Debug-logs every reject with the path and the reason — a
// customer asking "why doesn't Amp show up" must be answerable from --verbose
// alone. Debug and not Progress: Progress prints at LevelInfo, and rejecting a
// collider is an ordinary event on an ordinary machine.
// ---------------------------------------------------------------------------

// piPackageName is the npm package every Pi channel ships as, including the
// standalone tarball and the snap, which both carry it in a sibling manifest.
const piPackageName = "@earendil-works/pi-coding-agent"

// factoryMinBinaryBytes is the size floor for Droid's platform binary. Real
// builds run 117–157 MB across the three platforms; the known collider
// extracts to ~3–4 MB. The floor sits ~5.5× above the largest collider and
// ~5.6× below the smallest real build, and it stays a floor so a future
// slimmer build cannot fall through.
const factoryMinBinaryBytes int64 = 20 << 20

// bunxMaxBytes caps the .bunx pointer read. A pointer holds one absolute path,
// so the real file is a few hundred bytes; 64 KiB leaves two orders of
// magnitude of headroom while keeping a hostile file from being decoded.
const bunxMaxBytes int64 = 64 << 10

// siblingManifestMaxBytes caps the sibling package.json read. Published agent
// manifests are single-digit KB and even a pathological real one stays well
// under a megabyte, so 4 MiB cannot produce a false negative on a genuine
// install while still refusing a file sized to exhaust memory.
const siblingManifestMaxBytes int64 = 4 << 20

// resolvePi proves an Earendil Pi install. Two colliders make the bare name
// untrustworthy, and one of them is distro-shipped: npm `pi` (π's digits —
// `pi --version` prints "3") and Ubuntu's `pi 1.3.7` arbitrary-precision
// calculator at /usr/bin/pi, whose --version prints "pi (CLN 1.3.7)", a
// version-SHAPED string. Identity therefore comes from a manifest, never from
// output, and nothing is exec'd on any channel.
func resolvePi(_ context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool) {
	return resolveVerified(exec, log, skipper, spec, homeDir, func(found, resolved string) (string, bool) {
		// Rule 1 — npm, pnpm, yarn, Bun and the Windows .cmd shim.
		name, version, ok := npmIdentity(exec, found, resolved, piPackageName)
		if ok {
			return version, true
		}

		// Rule 2 — the standalone tarball and the snap payload: no
		// node_modules ancestor, so rule 1 derives no package root and a
		// genuine install would otherwise be rejected. The same read carries
		// the version out.
		if sibName, sibVersion := siblingManifest(exec, resolved); sibName == piPackageName {
			return sibVersion, true
		}

		// Rule 2b — the Windows Bun shim. ~\.bun\bin\pi.exe is a PE launcher
		// with no symlink and no sibling manifest; identity lives in the
		// pi.bunx pointer beside it, and the target still has to pass rule
		// 1's manifest gate.
		if exec.GOOS() == model.PlatformWindows {
			if target := bunxTarget(exec, found, homeDir); target != "" {
				if _, bunVersion, bunOK := npmIdentity(exec, target, target, piPackageName); bunOK {
					return bunVersion, true
				}
			}
		}

		// Rule 3 — reject. Both colliders land here: neither has a sibling
		// manifest nor a node_modules ancestor claiming the Pi package.
		if name != "" {
			log.Debug("pi: rejecting %s — npm package is %q, not %s", found, name, piPackageName)
		} else {
			log.Debug("pi: rejecting %s — nothing proves %s owns it (resolved %s)", found, piPackageName, resolved)
		}
		return "", false
	})
}

// resolveFactory proves a Factory Droid install. The collider is
// wasabeef/droid, an Android-version CLI shipped as a Homebrew FORMULA and via
// cargo; Factory ships a CASK. Homebrew keeps formulae and casks in separate
// roots, so Cellar-vs-Caskroom tells them apart statically, with no exec and
// no heuristic.
func resolveFactory(_ context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool) {
	return resolveVerified(exec, log, skipper, spec, homeDir, func(found, resolved string) (string, bool) {
		// Rule 1 — the collider's own channels, ahead of every accept rule so
		// a future Cellar/droid npm-shim layout still cannot sneak past.
		if underHomeDir(exec, homeDir, resolved, "~/.cargo") {
			log.Debug("factory: rejecting %s — under ~/.cargo, the cargo-installed droid collider", found)
			return "", false
		}
		if root, pkg := brewRoot(resolved); root == "Cellar" && pkg == "droid" {
			log.Debug("factory: rejecting %s — Homebrew Cellar/droid is the formula collider; Factory ships a cask", found)
			return "", false
		}

		// Rule 2 — npm, both the unscoped `droid` Factory owns and
		// @factory/cli. NO size floor: `npm i -g droid --ignore-scripts`
		// leaves a 3,024 B JS launcher whose manifest is still correct, and a
		// floor here would reject that install outright.
		if _, version, ok := npmIdentity(exec, found, resolved, "droid", "@factory/cli"); ok {
			return version, true
		}

		// Rule 3 — homebrew/cask droid. The floor stays even though the cask
		// root is already strong evidence, because a cask token is
		// attacker-choosable in a third-party tap. No exec is possible here
		// anyway: cask binaries are quarantined and spctl-rejects them, so
		// SafeToExec is false — getVersion instead recovers 0.183.0 from the
		// Caskroom version segment, statically.
		if root, pkg := brewRoot(resolved); root == "Caskroom" && pkg == "droid" && fileAtLeast(exec, found, factoryMinBinaryBytes) {
			return "", true
		}

		// Rule 4 — Factory's own installer target, plus one corroborator. The
		// corroborator is required, not belt-and-braces: the installer
		// creates only the bin dir, and ~/.factory is written the first time
		// droid runs, so a machine that installed but never launched has the
		// binary and no config dir at all.
		if underHomeDir(exec, homeDir, resolved, "~/.local/bin/droid") || // darwin, linux
			underHomeDir(exec, homeDir, resolved, "~/bin/droid.exe") { // windows
			if fileAtLeast(exec, found, factoryMinBinaryBytes) || nonEmptyDir(exec, expandTildePath("~/.factory", homeDir)) {
				return "", true
			}
			log.Debug("factory: rejecting %s — at the installer target but under %d bytes, with no ~/.factory content to corroborate", found, factoryMinBinaryBytes)
			return "", false
		}

		// Rule 5 — reject.
		log.Debug("factory: rejecting %s — no Factory channel claims it (resolved %s)", found, resolved)
		return "", false
	})
}

// resolveAmp proves a Sourcegraph Amp install. Amp is NEVER exec'd to
// establish identity: the collider is amp.rs, a terminal text editor and a
// formula in homebrew/core itself, which ignores both --version and -V and
// goes straight to terminal setup — with stdin closed it errors, and given a
// TTY it opens a full-screen editor and blocks for the whole timeout.
func resolveAmp(_ context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool) {
	return resolveVerified(exec, log, skipper, spec, homeDir, func(found, resolved string) (string, bool) {
		// Rule 1 — the installer's own root, on every OS. Reached directly or
		// through the ~/.local/bin/amp PATH symlink, since the resolved form
		// IS the anchor. No manifest and no version-bearing segment, so this
		// channel — the most common one — reports version unknown.
		if underHomeDir(exec, homeDir, resolved, "~/.amp/bin") {
			return "", true
		}

		// Rule 2 — npm. Both names nest: @sourcegraph/amp is a compat shim
		// whose own bin points into node_modules/@ampcode/cli, and
		// NodeModulesPackageRoot returns the INNERMOST root, so even the
		// legacy install reports @ampcode/cli. The legacy name stays in the
		// allowlist as cheap insurance against a future direct-bin republish.
		if _, version, ok := npmIdentity(exec, found, resolved, "@ampcode/cli", "@sourcegraph/amp"); ok {
			return version, true
		}

		// Rule 2a — winget portable. The publisher-qualified identifier is
		// exact; the Packages directory name encodes the source, not the
		// version, so this channel reports unknown too.
		if exec.GOOS() == model.PlatformWindows && wingetPackage(resolved, "Sourcegraph.Amp") {
			return "", true
		}

		// Rules 3 and 4, pacman half — /usr/bin/amp is genuinely ambiguous:
		// the AUR `ampcode` package puts the real Amp there and distro
		// packages put the collider there. Packaging makes them mutually
		// exclusive (ampcode declares provides=('amp') and
		// conflicts=('amp' 'ampcode-bin')), so pacman's own file manifest
		// settles it. Arch-only, and an unreadable DB rejects.
		if cleanPath(resolved) == "/usr/bin/amp" {
			if pacmanPackageOwns(exec, []string{"ampcode", "ampcode-bin"}, "usr/bin/amp") {
				return "", true
			}
			if pacmanPackageOwns(exec, []string{"amp"}, "usr/bin/amp") {
				log.Debug("amp: rejecting %s — pacman package `amp` owns usr/bin/amp, which is the amp.rs editor", found)
			} else {
				log.Debug("amp: rejecting %s — no installed ampcode/ampcode-bin package owns usr/bin/amp", found)
			}
			return "", false
		}

		// Rule 4 — the collider's other channels.
		if root, pkg := brewRoot(resolved); (root == "Cellar" || root == "Caskroom") && pkg == "amp" {
			log.Debug("amp: rejecting %s — Homebrew %s/amp is the amp.rs text editor", found, root)
			return "", false
		}
		if underHomeDir(exec, homeDir, resolved, "~/.cargo") {
			log.Debug("amp: rejecting %s — under ~/.cargo, the cargo-installed amp.rs editor", found)
			return "", false
		}

		// Rule 5 — reject.
		log.Debug("amp: rejecting %s — no Amp channel claims it (resolved %s)", found, resolved)
		return "", false
	})
}
