package configaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// maxNPMRCFiles caps the number of .npmrc files we report. Even on big
// monorepos this should be ample; the cap exists only to prevent a
// pathological case (someone committed `.npmrc` into thousands of subdirs)
// from blowing up the JSON payload.
const maxNPMRCFiles = 1000

// npmEnvVars is the set of environment variables we always record on the
// audit, regardless of whether they are set. Recording an unset var keeps
// the audit shape stable across hosts and is the natural extension point
// when a future change-tracking layer wants to detect transitions.
var npmEnvVars = []string{
	"NPM_TOKEN",
	"NPM_CONFIG_USERCONFIG",
	"NPM_CONFIG_GLOBALCONFIG",
	"NPM_CONFIG_REGISTRY",
	"npm_config_registry",
	"npm_config__authToken",
	"npm_config__auth",
	"NODE_OPTIONS",
	"NODE_TLS_REJECT_UNAUTHORIZED",
}

// secretEnvNamePattern matches env var names that should be redacted on output.
// The npm config layer accepts both `npm_config_*` (lowercase) and
// `NPM_CONFIG_*` (uppercase) — and any *_TOKEN / *_PASSWORD / *_KEY value
// is treated as a secret regardless of source.
var secretEnvNamePattern = regexp.MustCompile(`(?i)(token|password|secret|_auth|key)`)

// NPMRCDetector audits npm configuration: discovers all .npmrc files, parses
// them, captures the merged effective view, and surfaces relevant env vars.
//
// The detector intentionally keeps file metadata collection (owner, mode,
// hashes) and git-tracking checks pluggable so unit tests don't need real
// syscalls or a git binary.
type NPMRCDetector struct {
	exec    executor.Executor
	skipper *tcc.Skipper

	// ownerLookup returns owner info for a path. Defaults to the real
	// platform-specific impl in npmrc_stat_*.go; tests can override.
	ownerLookup func(path string) ownerInfo
	// gitTracked returns whether the file is tracked by git. Defaults to
	// shelling out via the executor; tests can override to a stub.
	gitTracked func(ctx context.Context, path string) bool
	// inGitRepo walks parent dirs looking for .git. Defaults to a
	// filesystem walk; tests can override.
	inGitRepo func(path string) bool
}

// NewNPMRCDetector returns a detector with default platform-specific
// metadata helpers wired in.
func NewNPMRCDetector(exec executor.Executor) *NPMRCDetector {
	d := &NPMRCDetector{exec: exec}
	d.ownerLookup = statOwner
	d.gitTracked = func(ctx context.Context, p string) bool { return gitTrackedViaExec(ctx, exec, p) }
	d.inGitRepo = defaultInGitRepo
	return d
}

// WithSkipper attaches a TCC skipper so .npmrc discovery skips macOS-protected
// directories. A nil skipper is a no-op. Returns the detector for chaining.
func (d *NPMRCDetector) WithSkipper(s *tcc.Skipper) *NPMRCDetector {
	d.skipper = s
	return d
}

// Detect runs the full audit. searchDirs are the dirs to walk for project-
// level .npmrc files (typically the user's $HOME plus any extra dirs
// configured by the operator). loggedInUser is the username whose ~/.npmrc
// we resolve for the user-scope file.
func (d *NPMRCDetector) Detect(ctx context.Context, searchDirs []string, loggedInUser *user.User) model.NPMRCAudit {
	audit := model.NPMRCAudit{
		Files: []model.NPMRCFile{},
		Env:   d.collectEnv(),
	}

	npmPath, npmErr := d.exec.LookPath("npm")
	if npmErr == nil {
		audit.Available = true
		audit.NPMPath = npmPath
		audit.NPMVersion = d.npmVersion(ctx)
	}

	// Resolve the four scopes. Each step is independent: if one fails (e.g.
	// `npm config get globalconfig` returns nothing), the rest still run.
	files := make([]model.NPMRCFile, 0, 8)
	seen := make(map[string]bool)
	add := func(scope, path string) {
		if path == "" {
			return
		}
		abs, err := filepath.Abs(path)
		if err == nil {
			path = abs
		}
		if seen[path] {
			return
		}
		seen[path] = true
		files = append(files, d.collectFile(ctx, path, scope))
	}

	add("builtin", d.npmConfigGet(ctx, "builtinconfig"))

	if v := d.exec.Getenv("NPM_CONFIG_GLOBALCONFIG"); v != "" {
		add("global", v)
	} else {
		add("global", d.npmConfigGet(ctx, "globalconfig"))
	}

	if v := d.exec.Getenv("NPM_CONFIG_USERCONFIG"); v != "" {
		add("user", v)
	} else if loggedInUser != nil && loggedInUser.HomeDir != "" {
		add("user", filepath.Join(loggedInUser.HomeDir, ".npmrc"))
	}

	for _, dir := range searchDirs {
		for _, p := range d.findProjectNPMRCs(dir) {
			if len(files) >= maxNPMRCFiles {
				break
			}
			add("project", p)
		}
	}

	audit.Files = files
	if eff := d.captureEffective(ctx); eff != nil {
		audit.Effective = eff
	}

	// Drift / change-tracking detection is intentionally out of scope here.
	// The npmrc audit currently surfaces inventory + parsed contents +
	// merged-effective view + relevant env vars. Diffing the audit against
	// a previous snapshot, attributing writers, and surfacing per-project
	// effective overrides ("if a developer cd's into this cloned repo and
	// runs npm install, what flips?") are documented as future extensions
	// in .plans/0005-npmrc-audit.md and were deliberately removed when
	// the requirements narrowed to surfacing only.
	return audit
}

// findProjectNPMRCs walks dir looking for .npmrc files, applying the same
// directory-skip rules as the node project scanner plus a small set of
// well-known cache locations (Go module cache, vendor dirs) — random .npmrc
// files inside cached/vendored dependencies aren't config the user authored
// and would only add noise to the audit. Returns absolute paths.
func (d *NPMRCDetector) findProjectNPMRCs(dir string) []string {
	if dir == "" {
		return nil
	}
	var results []string
	_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if d.skipper.ShouldSkip(path, dir) {
				return filepath.SkipDir
			}
			if shouldSkipNPMRCDir(path, entry.Name(), dir) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == ".npmrc" {
			if abs, err := filepath.Abs(path); err == nil {
				results = append(results, abs)
			} else {
				results = append(results, path)
			}
		}
		return nil
	})
	return results
}

// shouldSkipNPMRCDir returns true when the directory should be skipped during
// project-level .npmrc discovery. Mirrors nodescan.go's exclusions and adds
// well-known dependency-cache locations (Go module cache, vendor dirs,
// language-specific caches under $HOME).
func shouldSkipNPMRCDir(path, name, root string) bool {
	switch name {
	case "node_modules", ".git", ".cache", "vendor":
		return true
	}
	if strings.HasPrefix(name, ".") && path != root {
		return true
	}
	// Path-based skips for caches whose dir names alone aren't distinctive.
	slashed := filepath.ToSlash(path)
	if strings.HasSuffix(slashed, "/pkg/mod") || strings.Contains(slashed, "/pkg/mod/") {
		return true
	}
	if strings.Contains(slashed, "/Library/Caches/") {
		return true
	}
	return false
}

// collectFile gathers everything we know about one .npmrc path. Always
// returns a record — non-existent files are surfaced with Exists=false so
// the caller can see "we looked here, nothing was there."
func (d *NPMRCDetector) collectFile(ctx context.Context, path, scope string) model.NPMRCFile {
	f := model.NPMRCFile{
		Path:  path,
		Scope: scope,
	}

	// Lstat first so a symlink doesn't get followed silently.
	linfo, err := os.Lstat(path)
	if err != nil {
		// Distinguish "not found" from "not readable" so the user can act.
		if os.IsNotExist(err) {
			f.Exists = false
			return f
		}
		f.Exists = true
		f.ParseError = "lstat: " + err.Error()
		return f
	}
	f.Exists = true

	if linfo.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			f.SymlinkTo = target
		}
	}

	// Stat (follows symlinks) for size/mtime/mode.
	info, err := os.Stat(path)
	if err != nil {
		f.Readable = false
		f.ParseError = "stat: " + err.Error()
		return f
	}
	f.SizeBytes = info.Size()
	f.ModTimeUnix = info.ModTime().Unix()
	f.Mode = fmt.Sprintf("%#o", info.Mode().Perm())

	if info.IsDir() {
		f.ParseError = "path is a directory"
		return f
	}

	if d.ownerLookup != nil {
		if oi := d.ownerLookup(path); oi.OK {
			f.OwnerUID = oi.UID
			f.GroupGID = oi.GID
			f.OwnerName = oi.OwnerName
			f.GroupName = oi.GroupName
		}
	}

	// #nosec G304 -- path comes from the detector's own candidate
	// enumeration of well-known npmrc locations (built-in/global/user/
	// project); not from external input.
	data, err := os.ReadFile(path)
	if err != nil {
		f.Readable = false
		f.ParseError = "read: " + err.Error()
		return f
	}
	f.Readable = true

	sum := sha256.Sum256(data)
	f.SHA256 = hex.EncodeToString(sum[:])

	f.Entries = parseNPMRC(data)

	if d.inGitRepo != nil && d.inGitRepo(path) {
		f.InGitRepo = true
		if d.gitTracked != nil && d.gitTracked(ctx, path) {
			f.GitTracked = true
		}
	}

	return f
}

// captureEffective runs `npm config ls -l --json` and `npm config ls -l` for
// source attribution. Returns nil when npm is unavailable.
func (d *NPMRCDetector) captureEffective(ctx context.Context) *model.NPMRCEffective {
	if _, err := d.exec.LookPath("npm"); err != nil {
		return nil
	}
	eff := &model.NPMRCEffective{
		SourceByKey: map[string]string{},
		Config:      map[string]any{},
	}

	stdoutJSON, _, exit, _ := d.exec.RunWithTimeout(ctx, 15*time.Second, "npm", "config", "ls", "-l", "--json")
	if exit == 0 && strings.TrimSpace(stdoutJSON) != "" {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(stdoutJSON), &parsed); err != nil {
			eff.Error = "json decode: " + err.Error()
		} else {
			eff.Config = parsed
		}
	} else if eff.Error == "" && exit != 0 {
		eff.Error = fmt.Sprintf("npm config ls -l --json exited with %d", exit)
	}

	stdoutText, _, exitText, _ := d.exec.RunWithTimeout(ctx, 15*time.Second, "npm", "config", "ls", "-l")
	if exitText == 0 && stdoutText != "" {
		eff.SourceByKey = parseSourceAttribution(stdoutText)
	}

	return eff
}

// parseSourceAttribution scans the textual output of `npm config ls -l`,
// which groups keys under `; "<source>" config from "<path>"` headers.
//
//	; "user" config from "/Users/me/.npmrc"
//	registry = "https://registry.npmjs.org/"
//	; "default" values
//	access = null
//
// We map each non-comment, non-section key to the most recent header seen.
func parseSourceAttribution(text string) map[string]string {
	out := map[string]string{}
	headerRE := regexp.MustCompile(`^;\s*"([^"]+)"\s*(?:config from\s*"([^"]+)")?`)
	currentSource := "default"
	for _, line := range strings.Split(text, "\n") {
		raw := strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, ";") {
			if m := headerRE.FindStringSubmatch(trimmed); m != nil {
				if m[2] != "" {
					currentSource = m[2] // path is more specific than label
				} else {
					currentSource = m[1]
				}
			}
			continue
		}
		// `key = value` or `@scope:registry = value`.
		if eq := strings.IndexByte(trimmed, '='); eq > 0 {
			key := strings.TrimSpace(trimmed[:eq])
			if key != "" {
				out[key] = currentSource
			}
		}
	}
	return out
}

// npmVersion returns the npm CLI's version string, "unknown" on failure.
func (d *NPMRCDetector) npmVersion(ctx context.Context) string {
	stdout, _, exit, _ := d.exec.RunWithTimeout(ctx, 5*time.Second, "npm", "--version")
	if exit != 0 {
		return "unknown"
	}
	v := strings.TrimSpace(stdout)
	if v == "" {
		return "unknown"
	}
	return v
}

// npmConfigGet runs `npm config get <key>` and returns the trimmed value, or
// empty if the call failed or the value is "undefined" (npm's literal output
// for an unset key).
func (d *NPMRCDetector) npmConfigGet(ctx context.Context, key string) string {
	stdout, _, exit, _ := d.exec.RunWithTimeout(ctx, 5*time.Second, "npm", "config", "get", key)
	if exit != 0 {
		return ""
	}
	v := strings.TrimSpace(stdout)
	if v == "undefined" || v == "null" {
		return ""
	}
	return v
}

// collectEnv builds a snapshot of the npm-relevant environment. Sensitive
// values are redacted; the SHA-256 lets the change-tracking layer notice
// rotation without ever surfacing the secret.
func (d *NPMRCDetector) collectEnv() []model.NPMRCEnvVar {
	out := make([]model.NPMRCEnvVar, 0, len(npmEnvVars))
	for _, name := range npmEnvVars {
		v := d.exec.Getenv(name)
		ev := model.NPMRCEnvVar{Name: name, Set: v != ""}
		if v != "" {
			ev.ValueSHA256 = sha256Hex(v)
			if secretEnvNamePattern.MatchString(name) {
				ev.DisplayValue = redactSecret(v)
			} else {
				ev.DisplayValue = v
			}
		}
		out = append(out, ev)
	}
	return out
}
