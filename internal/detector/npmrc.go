package detector

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
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// maxNPMRCFiles caps the number of .npmrc files we report. Even on big
// monorepos this should be ample; the cap exists only to prevent a
// pathological case (someone committed `.npmrc` into thousands of subdirs)
// from blowing up the JSON payload.
const maxNPMRCFiles = 1000

// maxPerProjectEvaluations caps how many project-scope files we re-evaluate
// effective config for. Each evaluation is a `npm config ls -l --json`
// invocation in that project's directory (~200ms apiece), so this is a
// runtime budget, not a correctness cap. Anything past this gets the
// per-file static view but no overrides analysis.
const maxPerProjectEvaluations = 25

// npmEnvVars is the set of environment variables we always record on the
// audit, regardless of whether they are set. Recording an unset var lets the
// diff layer notice when one is *added* between runs (a common worm
// behavior — set NPM_TOKEN and run npm publish).
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
	exec executor.Executor

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

type ownerInfo struct {
	UID       int
	GID       int
	OwnerName string
	GroupName string
	OK        bool
}

// NewNPMRCDetector returns a detector with default platform-specific
// metadata helpers wired in.
func NewNPMRCDetector(exec executor.Executor) *NPMRCDetector {
	d := &NPMRCDetector{exec: exec}
	d.ownerLookup = func(p string) ownerInfo { return statOwner(p) }
	d.gitTracked = d.defaultGitTracked
	d.inGitRepo = defaultInGitRepo
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

	// Per-project effective evaluation: for every project file we found, run
	// `npm config ls -l --json` from that file's directory and diff against
	// the baseline. The result tells us "if a developer cd's into this
	// project and runs npm install, here's what actually changes" — which is
	// the threat model for cloned-repo supply-chain attacks.
	if audit.Available && audit.Effective != nil && audit.Effective.Error == "" {
		d.populateProjectOverrides(ctx, &audit)
	}

	return audit
}

// populateProjectOverrides re-runs `npm config ls -l --json` from each
// project-scope file's directory and computes the diff against the baseline
// effective config. Updates Files in-place (Files is a slice, but we look
// each file up by index since we mutate the embedded record).
//
// Bounded by maxPerProjectEvaluations to keep total runtime sane; projects
// past the cap are left without override info (they still show their
// static parsed contents).
//
// Auth-scope keys (//host/:_authToken etc.) are stripped from npm's
// effective JSON output, so we additionally diff the parsed entries of the
// project file against the baseline set of auth keys (user + global) to
// catch credentials a cloned repo silently ships.
func (d *NPMRCDetector) populateProjectOverrides(ctx context.Context, audit *model.NPMRCAudit) {
	baseline := audit.Effective.Config
	baselineSources := audit.Effective.SourceByKey
	baselineAuthKeys := collectBaselineAuthKeys(audit.Files)

	evaluated := 0
	for i := range audit.Files {
		f := &audit.Files[i]
		if f.Scope != "project" || !f.Exists || !f.Readable {
			continue
		}
		if evaluated >= maxPerProjectEvaluations {
			f.OverrideError = "skipped: per-project evaluation budget exhausted"
			continue
		}
		evaluated++

		projectDir := filepath.Dir(f.Path)
		projectConfig, projectSources, err := d.evaluateInDir(ctx, projectDir)
		if err != nil {
			f.OverrideError = err.Error()
			continue
		}

		overrides := computeOverrides(baseline, baselineSources, projectConfig, projectSources)
		// Append auth-key overrides that npm's JSON wouldn't surface.
		overrides = append(overrides, authOverridesFromEntries(f.Entries, baselineAuthKeys)...)
		// Re-sort: auth first, then alphabetical.
		sort.SliceStable(overrides, func(i, j int) bool {
			if overrides[i].IsAuth != overrides[j].IsAuth {
				return overrides[i].IsAuth
			}
			return overrides[i].Key < overrides[j].Key
		})
		f.EffectiveOverrides = overrides
	}
}

// collectBaselineAuthKeys returns the set of auth-key strings that already
// exist in the user or global scope. Used so per-project diffs can flag
// auth keys that appear *only* in the project file as new credentials.
func collectBaselineAuthKeys(files []model.NPMRCFile) map[string]struct{} {
	keys := map[string]struct{}{}
	for _, f := range files {
		if f.Scope != "user" && f.Scope != "global" && f.Scope != "builtin" {
			continue
		}
		for _, e := range f.Entries {
			if e.IsAuth {
				keys[e.Key] = struct{}{}
			}
		}
	}
	return keys
}

// authOverridesFromEntries returns NPMRCOverride records for auth keys in a
// project file's parsed entries that aren't already present in the baseline
// (user/global) auth-key set. The DisplayValue (already redacted) is used
// for the project-side value; baseline is "<unset>".
func authOverridesFromEntries(projectEntries []model.NPMRCEntry, baselineAuthKeys map[string]struct{}) []model.NPMRCOverride {
	var out []model.NPMRCOverride
	for _, e := range projectEntries {
		if !e.IsAuth {
			continue
		}
		if _, exists := baselineAuthKeys[e.Key]; exists {
			continue
		}
		out = append(out, model.NPMRCOverride{
			Key:           e.Key,
			BaselineValue: "<unset>",
			ProjectValue:  e.DisplayValue, // already redacted
			ProjectSource: "project",
			IsAuth:        true,
			IsNew:         true,
		})
	}
	return out
}

// evaluateInDir runs `npm config ls -l --json` and `npm config ls -l` from
// the given directory and returns the merged config map and the per-key
// source attribution. Errors are returned with enough context for the
// override-error string in the audit to be actionable.
func (d *NPMRCDetector) evaluateInDir(ctx context.Context, dir string) (map[string]any, map[string]string, error) {
	stdoutJSON, _, exit, _ := d.exec.RunInDir(ctx, dir, 15*time.Second, "npm", "config", "ls", "-l", "--json")
	if exit != 0 {
		return nil, nil, fmt.Errorf("npm config ls -l --json (cwd=%s) exited %d", dir, exit)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(stdoutJSON), &cfg); err != nil {
		return nil, nil, fmt.Errorf("npm config ls -l --json (cwd=%s) decode: %w", dir, err)
	}
	stdoutText, _, _, _ := d.exec.RunInDir(ctx, dir, 15*time.Second, "npm", "config", "ls", "-l")
	sources := parseSourceAttribution(stdoutText)
	return cfg, sources, nil
}

// computeOverrides diffs a project-cwd effective config against the baseline
// (typically $HOME) and returns the keys whose effective value changes.
// Auth-scoped keys are flagged so the renderer can surface them prominently.
func computeOverrides(baseline map[string]any, baselineSrc map[string]string, project map[string]any, projectSrc map[string]string) []model.NPMRCOverride {
	if baseline == nil || project == nil {
		return nil
	}

	// Walk every key in either map. Skip keys that come from npm's own
	// defaults on both sides — those are noise, not overrides the project
	// caused.
	seen := make(map[string]struct{}, len(baseline)+len(project))
	for k := range baseline {
		seen[k] = struct{}{}
	}
	for k := range project {
		seen[k] = struct{}{}
	}

	var out []model.NPMRCOverride
	for key := range seen {
		bv, bok := baseline[key]
		pv, pok := project[key]

		bsrc := baselineSrc[key]
		psrc := projectSrc[key]

		if bok && pok && jsonEqual(bv, pv) {
			continue // value unchanged
		}
		if !bok && !pok {
			continue
		}
		// Value identical AND both sides come from npm's compiled-in
		// defaults — no override happened.
		if jsonEqual(bv, pv) && bsrc == "default" && psrc == "default" {
			continue
		}

		ov := model.NPMRCOverride{
			Key:            key,
			BaselineValue:  formatOverrideValue(bv, bok),
			BaselineSource: bsrc,
			ProjectValue:   formatOverrideValue(pv, pok),
			ProjectSource:  psrc,
			IsAuth:         isAuthKey(key),
		}
		switch {
		case !bok:
			ov.IsNew = true
		case !pok:
			ov.IsRemoved = true
		}
		out = append(out, ov)
	}

	// Stable order: auth keys first (most actionable), then alphabetical.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsAuth != out[j].IsAuth {
			return out[i].IsAuth
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// formatOverrideValue stringifies a config value for display. Returns
// "<unset>" when the key wasn't present at all (distinct from being set to
// an empty string or null).
func formatOverrideValue(v any, present bool) string {
	if !present {
		return "<unset>"
	}
	if v == nil {
		return "null"
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// jsonEqual compares two values that came out of json.Unmarshal. Strings,
// numbers, and bools work as-is; slices/maps go through fmt.Sprintf which is
// good enough for this detection (we'd rather false-positive than miss a
// real change).
func jsonEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
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

// defaultGitTracked shells out to git to check if a file is tracked.
// Returns false on any error (git not installed, not in a repo, untracked).
func (d *NPMRCDetector) defaultGitTracked(ctx context.Context, path string) bool {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	_, _, exit, err := d.exec.RunWithTimeout(ctx, 5*time.Second, "git", "-C", dir, "ls-files", "--error-unmatch", base)
	return err == nil && exit == 0
}

// defaultInGitRepo walks parent directories looking for a .git entry.
// Stops at the filesystem root.
func defaultInGitRepo(path string) bool {
	dir := filepath.Dir(path)
	for {
		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitPath); err == nil {
			// .git can be a directory (regular repo) or a file (worktree).
			_ = info
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// sha256Hex returns the hex SHA-256 of a string.
func sha256Hex(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
