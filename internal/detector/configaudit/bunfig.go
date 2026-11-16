package configaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/execguard"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"github.com/step-security/dev-machine-guard/internal/versionmeta"
)

// maxBunfigFiles bounds the payload on pathological monorepos.
const maxBunfigFiles = 500

var bunEnvVars = []string{
	"BUN_CONFIG_REGISTRY",
	"BUN_CONFIG_TOKEN",
	"BUN_INSTALL",
	"BUN_INSTALL_BIN",
	"BUN_INSTALL_CACHE_DIR",
	"BUN_INSTALL_GLOBAL_DIR",
	"BUN_CONFIG_NO_CLEAR_TERMINAL_ON_RELOAD",
	"NPM_CONFIG_REGISTRY",
	"npm_config_registry",
	"NPM_CONFIG_TOKEN",
	"npm_config_token",
	"NPM_CONFIG_USERCONFIG",
	"npm_config_userconfig",
	"NPM_TOKEN",
	"NODE_OPTIONS",
	"NODE_TLS_REJECT_UNAUTHORIZED",
}

// BunDetector audits bun: the one global .bunfig.toml bun selects, project
// bunfig.toml files, plus any .npmrc bun would read as an auth side-channel.
type BunDetector struct {
	exec    executor.Executor
	skipper *tcc.Skipper
	log     *progress.Logger

	ownerLookup func(path string) ownerInfo
	gitTracked  func(ctx context.Context, path string) bool
	inGitRepo   func(path string) bool
}

// NewBunDetector returns a detector with platform-specific hooks wired in.
func NewBunDetector(exec executor.Executor) *BunDetector {
	d := &BunDetector{exec: exec, log: progress.NewNoop()}
	d.ownerLookup = statOwner
	d.gitTracked = func(ctx context.Context, p string) bool { return gitTrackedViaExec(ctx, exec, p) }
	d.inGitRepo = defaultInGitRepo
	return d
}

// WithLogger injects a logger (used to surface exec fallbacks when metadata
// version resolution misses). Chainable, like WithSkipper.
func (d *BunDetector) WithLogger(log *progress.Logger) *BunDetector {
	if log != nil {
		d.log = log
	}
	return d
}

// WithSkipper attaches a TCC skipper so discovery skips macOS-protected dirs.
func (d *BunDetector) WithSkipper(s *tcc.Skipper) *BunDetector {
	d.skipper = s
	return d
}

// Detect runs the full bun audit.
func (d *BunDetector) Detect(ctx context.Context, searchDirs []string, loggedInUser *user.User) model.BunAudit {
	audit := model.BunAudit{
		Files:              []model.BunConfigFile{},
		NPMRCFiles:         []model.NPMRCFile{},
		Env:                collectEnvVars(d.exec, bunEnvVars),
		ConfigAuditVersion: jsConfigAuditVersion,
	}
	homeDir := homeOf(loggedInUser)

	if path, err := d.exec.LookPath("bun"); err == nil {
		audit.Available = true
		audit.BunPath = path
		audit.BunVersion = d.bunVersion(ctx, homeDir)
		audit.ContextDirectory = homeDir
	}

	files := make([]model.BunConfigFile, 0, 4)
	seen := make(map[string]bool)
	add := func(scope, path, applies string) {
		if path == "" {
			return
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if seen[path] {
			return
		}
		seen[path] = true
		f := d.collectFile(ctx, path, scope)
		f.RuntimeApplicability = applies
		files = append(files, f)
	}

	// Bun loads exactly one global .bunfig.toml and never falls back when
	// the selected file is missing: an absolute XDG_CONFIG_HOME wins; an
	// empty or relative one is skipped from 1.4.4 but used by older bun.
	xdg := d.exec.Getenv("XDG_CONFIG_HOME")
	ver, known := semver3(audit.BunVersion)
	useXDG := filepath.IsAbs(xdg) || (xdg != "" && known && slices.Compare(ver[:], []int{1, 4, 4}) < 0)
	ambiguous := xdg != "" && !filepath.IsAbs(xdg) && !known
	if xdg != "" {
		add("user-xdg", filepath.Join(xdg, ".bunfig.toml"), applicability(!ambiguous, useXDG))
	}
	if homeDir != "" {
		add("user", filepath.Join(homeDir, ".bunfig.toml"), applicability(!ambiguous, !useXDG))
	}

	for _, dir := range searchDirs {
		for _, p := range d.findProjectBunfigs(ctx, dir) {
			if len(files) >= maxBunfigFiles {
				break
			}
			add("project", p, "unknown")
		}
	}

	audit.Files = files
	audit.NPMRCFiles = d.discoverAuthSideChannel(ctx, searchDirs, homeDir, xdg)
	return audit
}

// discoverAuthSideChannel lists the .npmrc files bun reads for registry
// auth, using bun's own selection rather than npm's: one user file
// (NPM_CONFIG_USERCONFIG, else an existing $XDG_CONFIG_HOME/.npmrc, else
// ~/.npmrc), then project files. Bun has no builtin/global npmrc.
//
// NB: the .npmrc walk overlaps with the npm + pnpm audits; if scan time
// becomes a concern, share results across detectors.
func (d *BunDetector) discoverAuthSideChannel(ctx context.Context, searchDirs []string, homeDir, xdg string) []model.NPMRCFile {
	side := NewNPMRCDetector(d.exec)
	side.skipper = d.skipper
	side.ownerLookup = d.ownerLookup
	side.gitTracked = d.gitTracked
	side.inGitRepo = d.inGitRepo

	out := []model.NPMRCFile{}
	seen := map[string]bool{}
	add := func(scope, path, applies string) {
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if key := pathKey(d.exec, path); !seen[key] {
			seen[key] = true
			f := side.collectFile(ctx, path, scope)
			f.RuntimeApplicability = applies
			out = append(out, f)
		}
	}

	userConfig, applies := firstEnv(d.exec, "NPM_CONFIG_USERCONFIG", "npm_config_userconfig"), "applicable"
	switch {
	case userConfig != "":
		if !filepath.IsAbs(userConfig) {
			applies = "unknown" // bun resolves it against the project dir
		}
	case filepath.IsAbs(xdg) && d.exec.FileExists(filepath.Join(xdg, ".npmrc")):
		userConfig = filepath.Join(xdg, ".npmrc")
	case homeDir != "":
		userConfig = filepath.Join(homeDir, ".npmrc")
	}
	if userConfig != "" {
		add("user", userConfig, applies)
	}
	for _, dir := range searchDirs {
		for _, p := range side.findProjectNPMRCs(ctx, dir) {
			if len(out) >= maxNPMRCFiles {
				break
			}
			add("project", p, "unknown")
		}
	}
	return out
}

// findProjectBunfigs walks dir for `bunfig.toml` files, applying the same
// skip rules as the npmrc walker. Returns absolute paths.
func (d *BunDetector) findProjectBunfigs(ctx context.Context, dir string) []string {
	if dir == "" {
		return nil
	}
	var results []string
	_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
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
		if entry.Name() == "bunfig.toml" {
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

// collectFile gathers metadata + parses a bunfig.toml. Non-existent files
// surface with Exists=false.
func (d *BunDetector) collectFile(ctx context.Context, path, scope string) model.BunConfigFile {
	f := model.BunConfigFile{Path: path, Scope: scope}

	linfo, err := os.Lstat(path)
	if err != nil {
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

	// #nosec G304 -- path comes from the detector's own candidate enumeration
	// (user-scope well-known locations + project walk).
	data, err := os.ReadFile(path)
	if err != nil {
		f.Readable = false
		f.ParseError = "read: " + err.Error()
		return f
	}
	f.Readable = true

	sum := sha256.Sum256(data)
	f.SHA256 = hex.EncodeToString(sum[:])

	sections, perr := parseBunfig(data)
	if perr != nil {
		f.ParseError = "invalid toml" // decoder text can quote secrets
	}
	f.Sections = sections

	if d.inGitRepo != nil && d.inGitRepo(path) {
		f.InGitRepo = true
		if d.gitTracked != nil && d.gitTracked(ctx, path) {
			f.GitTracked = true
		}
	}
	return f
}

// bunVersion returns the bun CLI's version string, "unknown" on failure.
// The exec fallback runs from home, like Yarn's.
func (d *BunDetector) bunVersion(ctx context.Context, home string) string {
	// Static-first, exec-last (AGENTS.md §3.4): bun's Homebrew install path
	// encodes the version; other installs fall through to exec.
	// Run the exact absolute path the guard assessed, not the bare name —
	// a PATH re-resolution at exec time could pick a different (unassessed)
	// binary. The name is only used when LookPath itself failed.
	target := "bun"
	if path, err := d.exec.LookPath("bun"); err == nil {
		if v := versionmeta.FromBinary(ctx, d.exec, path); v != "" {
			return v
		}
		if safe, reason := execguard.SafeToExec(ctx, d.exec, path); !safe {
			d.log.Warn("skipping %s version probe: %s", path, reason)
			return "unknown"
		}
		target = path
	}
	if home == "" {
		return "unknown"
	}
	d.log.Progress("exec fallback: running %s --version (no metadata version source)", target)
	stdout, _, exit, _ := d.exec.RunInDir(ctx, home, 5*time.Second, target, "--version")
	if exit != 0 {
		return "unknown"
	}
	v := strings.TrimSpace(stdout)
	if v == "" {
		return "unknown"
	}
	return v
}
