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
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
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
	"NPM_TOKEN",
	"NODE_OPTIONS",
	"NODE_TLS_REJECT_UNAUTHORIZED",
}

// BunDetector audits bun: bunfig.toml at user + XDG + project scopes, plus
// any .npmrc bun would read as an auth side-channel.
type BunDetector struct {
	exec    executor.Executor
	skipper *tcc.Skipper

	ownerLookup func(path string) ownerInfo
	gitTracked  func(ctx context.Context, path string) bool
	inGitRepo   func(path string) bool
}

// NewBunDetector returns a detector with platform-specific hooks wired in.
func NewBunDetector(exec executor.Executor) *BunDetector {
	d := &BunDetector{exec: exec}
	d.ownerLookup = statOwner
	d.gitTracked = func(ctx context.Context, p string) bool { return gitTrackedViaExec(ctx, exec, p) }
	d.inGitRepo = defaultInGitRepo
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
		Files:      []model.BunConfigFile{},
		NPMRCFiles: []model.NPMRCFile{},
		Env:        d.collectEnv(),
	}

	if path, err := d.exec.LookPath("bun"); err == nil {
		audit.Available = true
		audit.BunPath = path
		audit.BunVersion = d.bunVersion(ctx)
	}

	files := make([]model.BunConfigFile, 0, 4)
	seen := make(map[string]bool)
	add := func(scope, path string) {
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
		files = append(files, d.collectFile(ctx, path, scope))
	}

	homeDir := ""
	if loggedInUser != nil {
		homeDir = loggedInUser.HomeDir
	}
	if homeDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			homeDir = h
		}
	}
	if homeDir != "" {
		add("user", filepath.Join(homeDir, ".bunfig.toml"))
		xdgHome := d.exec.Getenv("XDG_CONFIG_HOME")
		if xdgHome == "" {
			xdgHome = filepath.Join(homeDir, ".config")
		}
		add("user-xdg", filepath.Join(xdgHome, ".bunfig.toml"))
	}

	for _, dir := range searchDirs {
		for _, p := range d.findProjectBunfigs(dir) {
			if len(files) >= maxBunfigFiles {
				break
			}
			add("project", p)
		}
	}

	audit.Files = files
	audit.NPMRCFiles = d.discoverAuthSideChannel(ctx, searchDirs, loggedInUser)
	return audit
}

// discoverAuthSideChannel reuses the npmrc walker for any .npmrc bun reads
// for registry auth. builtin/global belong to npm proper and are dropped;
// only user + project scopes — the ones bun actually consumes — are kept.
//
// NB: this re-invokes the full NPMRCDetector (npm subprocess calls + a fresh
// searchDirs walk). The .npmrc walk overlaps with the npm + pnpm audits; if
// scan time becomes a concern, share results across detectors.
func (d *BunDetector) discoverAuthSideChannel(ctx context.Context, searchDirs []string, loggedInUser *user.User) []model.NPMRCFile {
	side := NewNPMRCDetector(d.exec)
	side.skipper = d.skipper
	side.ownerLookup = d.ownerLookup
	side.gitTracked = d.gitTracked
	side.inGitRepo = d.inGitRepo
	audit := side.Detect(ctx, searchDirs, loggedInUser)
	out := make([]model.NPMRCFile, 0, len(audit.Files))
	for _, f := range audit.Files {
		if f.Scope == "builtin" || f.Scope == "global" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// findProjectBunfigs walks dir for `bunfig.toml` files, applying the same
// skip rules as the npmrc walker. Returns absolute paths.
func (d *BunDetector) findProjectBunfigs(dir string) []string {
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
		f.ParseError = perr.Error()
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
func (d *BunDetector) bunVersion(ctx context.Context) string {
	stdout, _, exit, _ := d.exec.RunWithTimeout(ctx, 5*time.Second, "bun", "--version")
	if exit != 0 {
		return "unknown"
	}
	v := strings.TrimSpace(stdout)
	if v == "" {
		return "unknown"
	}
	return v
}

func (d *BunDetector) collectEnv() []model.NPMRCEnvVar {
	out := make([]model.NPMRCEnvVar, 0, len(bunEnvVars))
	for _, name := range bunEnvVars {
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
