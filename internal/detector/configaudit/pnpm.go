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
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// pnpmEnvVars: pnpm-specific names plus the npm_config_* lowercase variants
// pnpm honors for back-compat.
var pnpmEnvVars = []string{
	"PNPM_HOME",
	"PNPM_CONFIG_REGISTRY",
	"PNPM_CONFIG_USERCONFIG",
	"PNPM_CONFIG_GLOBALCONFIG",
	"PNPM_CONFIG_STORE_DIR",
	"PNPM_CONFIG_VIRTUAL_STORE_DIR",
	"PNPM_CONFIG_MIN_RELEASE_AGE",
	"NPM_TOKEN",
	"NPM_CONFIG_REGISTRY",
	"npm_config_registry",
	"npm_config__authToken",
	"COREPACK_ENABLE_STRICT",
	"COREPACK_HOME",
	"NODE_OPTIONS",
	"NODE_TLS_REJECT_UNAUTHORIZED",
}

// PnpmDetector audits pnpm configuration. pnpm reads the same .npmrc syntax
// as npm; only the effective view (different key set, no source attribution)
// and env-var list diverge.
type PnpmDetector struct {
	exec    executor.Executor
	skipper *tcc.Skipper

	ownerLookup func(path string) ownerInfo
	gitTracked  func(ctx context.Context, path string) bool
	inGitRepo   func(path string) bool
}

// NewPnpmDetector returns a detector with platform-specific hooks wired in.
func NewPnpmDetector(exec executor.Executor) *PnpmDetector {
	d := &PnpmDetector{exec: exec}
	d.ownerLookup = statOwner
	d.gitTracked = func(ctx context.Context, p string) bool { return gitTrackedViaExec(ctx, exec, p) }
	d.inGitRepo = defaultInGitRepo
	return d
}

// WithSkipper attaches a TCC skipper so .npmrc discovery skips macOS-protected
// directories. nil is a no-op. Returns the detector for chaining.
func (d *PnpmDetector) WithSkipper(s *tcc.Skipper) *PnpmDetector {
	d.skipper = s
	return d
}

// Detect runs the full pnpm audit.
func (d *PnpmDetector) Detect(ctx context.Context, searchDirs []string, loggedInUser *user.User) model.PnpmAudit {
	audit := model.PnpmAudit{
		Files: []model.NPMRCFile{},
		Env:   d.collectEnv(),
	}

	if path, err := d.exec.LookPath("pnpm"); err == nil {
		audit.Available = true
		audit.PnpmPath = path
		audit.PnpmVersion = d.pnpmVersion(ctx)
	}

	files := make([]model.NPMRCFile, 0, 8)
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

	// pnpm has no `builtinconfig` equivalent; only global/user/project apply.
	if v := d.exec.Getenv("PNPM_CONFIG_GLOBALCONFIG"); v != "" {
		add("global", v)
	} else {
		add("global", d.pnpmConfigGet(ctx, "globalconfig"))
	}

	if v := d.exec.Getenv("PNPM_CONFIG_USERCONFIG"); v != "" {
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
	if audit.Available {
		audit.Effective = d.captureEffective(ctx)
	}
	return audit
}

// findProjectNPMRCs walks dir for .npmrc files using the same skip rules as
// the npm detector. Returns absolute paths.
func (d *PnpmDetector) findProjectNPMRCs(dir string) []string {
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

// collectFile mirrors the npm-side per-file metadata collection. Always
// returns a record; non-existent files surface with Exists=false.
func (d *PnpmDetector) collectFile(ctx context.Context, path, scope string) model.NPMRCFile {
	f := model.NPMRCFile{Path: path, Scope: scope}

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
	// of well-known npmrc locations; not external input.
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

// captureEffective runs `pnpm config list --json`. SourceByKey stays empty —
// pnpm doesn't emit per-key source attribution like `npm config ls -l` does.
func (d *PnpmDetector) captureEffective(ctx context.Context) *model.PnpmEffective {
	eff := &model.PnpmEffective{
		SourceByKey: map[string]string{},
		Config:      map[string]any{},
	}
	stdout, _, exit, _ := d.exec.RunWithTimeout(ctx, 15*time.Second, "pnpm", "config", "list", "--json")
	if exit != 0 || strings.TrimSpace(stdout) == "" {
		eff.Error = fmt.Sprintf("pnpm config list --json exited %d", exit)
		return eff
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		eff.Error = "json decode: " + err.Error()
		return eff
	}
	eff.Config = parsed
	return eff
}

// pnpmVersion returns the pnpm CLI's version string, "unknown" on failure.
func (d *PnpmDetector) pnpmVersion(ctx context.Context) string {
	stdout, _, exit, _ := d.exec.RunWithTimeout(ctx, 5*time.Second, "pnpm", "--version")
	if exit != 0 {
		return "unknown"
	}
	v := strings.TrimSpace(stdout)
	if v == "" {
		return "unknown"
	}
	return v
}

// pnpmConfigGet runs `pnpm config get <key>` and returns the trimmed value,
// or empty if the call failed or the value is pnpm's literal "undefined".
func (d *PnpmDetector) pnpmConfigGet(ctx context.Context, key string) string {
	stdout, _, exit, _ := d.exec.RunWithTimeout(ctx, 5*time.Second, "pnpm", "config", "get", key)
	if exit != 0 {
		return ""
	}
	v := strings.TrimSpace(stdout)
	if v == "undefined" || v == "null" {
		return ""
	}
	return v
}

func (d *PnpmDetector) collectEnv() []model.NPMRCEnvVar {
	out := make([]model.NPMRCEnvVar, 0, len(pnpmEnvVars))
	for _, name := range pnpmEnvVars {
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
