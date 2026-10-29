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

	"github.com/step-security/dev-machine-guard/internal/execguard"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"github.com/step-security/dev-machine-guard/internal/versionmeta"
)

// yarnEnvVars: classic and berry env names in one stable list. Berry's
// YARN_NPM_* keys override .yarnrc.yml; classic honors YARN_REGISTRY.
var yarnEnvVars = []string{
	"YARN_REGISTRY",
	"YARN_NPM_REGISTRY_SERVER",
	"YARN_NPM_AUTH_TOKEN",
	"YARN_NPM_AUTH_IDENT",
	"YARN_NPM_ALWAYS_AUTH",
	"YARN_ENABLE_STRICT_SSL",
	"YARN_ENABLE_SCRIPTS",
	"YARN_ENABLE_IMMUTABLE_INSTALLS",
	"YARN_HTTP_PROXY",
	"YARN_HTTPS_PROXY",
	"YARN_UNSAFE_HTTP_WHITELIST",
	"YARN_NPM_MINIMAL_AGE_GATE",
	"YARN_NPM_PREAPPROVED_PACKAGES",
	"YARN_RC_FILENAME",
	"NPM_TOKEN",
	"NPM_CONFIG_REGISTRY",
	"NODE_OPTIONS",
	"NODE_TLS_REJECT_UNAUTHORIZED",
}

// maxYarnFiles bounds the payload on pathological monorepos.
const maxYarnFiles = 1000

// YarnDetector audits both yarn flavors. Both file shapes are always
// discovered — a v1 binary with a berry file (or vice versa) is itself a
// signal the renderer surfaces.
type YarnDetector struct {
	exec    executor.Executor
	skipper *tcc.Skipper
	log     *progress.Logger

	ownerLookup func(path string) ownerInfo
	gitTracked  func(ctx context.Context, path string) bool
	inGitRepo   func(path string) bool
}

// NewYarnDetector returns a detector with platform-specific hooks wired in.
func NewYarnDetector(exec executor.Executor) *YarnDetector {
	d := &YarnDetector{exec: exec, log: progress.NewNoop()}
	d.ownerLookup = statOwner
	d.gitTracked = func(ctx context.Context, p string) bool { return gitTrackedViaExec(ctx, exec, p) }
	d.inGitRepo = defaultInGitRepo
	return d
}

// WithLogger injects a logger (used to surface exec fallbacks when metadata
// version resolution misses). Chainable, like WithSkipper.
func (d *YarnDetector) WithLogger(log *progress.Logger) *YarnDetector {
	if log != nil {
		d.log = log
	}
	return d
}

// WithSkipper attaches a TCC skipper so discovery skips macOS-protected dirs.
func (d *YarnDetector) WithSkipper(s *tcc.Skipper) *YarnDetector {
	d.skipper = s
	return d
}

// Detect runs the full yarn audit.
func (d *YarnDetector) Detect(ctx context.Context, searchDirs []string, loggedInUser *user.User) model.YarnAudit {
	audit := model.YarnAudit{
		Files:              []model.YarnConfigFile{},
		NPMRCFiles:         []model.NPMRCFile{},
		Env:                collectEnvVars(d.exec, yarnEnvVars),
		ConfigAuditVersion: jsConfigAuditVersion,
	}
	homeDir := homeOf(loggedInUser)

	if path, err := d.exec.LookPath("yarn"); err == nil {
		audit.Available = true
		audit.YarnPath = path
		audit.YarnVersion = d.yarnVersion(ctx, homeDir)
		audit.Flavor = yarnFlavorFromVersion(audit.YarnVersion)
		audit.ContextDirectory = homeDir
	}
	// Modern Yarn looks for a custom rc filename in the project and its
	// ancestors; the home rc is always .yarnrc.yml.
	rcName := firstEnv(d.exec, "YARN_RC_FILENAME", "yarn_rc_filename")

	files := make([]model.YarnConfigFile, 0, 4)
	seen := make(map[string]bool)
	add := func(scope, flavor, path string) {
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
		f := d.collectFile(ctx, path, scope, flavor)
		f.RuntimeApplicability = yarnApplicability(audit.Flavor, f, rcName)
		files = append(files, f)
	}

	if homeDir != "" {
		add("user", "classic", filepath.Join(homeDir, ".yarnrc"))
		add("user", "berry", filepath.Join(homeDir, ".yarnrc.yml"))
		// Yarn run from home (the capture context) reads the custom name
		// there too, whatever the search roots are.
		if rcName != "" {
			add("user", "berry", filepath.Join(homeDir, rcName))
		}
	}

	for _, dir := range searchDirs {
		for _, p := range d.findProjectYarnConfigs(ctx, dir, rcName) {
			if len(files) >= maxYarnFiles {
				break
			}
			scope := "project"
			flavor := yarnFlavorFromFilename(filepath.Base(p), rcName)
			add(scope, flavor, p)
		}
	}

	audit.Files = files
	audit.NPMRCFiles = d.discoverAuthSideChannel(ctx, searchDirs, loggedInUser, audit.Flavor)
	return audit
}

// yarnApplicability: a Yarn binary reads only its own flavor's files —
// Classic reads .yarnrc (and .npmrc), Modern reads .yarnrc.yml, or the
// YARN_RC_FILENAME name in projects. The home binary decides user files;
// a project can select another Yarn (Corepack, yarnPath), so its files stay
// unknown unless no Yarn would read them.
func yarnApplicability(binFlavor string, f model.YarnConfigFile, rcName string) string {
	switch {
	case f.Scope != "user":
		if f.Flavor == "berry" && rcName != "" && filepath.Base(f.Path) != rcName {
			return "ignored"
		}
		return "unknown"
	case binFlavor != "classic" && binFlavor != "berry":
		return "unknown"
	case f.Flavor != binFlavor:
		return "ignored"
	}
	return "applicable"
}

// discoverAuthSideChannel reuses the npmrc walker for any .npmrc yarn reads
// for auth. builtin/global belong to npm proper and are dropped. Only
// Classic reads .npmrc; Modern Yarn ignores it. See the bun-side note about
// overlapping work — same caveat applies.
func (d *YarnDetector) discoverAuthSideChannel(ctx context.Context, searchDirs []string, loggedInUser *user.User, flavor string) []model.NPMRCFile {
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
		switch {
		case f.Scope != "user":
		case flavor == "berry":
			f.RuntimeApplicability = "ignored"
		case flavor != "classic":
			f.RuntimeApplicability = "unknown"
		}
		out = append(out, f)
	}
	return out
}

// findProjectYarnConfigs walks dir for `.yarnrc`, `.yarnrc.yml` and any
// custom rc filename, applying the same skip rules as the npmrc walker.
// Yarn also reads these names in every ancestor of a project, so existing
// ones above dir are included.
func (d *YarnDetector) findProjectYarnConfigs(ctx context.Context, dir, rcName string) []string {
	if dir == "" {
		return nil
	}
	isRC := func(name string) bool {
		return name == ".yarnrc" || name == ".yarnrc.yml" || (rcName != "" && name == rcName)
	}
	var results []string
	if abs, err := filepath.Abs(dir); err == nil {
		for p := filepath.Dir(abs); ; p = filepath.Dir(p) {
			if ctx.Err() != nil {
				return nil
			}
			for _, name := range []string{".yarnrc", ".yarnrc.yml", rcName} {
				c := filepath.Join(p, name)
				if info, err := os.Lstat(c); name != "" && err == nil && !info.IsDir() {
					results = append(results, c)
				}
			}
			if filepath.Dir(p) == p {
				break
			}
		}
	}
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
		if isRC(entry.Name()) {
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

// collectFile gathers metadata + parses a yarn config file. Flavor selects
// the parser: classic for `.yarnrc`, berry for `.yarnrc.yml`.
func (d *YarnDetector) collectFile(ctx context.Context, path, scope, flavor string) model.YarnConfigFile {
	f := model.YarnConfigFile{Path: path, Scope: scope, Flavor: flavor}

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

	// #nosec G304 -- path comes from the detector's own candidate enumeration.
	data, err := os.ReadFile(path)
	if err != nil {
		f.Readable = false
		f.ParseError = "read: " + err.Error()
		return f
	}
	f.Readable = true

	sum := sha256.Sum256(data)
	f.SHA256 = hex.EncodeToString(sum[:])

	switch flavor {
	case "berry":
		entries, perr := parseYarnBerry(data)
		if perr != nil {
			f.ParseError = "invalid yaml" // decoder text can quote secrets
		}
		f.Entries = entries
	default:
		f.Entries = parseYarnClassic(data)
	}

	if d.inGitRepo != nil && d.inGitRepo(path) {
		f.InGitRepo = true
		if d.gitTracked != nil && d.gitTracked(ctx, path) {
			f.GitTracked = true
		}
	}
	return f
}

// yarnVersion returns the yarn CLI's version string, "unknown" on failure.
// The exec fallback runs from home so Corepack and version managers resolve
// the developer's default Yarn, not a project pin in the agent's cwd.
func (d *YarnDetector) yarnVersion(ctx context.Context, home string) string {
	// Static-first, exec-last (AGENTS.md §3.4): classic yarn is an npm
	// package whose manifest carries the version; a corepack shim's manifest
	// won't match "yarn" and falls through to exec.
	// Run the exact absolute path the guard assessed, not the bare name —
	// a PATH re-resolution at exec time could pick a different (unassessed)
	// binary. The name is only used when LookPath itself failed.
	target := "yarn"
	if path, err := d.exec.LookPath("yarn"); err == nil {
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

// yarnFlavorFromVersion maps a yarn --version string to flavor. v0.x and v1.x
// are "classic"; 2+ is "berry"; "unknown" when unparseable.
func yarnFlavorFromVersion(v string) string {
	if v == "" || v == "unknown" {
		return "unknown"
	}
	if strings.HasPrefix(v, "1.") || v == "1" {
		return "classic"
	}
	if dot := strings.IndexByte(v, '.'); dot > 0 {
		major := v[:dot]
		if major == "0" || major == "1" {
			return "classic"
		}
		return "berry"
	}
	return "unknown"
}

// yarnFlavorFromFilename returns "berry" for `.yarnrc.yml` or the custom
// YARN_RC_FILENAME, "classic" otherwise.
func yarnFlavorFromFilename(name, rcName string) string {
	if name == ".yarnrc.yml" || (rcName != "" && name == rcName) {
		return "berry"
	}
	return "classic"
}
