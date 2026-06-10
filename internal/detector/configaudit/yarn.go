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

	ownerLookup func(path string) ownerInfo
	gitTracked  func(ctx context.Context, path string) bool
	inGitRepo   func(path string) bool
}

// NewYarnDetector returns a detector with platform-specific hooks wired in.
func NewYarnDetector(exec executor.Executor) *YarnDetector {
	d := &YarnDetector{exec: exec}
	d.ownerLookup = statOwner
	d.gitTracked = func(ctx context.Context, p string) bool { return gitTrackedViaExec(ctx, exec, p) }
	d.inGitRepo = defaultInGitRepo
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
		Files:      []model.YarnConfigFile{},
		NPMRCFiles: []model.NPMRCFile{},
		Env:        d.collectEnv(),
	}

	if path, err := d.exec.LookPath("yarn"); err == nil {
		audit.Available = true
		audit.YarnPath = path
		audit.YarnVersion = d.yarnVersion(ctx)
		audit.Flavor = yarnFlavorFromVersion(audit.YarnVersion)
	}

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
		files = append(files, d.collectFile(ctx, path, scope, flavor))
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
		add("user", "classic", filepath.Join(homeDir, ".yarnrc"))
		add("user", "berry", filepath.Join(homeDir, ".yarnrc.yml"))
	}

	for _, dir := range searchDirs {
		for _, p := range d.findProjectYarnConfigs(dir) {
			if len(files) >= maxYarnFiles {
				break
			}
			scope := "project"
			flavor := yarnFlavorFromFilename(filepath.Base(p))
			add(scope, flavor, p)
		}
	}

	audit.Files = files
	audit.NPMRCFiles = d.discoverAuthSideChannel(ctx, searchDirs, loggedInUser)
	return audit
}

// discoverAuthSideChannel reuses the npmrc walker for any .npmrc yarn reads
// for auth. builtin/global belong to npm proper and are dropped. See the
// bun-side note about overlapping work — same caveat applies.
func (d *YarnDetector) discoverAuthSideChannel(ctx context.Context, searchDirs []string, loggedInUser *user.User) []model.NPMRCFile {
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

// findProjectYarnConfigs walks dir for both `.yarnrc` and `.yarnrc.yml`,
// applying the same skip rules as the npmrc walker.
func (d *YarnDetector) findProjectYarnConfigs(dir string) []string {
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
		if entry.Name() == ".yarnrc" || entry.Name() == ".yarnrc.yml" {
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
			f.ParseError = perr.Error()
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
func (d *YarnDetector) yarnVersion(ctx context.Context) string {
	stdout, _, exit, _ := d.exec.RunWithTimeout(ctx, 5*time.Second, "yarn", "--version")
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

// yarnFlavorFromFilename returns "berry" for `.yarnrc.yml`, "classic" otherwise.
func yarnFlavorFromFilename(name string) string {
	if name == ".yarnrc.yml" {
		return "berry"
	}
	return "classic"
}

func (d *YarnDetector) collectEnv() []model.NPMRCEnvVar {
	out := make([]model.NPMRCEnvVar, 0, len(yarnEnvVars))
	for _, name := range yarnEnvVars {
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
