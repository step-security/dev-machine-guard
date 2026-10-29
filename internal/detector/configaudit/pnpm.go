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
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// pnpmEnvVars: pnpm-specific names plus the npm_config_* variants pnpm
// honors. pnpm 11+ reads only all-lowercase or all-uppercase pnpm_config_*
// names; pnpm 10 reads npm_config_* in any case.
var pnpmEnvVars = []string{
	"PNPM_HOME",
	"PNPM_CONFIG_REGISTRY",
	"PNPM_CONFIG_USERCONFIG",
	"pnpm_config_userconfig",
	"PNPM_CONFIG_NPMRC_AUTH_FILE",
	"pnpm_config_npmrc_auth_file",
	"PNPM_CONFIG_GLOBALCONFIG",
	"PNPM_CONFIG_STORE_DIR",
	"PNPM_CONFIG_VIRTUAL_STORE_DIR",
	"PNPM_CONFIG_MIN_RELEASE_AGE",
	"PNPM_CONFIG_MINIMUM_RELEASE_AGE",
	"pnpm_config_minimum_release_age",
	"PNPM_CONFIG_MINIMUM_RELEASE_AGE_EXCLUDE",
	"pnpm_config_minimum_release_age_exclude",
	"PNPM_CONFIG_MINIMUM_RELEASE_AGE_STRICT",
	"pnpm_config_minimum_release_age_strict",
	"PNPM_CONFIG_MINIMUM_RELEASE_AGE_IGNORE_MISSING_TIME",
	"pnpm_config_minimum_release_age_ignore_missing_time",
	"NPM_CONFIG_MINIMUM_RELEASE_AGE",
	"npm_config_minimum_release_age",
	"NPM_CONFIG_USERCONFIG",
	"npm_config_userconfig",
	"NPM_TOKEN",
	"NPM_CONFIG_REGISTRY",
	"npm_config_registry",
	"npm_config__authToken",
	"COREPACK_ENABLE_STRICT",
	"COREPACK_HOME",
	"NODE_OPTIONS",
	"NODE_TLS_REJECT_UNAUTHORIZED",
}

// PnpmDetector audits pnpm configuration: .npmrc-syntax files (native rc,
// auth.ini, user and project .npmrc) and, from pnpm 11, YAML settings in the
// native config.yaml and pnpm-workspace.yaml.
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
		Files:              []model.NPMRCFile{},
		Env:                collectEnvVars(d.exec, pnpmEnvVars),
		ConfigAuditVersion: jsConfigAuditVersion,
	}
	home := homeOf(loggedInUser)

	if path, err := d.exec.LookPath("pnpm"); err == nil {
		audit.Available = true
		audit.PnpmPath = path
		audit.PnpmVersion = d.pnpmVersion(ctx, home)
	}
	ver, known := semver3(audit.PnpmVersion)
	// olderThan is false for an unknown version, so the newest rules apply.
	olderThan := func(v ...int) bool { return known && slices.Compare(ver[:], v) < 0 }
	yamlConfig := !olderThan(11, 0, 0)

	files := make([]model.NPMRCFile, 0, 8)
	seen := make(map[string]bool)
	add := func(scope, path, applies string) {
		if path == "" {
			return
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if key := pathKey(d.exec, path); !seen[key] {
			seen[key] = true
			f := d.collectFile(ctx, path, scope)
			f.RuntimeApplicability = applies
			files = append(files, f)
		}
	}

	// pnpm 10 reads the native rc; 11+ reads config.yaml and auth.ini there
	// and ignores rc. pnpm has no `builtinconfig` equivalent.
	if dir := pnpmConfigDir(d.exec, home); dir != "" {
		// Only recent pnpm expands Windows %VAR% in the dir; never guess.
		dirKnown := known && !strings.Contains(dir, "%")
		add("global", filepath.Join(dir, "rc"), applicability(dirKnown, !yamlConfig))
		add("global", filepath.Join(dir, "config.yaml"), applicability(dirKnown, yamlConfig))
		add("global", filepath.Join(dir, "auth.ini"), applicability(dirKnown, yamlConfig))
	}
	if v := d.exec.Getenv("PNPM_CONFIG_GLOBALCONFIG"); v != "" {
		add("global", v, "unknown")
	} else if !pnpmGlobalQueryUnreliable(ver, known) {
		q := d.pnpmConfigGet(ctx, home, "globalconfig")
		add("global", q, applicability(known, (filepath.Ext(q) == ".yaml") == yamlConfig))
	}

	// The user auth .npmrc: pnpm 10 follows npm's userconfig; 11+ checks its
	// own overrides, then config.yaml's npmrcAuthFile, then npm's userconfig.
	userConfig := ""
	if !yamlConfig {
		userConfig = firstEnv(d.exec, "npm_config_userconfig", "NPM_CONFIG_USERCONFIG")
	} else {
		if !olderThan(11, 0, 6) {
			userConfig = firstEnv(d.exec, "pnpm_config_npmrc_auth_file", "PNPM_CONFIG_NPMRC_AUTH_FILE", "pnpm_config_userconfig", "PNPM_CONFIG_USERCONFIG")
		}
		if userConfig == "" {
			userConfig = pnpmYAMLAuthFile(files)
		}
		if userConfig == "" && !olderThan(11, 0, 9) {
			userConfig = firstEnv(d.exec, "npm_config_userconfig", "NPM_CONFIG_USERCONFIG")
		}
	}
	if userConfig == "" && home != "" {
		userConfig = filepath.Join(home, ".npmrc")
	}
	add("user", resolveInHome(userConfig, home), applicability(known, true))

	for _, dir := range searchDirs {
		for _, p := range d.findProjectNPMRCs(ctx, dir) {
			if len(files) >= maxNPMRCFiles {
				break
			}
			add("project", p, "unknown")
		}
	}

	audit.Files = files
	if audit.Available {
		audit.Effective = d.captureEffective(ctx, home)
	}
	return audit
}

// pnpmConfigDir mirrors pnpm's global config directory lookup. PNPM_HOME is
// the install dir, never the config root.
func pnpmConfigDir(exec executor.Executor, home string) string {
	if xdg := exec.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "pnpm")
	}
	if exec.GOOS() == model.PlatformWindows {
		if local := exec.Getenv("LOCALAPPDATA"); local != "" {
			return filepath.Join(local, "pnpm", "config")
		}
	}
	if home == "" {
		return ""
	}
	if exec.GOOS() == model.PlatformDarwin {
		return filepath.Join(home, "Library", "Preferences", "pnpm")
	}
	return filepath.Join(home, ".config", "pnpm")
}

// pnpmGlobalQueryUnreliable reports versions whose `config get globalconfig`
// answer doesn't match the file pnpm reads; the native dir covers them.
func pnpmGlobalQueryUnreliable(ver [3]int, known bool) bool {
	in := func(lo, hi []int) bool { return slices.Compare(ver[:], lo) >= 0 && slices.Compare(ver[:], hi) < 0 }
	return known && (in([]int{10, 16, 0}, []int{10, 21, 0}) || in([]int{11, 0, 0}, []int{11, 5, 3}))
}

// pnpmYAMLAuthFile returns npmrcAuthFile from an already-collected global
// config.yaml.
func pnpmYAMLAuthFile(files []model.NPMRCFile) string {
	for _, f := range files {
		if f.Format != "yaml" {
			continue
		}
		for _, e := range f.Entries {
			if e.Key == "npmrcAuthFile" {
				return e.DisplayValue
			}
		}
	}
	return ""
}

// resolveInHome resolves `~` and relative paths against home, where pnpm
// runs, instead of the agent's working directory.
func resolveInHome(p, home string) string {
	if home == "" || p == "" || filepath.IsAbs(p) {
		return p
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		p = p[1:]
	}
	return filepath.Join(home, p)
}

// semver3 parses the leading major.minor.patch of a version string.
func semver3(v string) ([3]int, bool) {
	var ver [3]int
	n, _ := fmt.Sscanf(v, "%d.%d.%d", &ver[0], &ver[1], &ver[2])
	return ver, n == 3
}

// findProjectNPMRCs walks dir for .npmrc and pnpm-workspace.yaml files using
// the same skip rules as the npm detector. Returns absolute paths.
func (d *PnpmDetector) findProjectNPMRCs(ctx context.Context, dir string) []string {
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
		if entry.Name() == ".npmrc" || entry.Name() == "pnpm-workspace.yaml" {
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
// returns a record; non-existent files surface with Exists=false. `.yaml`
// files are pnpm settings YAML; everything else is .npmrc syntax.
func (d *PnpmDetector) collectFile(ctx context.Context, path, scope string) model.NPMRCFile {
	f := model.NPMRCFile{Path: path, Scope: scope, Format: "ini"}
	if filepath.Ext(path) == ".yaml" {
		f.Format = "yaml"
	}

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
	if f.Format == "yaml" && info.Size() > maxPnpmYAMLBytes {
		f.ParseError = "file too large"
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
	if f.Format == "yaml" {
		f.Entries, f.ParseError = parsePnpmYAML(data)
	} else {
		f.Entries, f.ParseError = parseNPMRC(data)
	}

	if d.inGitRepo != nil && d.inGitRepo(path) {
		f.InGitRepo = true
		if d.gitTracked != nil && d.gitTracked(ctx, path) {
			f.GitTracked = true
		}
	}
	return f
}

// captureEffective runs `pnpm config list --json` from the developer's home.
// SourceByKey stays empty — pnpm doesn't emit per-key source attribution
// like `npm config ls -l` does. pnpm prints every raw .npmrc key, including
// uncensored `//host/:*` settings and proxy URLs, so only pnpmEffectiveKeys
// are kept.
func (d *PnpmDetector) captureEffective(ctx context.Context, home string) *model.PnpmEffective {
	eff := &model.PnpmEffective{
		SourceByKey: map[string]string{},
		Config:      map[string]any{},
	}
	if home == "" {
		eff.Error = errNoCaptureContext
		return eff
	}
	eff.CaptureDirectory = home
	stdout, _, exit, _ := d.exec.RunInDir(ctx, home, 15*time.Second, "pnpm", "config", "list", "--json")
	parsed, msg := decodeCapture(stdout, exit)
	if msg != "" {
		eff.Error = msg
		return eff
	}
	eff.Config = safeEffective(parsed, isPnpmEffectiveKey)
	return eff
}

// pnpmEffectiveKeys covers registry routing, release-age policy and its
// qualifications, and proxy/TLS settings, in pnpm 10 (kebab) and 11+
// (camel) spellings.
var pnpmEffectiveKeys = map[string]bool{
	"registry": true, "registries": true,
	"minimum-release-age": true, "minimumReleaseAge": true,
	"minimum-release-age-exclude": true, "minimumReleaseAgeExclude": true,
	"minimumReleaseAgeStrict": true, "minimumReleaseAgeIgnoreMissingTime": true, "trustLockfile": true,
	"proxy": true, "httpProxy": true, "https-proxy": true, "httpsProxy": true, "noproxy": true, "noProxy": true,
	"strict-ssl": true, "strictSsl": true,
}

func isPnpmEffectiveKey(k string) bool {
	return pnpmEffectiveKeys[k] || (strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry"))
}

// pnpmVersion returns the pnpm CLI's version string, "unknown" on failure.
func (d *PnpmDetector) pnpmVersion(ctx context.Context, home string) string {
	if home == "" {
		return "unknown"
	}
	stdout, _, exit, _ := d.exec.RunInDir(ctx, home, 5*time.Second, "pnpm", "--version")
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
func (d *PnpmDetector) pnpmConfigGet(ctx context.Context, home, key string) string {
	if home == "" {
		return ""
	}
	stdout, _, exit, _ := d.exec.RunInDir(ctx, home, 5*time.Second, "pnpm", "config", "get", key)
	if exit != 0 {
		return ""
	}
	v := strings.TrimSpace(stdout)
	if v == "undefined" || v == "null" {
		return ""
	}
	return v
}

// maxPnpmYAMLBytes and maxPnpmYAMLEntries bound pnpm YAML reads; depth is
// bounded by rubyYAMLData.
const (
	maxPnpmYAMLBytes   = 1 << 20
	maxPnpmYAMLEntries = 1000
)

// pnpmYAMLKeys are the settings read from config.yaml and
// pnpm-workspace.yaml, with the node kind each must have. Catalogs,
// dependency maps and hooks are never read or executed.
var pnpmYAMLKeys = map[string]yaml.Kind{
	"registry": yaml.ScalarNode, "registries": yaml.MappingNode, "namedRegistries": yaml.MappingNode,
	"minimumReleaseAge": yaml.ScalarNode, "minimumReleaseAgeExclude": yaml.SequenceNode,
	"minimumReleaseAgeStrict": yaml.ScalarNode, "minimumReleaseAgeIgnoreMissingTime": yaml.ScalarNode,
	"trustLockfile": yaml.ScalarNode, "httpProxy": yaml.ScalarNode, "httpsProxy": yaml.ScalarNode,
	"noProxy": yaml.ScalarNode, "strictSsl": yaml.ScalarNode, "npmrcAuthFile": yaml.ScalarNode,
	"_auth": yaml.MappingNode,
}

// parsePnpmYAML reads the relevant top-level pnpm settings into the same
// entry shape as .npmrc lines: maps flatten to dotted keys, each list item
// is an array entry in order, and YAML null shows as "null" (distinct from
// 0). A relevant key with the wrong shape is reported but still shown.
func parsePnpmYAML(data []byte) ([]model.NPMRCEntry, string) {
	var doc yaml.Node
	if !utf8.Valid(data) || yaml.Unmarshal(data, &doc) != nil {
		return nil, "invalid yaml"
	}
	if len(doc.Content) == 0 {
		return nil, ""
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, "invalid yaml"
	}
	var entries []model.NPMRCEntry
	parseErr := ""
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		kind, ok := pnpmYAMLKeys[k.Value]
		if !ok {
			continue
		}
		if !rubyYAMLData(v, 0) {
			parseErr = "unsupported value for " + k.Value
			continue
		}
		if v.Kind != kind && v.ShortTag() != "!!null" {
			parseErr = "unexpected type for " + k.Value
		}
		appendPnpmYAML(&entries, k.Value, v)
	}
	if len(entries) > maxPnpmYAMLEntries {
		entries, parseErr = entries[:maxPnpmYAMLEntries], "too many entries"
	}
	return entries, parseErr
}

func appendPnpmYAML(out *[]model.NPMRCEntry, key string, n *yaml.Node) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			appendPnpmYAML(out, key+"."+n.Content[i].Value, n.Content[i+1])
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			appendPnpmYAML(out, strings.TrimSuffix(key, "[]")+"[]", item)
		}
	default:
		value := n.Value
		if n.ShortTag() == "!!null" {
			value = "null"
		}
		quoted := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0
		*out = append(*out, buildEntry(key, value, quoted, n.Line))
	}
}
