package configaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// devNullPaths are values of $PIP_CONFIG_FILE that disable all config-file
// loading. We compare case-insensitively so `NUL`, `nul`, etc. all match.
var devNullPaths = map[string]struct{}{
	"/dev/null": {},
	"nul":       {},
}

// pipEnvVarsToWatch is the set of environment variables we always record on
// the audit. Recording an unset var lets a future change-tracking layer
// notice when one is *added* between runs (the same logic the npmrc
// detector uses). Includes a small set of credential-bearing names that
// pip itself will never define but that worms commonly use to inject
// transient creds.
var pipEnvVarsToWatch = []string{
	"PIP_CONFIG_FILE",
	"PIP_INDEX_URL",
	"PIP_EXTRA_INDEX_URL",
	"PIP_TRUSTED_HOST",
	"PIP_FIND_LINKS",
	"PIP_NO_CACHE_DIR",
	"PIP_NO_BUILD_ISOLATION",
	"PIP_REQUIRE_HASHES",
	"PIP_KEYRING_PROVIDER",
	"PIP_CACHE_DIR",
	"PIP_CERT",
	"PIP_CLIENT_CERT",
	"PIP_PROXY",
	"VIRTUAL_ENV",
	"HTTP_PROXY",
	"HTTPS_PROXY",
}

type pipInvocationCandidate struct {
	binary  string
	args    []string // args prepended to the binary call (e.g., "-m" "pip")
	display string
}

// pipInvocationsToTry orders the candidate ways to find pip on the host.
// The detector probes each in turn and uses the first that resolves.
var pipInvocationsToTry = []pipInvocationCandidate{
	{"pip", nil, "pip"},
	{"pip3", nil, "pip3"},
	{"python3", []string{"-m", "pip"}, "python3 -m pip"},
	{"python", []string{"-m", "pip"}, "python -m pip"},
}

func pipEnforcementInvocationCandidates(goos string) []pipInvocationCandidate {
	out := append([]pipInvocationCandidate(nil), pipInvocationsToTry...)
	if goos == model.PlatformWindows {
		out = append(out,
			pipInvocationCandidate{"py", []string{"-m", "pip"}, "py -m pip"},
			pipInvocationCandidate{"py", []string{"-3", "-m", "pip"}, "py -3 -m pip"},
		)
	}
	return out
}

// pipConfigDebugSectionRE matches the layer headers in `pip config debug`
// output: `env_var:`, `env:`, `global:`, `site:`, `user:`.
var pipConfigDebugSectionRE = regexp.MustCompile(`^(env_var|env|global|site|user):$`)

// pipConfigDebugFileRE matches a discovered file line, e.g.
// `  /etc/pip.conf, exists: False`.
var pipConfigDebugFileRE = regexp.MustCompile(`^\s+(.+),\s+exists:\s+(True|False)\s*$`)

// PipConfigDetector performs the read-only pip config audit.
type PipConfigDetector struct {
	skipper *tcc.Skipper
	exec    executor.Executor

	// Hooks for tests; default to platform-specific impls. Owner lookup
	// uses syscall.Stat_t on Unix and is a no-op on Windows.
	ownerLookup func(path string) ownerInfo
	gitTracked  func(ctx context.Context, path string) bool
	inGitRepo   func(path string) bool
}

// NewPipConfigDetector wires platform-specific hooks; tests override.
func NewPipConfigDetector(exec executor.Executor) *PipConfigDetector {
	d := &PipConfigDetector{exec: exec}
	d.ownerLookup = statOwner
	d.gitTracked = func(ctx context.Context, p string) bool { return gitTrackedViaExec(ctx, exec, p) }
	d.inGitRepo = defaultInGitRepo
	return d
}

// Detect runs the full audit.
//
// loggedInUser drives where we look for the user's pip config when
// running as root (launchd / systemd context). Pass nil when the agent
// is already running as the user.
func (d *PipConfigDetector) Detect(ctx context.Context, loggedInUser *user.User) model.PipAudit {
	audit := model.PipAudit{
		Files:    []model.PipConfigFile{},
		EnvVars:  d.collectEnvVars(),
		Findings: []model.PipFinding{},
	}

	// 1) Detect pip itself.
	if path, args, display, version, ok := d.detectPip(ctx); ok {
		audit.Available = true
		audit.Path = path
		audit.Invocation = display
		audit.Version = version
		_ = args // args are consumed by runPip, not surfaced on the audit
	}

	// 2) Discover config files. Prefer `pip config debug` output; fall back
	// to OS-specific path enumeration when pip is unavailable or its
	// output looks malformed.
	files := d.discoverFiles(ctx, audit.Available, loggedInUser)
	for i := range files {
		d.populateFileMetadata(ctx, &files[i])
	}
	audit.Files = files

	// 3) Effective merged view (only meaningful when pip is available).
	if audit.Available {
		eff, err := d.captureEffective(ctx)
		if err == nil {
			audit.Effective = eff
		} else {
			audit.Effective = &model.PipEffective{Error: err.Error()}
		}
	}

	// 4) ~/.netrc presence + permissions (informational only — see plan).
	audit.Netrc = d.probeNetrc(loggedInUser)

	// 5) Findings from the rule catalog (pip-001 .. pip-024).
	audit.Findings = evaluatePipFindings(&audit)

	return audit
}

// --- pip detection ----------------------------------------------------------

// detectPip probes the candidate invocations and returns the first that
// successfully reports its version. Returns:
//
//	path     — absolute path to the binary that fronts pip (e.g. /usr/bin/pip3)
//	args     — extra args to prepend (`["-m", "pip"]` for python -m pip)
//	display  — human-readable invocation form
//	version  — `pip --version` first-token version string
//	ok       — true when a working pip was found
func (d *PipConfigDetector) detectPip(ctx context.Context) (string, []string, string, string, bool) {
	for _, cand := range pipInvocationsToTry {
		path, err := executor.LookPathWithContext(ctx, d.exec, cand.binary)
		if err != nil {
			continue
		}
		if d.exec.IsAppleCLTStub(ctx, path) {
			// Skip Apple's /usr/bin/ shims on Macs without Command Line Tools;
			// invoking --version against them pops a GUI install prompt.
			continue
		}
		if tcc.ProtectedReadsDisabled(d.exec, d.skipper) {
			return path, cand.args, cand.display, "unknown", true
		}
		args := append([]string(nil), cand.args...)
		args = append(args, "--version")
		stdout, _, exit, err := d.exec.RunWithTimeout(ctx, 5*time.Second, cand.binary, args...)
		if err != nil || exit != 0 {
			continue
		}
		// `pip --version` outputs "pip X.Y.Z from /path/... (python ...)"
		fields := strings.Fields(strings.TrimSpace(stdout))
		version := ""
		if len(fields) >= 2 {
			version = fields[1]
		}
		return path, cand.args, cand.display, version, true
	}
	return "", nil, "", "", false
}

// runPip runs `pip <args...>` using the detected invocation. We re-detect
// the invocation each call (cheap; LookPath is cached by the OS) so the
// detector remains stateless. Returns stdout, exit code, and whether pip
// was available at all.
func (d *PipConfigDetector) runPip(ctx context.Context, timeout time.Duration, pipArgs ...string) (string, int, bool) {
	for _, cand := range pipInvocationsToTry {
		path, err := executor.LookPathWithContext(ctx, d.exec, cand.binary)
		if err != nil {
			continue
		}
		if d.exec.IsAppleCLTStub(ctx, path) {
			// Same guard as detectPip: don't invoke Apple's /usr/bin/ shims
			// on Macs without Command Line Tools — they pop a GUI install
			// prompt. detectPip should have already returned ok=false in
			// this case, but guard here too so a future caller can't bypass.
			continue
		}
		args := append([]string(nil), cand.args...)
		args = append(args, pipArgs...)
		stdout, _, exit, err := d.exec.RunWithTimeout(ctx, timeout, cand.binary, args...)
		if err != nil && exit == 0 {
			// hard error; skip and try next candidate
			continue
		}
		return stdout, exit, true
	}
	return "", 0, false
}

// --- discovery --------------------------------------------------------------

// PipUserConfigDiscovery is the trusted user-tier path and invocation set used
// by package policy enforcement. Paths are resolved beneath the interactive
// user's home; pip output can only confirm entries already in that allowlist.
type PipUserConfigDiscovery struct {
	AllowedUserPaths  []string
	ExistingUserPaths []string
	Invocations       [][]string
}

// DiscoverPipUserConfig discovers every supported pip invocation and only
// documented user-tier configuration paths for the resolved interactive user.
func DiscoverPipUserConfig(ctx context.Context, exec executor.Executor) (PipUserConfigDiscovery, error) {
	u, err := exec.LoggedInUser()
	if err != nil {
		return PipUserConfigDiscovery{}, fmt.Errorf("pip discovery: resolving interactive user: %w", err)
	}
	if u == nil || u.HomeDir == "" {
		return PipUserConfigDiscovery{}, errors.New("pip discovery: resolved interactive user has no home directory")
	}
	home := filepath.Clean(u.HomeDir)
	userExec := executor.NewUserAwareExecutor(exec, u.Username)
	allowed := pipAllowedUserPaths(userExec, home)
	if err := executor.UserEnvironmentError(userExec); err != nil {
		return PipUserConfigDiscovery{}, fmt.Errorf("pip discovery: resolving user environment: %w", err)
	}

	invocations := make([][]string, 0, len(pipInvocationsToTry)+2)
	seenInvocations := map[string]bool{}
	confirmed := map[string]bool{}
	for _, candidate := range pipEnforcementInvocationCandidates(exec.GOOS()) {
		path, err := executor.LookPathWithContext(ctx, userExec, candidate.binary)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return PipUserConfigDiscovery{}, ctxErr
		}
		if err != nil || userExec.IsAppleCLTStub(ctx, path) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return PipUserConfigDiscovery{}, ctxErr
			}
			continue
		}
		key := filepath.Clean(path) + "\x00" + strings.Join(candidate.args, "\x00")
		if seenInvocations[key] {
			continue
		}
		versionArgs := append(append([]string(nil), candidate.args...), "--version")
		stdout, _, exit, err := userExec.RunWithTimeout(ctx, 5*time.Second, candidate.binary, versionArgs...)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return PipUserConfigDiscovery{}, ctxErr
		}
		if err != nil || exit != 0 || !strings.HasPrefix(strings.TrimSpace(stdout), "pip ") {
			continue
		}
		seenInvocations[key] = true
		invocation := append([]string{candidate.binary}, candidate.args...)
		invocations = append(invocations, invocation)

		debugArgs := append(append([]string(nil), candidate.args...), "config", "debug")
		debug, _, exit, err := userExec.RunWithTimeout(ctx, 10*time.Second, candidate.binary, debugArgs...)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return PipUserConfigDiscovery{}, ctxErr
		}
		if err != nil || exit != 0 {
			continue
		}
		for _, discovered := range parsePipConfigDebug(debug) {
			if discovered.layer != "user" || !discovered.exists {
				continue
			}
			if trusted, ok := matchingPipAllowedPath(discovered.path, allowed, exec.GOOS()); ok {
				confirmed[trusted] = true
			}
		}
	}

	existing := make([]string, 0, len(allowed))
	for _, path := range allowed {
		if exec.FileExists(path) || confirmed[path] {
			existing = append(existing, path)
		}
	}
	return PipUserConfigDiscovery{AllowedUserPaths: allowed, ExistingUserPaths: existing, Invocations: invocations}, nil
}

func pipAllowedUserPaths(exec executor.Executor, home string) []string {
	paths := pipUserConfigPaths(exec, home, true)
	out := make([]string, len(paths))
	for i := range paths {
		out[i] = paths[i].path
	}
	return out
}

// TrustedPipUserPaths returns the static home-confined pip user paths without
// locating or executing a package manager.
func TrustedPipUserPaths(exec executor.Executor, home string) []string {
	return pipAllowedUserPaths(exec, home)
}

type pipUserConfigPath struct {
	path  string
	layer string
}

// pipUserConfigPaths is the shared documented user-path source for inventory
// and enforcement. Enforcement requests current-first, home-confined paths;
// inventory retains its historical platform order and visibility.
func pipUserConfigPaths(exec executor.Executor, home string, trusted bool) []pipUserConfigPath {
	if home == "" {
		return nil
	}
	var paths []pipUserConfigPath
	switch exec.GOOS() {
	case model.PlatformWindows:
		appData := strings.TrimSpace(exec.Getenv("APPDATA"))
		if trusted && !pipPathWithinHome(appData, home, true) {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		if appData != "" {
			paths = append(paths, pipUserConfigPath{filepath.Join(appData, "pip", "pip.ini"), "user"})
		}
		paths = append(paths, pipUserConfigPath{filepath.Join(home, "pip", "pip.ini"), "user-legacy"})
	case model.PlatformDarwin:
		applicationSupportDir := filepath.Join(home, "Library", "Application Support", "pip")
		applicationSupport := filepath.Join(applicationSupportDir, "pip.conf")
		xdg := filepath.Join(home, ".config", "pip", "pip.conf")
		if trusted && !exec.DirExists(applicationSupportDir) {
			paths = append(paths, pipUserConfigPath{xdg, "user"}, pipUserConfigPath{applicationSupport, "user"})
		} else {
			paths = append(paths, pipUserConfigPath{applicationSupport, "user"}, pipUserConfigPath{xdg, "user"})
		}
		paths = append(paths, pipUserConfigPath{filepath.Join(home, ".pip", "pip.conf"), "user-legacy"})
	default:
		xdgHome := strings.TrimSpace(exec.Getenv("XDG_CONFIG_HOME"))
		if xdgHome == "" || trusted && !pipPathWithinHome(xdgHome, home, false) {
			xdgHome = filepath.Join(home, ".config")
		}
		paths = append(paths,
			pipUserConfigPath{filepath.Join(xdgHome, "pip", "pip.conf"), "user"},
			pipUserConfigPath{filepath.Join(home, ".pip", "pip.conf"), "user-legacy"},
		)
	}
	out := make([]pipUserConfigPath, 0, len(paths))
	seen := map[string]bool{}
	for _, candidate := range paths {
		candidate.path = filepath.Clean(candidate.path)
		if candidate.path == "." || seen[candidate.path] {
			continue
		}
		seen[candidate.path] = true
		out = append(out, candidate)
	}
	return out
}

func pipPathWithinHome(path, home string, windows bool) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	path, home = filepath.Clean(path), filepath.Clean(home)
	if windows {
		path, home = strings.ToLower(path), strings.ToLower(home)
	}
	rel, err := filepath.Rel(home, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

type pipDebugPath struct {
	path   string
	layer  string
	exists bool
}

func parsePipConfigDebug(stdout string) []pipDebugPath {
	var out []pipDebugPath
	currentLayer := ""
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		if match := pipConfigDebugSectionRE.FindStringSubmatch(line); match != nil {
			currentLayer = match[1]
			continue
		}
		if currentLayer != "global" && currentLayer != "user" && currentLayer != "site" {
			continue
		}
		if match := pipConfigDebugFileRE.FindStringSubmatch(line); match != nil {
			out = append(out, pipDebugPath{path: strings.TrimSpace(match[1]), layer: currentLayer, exists: match[2] == "True"})
		}
	}
	return out
}

func matchingPipAllowedPath(reported string, allowed []string, goos string) (string, bool) {
	reported = filepath.Clean(reported)
	for _, trusted := range allowed {
		if reported == trusted || goos == model.PlatformWindows && strings.EqualFold(reported, trusted) {
			return trusted, true
		}
	}
	return "", false
}

// discoverFiles returns the union of (`pip config debug`-derived paths) and
// (PIP_CONFIG_FILE / VIRTUAL_ENV-derived paths). Deduplicates by absolute
// path; the first layer assignment wins.
func (d *PipConfigDetector) discoverFiles(ctx context.Context, pipAvailable bool, loggedInUser *user.User) []model.PipConfigFile {
	type entry struct {
		path  string
		layer string
	}
	var ordered []entry
	seen := map[string]struct{}{}
	add := func(layer, path string) {
		if path == "" {
			return
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if _, dup := seen[path]; dup {
			return
		}
		seen[path] = struct{}{}
		ordered = append(ordered, entry{path: path, layer: layer})
	}

	// Track devnull explicitly so the findings engine can emit pip-021.
	if v := strings.TrimSpace(d.exec.Getenv("PIP_CONFIG_FILE")); v != "" {
		if _, isDevNull := devNullPaths[strings.ToLower(filepath.Base(v))]; !isDevNull {
			add("PIP_CONFIG_FILE", v)
		}
		// devnull case: still scan env vars; don't add the path.
	}

	// VIRTUAL_ENV is set by `source .../activate`. Its pip.conf is the site
	// scope — only relevant when the venv is active for the running shell.
	if v := strings.TrimSpace(d.exec.Getenv("VIRTUAL_ENV")); v != "" {
		add("site", filepath.Join(v, pipConfigFilename(d.exec.GOOS())))
	}

	// Preferred: `pip config debug`. Falls back to manual path enumeration
	// when pip isn't installed or the output is unparseable.
	usedPipDebug := false
	if pipAvailable && !tcc.ProtectedReadsDisabled(d.exec, d.skipper) {
		if discovered, ok := d.discoverViaPipDebug(ctx); ok {
			usedPipDebug = true
			for _, e := range discovered {
				add(e.layer, e.path)
			}
		}
	}
	if !usedPipDebug {
		for _, e := range d.discoverViaPathEnumeration(loggedInUser) {
			add(e.layer, e.path)
		}
	}

	out := make([]model.PipConfigFile, 0, len(ordered))
	for _, e := range ordered {
		out = append(out, model.PipConfigFile{Path: e.path, Layer: e.layer})
	}
	return out
}

// discoverViaPipDebug runs `pip config debug` and parses its grouped output.
// Returns false if parsing failed; the caller should then fall back to
// manual path enumeration.
func (d *PipConfigDetector) discoverViaPipDebug(ctx context.Context) ([]struct{ path, layer string }, bool) {
	stdout, exit, ok := d.runPip(ctx, 10*time.Second, "config", "debug")
	if !ok || exit != 0 || strings.TrimSpace(stdout) == "" {
		return nil, false
	}
	var out []struct{ path, layer string }
	currentLayer := ""
	for _, line := range strings.Split(stdout, "\n") {
		// Layer header.
		if m := pipConfigDebugSectionRE.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			currentLayer = m[1]
			continue
		}
		// File line. Only emit when we're in a layer that maps to a real
		// config file — `env_var:` and `env:` describe vars, not files.
		if currentLayer != "global" && currentLayer != "user" && currentLayer != "site" {
			continue
		}
		if m := pipConfigDebugFileRE.FindStringSubmatch(line); m != nil {
			path := strings.TrimSpace(m[1])
			out = append(out, struct{ path, layer string }{path: path, layer: currentLayer})
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// discoverViaPathEnumeration walks the OS-specific paths from spec §3.
// Used when pip isn't installed (so we still surface stranded config
// files) and as a fallback when `pip config debug` parsing failed.
func (d *PipConfigDetector) discoverViaPathEnumeration(loggedInUser *user.User) []struct{ path, layer string } {
	homeDir := ""
	if loggedInUser != nil {
		homeDir = loggedInUser.HomeDir
	}
	if homeDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			homeDir = h
		}
	}
	goos := d.exec.GOOS()
	var out []struct{ path, layer string }

	switch goos {
	case model.PlatformWindows:
		// Global. Vista is unsupported; skip.
		if pd := d.exec.Getenv("ProgramData"); pd != "" {
			out = append(out, struct{ path, layer string }{filepath.Join(pd, "pip", "pip.ini"), "global"})
		}
	case model.PlatformDarwin:
		out = append(out, struct{ path, layer string }{"/Library/Application Support/pip/pip.conf", "global"})
	default: // linux + everything else
		// XDG_CONFIG_DIRS is colon-separated; check each.
		xdgDirs := d.exec.Getenv("XDG_CONFIG_DIRS")
		if xdgDirs == "" {
			xdgDirs = "/etc/xdg"
		}
		for _, dir := range strings.Split(xdgDirs, ":") {
			dir = strings.TrimSpace(dir)
			if dir == "" {
				continue
			}
			out = append(out, struct{ path, layer string }{filepath.Join(dir, "pip", "pip.conf"), "global"})
		}
		out = append(out, struct{ path, layer string }{"/etc/pip.conf", "global"})
	}
	for _, candidate := range pipUserConfigPaths(d.exec, homeDir, false) {
		out = append(out, struct{ path, layer string }{candidate.path, candidate.layer})
	}
	return out
}

// pipConfigFilename returns "pip.conf" or "pip.ini" depending on OS.
func pipConfigFilename(goos string) string {
	if goos == "windows" {
		return "pip.ini"
	}
	return "pip.conf"
}

// --- per-file metadata ------------------------------------------------------

func (d *PipConfigDetector) populateFileMetadata(ctx context.Context, f *model.PipConfigFile) {
	info, err := auditLstat(d.exec, d.skipper, f.Path)
	if err != nil {
		if os.IsNotExist(err) {
			f.Exists = false
			return
		}
		f.Exists = true
		f.ParseError = "lstat: " + err.Error()
		return
	}
	f.Exists = true

	// Follow through any symlink for size/mtime/mode (lstat already proved
	// the symlink itself exists; a broken symlink target shouldn't crash
	// the audit).
	if info.Mode()&os.ModeSymlink != 0 {
		stat, statErr := auditStat(d.exec, d.skipper, f.Path)
		if statErr != nil {
			f.Readable = false
			f.ParseError = "stat (followed symlink): " + statErr.Error()
			return
		}
		info = stat
	}
	f.SizeBytes = info.Size()
	f.ModTimeUnix = info.ModTime().Unix()
	f.Mode = fmt.Sprintf("%#o", info.Mode().Perm())

	if !info.Mode().IsRegular() {
		f.ParseError = "path is not a regular file"
		return
	}

	if d.ownerLookup != nil {
		oi := d.ownerLookup(f.Path)
		if oi.OK {
			f.OwnerName = oi.OwnerName
			f.GroupName = oi.GroupName
		}
	}

	data, err := auditReadFile(d.exec, d.skipper, f.Path)
	if err != nil {
		f.Readable = false
		f.ParseError = "read: " + err.Error()
		return
	}
	f.Readable = true
	sum := sha256.Sum256(data)
	f.SHA256 = hex.EncodeToString(sum[:])

	f.Sections = parsePipConfig(data)

	if d.inGitRepo != nil && d.inGitRepo(f.Path) {
		f.InGitRepo = true
		if d.gitTracked != nil && d.gitTracked(ctx, f.Path) {
			f.GitTracked = true
		}
	}
}

// --- effective view ---------------------------------------------------------

// pipConfigListLineRE captures `<section>.<key>='<value>' from <source>`
// lines. We split on the literal substring `' from ` rather than greedy
// regex so values containing single quotes don't fool us.
//
// Match group 1 = section.key (split on '.' for individual fields).
// Match group 2 = quoted value (still wrapped in single quotes; strip
// after match).
var pipConfigListPrefix = regexp.MustCompile(`^([A-Za-z0-9_\-]+)\.([A-Za-z0-9_\-]+)='`)

func (d *PipConfigDetector) captureEffective(ctx context.Context) (*model.PipEffective, error) {
	if tcc.ProtectedReadsDisabled(d.exec, d.skipper) {
		return nil, errors.New(protectedCommandReason)
	}
	stdout, exit, ok := d.runPip(ctx, 10*time.Second, "config", "list", "-v")
	if !ok || exit != 0 {
		return nil, fmt.Errorf("pip config list -v exited %d", exit)
	}
	eff := &model.PipEffective{
		SourceByKey: map[string]string{},
		Config:      map[string]string{},
	}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		// Skip the discovery preamble lines.
		if strings.HasPrefix(line, "For variant ") {
			continue
		}
		if !pipConfigListPrefix.MatchString(line) {
			continue
		}
		// Two shapes seen across pip versions:
		//   global.index-url='https://...' from /path/file   (older)
		//   global.index-url='https://...'                   (pip 24.x)
		// Split off the optional ` from <path>` trailer; fall back to
		// the closing quote when it isn't there.
		var header, source string
		if idx := strings.Index(line, "' from "); idx >= 0 {
			header = line[:idx]
			source = strings.TrimSpace(line[idx+len("' from "):])
		} else if idx := strings.LastIndex(line, "'"); idx > 0 {
			header = line[:idx]
		} else {
			continue
		}

		// header is `<section>.<key>='<value>` — strip the `<section>.<key>=` prefix.
		eq := strings.IndexByte(header, '=')
		if eq < 0 {
			continue
		}
		secKey := header[:eq]
		value := header[eq+1:]
		// Trim leading single quote from value.
		value = strings.TrimPrefix(value, "'")

		// Split section.key.
		dot := strings.IndexByte(secKey, '.')
		if dot < 0 {
			continue
		}
		section := secKey[:dot]
		key := secKey[dot+1:]
		full := section + "." + key

		// Pip's text output emits URL values verbatim, including any
		// embedded `user:pass@host` userinfo. We must redact before
		// storing — the per-file `entries` view redacts; the effective
		// view has to as well, otherwise it becomes the credential leak
		// the audit was supposed to prevent.
		eff.Config[full] = redactCredsInValue(value)
		eff.SourceByKey[full] = source
	}
	return eff, nil
}

// --- env vars ---------------------------------------------------------------

func (d *PipConfigDetector) collectEnvVars() []model.PipEnvVar {
	out := make([]model.PipEnvVar, 0, len(pipEnvVarsToWatch))
	for _, name := range pipEnvVarsToWatch {
		v := d.exec.Getenv(name)
		ev := model.PipEnvVar{Name: name, Set: v != ""}
		if v != "" {
			ev.Value = v
			ev.Display = redactCredsInValue(v)
			ev.SHA256 = hashCredential(v)
		}
		out = append(out, ev)
	}
	return out
}

// --- ~/.netrc check ---------------------------------------------------------

func (d *PipConfigDetector) probeNetrc(loggedInUser *user.User) *model.PipNetrcStatus {
	homeDir := ""
	if loggedInUser != nil {
		homeDir = loggedInUser.HomeDir
	}
	if homeDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			homeDir = h
		}
	}
	if homeDir == "" {
		return nil
	}
	path := filepath.Join(homeDir, ".netrc")
	if d.exec.GOOS() == "windows" {
		// Windows uses _netrc; allow either spelling.
		path = filepath.Join(homeDir, "_netrc")
	}
	out := &model.PipNetrcStatus{Path: path}
	info, err := auditStat(d.exec, d.skipper, path)
	if err != nil {
		if !os.IsNotExist(err) {
			out.Exists = true // probe error; surface that we tried
		}
		return out
	}
	out.Exists = true
	if d.exec.GOOS() != "windows" {
		out.Mode = fmt.Sprintf("%#o", info.Mode().Perm())
	}
	return out
}

// pipFsWalkEntries is here so the detector stays self-contained even if
// future versions want to enumerate venvs on disk (out of scope for v1
// per the plan; keeping the helper around for symmetry with nodescan).
var _ = func() fs.WalkDirFunc { return nil }

// formatModeOctal is unused today (mode is rendered via fmt.Sprintf in
// populateFileMetadata) but kept for tests; suppress unused warning.
var _ = strconv.FormatUint

func (d *PipConfigDetector) WithSkipper(s *tcc.Skipper) *PipConfigDetector {
	d.skipper = s
	d.exec = tcc.GuardedFiles(d.exec, s, maxConfigFileSize, "Application Support/pip/pip.conf")
	if tcc.ProtectedReadsDisabled(d.exec, s) {
		d.ownerLookup = guardedOwner(d.exec)
		d.inGitRepo = guardedInGitRepo(d.exec)
		// Git loads user-controlled config and includes in its own process.
		d.gitTracked = nil
	}
	return d
}
