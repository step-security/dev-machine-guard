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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
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

// pipInvocationsToTry orders the candidate ways to find pip on the host.
// The detector probes each in turn and uses the first that resolves.
var pipInvocationsToTry = []struct {
	binary  string
	args    []string // args prepended to the binary call (e.g., "-m" "pip")
	display string
}{
	{"pip", nil, "pip"},
	{"pip3", nil, "pip3"},
	{"python3", []string{"-m", "pip"}, "python3 -m pip"},
	{"python", []string{"-m", "pip"}, "python -m pip"},
}

// pipConfigDebugSectionRE matches the layer headers in `pip config debug`
// output: `env_var:`, `env:`, `global:`, `site:`, `user:`.
var pipConfigDebugSectionRE = regexp.MustCompile(`^(env_var|env|global|site|user):$`)

// pipConfigDebugFileRE matches a discovered file line, e.g.
// `  /etc/pip.conf, exists: False`.
var pipConfigDebugFileRE = regexp.MustCompile(`^\s+(.+),\s+exists:\s+(True|False)\s*$`)

// PipConfigDetector performs the read-only pip config audit.
type PipConfigDetector struct {
	exec executor.Executor

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
		path, err := d.exec.LookPath(cand.binary)
		if err != nil {
			continue
		}
		if d.exec.IsAppleCLTStub(ctx, path) {
			// Skip Apple's /usr/bin/ shims on Macs without Command Line Tools;
			// invoking --version against them pops a GUI install prompt.
			continue
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
		path, err := d.exec.LookPath(cand.binary)
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
	if pipAvailable {
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
	case "windows":
		// Global. Vista is unsupported; skip.
		if pd := d.exec.Getenv("ProgramData"); pd != "" {
			out = append(out, struct{ path, layer string }{filepath.Join(pd, "pip", "pip.ini"), "global"})
		}
		// User.
		if appdata := d.exec.Getenv("APPDATA"); appdata != "" {
			out = append(out, struct{ path, layer string }{filepath.Join(appdata, "pip", "pip.ini"), "user"})
		}
		if homeDir != "" {
			out = append(out, struct{ path, layer string }{filepath.Join(homeDir, "pip", "pip.ini"), "user-legacy"})
		}
	case "darwin":
		// Global.
		out = append(out, struct{ path, layer string }{"/Library/Application Support/pip/pip.conf", "global"})
		if homeDir != "" {
			// pip itself prefers ~/Library/Application Support/pip when that
			// directory exists, and otherwise reads ~/.config/pip. We surface
			// both candidates: the audit is inventory-only, and having a
			// stray config at the unused path is itself worth showing.
			out = append(out, struct{ path, layer string }{filepath.Join(homeDir, "Library", "Application Support", "pip", "pip.conf"), "user"})
			out = append(out, struct{ path, layer string }{filepath.Join(homeDir, ".config", "pip", "pip.conf"), "user"})
			// Legacy.
			out = append(out, struct{ path, layer string }{filepath.Join(homeDir, ".pip", "pip.conf"), "user-legacy"})
		}
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

		if homeDir != "" {
			xdgHome := d.exec.Getenv("XDG_CONFIG_HOME")
			if xdgHome == "" {
				xdgHome = filepath.Join(homeDir, ".config")
			}
			out = append(out, struct{ path, layer string }{filepath.Join(xdgHome, "pip", "pip.conf"), "user"})
			out = append(out, struct{ path, layer string }{filepath.Join(homeDir, ".pip", "pip.conf"), "user-legacy"})
		}
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
	info, err := os.Lstat(f.Path)
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
		stat, statErr := os.Stat(f.Path)
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

	if info.IsDir() {
		f.ParseError = "path is a directory"
		return
	}

	if d.ownerLookup != nil {
		oi := d.ownerLookup(f.Path)
		if oi.OK {
			f.OwnerName = oi.OwnerName
			f.GroupName = oi.GroupName
		}
	}

	data, err := os.ReadFile(f.Path)
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
	info, err := os.Stat(path)
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
