package configaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/safepath"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// maxGoEnvBytes caps each Go env file read.
// ponytail: unmeasured starting value from the spec; tune with lab sizes.
var maxGoEnvBytes int64 = 2 << 20

// goEnvKeys are the only settings read from a Go env source. Everything else
// is dropped in memory and never reaches the model or a log.
var goEnvKeys = []string{
	"GO111MODULE", "GOAUTH", "GOBIN", "GOFLAGS", "GOINSECURE", "GOMODCACHE", "GONOPROXY",
	"GONOSUMDB", "GOPATH", "GOPRIVATE", "GOPROXY", "GOROOT", "GOSUMDB", "GOTOOLCHAIN", "GOVCS", "GOWORK",
}

// goSecurityKeys change where modules come from or how they are checked; a
// duplicate of one in a file is reported.
var goSecurityKeys = map[string]bool{
	"GOAUTH": true, "GOINSECURE": true, "GONOPROXY": true, "GONOSUMDB": true,
	"GOPRIVATE": true, "GOPROXY": true, "GOSUMDB": true, "GOVCS": true,
}

var goPublicProxyHosts = map[string]bool{"proxy.golang.org": true, "goproxy.io": true, "goproxy.cn": true}

const goRedacted = "[redacted]"

// GoEnvScope is what the Go config audit may read, all decided by the caller
// from the resolved developer identity rather than from the process.
type GoEnvScope struct {
	Username string   // resolved developer identity, part of every source ID
	Home     string   // from the OS user record
	Roots    []string // approved filesystem scope: home plus configured search roots
	// Protected returns a reason code for a path that must not be touched, "" to
	// allow it. It must stay on regardless of other scanners' TCC opt-ins.
	Protected func(path string) string
	// Volume reports a skipped network volume, which even the exact default-file
	// exception may not enter.
	Volume func(path string) bool
	// ProcessVerified means this process runs as the developer, so its own
	// environment is an observed context for that developer.
	ProcessVerified bool
}

// GoEnvSnapshot carries effective raw values, by Go precedence, from the
// sources the audit could read. It stays in memory: values may hold secrets.
type GoEnvSnapshot struct {
	values map[string]string
	// RedirectUnknown is set when the user env file could not be established,
	// so a default root may not be the one Go uses.
	RedirectUnknown bool
}

// ModCacheRoot is GOMODCACHE, else the first GOPATH entry's pkg/mod. ok is
// false for a relative value, which Go itself rejects.
func (s GoEnvSnapshot) ModCacheRoot(home string) (string, bool) {
	if v := s.values["GOMODCACHE"]; v != "" {
		return filepath.Clean(v), filepath.IsAbs(v)
	}
	gopath, ok := s.gopath0(home)
	return filepath.Join(gopath, "pkg", "mod"), ok
}

// BinRoot is GOBIN, else the first GOPATH entry's bin.
func (s GoEnvSnapshot) BinRoot(home string) (string, bool) {
	if v := s.values["GOBIN"]; v != "" {
		return filepath.Clean(v), filepath.IsAbs(v)
	}
	gopath, ok := s.gopath0(home)
	return filepath.Join(gopath, "bin"), ok
}

// DefaultModCacheRoot is gopath0/pkg/mod, which a project walk skips even when
// GOMODCACHE points elsewhere.
func (s GoEnvSnapshot) DefaultModCacheRoot(home string) (string, bool) {
	gopath, ok := s.gopath0(home)
	return filepath.Join(gopath, "pkg", "mod"), ok
}

func (s GoEnvSnapshot) gopath0(home string) (string, bool) {
	list := filepath.SplitList(s.values["GOPATH"])
	if len(list) == 0 || list[0] == "" {
		return filepath.Join(home, "go"), true
	}
	return filepath.Clean(list[0]), filepath.IsAbs(list[0])
}

// Modfile is the last -modfile in the effective GOFLAGS, as written; ok is
// false when GOFLAGS cannot be split as Go would.
func (s GoEnvSnapshot) Modfile() (modfile string, ok bool) {
	flags, ok := splitGoFlags(s.values["GOFLAGS"])
	for _, f := range flags {
		if v, isModfile := goFlagValue(f, "modfile"); isModfile {
			modfile = v
		}
	}
	return modfile, ok
}

// GoSourceID is the stable source identity shared by both Go sections:
// sha256 of the canonical JSON tuple [identity, kind, clean path].
func GoSourceID(identity, kind, path string) string {
	if path != "" {
		path = filepath.Clean(path)
	}
	b, _ := json.Marshal([]string{identity, kind, path})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// GoProtection builds the Go collector's guards. Protected directories stay
// excluded whatever another scanner's include_tcc_protected says, and match
// case-insensitively because tcc compares bytes while APFS folds case by
// default. volume matches only the skipped network volumes, which even the
// exact default-file exception may not enter.
func GoProtection(home string, includeNetworkVolumes *bool) (protected func(string) string, volume func(string) bool) {
	skipper := tcc.ForRun(home, nil, includeNetworkVolumes)
	include := true
	volumes := tcc.ForRun(home, &include, includeNetworkVolumes)
	candidates := skipper.Candidates() // home-anchored; nil off darwin
	protected = func(p string) string {
		p = filepath.Clean(p)
		if skipper.WithinProtected(p) {
			return model.GoReasonSkippedProtected
		}
		for _, c := range candidates {
			if len(p) >= len(c) && strings.EqualFold(p[:len(c)], c) && (len(p) == len(c) || p[len(c)] == filepath.Separator) {
				return model.GoReasonSkippedProtected
			}
		}
		return ""
	}
	volume = func(p string) bool { return volumes.WithinProtected(p) }
	return protected, volume
}

// GoReadReason maps a guarded-read failure to a Go reason code. A guard's own
// refusal already speaks that vocabulary.
func GoReadReason(err error) string {
	switch reason := safepath.ReasonOf(err); reason {
	case safepath.ReasonOutsideRoots:
		return model.GoReasonOutsideApprovedRoots
	case safepath.ReasonUnresolved, safepath.ReasonSymlink:
		return model.GoReasonPathUnresolved
	case safepath.ReasonDenied, "":
		return model.GoReasonPermissionDenied
	default:
		return reason
	}
}

// GoEnvDetector audits Go's configuration sources without running Go.
// It must be built with the raw executor: UserAwareExecutor.Getenv sources a
// login shell for some keys.
type GoEnvDetector struct {
	exec executor.Executor
}

func NewGoEnvDetector(exec executor.Executor) *GoEnvDetector {
	return &GoEnvDetector{exec: exec}
}

// goEnvSource is one parsed source before it becomes a model file.
type goEnvSource struct {
	file   model.GoConfigFile
	values map[string]string // raw, allowlisted; nil when unusable
	dups   []string
	crKey  string
}

// Detect returns the audit and the snapshot inventory uses to resolve roots.
func (d *GoEnvDetector) Detect(ctx context.Context, scope GoEnvScope) (model.GoConfigAudit, GoEnvSnapshot) {
	audit := model.GoConfigAudit{
		SchemaVersion: model.GoInventorySchemaVersion,
		Status:        model.GoStatusComplete,
		Reasons:       []string{},
		Files:         []model.GoConfigFile{},
		Findings:      []model.GoConfigFinding{},
	}
	snap := GoEnvSnapshot{values: map[string]string{}}
	if scope.Username == "" || scope.Home == "" {
		audit.Status, audit.Reasons = model.GoStatusPartial, []string{model.GoReasonUserUnresolved}
		snap.RedirectUnknown = true
		return audit, snap
	}
	if ctx.Err() != nil {
		audit.Status, audit.Reasons = model.GoStatusPartial, []string{model.GoReasonDeadlineExceeded}
		snap.RedirectUnknown = true
		return audit, snap
	}

	proc := d.processSource(scope)
	user := d.userSource(scope)
	var sources []goEnvSource
	if toolchain, ok := d.toolchainSource(scope, proc.values, user.values); ok {
		sources = append(sources, toolchain)
	}
	sources = append(sources, user, proc)

	// Go precedence: process over user file over toolchain defaults.
	for _, src := range sources {
		for k, v := range src.values {
			snap.values[k] = v
		}
	}
	switch user.file.Status {
	case model.GoConfigPresent, model.GoConfigAbsent, model.GoConfigDisabled:
	default:
		snap.RedirectUnknown = true
	}

	for _, src := range sources {
		audit.Files = append(audit.Files, src.file)
		audit.Findings = append(audit.Findings, goEnvFindings(src)...)
		if src.file.Scope == model.GoConfigScopeProcess {
			continue // DMG's own context is never an approved developer source
		}
		switch src.file.Status {
		case model.GoConfigSkippedProtected, model.GoConfigUnreadable, model.GoConfigInvalid, model.GoConfigUnsupported:
			audit.Status = model.GoStatusPartial
			audit.Reasons = append(audit.Reasons, src.file.Reasons...)
		}
	}
	slices.Sort(audit.Reasons)
	audit.Reasons = slices.Compact(audit.Reasons)
	slices.SortFunc(audit.Files, func(a, b model.GoConfigFile) int {
		return strings.Compare(a.Scope+"\x00"+a.Path, b.Scope+"\x00"+b.Path)
	})
	slices.SortFunc(audit.Findings, func(a, b model.GoConfigFinding) int {
		return strings.Compare(a.Code+"\x00"+a.SourceID+"\x00"+a.Key, b.Code+"\x00"+b.SourceID+"\x00"+b.Key)
	})
	return audit, snap
}

func (d *GoEnvDetector) newFile(scope GoEnvScope, kind, defaultPath, path string) model.GoConfigFile {
	id := path
	if id == "" {
		id = defaultPath
	}
	return model.GoConfigFile{
		SourceID:    GoSourceID(scope.Username, "go_config_"+kind, id),
		Scope:       kind,
		DefaultPath: defaultPath,
		Path:        path,
		Reasons:     []string{},
		Settings:    []model.GoConfigSetting{},
	}
}

func (d *GoEnvDetector) processSource(scope GoEnvScope) goEnvSource {
	src := goEnvSource{file: d.newFile(scope, model.GoConfigScopeProcess, "", "")}
	if !scope.ProcessVerified {
		src.file.Status = model.GoConfigUnsupported
		src.file.Reasons = []string{model.GoReasonProcessContextUnverified}
		return src
	}
	src.values = map[string]string{}
	for _, k := range append(slices.Clone(goEnvKeys), "GOENV") {
		if v := d.exec.Getenv(k); v != "" {
			src.values[k] = v
		}
	}
	src.file.Status = model.GoConfigAbsent
	if len(src.values) > 0 {
		src.file.Status = model.GoConfigPresent
	}
	src.finish()
	return src
}

// userEnvDefault mirrors os.UserConfigDir for the resolved user: the home
// comes from the OS user record, and XDG_CONFIG_HOME / AppData only from a
// verified process context.
func (d *GoEnvDetector) userEnvDefault(scope GoEnvScope) (string, string) {
	var root string
	switch d.exec.GOOS() {
	case model.PlatformDarwin:
		root = filepath.Join(scope.Home, "Library", "Application Support")
	case model.PlatformLinux:
		root = filepath.Join(scope.Home, ".config")
		if v := d.processValue(scope, "XDG_CONFIG_HOME"); v != "" {
			if !filepath.IsAbs(v) {
				return "", model.GoReasonPathUnresolved
			}
			root = v
		}
	case model.PlatformWindows:
		root = filepath.Join(scope.Home, "AppData", "Roaming")
		if v := d.processValue(scope, "APPDATA"); v != "" {
			if !filepath.IsAbs(v) {
				return "", model.GoReasonPathUnresolved
			}
			root = v
		}
	default:
		return "", model.GoReasonPathUnresolved
	}
	return filepath.Join(filepath.Clean(root), "go", "env"), ""
}

func (d *GoEnvDetector) processValue(scope GoEnvScope, key string) string {
	if !scope.ProcessVerified {
		return ""
	}
	return d.exec.Getenv(key)
}

func (d *GoEnvDetector) userSource(scope GoEnvScope) goEnvSource {
	defaultPath, reason := d.userEnvDefault(scope)
	path := defaultPath
	switch goenv := d.processValue(scope, "GOENV"); {
	case goenv == "off":
		src := goEnvSource{file: d.newFile(scope, model.GoConfigScopeUser, defaultPath, "")}
		src.file.Status = model.GoConfigDisabled
		return src
	case goenv != "" && !filepath.IsAbs(goenv):
		path, reason = "", model.GoReasonPathUnresolved
	case goenv != "":
		path, reason = filepath.Clean(goenv), ""
	}
	src := goEnvSource{file: d.newFile(scope, model.GoConfigScopeUser, defaultPath, path)}
	if reason != "" {
		src.file.Status, src.file.Reasons = model.GoConfigUnsupported, []string{reason}
		return src
	}
	d.readSource(&src, scope, path, d.exec.GOOS() == model.PlatformDarwin && path == defaultPath)
	return src
}

// toolchainSource reads GOROOT/go.env only when GOROOT is already known from
// an observed source; DMG never searches for a Go installation.
func (d *GoEnvDetector) toolchainSource(scope GoEnvScope, proc, user map[string]string) (goEnvSource, bool) {
	goroot := proc["GOROOT"]
	if goroot == "" {
		goroot = user["GOROOT"]
	}
	if goroot == "" {
		return goEnvSource{}, false
	}
	if !filepath.IsAbs(goroot) {
		src := goEnvSource{file: d.newFile(scope, model.GoConfigScopeToolchain, "", "")}
		src.file.Status, src.file.Reasons = model.GoConfigUnsupported, []string{model.GoReasonPathUnresolved}
		return src, true
	}
	path := filepath.Join(filepath.Clean(goroot), "go.env")
	src := goEnvSource{file: d.newFile(scope, model.GoConfigScopeToolchain, "", path)}
	d.readSource(&src, scope, path, false)
	return src, true
}

// readSource reads one env file through a guarded executor. exact selects the
// macOS default-file exception: its own root is the literal file, and its
// guard admits only that file and the ancestors needed to open it.
func (d *GoEnvDetector) readSource(src *goEnvSource, scope GoEnvScope, path string, exact bool) {
	fail := func(status, reason string) {
		src.file.Status, src.file.Reasons = status, []string{reason}
	}
	var files executor.Executor
	if exact {
		files = d.exec.GuardedFiles([]string{path}, goExactFileGuard(path, scope.Volume), maxGoEnvBytes)
	} else {
		if !withinGoRoots(path, scope.Roots) {
			fail(model.GoConfigUnsupported, model.GoReasonOutsideApprovedRoots)
			return
		}
		if scope.Protected != nil && scope.Protected(path) != "" {
			fail(model.GoConfigSkippedProtected, model.GoReasonSkippedProtected)
			return
		}
		files = d.exec.GuardedFiles(scope.Roots, scope.Protected, maxGoEnvBytes)
	}
	readFailure := func(err error) {
		if reason := GoReadReason(err); reason == model.GoReasonSkippedProtected {
			fail(model.GoConfigSkippedProtected, reason)
		} else {
			fail(model.GoConfigUnreadable, reason)
		}
	}
	info, err := files.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		src.file.Status = model.GoConfigAbsent
		return
	}
	if err != nil {
		readFailure(err)
		return
	}
	// The guard admits ancestors so they can be traversed; a leaf link that
	// lands on one is still a redirect of the exception path.
	if exact {
		if resolved, err := files.EvalSymlinks(path); err != nil || resolved != path {
			fail(model.GoConfigSkippedProtected, model.GoReasonSkippedProtected)
			return
		}
	}
	if !info.Mode().IsRegular() {
		fail(model.GoConfigUnreadable, model.GoReasonUnsupportedEntry)
		return
	}
	if info.Size() > maxGoEnvBytes {
		fail(model.GoConfigUnreadable, model.GoReasonSizeLimit)
		return
	}
	data, err := files.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		fail(model.GoConfigUnreadable, model.GoReasonChangedDuringScan)
		return
	}
	if err != nil {
		readFailure(err)
		return
	}
	src.values, src.dups, src.crKey = parseGoEnv(data)
	if src.crKey != "" {
		// Go rejects such a value; reporting a trimmed one would claim Go accepts it.
		src.file.Status, src.file.Reasons = model.GoConfigInvalid, []string{model.GoReasonCarriageReturn}
		src.values = nil
		return
	}
	src.file.Status = model.GoConfigPresent
	if len(src.dups) > 0 {
		src.file.Reasons = []string{model.GoReasonDuplicateKey}
	}
	src.finish()
}

// finish renders sanitized settings from the raw values.
func (src *goEnvSource) finish() {
	for k, v := range src.values {
		if v == "" {
			continue
		}
		display, redacted := sanitizeGoSetting(k, v)
		src.file.Settings = append(src.file.Settings, model.GoConfigSetting{
			Key: k, Display: display, Redacted: redacted, SourceID: src.file.SourceID,
		})
	}
	slices.SortFunc(src.file.Settings, func(a, b model.GoConfigSetting) int { return strings.Compare(a.Key, b.Key) })
}

// goExactFileGuard admits the literal file and its lexical ancestors and
// refuses every other path, so a redirected ancestor or leaf link (into
// Documents, another Library subtree or another user) is never traversed.
func goExactFileGuard(file string, volume func(string) bool) safepath.Guard {
	return func(p string) string {
		p = filepath.Clean(p)
		if volume != nil && volume(p) {
			return model.GoReasonSkippedProtected
		}
		if p == file || isLexicalAncestor(p, file) {
			return ""
		}
		return model.GoReasonSkippedProtected
	}
}

func isLexicalAncestor(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func withinGoRoots(path string, roots []string) bool {
	path = filepath.Clean(path)
	for _, root := range roots {
		if root = filepath.Clean(root); path == root || isLexicalAncestor(root, path) {
			return true
		}
	}
	return false
}

// parseGoEnv ports Go's readEnvFile: split on \n, skip lines with no '=' or
// not starting with A-Z, last value wins. Carriage returns are kept, as Go
// keeps them; crKey names the first allowlisted key whose value has one.
func parseGoEnv(data []byte) (values map[string]string, dups []string, crKey string) {
	values = map[string]string{}
	seen := map[string]int{}
	for line := range strings.SplitSeq(string(data), "\n") {
		i := strings.IndexByte(line, '=')
		if i < 0 || line[0] < 'A' || line[0] > 'Z' {
			continue
		}
		key, val := line[:i], line[i+1:]
		if !slices.Contains(goEnvKeys, key) {
			continue
		}
		values[key] = val
		if seen[key]++; seen[key] == 2 && goSecurityKeys[key] {
			dups = append(dups, key)
		}
		if crKey == "" && strings.ContainsRune(val, '\r') {
			crKey = key
		}
	}
	slices.Sort(dups)
	return values, dups, crKey
}

// sanitizeGoSetting returns a display value safe for telemetry and logs.
func sanitizeGoSetting(key, value string) (string, bool) {
	switch key {
	case "GOPROXY":
		return sanitizeGoProxy(value)
	case "GOSUMDB":
		return sanitizeGoSumDB(value)
	case "GOAUTH":
		return sanitizeGoAuth(value)
	case "GOFLAGS":
		return sanitizeGoFlags(value)
	}
	return value, false
}

// sanitizeGoURL strips userinfo, query and fragment. Anything that still
// carries an '@', or cannot be parsed and might, is redacted whole.
func sanitizeGoURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		if strings.ContainsAny(raw, "@?#") {
			return goRedacted, true
		}
		return raw, false
	}
	redacted := u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != ""
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	out := u.String()
	if strings.Contains(out, "@") {
		return goRedacted, true
	}
	return out, redacted
}

// sanitizeGoProxy keeps entry order and each ',' or '|' separator, whose
// fallback semantics differ.
func sanitizeGoProxy(raw string) (string, bool) {
	var b strings.Builder
	redacted, start := false, 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] != ',' && raw[i] != '|' {
			continue
		}
		if entry := strings.TrimSpace(raw[start:i]); entry == "direct" || entry == "off" {
			b.WriteString(entry)
		} else if entry != "" {
			v, r := sanitizeGoURL(entry)
			b.WriteString(v)
			redacted = redacted || r
		}
		if i < len(raw) {
			b.WriteByte(raw[i])
		}
		start = i + 1
	}
	return b.String(), redacted
}

func goProxyEntries(raw string) []string {
	var out []string
	for _, e := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '|' }) {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func sanitizeGoSumDB(raw string) (string, bool) {
	fields := strings.Fields(raw)
	redacted := false
	for i, f := range fields {
		switch {
		case strings.Contains(f, "://"):
			var r bool
			fields[i], r = sanitizeGoURL(f)
			redacted = redacted || r
		case strings.ContainsAny(f, "@?#"):
			fields[i], redacted = goRedacted, true
		}
	}
	return strings.Join(fields, " "), redacted
}

// sanitizeGoAuth keeps only each entry's method; arguments (directories,
// command lines) never leave the process.
func sanitizeGoAuth(raw string) (string, bool) {
	var methods []string
	redacted := false
	for entry := range strings.SplitSeq(raw, ";") {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		method := goAuthMethod(fields)
		methods = append(methods, method)
		redacted = redacted || len(fields) > 1 || method == "command"
	}
	return strings.Join(methods, "; "), redacted
}

func goAuthMethod(fields []string) string {
	switch fields[0] {
	case "off", "netrc", "git":
		return fields[0]
	}
	return "command"
}

// sanitizeGoFlags keeps -mod and -modfile; any other flag may carry an
// arbitrary argument and is dropped. An unsplittable value shows nothing.
func sanitizeGoFlags(raw string) (string, bool) {
	flags, ok := splitGoFlags(raw)
	if !ok {
		return "", true
	}
	var kept []string
	redacted := false
	for _, f := range flags {
		_, isMod := goFlagValue(f, "mod")
		_, isModfile := goFlagValue(f, "modfile")
		switch {
		case !isMod && !isModfile:
			redacted = true
		case strings.ContainsAny(f, " \t\n\r"):
			kept = append(kept, goQuoteFlag(f))
		default:
			kept = append(kept, f)
		}
	}
	return strings.Join(kept, " "), redacted
}

// splitGoFlags mirrors cmd/internal/quoted.Split, which cmd/go applies to
// GOFLAGS: whitespace separates fields, and a field opening with ' or " runs
// to the next same quote with no unescaping. An unterminated quote makes Go
// reject GOFLAGS, so it is reported rather than guessed at.
func splitGoFlags(s string) ([]string, bool) {
	var fields []string
	for {
		s = strings.TrimLeft(s, " \t\n\r")
		if s == "" {
			return fields, true
		}
		if q := s[0]; q == '"' || q == '\'' {
			end := strings.IndexByte(s[1:], q)
			if end < 0 {
				return nil, false
			}
			fields, s = append(fields, s[1:end+1]), s[end+2:]
			continue
		}
		end := strings.IndexAny(s, " \t\n\r")
		if end < 0 {
			end = len(s)
		}
		fields, s = append(fields, s[:end]), s[end:]
	}
}

// goQuoteFlag re-quotes a field so the display splits back the same way.
func goQuoteFlag(f string) string {
	if strings.Contains(f, `"`) {
		return "'" + f + "'"
	}
	return `"` + f + `"`
}

func goFlagValue(flag, name string) (string, bool) {
	for _, prefix := range []string{"-" + name + "=", "--" + name + "="} {
		if v, ok := strings.CutPrefix(flag, prefix); ok {
			return v, true
		}
	}
	return "", false
}

// goEnvFindings evaluates one source's own values; there is no merged
// effective verdict because other invocation contexts remain unknown.
func goEnvFindings(src goEnvSource) []model.GoConfigFinding {
	id := src.file.SourceID
	var out []model.GoConfigFinding
	add := func(code, severity, key, detail string) {
		out = append(out, model.GoConfigFinding{Code: code, Severity: severity, SourceID: id, Key: key, Detail: detail})
	}
	if src.crKey != "" {
		add("go-006", pipSevMedium, src.crKey, "setting value contains a carriage return, which Go rejects")
	}
	for _, key := range src.dups {
		add("go-006", pipSevMedium, key, "security setting is defined more than once; the last value wins")
	}
	v := src.values
	if v["GOSUMDB"] == "off" {
		add("go-001", pipSevHigh, "GOSUMDB", "checksum database verification is disabled")
	}
	if v["GOINSECURE"] != "" {
		add("go-002", pipSevHigh, "GOINSECURE", "insecure fetching is allowed for matching module paths")
	}
	if goProxyFallsBackPublic(v["GOPROXY"]) {
		add("go-003", pipSevMedium, "GOPROXY", "a non-public proxy falls back to a public proxy or direct fetch")
	}
	for _, key := range []string{"GOPROXY", "GOSUMDB"} {
		if v[key] == "" {
			continue
		}
		if _, redacted := sanitizeGoSetting(key, v[key]); redacted {
			add("go-004", pipSevHigh, key, "URL embeds credentials or query values; redacted before reporting")
		}
	}
	if v["GOAUTH"] != "" {
		for entry := range strings.SplitSeq(v["GOAUTH"], ";") {
			if fields := strings.Fields(entry); len(fields) > 0 && goAuthMethod(fields) == "command" {
				add("go-005", pipSevMedium, "GOAUTH", "GOAUTH runs a command to obtain credentials")
				break
			}
		}
	}
	return out
}

func goProxyFallsBackPublic(raw string) bool {
	private := false
	for _, e := range goProxyEntries(raw) {
		switch public := goIsPublicProxy(e); {
		case e == "off":
			return false
		case e == "direct" || public:
			if private {
				return true
			}
		default:
			private = true
		}
	}
	return false
}

func goIsPublicProxy(entry string) bool {
	u, err := url.Parse(entry)
	return err == nil && goPublicProxyHosts[strings.ToLower(u.Hostname())]
}
