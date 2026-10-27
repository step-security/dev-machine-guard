package configaudit

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

var maxCondaAuditBytes = 256 << 10

const condaConfigBytes int64 = 2 << 20
const condaSettingLimit = 256

var (
	condaTokenPattern        = regexp.MustCompile(`/t/[^/?#]*`)
	condaLiteralTokenPattern = regexp.MustCompile(`/t/[^/?#]+`)
	condaReferencePattern    = regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%`)
	condaChannelPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)
	condaSchemePattern       = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)
	condaExcludeNewerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .:+_/-]{0,63}$`)
)

// CondaConfigKind is the source-ID kind for a Conda configuration scope.
func CondaConfigKind(scope string) string { return "conda_config_" + scope }

// CondaSanitizeURL removes Anaconda token path components before the shared
// URL sanitizer strips userinfo, query and fragment. Every `/t/<token>`
// component goes whole (the loader stops at non-token characters, which
// would leak a malformed token's tail), and a token that survives
// percent-decoding redacts the URL.
func CondaSanitizeURL(raw string) (string, bool) {
	if !composerSafeText(raw, 4096) {
		return goRedacted, true
	}
	clean := condaTokenPattern.ReplaceAllString(raw, "")
	redacted := clean != raw
	decoded, err := url.PathUnescape(clean)
	if err != nil || condaTokenPattern.MatchString(decoded) {
		return goRedacted, true
	}
	display, r := SanitizeRubyURL(clean)
	return display, redacted || r
}

// CondaChannelDisplay keeps a safe channel label, a sanitized URL or a local
// repository path; anything else is redacted.
func CondaChannelDisplay(raw string) (string, bool) {
	switch {
	case !composerSafeText(raw, 4096):
		return goRedacted, true
	case strings.Contains(raw, "://"):
		return CondaSanitizeURL(raw)
	case filepath.IsAbs(raw) || strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, `\\`) || len(raw) > 2 && raw[1] == ':':
		return SanitizeComposerURL(raw)
	case len(raw) <= 256 && condaChannelPattern.MatchString(raw):
		return raw, false
	}
	return goRedacted, true
}

// condaURLCredential reports an embedded secret: userinfo or a token path.
// A $VAR, ${VAR} or %VAR% reference holds no secret, so it is blanked first.
func condaURLCredential(raw string) bool {
	if !strings.Contains(raw, "://") {
		return false
	}
	raw = condaReferencePattern.ReplaceAllString(raw, "")
	if condaLiteralTokenPattern.MatchString(raw) {
		return true
	}
	if decoded, err := url.PathUnescape(raw); err == nil && condaLiteralTokenPattern.MatchString(decoded) {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return false
	}
	password, _ := u.User.Password()
	return u.User.Username() != "" || password != ""
}

// condaProxySelector admits a plain scheme or scheme://host[:port].
func condaProxySelector(raw string) (string, bool) {
	if !composerSafeText(raw, 128) {
		return goRedacted, true
	}
	if condaSchemePattern.MatchString(raw) {
		return raw, false
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.Contains(raw, "://") || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || !condaSchemePattern.MatchString(u.Scheme) {
		return goRedacted, true
	}
	return raw, false
}

// condaBool follows Conda's boolify sets; anything else is not a boolean.
func condaBool(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on", "y":
		return "true", true
	case "false", "off", "n", "no", "non", "none", "":
		return "false", true
	}
	return "", false
}

// CondaConfigScope comes from the resolved developer, never a login shell.
type CondaConfigScope struct {
	Username, Home  string
	Protected       func(string) string
	Volume          func(string) bool
	ProcessVerified bool
}

// CondaConfigSnapshot accumulates .condarc-family observations as inventory
// discovers installation roots and prefixes. Leads are absolute paths from
// verified process variables and present files; they are not effective config.
type CondaConfigSnapshot struct {
	EnvsDirs, PkgsDirs, Prefixes []string
	exec                         executor.Executor
	ctx                          context.Context
	scope                        CondaConfigScope
	audit                        model.CondaConfigAudit
	files                        map[string]*model.CondaConfigFile
	env                          map[string]string
	literal                      map[string]bool
	leads                        map[string]bool
	credentialPaths              map[string]bool
	credentials                  map[string]bool
	process, condarc             *model.CondaConfigFile
	environments                 []condaEnvironmentContext
	system, user                 []*model.CondaConfigFile // lowest precedence first
	roots                        []*model.CondaConfigFile
	rootKeys                     map[string]bool
	contexts                     map[string]bool
	partial, rootsPartial        bool
	rootsPresent                 int
	bytes                        int
	limited                      bool
}

// condaEnvironmentContext holds a prefix's own sources until every root is
// known, since roots found later still apply to it.
type condaEnvironmentContext struct {
	prefix  string
	own     []*model.CondaConfigFile
	state   *model.CondaConfigFile
	partial bool
}

type CondaConfigDetector struct{ exec executor.Executor }

func NewCondaConfigDetector(exec executor.Executor) *CondaConfigDetector {
	return &CondaConfigDetector{exec: exec}
}

func emptyCondaAudit() model.CondaConfigAudit {
	return model.CondaConfigAudit{SchemaVersion: model.CondaInventorySchemaVersion, Status: "complete", Reasons: []string{}, Files: []model.CondaConfigFile{}, Contexts: []model.CondaConfigContext{}, CredentialFiles: []model.CondaCredentialFile{}, Findings: []model.CargoConfigFinding{}}
}

func (d *CondaConfigDetector) Detect(ctx context.Context, scope CondaConfigScope) *CondaConfigSnapshot {
	a := &CondaConfigSnapshot{exec: d.exec, ctx: ctx, scope: scope, audit: emptyCondaAudit(), files: map[string]*model.CondaConfigFile{}, env: map[string]string{},
		literal: map[string]bool{}, leads: map[string]bool{}, credentialPaths: map[string]bool{}, credentials: map[string]bool{}, rootKeys: map[string]bool{}, contexts: map[string]bool{}}
	if scope.Username == "" || scope.Home == "" {
		a.degrade("user_unresolved")
		return a
	}
	if ctx.Err() != nil {
		a.degrade("deadline_exceeded")
		return a
	}
	home, goos := scope.Home, d.exec.GOOS()
	a.process = a.record("process", "")
	if scope.ProcessVerified {
		a.processEnv()
	} else {
		a.fileReason(a.process, "unsupported", "user_unresolved")
		a.partial = true
	}
	// Existence only: requests' netrc and anaconda-client's token store.
	binstar := filepath.Join(cmpOr(a.env["XDG_CONFIG_HOME"], filepath.Join(home, ".config")), "binstar")
	switch goos {
	case model.PlatformDarwin:
		binstar = filepath.Join(home, "Library", "Application Support", "binstar")
	case model.PlatformWindows:
		binstar = filepath.Join(cmpOr(a.env["LOCALAPPDATA"], filepath.Join(home, "AppData", "Local")), "ContinuumIO", "binstar")
	}
	credentialFiles := []string{filepath.Join(home, ".netrc"), filepath.Join(home, "_netrc"), filepath.Join(binstar, "data")}
	for _, p := range credentialFiles {
		a.credentialPaths[a.key(p)] = true
		if resolved, err := a.exec.GuardedFiles([]string{p}, scope.Protected, 0).EvalSymlinks(p); err == nil {
			a.credentialPaths[a.key(resolved)] = true
		}
	}
	systemDirs := []string{"/etc/conda", "/var/lib/conda"}
	switch goos {
	case model.PlatformDarwin:
		// Missing directories cannot establish roots through /etc and /var symlinks.
		systemDirs = []string{"/private/etc/conda", "/private/var/lib/conda"}
	case model.PlatformWindows:
		// The loader hardcodes this directory; %PROGRAMDATA% is not consulted.
		systemDirs = []string{filepath.Join(`C:\ProgramData`, "conda")}
	}
	for _, dir := range systemDirs {
		a.system = append(a.system, a.entries("system", dir)...)
	}
	if root := a.env["CONDA_ROOT"]; root != "" {
		a.rootKeys[a.key(root)] = true
		a.system = append(a.system, a.entries("system", root)...)
	}
	if xdg := a.env["XDG_CONFIG_HOME"]; xdg != "" {
		a.user = append(a.user, a.entries("user", filepath.Join(xdg, "conda"))...)
	}
	a.user = append(a.user, a.entries("user", filepath.Join(home, ".config", "conda"))...)
	a.user = append(a.user, a.entries("user", filepath.Join(home, ".conda"))...)
	a.user = append(a.user, a.readFile("user", filepath.Join(home, ".condarc")))
	if p := a.env["CONDARC"]; p != "" {
		// The loader admits only its own filenames; a path it would ignore is
		// not an applicable source and is never read.
		if condaConfigName(p) {
			a.condarc = a.readFile(a.scopeOf(p), p)
		} else {
			a.unresolved()
		}
	}
	for _, p := range credentialFiles {
		a.credential(p)
	}
	return a
}

// condaConfigName mirrors the native loader's filename admission.
func condaConfigName(p string) bool {
	base := filepath.Base(p)
	return base == ".condarc" || base == "condarc" || strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")
}

func (a *CondaConfigSnapshot) scopeOf(p string) string {
	if GoWithinRoots(a.exec.GOOS(), p, []string{a.scope.Home}) {
		return "user"
	}
	return "system"
}

// Env returns a verified developer-process selector as a safe absolute path.
func (a *CondaConfigSnapshot) Env(key string) string { return a.env[key] }

// ContentGuard keeps credential files existence-only, including a token
// directory's contents and redirected reads.
func (a *CondaConfigSnapshot) ContentGuard(path string) string {
	if a.scope.Protected != nil {
		if reason := a.scope.Protected(path); reason != "" {
			return reason
		}
	}
	key := a.key(path)
	for p := range a.credentialPaths {
		if key == p || isLexicalAncestor(p, key) {
			return "skipped_protected"
		}
	}
	return ""
}

func (a *CondaConfigSnapshot) key(p string) string { return GoPathKey(a.exec.GOOS(), p) }
func (a *CondaConfigSnapshot) degrade(reason string) {
	a.audit.Status = "partial"
	if !slices.Contains(a.audit.Reasons, reason) {
		a.audit.Reasons = append(a.audit.Reasons, reason)
	}
}
func (a *CondaConfigSnapshot) fileReason(f *model.CondaConfigFile, status, reason string) {
	if f != nil {
		f.Status = status
		if !slices.Contains(f.Reasons, reason) {
			f.Reasons = append(f.Reasons, reason)
		}
	}
	a.degrade(reason)
}

// limitation keeps a parseable file present with its supported settings
// while recording why its coverage is incomplete.
func (a *CondaConfigSnapshot) limitation(f *model.CondaConfigFile, reason string) {
	if f != nil && !slices.Contains(f.Reasons, reason) {
		f.Reasons = append(f.Reasons, reason)
	}
	a.partial = true
	a.degrade(reason)
}
func (a *CondaConfigSnapshot) unresolved() {
	a.partial = true
	a.degrade("path_unresolved")
}

func (a *CondaConfigSnapshot) record(scope, path string) *model.CondaConfigFile {
	id := GoSourceID(a.scope.Username, CondaConfigKind(scope), path)
	if f := a.files[id]; f != nil {
		return f
	}
	if a.limited || a.bytes+len(path)+256 > maxCondaAuditBytes {
		a.limited = true
		a.degrade("output_size_limit")
		return nil
	}
	f := &model.CondaConfigFile{SourceID: id, Manager: "conda", Scope: scope, Path: path, Status: "absent", Reasons: []string{}, Settings: []model.CargoConfigSetting{}}
	a.files[id] = f
	a.bytes += len(path) + 256
	return f
}

func (a *CondaConfigSnapshot) setting(f *model.CondaConfigFile, key, value string, redacted bool) {
	if f == nil {
		return
	}
	if !composerSafeText(value, 4096) || len(key) > 512 {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	if slices.ContainsFunc(f.Settings, func(s model.CargoConfigSetting) bool { return s.Key == key && s.Display == value }) {
		return
	}
	if len(f.Settings) >= condaSettingLimit {
		a.limitation(f, "record_limit")
		return
	}
	if a.bytes+len(key)+len(value)+128 > maxCondaAuditBytes {
		a.limited = true
		a.fileReason(f, "unsupported", "output_size_limit")
		return
	}
	a.bytes += len(key) + len(value) + 128
	f.Settings = append(f.Settings, model.CargoConfigSetting{Key: key, Display: value, SourceID: f.SourceID, Redacted: redacted})
}

// entries lists one search-path directory in loader order: .condarc,
// condarc, then condarc.d fragments by name, later entries winning.
func (a *CondaConfigSnapshot) entries(scope, dir string) []*model.CondaConfigFile {
	out := []*model.CondaConfigFile{a.readFile(scope, filepath.Join(dir, ".condarc")), a.readFile(scope, filepath.Join(dir, "condarc"))}
	fragments := filepath.Join(dir, "condarc.d")
	if a.ctx.Err() != nil {
		a.degrade("deadline_exceeded")
		a.partial = true
		return out
	}
	names, more, err := a.exec.GuardedFiles([]string{fragments}, a.ContentGuard, 0).ReadDirLimit(fragments, condaSettingLimit)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			a.partial = true
			a.degrade(CargoReadReason(err, fragments, a.scope.Volume))
		}
		return out
	}
	if more {
		a.partial = true
		a.degrade("entry_limit")
	}
	var sorted []string
	for _, e := range names {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
			sorted = append(sorted, e.Name())
		}
	}
	slices.Sort(sorted)
	for _, name := range sorted {
		out = append(out, a.readFile(scope, filepath.Join(fragments, name)))
	}
	return out
}

func (a *CondaConfigSnapshot) readFile(scope, p string) *model.CondaConfigFile {
	if f := a.files[GoSourceID(a.scope.Username, CondaConfigKind(scope), p)]; f != nil {
		return f
	}
	f := a.record(scope, p)
	if f == nil {
		return nil
	}
	if a.ctx.Err() != nil {
		a.fileReason(f, "unreadable", "deadline_exceeded")
		return f
	}
	// A missing file cannot establish its own root through a parent symlink.
	files := a.exec.GuardedFiles([]string{filepath.Dir(p), p}, a.ContentGuard, condaConfigBytes)
	info, err := files.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return f
	}
	if err != nil {
		a.readFailure(f, err, p)
		return f
	}
	if !info.Mode().IsRegular() {
		a.fileReason(f, "unsupported", "unsupported_entry")
		return f
	}
	if info.Size() > condaConfigBytes {
		a.fileReason(f, "unreadable", "size_limit")
		return f
	}
	data, err := files.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		a.fileReason(f, "unreadable", "changed_during_scan")
		return f
	}
	if err != nil {
		a.readFailure(f, err, p)
		return f
	}
	a.parseCondarc(f, data)
	return f
}
func (a *CondaConfigSnapshot) readFailure(f *model.CondaConfigFile, err error, p string) {
	reason := CargoReadReason(err, p, a.scope.Volume)
	status := "unreadable"
	if reason == "skipped_protected" || reason == "refused_network_volume" {
		status = "skipped_protected"
	}
	a.fileReason(f, status, reason)
}

// condaPathSelectors are process variables that only steer discovery.
var condaPathSelectors = []string{"CONDA_PREFIX", "CONDA_ROOT", "MAMBA_ROOT_PREFIX", "CONDARC", "XDG_CONFIG_HOME", "LOCALAPPDATA"}

// condaEnvSettings maps process variables to canonical keys; a pair shares
// one key and conflicts when both are set.
var condaEnvSettings = [][2]string{
	{"CONDA_ENVS_DIRS", "CONDA_ENVS_PATH"}, {"CONDA_PKGS_DIRS", ""}, {"CONDA_CHANNELS", "CONDA_CHANNEL"}, {"CONDA_DEFAULT_CHANNELS", ""},
	{"CONDA_ALLOWLIST_CHANNELS", "CONDA_WHITELIST_CHANNELS"}, {"CONDA_DENYLIST_CHANNELS", ""}, {"CONDA_CHANNEL_ALIAS", ""}, {"CONDA_SSL_VERIFY", "CONDA_VERIFY_SSL"},
	{"CONDA_OFFLINE", ""}, {"CONDA_CHANNEL_PRIORITY", ""}, {"CONDA_SAFETY_CHECKS", ""}, {"CONDA_EXTRA_SAFETY_CHECKS", ""}, {"CONDA_EXCLUDE_NEWER", ""},
}

var condaProxyEnv = [][2]string{{"HTTP_PROXY", "http"}, {"HTTPS_PROXY", "https"}, {"ALL_PROXY", "all"}}

// processEnv reads only allowlisted names from the verified process.
func (a *CondaConfigSnapshot) processEnv() {
	if a.process == nil {
		return
	}
	e := a.exec
	for _, key := range condaPathSelectors {
		v := e.Getenv(key)
		if v == "" {
			continue
		}
		if !filepath.IsAbs(v) || !composerSafeText(v, 4096) {
			a.unresolved()
			continue
		}
		a.env[key] = filepath.Clean(v)
	}
	for _, key := range []string{"CONDA_PREFIX", "CONDA_ROOT", "MAMBA_ROOT_PREFIX"} {
		if v := a.env[key]; v != "" && !slices.Contains(a.Prefixes, v) {
			a.Prefixes = append(a.Prefixes, v)
		}
	}
	values := map[string]string{}
	for _, pair := range condaEnvSettings {
		v, alias := e.Getenv(pair[0]), ""
		if pair[1] != "" {
			alias = e.Getenv(pair[1])
		}
		switch {
		case v != "" && alias != "":
			a.limitation(a.process, "unsupported_format")
		case v != "":
			values[pair[0]] = v
		case alias != "":
			values[pair[0]] = alias
		}
	}
	a.settings(a.process, values, true)
	proxies := map[string]string{}
	for _, p := range condaProxyEnv {
		names := []string{p[0], strings.ToLower(p[0])}
		if e.GOOS() == model.PlatformWindows {
			// Windows names are case-insensitive, so both spellings are one capture.
			names = names[:1]
		}
		for _, name := range names {
			if v := e.Getenv(name); v != "" {
				proxies[p[1]+"\x00"+name] = v
			}
		}
	}
	a.proxies(a.process, proxies)
	if a.process.Status == "absent" && len(a.process.Settings) > 0 {
		a.process.Status = "present"
	}
}

func (a *CondaConfigSnapshot) proxies(f *model.CondaConfigFile, proxies map[string]string) {
	keys := slices.Sorted(maps.Keys(proxies))
	if len(keys) > condaSettingLimit {
		a.limitation(f, "record_limit")
		keys = keys[:condaSettingLimit]
	}
	for i, k := range keys {
		scheme, _, _ := strings.Cut(k, "\x00")
		selector, bad := condaProxySelector(scheme)
		display, redacted := sanitizeComposerProxy(proxies[k])
		if display != goRedacted {
			// A proxy is still a URL that may carry a token path.
			var r bool
			display, r = CondaSanitizeURL(display)
			redacted = redacted || r
		}
		prefix := "proxy_servers." + strconv.Itoa(i) + "."
		a.setting(f, prefix+"scheme", selector, bad)
		a.setting(f, prefix+"url", display, redacted)
	}
}

func condaSplit(v, sep string) []string {
	var out []string
	for item := range strings.SplitSeq(v, sep) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// settings applies canonical scalar and list values from process variables
// or a saved state file, where every value is text.
func (a *CondaConfigSnapshot) settings(f *model.CondaConfigFile, values map[string]string, leads bool) {
	sep := ":"
	if a.exec.GOOS() == model.PlatformWindows {
		sep = ";"
	}
	literal := false
	for _, key := range slices.Sorted(maps.Keys(values)) {
		v := values[key]
		switch key {
		case "CONDA_ENVS_DIRS", "CONDA_PKGS_DIRS":
			name, s := "envs_dirs", sep
			if key == "CONDA_PKGS_DIRS" {
				name, s = "pkgs_dirs", ","
			}
			a.dirs(f, name, condaSplit(v, s), leads)
		case "CONDA_CHANNELS", "CONDA_DEFAULT_CHANNELS":
			name := strings.ToLower(strings.TrimPrefix(key, "CONDA_"))
			for i, c := range condaSplit(v, ",") {
				if i >= condaSettingLimit {
					a.limitation(f, "record_limit")
					break
				}
				display, redacted := CondaChannelDisplay(c)
				literal = literal || condaURLCredential(c)
				a.setting(f, name+"."+strconv.Itoa(i)+".url", display, redacted)
			}
		case "CONDA_ALLOWLIST_CHANNELS", "CONDA_DENYLIST_CHANNELS":
			a.channelList(f, strings.ToLower(strings.TrimPrefix(key, "CONDA_")), condaSplit(v, ","))
		case "CONDA_CHANNEL_ALIAS":
			literal = literal || condaURLCredential(v)
			a.channelAlias(f, v)
		case "CONDA_SSL_VERIFY":
			a.sslVerify(f, v)
		case "CONDA_OFFLINE", "CONDA_EXTRA_SAFETY_CHECKS":
			a.boolean(f, strings.ToLower(strings.TrimPrefix(key, "CONDA_")), v)
		case "CONDA_CHANNEL_PRIORITY":
			a.channelPriority(f, v)
		case "CONDA_SAFETY_CHECKS":
			a.enum(f, "safety_checks", v, "enabled", "warn", "disabled")
		case "CONDA_EXCLUDE_NEWER":
			a.excludeNewer(f, v)
		}
	}
	if literal {
		a.setting(f, "auth_configured", "true", true)
		if f.Scope != "process" {
			a.literal[f.SourceID] = true
		}
	}
}

// dirs records envs_dirs/pkgs_dirs text and resolves discovery leads only
// through the verified home; a relative or variable path stays unresolved.
func (a *CondaConfigSnapshot) dirs(f *model.CondaConfigFile, name string, values []string, leads bool) {
	display := []string{}
	for _, v := range values {
		if !composerSafeText(v, 4096) {
			a.fileReason(f, "invalid", "parse_error")
			return
		}
		d, redacted := SanitizeComposerURL(v)
		if redacted {
			display = append(display, goRedacted)
			continue
		}
		display = append(display, d)
		p := v
		if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
			p = filepath.Join(a.scope.Home, p[1:])
		}
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "$%") {
			a.unresolved()
			continue
		}
		if !leads {
			continue
		}
		p = filepath.Clean(p)
		if a.leads[name+"\x00"+a.key(p)] {
			continue
		}
		a.leads[name+"\x00"+a.key(p)] = true
		if name == "envs_dirs" {
			a.EnvsDirs = append(a.EnvsDirs, p)
		} else {
			a.PkgsDirs = append(a.PkgsDirs, p)
		}
	}
	if len(display) > condaSettingLimit {
		a.limitation(f, "record_limit")
		display = display[:condaSettingLimit]
	}
	encoded, _ := json.Marshal(display)
	a.setting(f, name, string(encoded), slices.Contains(display, goRedacted))
}

func (a *CondaConfigSnapshot) channelList(f *model.CondaConfigFile, name string, values []string) {
	display, redacted := []string{}, false
	for _, v := range values {
		d, r := CondaChannelDisplay(v)
		display, redacted = append(display, d), redacted || r
	}
	if len(display) > condaSettingLimit {
		a.limitation(f, "record_limit")
		display = display[:condaSettingLimit]
	}
	encoded, _ := json.Marshal(display)
	a.setting(f, name, string(encoded), redacted)
}

func (a *CondaConfigSnapshot) channelAlias(f *model.CondaConfigFile, v string) {
	if !strings.Contains(v, "://") {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	display, redacted := CondaSanitizeURL(v)
	a.setting(f, "channel_alias", display, redacted)
}

func (a *CondaConfigSnapshot) sslVerify(f *model.CondaConfigFile, v string) {
	switch b, ok := condaBool(v); {
	case strings.TrimSpace(v) == "":
		a.limitation(f, "unsupported_format")
	case ok:
		a.setting(f, "ssl_verify", b, false)
	case strings.EqualFold(strings.TrimSpace(v), "truststore"):
		a.setting(f, "ssl_verify", "truststore", false)
	default:
		// A CA bundle path; its contents are never read.
		display, redacted := SanitizeComposerURL(v)
		a.setting(f, "ssl_verify", display, redacted)
	}
}

func (a *CondaConfigSnapshot) boolean(f *model.CondaConfigFile, key, v string) {
	if b, ok := condaBool(v); ok {
		a.setting(f, key, b, false)
		return
	}
	a.fileReason(f, "invalid", "parse_error")
}

func (a *CondaConfigSnapshot) channelPriority(f *model.CondaConfigFile, v string) {
	// Conda reads the legacy boolean as flexible (true) or disabled (false).
	if b, ok := condaBool(v); ok {
		if b == "true" {
			a.setting(f, "channel_priority", "flexible", false)
		} else {
			a.setting(f, "channel_priority", "disabled", false)
		}
		return
	}
	a.enum(f, "channel_priority", v, "strict", "flexible", "disabled")
}

func (a *CondaConfigSnapshot) enum(f *model.CondaConfigFile, key, v string, allowed ...string) {
	v = strings.ToLower(strings.TrimSpace(v))
	if slices.Contains(allowed, v) {
		a.setting(f, key, v, false)
		return
	}
	a.fileReason(f, "invalid", "parse_error")
}

func (a *CondaConfigSnapshot) excludeNewer(f *model.CondaConfigFile, v string) {
	v = strings.TrimSpace(v)
	if condaExcludeNewerPattern.MatchString(v) {
		a.setting(f, "exclude_newer", v, false)
		return
	}
	a.limitation(f, "unsupported_format")
}

// condaKeyAliases are older spellings the loader still accepts.
var condaKeyAliases = map[string]string{"channel": "channels", "envs_path": "envs_dirs", "verify_ssl": "ssl_verify", "whitelist_channels": "allowlist_channels", "cooldown": "exclude_newer"}

var condaKeys = []string{"channels", "default_channels", "channel_alias", "custom_channels", "custom_multichannels", "envs_dirs", "pkgs_dirs", "ssl_verify", "proxy_servers",
	"offline", "extra_safety_checks", "channel_priority", "safety_checks", "allowlist_channels", "denylist_channels", "exclude_newer"}

// yamlRoot returns root mapping pairs. A merge or aliased key could inject
// relevant settings, so either rejects the file.
func (a *CondaConfigSnapshot) yamlRoot(f *model.CondaConfigFile, data []byte) ([][2]*yaml.Node, bool) {
	var doc yaml.Node
	if !utf8.Valid(data) || yaml.Unmarshal(data, &doc) != nil {
		a.fileReason(f, "invalid", "parse_error")
		return nil, false
	}
	if len(doc.Content) == 0 {
		return nil, true
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || root.Anchor != "" || root.Style&yaml.TaggedStyle != 0 {
		a.fileReason(f, "invalid", "parse_error")
		return nil, false
	}
	var out [][2]*yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i]
		if k.Kind != yaml.ScalarNode || k.Value == "<<" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
			a.fileReason(f, "unsupported", "unsupported_format")
			return nil, false
		}
		out = append(out, [2]*yaml.Node{k, root.Content[i+1]})
	}
	return out, true
}

func condaScalars(n *yaml.Node) ([]string, bool) {
	if v, ok := rubyScalar(n); ok {
		if v == "" {
			return []string{}, true
		}
		return []string{v}, true
	}
	if n.Kind != yaml.SequenceNode {
		return nil, false
	}
	out := []string{}
	for _, item := range n.Content {
		v, ok := rubyScalar(item)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// parseCondarc reads allowlisted keys only. Unknown keys and the `#!final`
// family of comment flags are ignored; an alias beside its canonical key is
// not resolved into a guessed effective value.
func (a *CondaConfigSnapshot) parseCondarc(f *model.CondaConfigFile, data []byte) {
	pairs, ok := a.yamlRoot(f, data)
	if !ok {
		return
	}
	f.Status = "present"
	values := map[string]*yaml.Node{}
	conflict := map[string]bool{}
	for _, kv := range pairs {
		key := kv[0].Value
		if alias := condaKeyAliases[key]; alias != "" {
			key = alias
		}
		if !slices.Contains(condaKeys, key) {
			continue
		}
		if !rubyYAMLData(kv[1], 0) {
			a.limitation(f, "unsupported_format")
			continue
		}
		if values[key] != nil {
			conflict[key] = true
			continue
		}
		values[key] = kv[1]
	}
	for key := range conflict {
		delete(values, key)
		a.limitation(f, "unsupported_format")
	}
	invalid := func() { a.fileReason(f, "invalid", "parse_error") }
	literal := false
	for _, key := range []string{"channels", "default_channels"} {
		n := values[key]
		if n == nil {
			continue
		}
		list, ok := condaScalars(n)
		if !ok {
			invalid()
			continue
		}
		for i, c := range list {
			if i >= condaSettingLimit {
				a.limitation(f, "record_limit")
				break
			}
			display, redacted := CondaChannelDisplay(c)
			literal = literal || condaURLCredential(c)
			a.setting(f, key+"."+strconv.Itoa(i)+".url", display, redacted)
		}
	}
	if n := values["channel_alias"]; n != nil {
		if v, ok := rubyScalar(n); ok && v != "" {
			literal = literal || condaURLCredential(v)
			a.channelAlias(f, v)
		} else {
			invalid()
		}
	}
	for _, key := range []string{"custom_channels", "custom_multichannels"} {
		n := values[key]
		if n == nil {
			continue
		}
		if n.Kind != yaml.MappingNode {
			invalid()
			continue
		}
		type entry struct {
			name string
			urls []string
		}
		var entries []entry
		for i := 0; i+1 < len(n.Content); i += 2 {
			urls, ok := condaScalars(n.Content[i+1])
			if !ok || key == "custom_channels" && len(urls) != 1 {
				invalid()
				continue
			}
			entries = append(entries, entry{n.Content[i].Value, urls})
		}
		slices.SortFunc(entries, func(x, y entry) int { return strings.Compare(x.name, y.name) })
		if len(entries) > condaSettingLimit {
			a.limitation(f, "record_limit")
			entries = entries[:condaSettingLimit]
		}
		for i, e := range entries {
			prefix := key + "." + strconv.Itoa(i) + "."
			name, bad := nugetAlias(e.name)
			a.setting(f, prefix+"name", name, bad)
			display, redacted := []string{}, false
			for _, u := range e.urls {
				d, r := CondaChannelDisplay(u)
				literal = literal || condaURLCredential(u)
				display, redacted = append(display, d), redacted || r
			}
			if key == "custom_channels" {
				a.setting(f, prefix+"url", display[0], redacted)
				continue
			}
			encoded, _ := json.Marshal(display)
			a.setting(f, prefix+"urls", string(encoded), redacted)
		}
	}
	for _, key := range []string{"envs_dirs", "pkgs_dirs"} {
		if n := values[key]; n != nil {
			if list, ok := condaScalars(n); ok {
				a.dirs(f, key, list, true)
			} else {
				invalid()
			}
		}
	}
	if n := values["ssl_verify"]; n != nil {
		if v, ok := rubyScalar(n); ok {
			a.sslVerify(f, v)
		} else {
			invalid()
		}
	}
	if n := values["proxy_servers"]; n != nil {
		if n.Kind != yaml.MappingNode {
			invalid()
		} else {
			proxies := map[string]string{}
			for i := 0; i+1 < len(n.Content); i += 2 {
				v, ok := rubyScalar(n.Content[i+1])
				if !ok {
					invalid()
					continue
				}
				proxies[n.Content[i].Value+"\x00"] = v
				if !strings.Contains(v, "://") {
					v = "http://" + v
				}
				literal = literal || condaURLCredential(v)
			}
			a.proxies(f, proxies)
		}
	}
	for _, key := range []string{"offline", "extra_safety_checks"} {
		if n := values[key]; n != nil {
			if v, ok := rubyScalar(n); ok {
				a.boolean(f, key, v)
			} else {
				invalid()
			}
		}
	}
	if n := values["channel_priority"]; n != nil {
		if v, ok := rubyScalar(n); ok {
			a.channelPriority(f, v)
		} else {
			invalid()
		}
	}
	if n := values["safety_checks"]; n != nil {
		if v, ok := rubyScalar(n); ok {
			a.enum(f, "safety_checks", v, "enabled", "warn", "disabled")
		} else {
			invalid()
		}
	}
	for _, key := range []string{"allowlist_channels", "denylist_channels"} {
		if n := values[key]; n != nil {
			if list, ok := condaScalars(n); ok {
				a.channelList(f, key, list)
			} else {
				invalid()
			}
		}
	}
	if n := values["exclude_newer"]; n != nil {
		if v, ok := rubyScalar(n); ok {
			a.excludeNewer(f, v)
		} else {
			invalid()
		}
	}
	if literal {
		a.setting(f, "auth_configured", "true", true)
		a.literal[f.SourceID] = true
	}
}

// parseState reads conda-meta/state's saved activation variables through the
// process allowlist. The unset sentinel means the variable is absent.
func (a *CondaConfigSnapshot) parseState(f *model.CondaConfigFile, data []byte) {
	var doc struct {
		EnvVars map[string]json.RawMessage `json:"env_vars"`
	}
	if !utf8.Valid(data) || json.Unmarshal(data, &doc) != nil {
		a.fileReason(f, "invalid", "parse_error")
		return
	}
	f.Status = "present"
	values, proxies := map[string]string{}, map[string]string{}
	read := func(name string) (string, bool) {
		raw := doc.EnvVars[name]
		if raw == nil {
			return "", false
		}
		var v string
		if json.Unmarshal(raw, &v) != nil || !composerSafeText(v, 4096) {
			a.fileReason(f, "invalid", "parse_error")
			return "", false
		}
		if v == "***unset***" || v == "" {
			return "", false
		}
		return v, true
	}
	for _, pair := range condaEnvSettings {
		v, ok := read(pair[0])
		alias, ok2 := "", false
		if pair[1] != "" {
			alias, ok2 = read(pair[1])
		}
		switch {
		case ok && ok2:
			a.limitation(f, "unsupported_format")
		case ok:
			values[pair[0]] = v
		case ok2:
			values[pair[0]] = alias
		}
	}
	a.settings(f, values, false)
	for _, p := range condaProxyEnv {
		for _, name := range []string{p[0], strings.ToLower(p[0])} {
			if v, ok := read(name); ok {
				proxies[p[1]+"\x00"+name] = v
				if !strings.Contains(v, "://") {
					v = "http://" + v
				}
				if condaURLCredential(v) {
					a.literal[f.SourceID] = true
					a.setting(f, "auth_configured", "true", true)
				}
			}
		}
	}
	a.proxies(f, proxies)
}

// Root observes an installation root's own search-path files as system
// scope. Which root a past invocation used is unknowable, so more than one
// root with a present file leaves the ambient context partial.
func (a *CondaConfigSnapshot) Root(path string, partial bool) {
	if a.scope.Username == "" || path == "" {
		return
	}
	if partial {
		a.rootsPartial = true
	}
	if a.rootKeys[a.key(path)] {
		return
	}
	a.rootKeys[a.key(path)] = true
	files := a.entries("system", path)
	if slices.ContainsFunc(files, func(f *model.CondaConfigFile) bool { return f != nil && f.Status == "present" }) {
		a.rootsPresent++
	}
	a.roots = append(a.roots, files...)
}

// Environment observes one prefix's own files and saved state variables; its
// context is emitted by Finish once every root is known. A root prefix's
// files are already its system-scope root files.
func (a *CondaConfigSnapshot) Environment(prefix string, partial bool) {
	if a.scope.Username == "" || prefix == "" || a.contexts[a.key(prefix)] {
		return
	}
	a.contexts[a.key(prefix)] = true
	var own []*model.CondaConfigFile
	if !a.rootKeys[a.key(prefix)] {
		own = a.entries("environment", prefix)
	}
	state := a.record("environment", filepath.Join(prefix, "conda-meta", "state"))
	if state != nil {
		a.readState(state)
	}
	a.environments = append(a.environments, condaEnvironmentContext{prefix: prefix, own: own, state: state, partial: partial})
}

func (a *CondaConfigSnapshot) readState(f *model.CondaConfigFile) {
	if a.ctx.Err() != nil {
		a.fileReason(f, "unreadable", "deadline_exceeded")
		return
	}
	p := f.Path
	files := a.exec.GuardedFiles([]string{filepath.Dir(p), p}, a.ContentGuard, condaConfigBytes)
	info, err := files.Stat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		a.readFailure(f, err, p)
		return
	case !info.Mode().IsRegular():
		a.fileReason(f, "unsupported", "unsupported_entry")
		return
	case info.Size() > condaConfigBytes:
		a.fileReason(f, "unreadable", "size_limit")
		return
	}
	data, err := files.ReadFile(p)
	if err != nil {
		a.readFailure(f, err, p)
		return
	}
	a.parseState(f, data)
}

// chain lists applicable sources highest precedence first: process
// variables, saved state, the explicit CONDARC file, the prefix's own files,
// then user, installation-root and system files.
func (a *CondaConfigSnapshot) chain(own []*model.CondaConfigFile, state *model.CondaConfigFile) ([]string, bool) {
	ids, partial := []string{}, a.partial || a.rootsPartial
	add := func(files ...*model.CondaConfigFile) {
		for _, f := range slices.Backward(files) {
			if f == nil {
				partial = true
				continue
			}
			ids = append(ids, f.SourceID)
			if f.Status != "present" && f.Status != "absent" {
				partial = true
			}
		}
	}
	add(a.process)
	if state != nil {
		add(state)
	}
	if a.condarc != nil {
		add(a.condarc)
	}
	add(own...)
	add(a.user...)
	if a.env["CONDA_ROOT"] == "" {
		add(a.roots...)
	}
	add(a.system...)
	return ids, partial || a.rootsPresent > 1 && a.env["CONDA_ROOT"] == ""
}

func condaSelection(partial bool) string {
	if partial {
		return "partial"
	}
	return "observed"
}

// Manifest records a recognized environment manifest's declared channels as
// a project-scope source with its own context. It reports whether that
// context is partial.
func (a *CondaConfigSnapshot) Manifest(path string, channels []string, status string, reasons []string) bool {
	if a.scope.Username == "" {
		return true
	}
	f := a.record("project", path)
	if f == nil {
		return true
	}
	f.Status, f.Reasons = status, append([]string{}, reasons...)
	// Unsupported manifest content may hide channels, so its context is partial.
	partial := a.partial || status != "present" || len(reasons) > 0
	if status == "present" {
		literal := false
		for i, c := range channels {
			if i >= condaSettingLimit {
				a.limitation(f, "record_limit")
				partial = true
				break
			}
			display, redacted := CondaChannelDisplay(c)
			literal = literal || condaURLCredential(c)
			a.setting(f, "channels."+strconv.Itoa(i)+".url", display, redacted)
		}
		if literal {
			a.setting(f, "auth_configured", "true", true)
			a.literal[f.SourceID] = true
		}
	}
	a.context(model.CondaConfigContext{Manager: "conda", ProjectPath: filepath.Dir(path), ConfigSourceIDs: []string{f.SourceID}, SelectionStatus: condaSelection(partial)})
	return partial
}

func (a *CondaConfigSnapshot) context(c model.CondaConfigContext) {
	if a.limited {
		return
	}
	size := len(c.EnvironmentPath) + len(c.ProjectPath) + len(c.ConfigSourceIDs)*70 + 128
	if a.bytes+size > maxCondaAuditBytes {
		a.limited, a.partial = true, true
		a.degrade("output_size_limit")
		return
	}
	a.audit.Contexts = append(a.audit.Contexts, c)
	a.bytes += size
}

func (a *CondaConfigSnapshot) credential(path string) {
	if a.limited || a.credentials[a.key(path)] {
		return
	}
	a.credentials[a.key(path)] = true
	c := model.CondaCredentialFile{Path: path, Status: "present", Presence: "present"}
	if a.ctx.Err() != nil {
		c.Status, c.Presence = "unreadable", "unknown"
		a.degrade("deadline_exceeded")
	} else {
		info, err := a.exec.GuardedFiles([]string{path}, a.scope.Protected, 0).Stat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			c.Status, c.Presence = "absent", "absent"
		case err != nil:
			c.Status, c.Presence = "unreadable", "unknown"
			reason := CargoReadReason(err, path, a.scope.Volume)
			if reason == "skipped_protected" || reason == "refused_network_volume" {
				c.Status = "skipped_protected"
			}
			a.degrade(reason)
		case filepath.Base(path) == "data" && !info.IsDir(), filepath.Base(path) != "data" && !info.Mode().IsRegular():
			c.Status, c.Presence = "unsupported", "unknown"
			a.degrade("unsupported_entry")
		}
	}
	a.audit.CredentialFiles = append(a.audit.CredentialFiles, c)
	a.bytes += len(path) + 128
}

func (a *CondaConfigSnapshot) Finish() model.CondaConfigAudit {
	if a.process != nil {
		ids, partial := a.chain(nil, nil)
		a.context(model.CondaConfigContext{Manager: "conda", ConfigSourceIDs: ids, SelectionStatus: condaSelection(partial)})
	}
	for _, e := range a.environments {
		ids, partial := a.chain(e.own, e.state)
		a.context(model.CondaConfigContext{Manager: "conda", EnvironmentPath: e.prefix, ConfigSourceIDs: ids, SelectionStatus: condaSelection(e.partial || partial)})
	}
	for _, f := range a.files {
		// An incomplete source has no current settings or findings.
		if f.Status != "present" {
			f.Settings = []model.CargoConfigSetting{}
		}
		slices.Sort(f.Reasons)
		slices.SortFunc(f.Settings, func(x, y model.CargoConfigSetting) int {
			return strings.Compare(x.Key+"\x00"+x.Display, y.Key+"\x00"+y.Display)
		})
		a.audit.Files = append(a.audit.Files, *f)
		a.audit.Findings = append(a.audit.Findings, condaFindings(*f, a.literal[f.SourceID])...)
		for _, r := range f.Reasons {
			a.degrade(r)
		}
	}
	slices.SortFunc(a.audit.Files, func(x, y model.CondaConfigFile) int {
		return strings.Compare(x.Scope+"\x00"+x.Path, y.Scope+"\x00"+y.Path)
	})
	// Two manifests in one directory share a project path; their chains order them.
	slices.SortFunc(a.audit.Contexts, func(x, y model.CondaConfigContext) int {
		return strings.Compare(x.EnvironmentPath+"\x00"+x.ProjectPath+"\x00"+strings.Join(x.ConfigSourceIDs, ","), y.EnvironmentPath+"\x00"+y.ProjectPath+"\x00"+strings.Join(y.ConfigSourceIDs, ","))
	})
	slices.SortFunc(a.audit.CredentialFiles, func(x, y model.CondaCredentialFile) int { return strings.Compare(x.Path, y.Path) })
	slices.SortFunc(a.audit.Findings, func(x, y model.CargoConfigFinding) int {
		return strings.Compare(x.Code+x.SourceID+x.Key, y.Code+y.SourceID+y.Key)
	})
	slices.Sort(a.audit.Reasons)
	data, _ := json.Marshal(a.audit)
	if len(data) > maxCondaAuditBytes {
		a.audit = emptyCondaAudit()
		a.degrade("output_size_limit")
	}
	return a.audit
}

// condaFindings derives 001/002/004 from kept settings. 003 comes from the
// pre-redaction literal-credential flag and never carries secret text.
func condaFindings(f model.CondaConfigFile, literal bool) []model.CargoConfigFinding {
	var out []model.CargoConfigFinding
	seen := map[string]bool{}
	add := func(code, key, detail string) {
		if !seen[code+"\x00"+key] {
			seen[code+"\x00"+key] = true
			out = append(out, model.CargoConfigFinding{SourceID: f.SourceID, Code: code, Severity: "MEDIUM", Key: key, Detail: detail})
		}
	}
	for _, s := range f.Settings {
		lower := strings.ToLower(s.Display)
		channel := s.Key == "channel_alias" || strings.HasSuffix(s.Key, ".url") && !strings.HasPrefix(s.Key, "proxy_servers.") || strings.HasSuffix(s.Key, ".urls")
		switch {
		case channel && strings.Contains(lower, "http://"):
			add("conda-001", s.Key, "Conda package channel uses an unencrypted connection.")
		case s.Key == "ssl_verify" && s.Display == "false":
			add("conda-002", s.Key, "TLS certificate verification is disabled by Conda configuration.")
		case s.Key == "safety_checks" && s.Display == "disabled":
			add("conda-004", s.Key, "Conda package safety checks are disabled.")
		case s.Key == "auth_configured" && literal && f.Scope != "process":
			add("conda-003", s.Key, "Credentials are embedded in Conda configuration.")
		}
	}
	return out
}
