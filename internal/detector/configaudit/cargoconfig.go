package configaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Cargo config limits.
// ponytail: unmeasured starting values; tune with lab sizes.
var (
	maxCargoConfigBytes  int64 = 2 << 20
	maxCargoIncludeDepth       = 8
	maxCargoIncludeFiles       = 64 // config files loaded for one context chain
	maxCargoAuditBytes         = 256 << 10
	maxCargoSettingLen         = 4096
	maxCargoKeyPartLen         = 256
)

// cargoBuiltinProviders are credential providers shipped with Cargo; their
// names carry no secret. Anything else is shown as custom.
var cargoBuiltinProviders = map[string]bool{
	"cargo:token": true, "cargo:wincred": true, "cargo:macos-keychain": true, "cargo:libsecret": true,
}

// SanitizeCargoURL strips userinfo, query and fragment from a URL; anything
// that still carries an '@' is redacted whole.
func SanitizeCargoURL(raw string) (string, bool) { return sanitizeGoURL(raw) }

// CargoReadReason maps a guarded-read failure to a Cargo reason code,
// separating a skipped network volume from a protected directory.
func CargoReadReason(err error, path string, volume func(string) bool) string {
	reason := GoReadReason(err)
	if reason == model.CargoReasonSkippedProtected && volume != nil && volume(path) {
		return model.CargoReasonRefusedNetworkVolume
	}
	return reason
}

// CargoConfigScope is what the Cargo config audit may read, decided by the
// caller from the resolved developer identity.
type CargoConfigScope struct {
	Username string   // resolved developer identity, part of every source ID
	Home     string   // from the OS user record
	Roots    []string // approved scope for ancestor .cargo probes
	// Protected returns a reason code for a path that must not be touched.
	Protected func(path string) string
	// Volume reports a skipped network volume.
	Volume func(path string) bool
	// ProcessVerified means this process runs as the developer, so its own
	// environment is an observed context for that developer.
	ProcessVerified bool
	// CargoHome is the effective Cargo home; empty when it is unresolved.
	CargoHome string
	// Contexts are the directories Cargo would be invoked in.
	Contexts []CargoContextDir
	// RegistryNames are registry aliases named by manifests, whose process
	// environment keys are probed.
	RegistryNames []string
}

// CargoContextDir is one invocation directory and the workspace root it
// belongs to, if any.
type CargoContextDir struct{ Project, Workspace string }

// CargoConfigSnapshot is the sanitized view inventory uses: per-context
// registry and lockfile values plus configured roots. Token values are never
// held.
type CargoConfigSnapshot struct {
	goos            string
	contexts        map[string]*cargoContextValues // context dir key -> merged values
	directories     []string
	localRegistries []string
	installRoots    []string
	localPaths      []string
}

type cargoContextValues struct {
	registries    map[string]string // alias -> sanitized index URL
	envRegistries map[string]string // CARGO_REGISTRIES_<ALIAS>_INDEX -> sanitized index URL
	lockfile      cargoSetting
	lockfileSet   bool
	partial       bool
}

// RegistryIndex returns the index URL a context maps alias to; ok is false
// when no readable source defines it, or when a config file of the context
// was not read and so may redefine it.
func (s CargoConfigSnapshot) RegistryIndex(contextDir, alias string) (string, bool) {
	if c := s.contexts[GoPathKey(s.goos, contextDir)]; c != nil {
		return c.registryIndex(alias)
	}
	return "", false
}

// LockfilePath is the resolver.lockfile-path selected in contextDir. path is
// empty for the default location; unresolved means a value or a source could
// not be established, so the returned path is not known to be the one Cargo
// uses.
func (s CargoConfigSnapshot) LockfilePath(contextDir string) (path string, unresolved bool) {
	c := s.contexts[GoPathKey(s.goos, contextDir)]
	if c == nil {
		return "", true
	}
	if c.lockfileSet {
		// Cargo rejects a selected path that is not named Cargo.lock.
		if c.lockfile.unresolved || filepath.Base(c.lockfile.Display) != "Cargo.lock" {
			return "", true
		}
		return c.lockfile.Display, c.partial && !c.lockfile.env
	}
	return "", c.partial
}

// DirectorySources are the resolved source.<name>.directory roots.
func (s CargoConfigSnapshot) DirectorySources() []string { return s.directories }

// LocalRegistries are the resolved source.<name>.local-registry roots.
func (s CargoConfigSnapshot) LocalRegistries() []string { return s.localRegistries }

// InstallRoots are the resolved install.root values and an absolute
// CARGO_INSTALL_ROOT.
func (s CargoConfigSnapshot) InstallRoots() []string { return s.installRoots }

// LocalPaths are package directories named by config paths and patch entries.
func (s CargoConfigSnapshot) LocalPaths() []string { return s.localPaths }

// CargoConfigDetector audits Cargo's configuration sources without running
// Cargo. It must be built with the raw executor: UserAwareExecutor.Getenv
// sources a login shell for some keys.
type CargoConfigDetector struct {
	exec executor.Executor
}

func NewCargoConfigDetector(exec executor.Executor) *CargoConfigDetector {
	return &CargoConfigDetector{exec: exec}
}

// cargoSetting is one allowlisted value. For path settings Display is the
// resolved absolute path unless unresolved is set.
type cargoSetting struct {
	model.CargoConfigSetting
	unresolved bool
	token      bool // a literal token value, which never leaves the process
	url        bool
	env        bool // from the process environment, which overrides every file
}

// cargoInclude is one include entry of a config file.
type cargoInclude struct {
	path     string
	optional bool
	invalid  bool // not a .toml path
}

// cargoConfigRead is one physical read, shared by every record of that path.
type cargoConfigRead struct {
	status   string
	reasons  []string
	settings []cargoSetting // SourceID unset
	includes []cargoInclude
}

// cargoAudit is the state of one Detect call.
type cargoAudit struct {
	d       *CargoConfigDetector
	ctx     context.Context
	scope   CargoConfigScope
	goos    string
	reads   map[string]*cargoConfigRead // path key -> read
	files   map[string]*cargoConfigFile // source ID -> record
	process *cargoConfigFile
}

type cargoConfigFile struct {
	file     model.CargoConfigFile
	settings []cargoSetting
	includes []cargoInclude
}

// Detect returns the audit and the snapshot inventory uses.
func (d *CargoConfigDetector) Detect(ctx context.Context, scope CargoConfigScope) (model.CargoConfigAudit, CargoConfigSnapshot) {
	audit := model.CargoConfigAudit{
		SchemaVersion: model.CargoInventorySchemaVersion, Status: model.CargoStatusComplete, Reasons: []string{},
		Files: []model.CargoConfigFile{}, Findings: []model.CargoConfigFinding{},
		Contexts: []model.CargoConfigContext{}, CredentialFiles: []model.CargoCredentialFile{},
	}
	snap := CargoConfigSnapshot{goos: d.exec.GOOS(), contexts: map[string]*cargoContextValues{}}
	if scope.Username == "" || scope.Home == "" {
		audit.Status, audit.Reasons = model.CargoStatusPartial, []string{model.CargoReasonUserUnresolved}
		return audit, snap
	}
	if ctx.Err() != nil {
		audit.Status, audit.Reasons = model.CargoStatusPartial, []string{model.CargoReasonDeadlineExceeded}
		return audit, snap
	}
	a := &cargoAudit{d: d, ctx: ctx, scope: scope, goos: d.exec.GOOS(), reads: map[string]*cargoConfigRead{}, files: map[string]*cargoConfigFile{}}

	homeChain, homePartial := a.homeChain()
	type observed struct {
		ctx     model.CargoConfigContext
		chain   []*cargoConfigFile // lowest precedence first
		partial bool
	}
	var contexts []observed
	seen := map[string]bool{}
	for _, c := range scope.Contexts {
		if k := GoPathKey(a.goos, c.Project); c.Project == "" || seen[k] {
			continue
		} else {
			seen[k] = true
		}
		chain, partial := a.dirChain(c.Project)
		chain = append(slices.Clone(homeChain), chain...)
		contexts = append(contexts, observed{
			ctx:   model.CargoConfigContext{ProjectPath: c.Project, WorkspacePath: c.Workspace},
			chain: chain, partial: partial || homePartial,
		})
	}
	contexts = append(contexts, observed{chain: homeChain, partial: homePartial})

	// The process source is read last so it can probe every alias seen above.
	a.process = a.processSource()
	for _, o := range contexts {
		chain := o.chain
		if a.scope.ProcessVerified {
			chain = append(slices.Clone(chain), a.process)
		}
		values := &cargoContextValues{registries: map[string]string{}, envRegistries: map[string]string{}, partial: o.partial}
		ids := []string{}
		for i := len(chain) - 1; i >= 0; i-- {
			ids = append(ids, chain[i].file.SourceID)
		}
		for _, f := range chain {
			values.apply(f.settings)
		}
		o.ctx.ConfigSourceIDs, o.ctx.SelectionStatus = ids, model.CargoSelectionObserved
		if o.partial {
			o.ctx.SelectionStatus = model.CargoSelectionPartial
		}
		audit.Contexts = append(audit.Contexts, o.ctx)
		snap.contexts[GoPathKey(a.goos, o.ctx.ProjectPath)] = values
	}
	audit.CredentialFiles = a.credentialFiles()

	for _, f := range a.sortedFiles() {
		audit.Files = append(audit.Files, f.file)
		audit.Findings = append(audit.Findings, cargoFindings(f)...)
		if f.file.ShadowedBy == "" && f.file.Status == model.CargoConfigPresent {
			snap.collect(f.settings)
		}
		if f.file.Scope == model.CargoConfigScopeProcess {
			continue // DMG's own context is never a developer config source
		}
		switch f.file.Status {
		case model.CargoConfigPresent, model.CargoConfigAbsent:
		default:
			audit.Status = model.CargoStatusPartial
		}
		audit.Reasons = append(audit.Reasons, f.file.Reasons...)
	}
	for _, c := range audit.Contexts {
		if c.SelectionStatus == model.CargoSelectionPartial {
			audit.Status = model.CargoStatusPartial
		}
	}
	if len(audit.Reasons) > 0 {
		audit.Status = model.CargoStatusPartial
	}
	slices.Sort(audit.Reasons)
	audit.Reasons = slices.Compact(audit.Reasons)
	slices.SortFunc(audit.Findings, func(a, b model.CargoConfigFinding) int {
		return strings.Compare(a.Code+"\x00"+a.SourceID+"\x00"+a.Key, b.Code+"\x00"+b.SourceID+"\x00"+b.Key)
	})
	slices.SortFunc(audit.Contexts, func(a, b model.CargoConfigContext) int {
		return strings.Compare(a.ProjectPath+"\x00"+a.WorkspacePath, b.ProjectPath+"\x00"+b.WorkspacePath)
	})
	snap.finish(a.goos)

	if b, err := json.Marshal(audit); err == nil && len(b) > maxCargoAuditBytes {
		audit = model.CargoConfigAudit{
			SchemaVersion: model.CargoInventorySchemaVersion, Status: model.CargoStatusPartial,
			Reasons: []string{model.CargoReasonOutputSizeLimit}, Files: []model.CargoConfigFile{},
			Findings: []model.CargoConfigFinding{}, Contexts: []model.CargoConfigContext{}, CredentialFiles: []model.CargoCredentialFile{},
		}
	}
	return audit, snap
}

func (a *cargoAudit) sortedFiles() []*cargoConfigFile {
	out := make([]*cargoConfigFile, 0, len(a.files)+1)
	for _, f := range a.files {
		out = append(out, f)
	}
	out = append(out, a.process)
	slices.SortFunc(out, func(x, y *cargoConfigFile) int {
		return strings.Compare(x.file.Scope+"\x00"+x.file.Path, y.file.Scope+"\x00"+y.file.Path)
	})
	return out
}

// homeChain loads the Cargo home config, lowest precedence first.
func (a *cargoAudit) homeChain() ([]*cargoConfigFile, bool) {
	if a.scope.CargoHome == "" {
		f := a.record(model.CargoConfigScopeUser, "", "")
		f.file.Status, f.file.Reasons = model.CargoConfigUnsupported, []string{model.CargoReasonPathUnresolved}
		return nil, true
	}
	var chain []*cargoConfigFile
	partial := a.dotCargo(a.scope.CargoHome, model.CargoConfigScopeUser, []string{a.scope.CargoHome}, &chain)
	return chain, partial
}

// dirChain loads the .cargo configs of dir and each ancestor inside the
// approved roots, lowest precedence (outermost) first. The Cargo home's own
// directory is loaded once, as the home source.
func (a *cargoAudit) dirChain(dir string) ([]*cargoConfigFile, bool) {
	var dirs []string
	for d := filepath.Clean(dir); GoWithinRoots(a.goos, d, a.scope.Roots); d = filepath.Dir(d) {
		dirs = append(dirs, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	var chain []*cargoConfigFile
	partial := false
	for i := len(dirs) - 1; i >= 0; i-- {
		dotCargo := filepath.Join(dirs[i], ".cargo")
		if a.scope.CargoHome != "" && GoPathKey(a.goos, dotCargo) == GoPathKey(a.goos, a.scope.CargoHome) {
			continue
		}
		if a.dotCargo(dotCargo, model.CargoConfigScopeProject, a.scope.Roots, &chain) {
			partial = true
		}
	}
	return chain, partial
}

// dotCargo loads one directory's config pair. The legacy extensionless config
// wins when both exist; the other file is still read and reported, but
// marked shadowed and never applied. Absent files are reported only for the
// Cargo home, where their absence is informative.
func (a *cargoAudit) dotCargo(dir, scope string, roots []string, chain *[]*cargoConfigFile) bool {
	legacy, current := filepath.Join(dir, "config"), filepath.Join(dir, "config.toml")
	legacyRead, currentRead := a.read(legacy, roots), a.read(current, roots)
	var chosen string
	switch {
	case legacyRead.status != model.CargoConfigAbsent:
		chosen = legacy
		if currentRead.status != model.CargoConfigAbsent {
			shadowed := a.record(scope, current, "")
			a.fill(shadowed, currentRead)
			shadowed.file.ShadowedBy = a.id(scope, legacy)
		}
	case currentRead.status != model.CargoConfigAbsent:
		chosen = current
	default:
		if scope == model.CargoConfigScopeUser {
			a.fill(a.record(scope, current, ""), currentRead)
		}
		return false
	}
	return a.load(chosen, scope, "", 0, map[string]bool{}, chain)
}

// load appends path's include graph to out, lowest precedence first:
// includes left to right, then the file itself. Cargo rejects a path loaded
// twice in one graph, so a repeat marks the including file invalid.
func (a *cargoAudit) load(path, scope, parentID string, depth int, seen map[string]bool, out *[]*cargoConfigFile) (partial bool) {
	f := a.record(scope, path, parentID)
	r := a.read(path, a.includeRoots(scope, path))
	a.fill(f, r)
	seen[GoPathKey(a.goos, path)] = true
	if r.status != model.CargoConfigPresent {
		return r.status != model.CargoConfigAbsent
	}
	unresolved := func() {
		f.file.Status = model.CargoConfigInvalid
		f.addReason(model.CargoReasonConfigIncludeUnresolved)
		partial = true
	}
	for _, inc := range f.includes {
		k := GoPathKey(a.goos, inc.path)
		switch {
		case inc.invalid, seen[k], depth+1 > maxCargoIncludeDepth, len(*out) >= maxCargoIncludeFiles:
			unresolved()
			continue
		}
		if !inc.optional || a.read(inc.path, a.includeRoots(model.CargoConfigScopeIncluded, inc.path)).status != model.CargoConfigAbsent {
			if a.load(inc.path, model.CargoConfigScopeIncluded, f.file.SourceID, depth+1, seen, out) {
				partial = true
			}
			if child := a.files[a.id(model.CargoConfigScopeIncluded, inc.path)]; child != nil && child.file.Status == model.CargoConfigAbsent {
				unresolved() // a required include is missing
			}
		}
	}
	*out = append(*out, f)
	return partial
}

// includeRoots scopes a read: ancestor files stay inside the approved roots;
// the Cargo home and included files are exact targeted reads.
func (a *cargoAudit) includeRoots(scope, path string) []string {
	if scope == model.CargoConfigScopeProject {
		return a.scope.Roots
	}
	return []string{path}
}

func (a *cargoAudit) id(scope, path string) string {
	return GoSourceID(a.scope.Username, "cargo_config_"+scope, path)
}

// record returns the one record for scope and path.
func (a *cargoAudit) record(scope, path, parentID string) *cargoConfigFile {
	id := a.id(scope, path)
	if f := a.files[id]; f != nil {
		return f
	}
	f := &cargoConfigFile{file: model.CargoConfigFile{
		SourceID: id, Scope: scope, Path: path, Status: model.CargoConfigAbsent,
		Reasons: []string{}, Settings: []model.CargoConfigSetting{}, IncludeParentSourceID: parentID,
	}}
	a.files[id] = f
	return f
}

func (f *cargoConfigFile) addReason(r string) {
	if !slices.Contains(f.file.Reasons, r) {
		f.file.Reasons = append(f.file.Reasons, r)
	}
}

// fill copies a physical read into a record, stamping settings with its ID.
func (a *cargoAudit) fill(f *cargoConfigFile, r *cargoConfigRead) {
	if len(f.settings) > 0 || f.file.Status != model.CargoConfigAbsent {
		return // already filled
	}
	f.file.Status = r.status
	for _, reason := range r.reasons {
		f.addReason(reason)
	}
	f.includes = r.includes
	for _, s := range r.settings {
		s.SourceID = f.file.SourceID
		f.settings = append(f.settings, s)
		f.file.Settings = append(f.file.Settings, s.CargoConfigSetting)
	}
}

// read reads and parses path once, however many records share it.
func (a *cargoAudit) read(path string, roots []string) *cargoConfigRead {
	k := GoPathKey(a.goos, path)
	if r := a.reads[k]; r != nil {
		return r
	}
	r := &cargoConfigRead{status: model.CargoConfigAbsent}
	a.reads[k] = r
	fail := func(status, reason string) { r.status, r.reasons = status, []string{reason} }
	if a.ctx.Err() != nil {
		fail(model.CargoConfigUnreadable, model.CargoReasonDeadlineExceeded)
		return r
	}
	if a.scope.Protected != nil && a.scope.Protected(path) != "" {
		fail(model.CargoConfigSkippedProtected, a.reason(nil, path))
		return r
	}
	files := a.d.exec.GuardedFiles(roots, a.scope.Protected, maxCargoConfigBytes)
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return r
	case err != nil:
		fail(a.failStatus(err, path), a.reason(err, path))
		return r
	case !info.Mode().IsRegular():
		fail(model.CargoConfigUnreadable, model.CargoReasonUnsupportedEntry)
		return r
	case info.Size() > maxCargoConfigBytes:
		fail(model.CargoConfigUnreadable, model.CargoReasonSizeLimit)
		return r
	}
	data, err := files.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		fail(model.CargoConfigUnreadable, model.CargoReasonChangedDuringScan)
		return r
	} else if err != nil {
		fail(a.failStatus(err, path), a.reason(err, path))
		return r
	}
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		fail(model.CargoConfigInvalid, model.CargoReasonParseError)
		return r
	}
	r.status = model.CargoConfigPresent
	r.settings, r.includes = cargoConfigSettings(doc, path)
	return r
}

func (a *cargoAudit) reason(err error, path string) string {
	if err == nil {
		if a.scope.Volume != nil && a.scope.Volume(path) {
			return model.CargoReasonRefusedNetworkVolume
		}
		return model.CargoReasonSkippedProtected
	}
	return CargoReadReason(err, path, a.scope.Volume)
}

func (a *cargoAudit) failStatus(err error, path string) string {
	switch a.reason(err, path) {
	case model.CargoReasonSkippedProtected, model.CargoReasonRefusedNetworkVolume:
		return model.CargoConfigSkippedProtected
	case model.CargoReasonOutsideApprovedRoots:
		return model.CargoConfigUnsupported
	}
	return model.CargoConfigUnreadable
}

// cargoProcessKeys are the fixed process environment keys read; registry
// keys are added per alias.
var cargoProcessKeys = []string{
	"CARGO_HOME", "CARGO_INSTALL_ROOT", "CARGO_RESOLVER_LOCKFILE_PATH", "CARGO_REGISTRY_DEFAULT",
	"CARGO_REGISTRY_TOKEN", "CARGO_REGISTRY_CREDENTIAL_PROVIDER", "CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS",
	"CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "CARGO_HTTP_PROXY", "CARGO_HTTP_CAINFO", "CARGO_HTTP_PROXY_CAINFO",
	"CARGO_HTTP_SSL_VERSION", "CARGO_HTTP_CHECK_REVOKE", "CARGO_NET_OFFLINE", "CARGO_NET_GIT_FETCH_WITH_CLI",
}

// processSource reads the allowlisted keys of this process's environment,
// only when it runs as the developer. Relative paths stay unresolved: the
// originating shell's working directory is unknown.
func (a *cargoAudit) processSource() *cargoConfigFile {
	f := &cargoConfigFile{file: model.CargoConfigFile{
		SourceID: a.id(model.CargoConfigScopeProcess, ""), Scope: model.CargoConfigScopeProcess,
		Status: model.CargoConfigAbsent, Reasons: []string{}, Settings: []model.CargoConfigSetting{},
	}}
	if !a.scope.ProcessVerified {
		f.file.Status = model.CargoConfigUnsupported
		return f
	}
	aliases := slices.Clone(a.scope.RegistryNames)
	for _, file := range a.files {
		for _, s := range file.settings {
			if rest, ok := strings.CutPrefix(s.Key, "registries."); ok {
				if name, _, ok := strings.Cut(rest, "."); ok {
					aliases = append(aliases, name)
				}
			}
		}
	}
	slices.Sort(aliases)
	keys := slices.Clone(cargoProcessKeys)
	for _, name := range slices.Compact(aliases) {
		env := cargoRegistryEnv(name)
		keys = append(keys, env+"_INDEX", env+"_TOKEN", env+"_CREDENTIAL_PROVIDER")
	}
	b := &cargoSettings{}
	for _, k := range keys {
		v := a.d.exec.Getenv(k)
		if v == "" {
			continue
		}
		switch {
		case strings.HasSuffix(k, "_TOKEN"):
			b.token(k, v)
		case strings.HasSuffix(k, "_CREDENTIAL_PROVIDER"):
			b.provider(k, v)
		case k == "CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS":
			for _, p := range strings.Fields(v) {
				b.provider(k, p)
			}
		case strings.HasSuffix(k, "_INDEX"), k == "CARGO_HTTP_PROXY":
			b.url(k, v)
		case k == "CARGO_HOME", k == "CARGO_INSTALL_ROOT", k == "CARGO_RESOLVER_LOCKFILE_PATH",
			k == "CARGO_HTTP_CAINFO", k == "CARGO_HTTP_PROXY_CAINFO":
			b.envPath(k, v)
		default:
			b.str(k, v)
		}
	}
	f.settings = b.out
	for i := range f.settings {
		f.settings[i].SourceID, f.settings[i].env = f.file.SourceID, true
		f.file.Settings = append(f.file.Settings, f.settings[i].CargoConfigSetting)
	}
	if len(f.settings) > 0 {
		f.file.Status = model.CargoConfigPresent
	}
	return f
}

// credentialFiles reports the Cargo home credential files by Stat alone.
func (a *cargoAudit) credentialFiles() []model.CargoCredentialFile {
	out := []model.CargoCredentialFile{}
	if a.scope.CargoHome == "" {
		return out
	}
	for _, name := range []string{"credentials", "credentials.toml"} {
		p := filepath.Join(a.scope.CargoHome, name)
		c := model.CargoCredentialFile{Path: p, Status: model.CargoConfigPresent, Presence: model.CargoPresencePresent}
		if a.scope.Protected != nil && a.scope.Protected(p) != "" {
			c.Status, c.Presence = model.CargoConfigSkippedProtected, model.CargoPresenceUnknown
		} else if info, err := a.d.exec.GuardedFiles([]string{p}, a.scope.Protected, 0).Stat(p); errors.Is(err, fs.ErrNotExist) {
			c.Status, c.Presence = model.CargoConfigAbsent, model.CargoPresenceAbsent
		} else if err != nil {
			c.Status, c.Presence = a.failStatus(err, p), model.CargoPresenceUnknown
		} else if !info.Mode().IsRegular() {
			c.Status, c.Presence = model.CargoConfigUnreadable, model.CargoPresenceUnknown
		}
		out = append(out, c)
	}
	return out
}

// apply merges one source's settings over lower-precedence ones.
func (v *cargoContextValues) apply(settings []cargoSetting) {
	for _, s := range settings {
		switch {
		case s.Key == "resolver.lockfile-path", s.Key == "CARGO_RESOLVER_LOCKFILE_PATH":
			v.lockfile, v.lockfileSet = s, true
		case strings.HasPrefix(s.Key, "registries.") && strings.HasSuffix(s.Key, ".index"):
			v.registries[strings.TrimSuffix(strings.TrimPrefix(s.Key, "registries."), ".index")] = s.Display
		case strings.HasPrefix(s.Key, "CARGO_REGISTRIES_") && strings.HasSuffix(s.Key, "_INDEX"):
			v.envRegistries[s.Key] = s.Display
		}
	}
}

// collect gathers configured roots from an applied source.
func (s *CargoConfigSnapshot) collect(settings []cargoSetting) {
	for _, st := range settings {
		if st.unresolved {
			continue
		}
		switch k := st.Key; {
		case strings.HasPrefix(k, "source.") && strings.HasSuffix(k, ".directory"):
			s.directories = append(s.directories, st.Display)
		case strings.HasPrefix(k, "source.") && strings.HasSuffix(k, ".local-registry"):
			s.localRegistries = append(s.localRegistries, st.Display)
		case k == "install.root", k == "CARGO_INSTALL_ROOT":
			s.installRoots = append(s.installRoots, st.Display)
		case k == "paths", strings.HasPrefix(k, "patch.") && strings.HasSuffix(k, ".path"):
			s.localPaths = append(s.localPaths, st.Display)
		}
	}
}

func (s *CargoConfigSnapshot) finish(goos string) {
	for _, list := range []*[]string{&s.directories, &s.localRegistries, &s.installRoots, &s.localPaths} {
		slices.SortFunc(*list, func(a, b string) int { return strings.Compare(GoPathKey(goos, a), GoPathKey(goos, b)) })
		*list = slices.CompactFunc(*list, func(a, b string) bool { return GoPathKey(goos, a) == GoPathKey(goos, b) })
	}
}

// registryIndex prefers the process environment key, which overrides every
// config file. A file value is not definitive while any file of the context
// is unread.
func (v *cargoContextValues) registryIndex(alias string) (string, bool) {
	if u, ok := v.envRegistries[cargoRegistryEnv(alias)+"_INDEX"]; ok {
		return u, true
	}
	if v.partial {
		return "", false
	}
	u, ok := v.registries[alias]
	return u, ok
}

// cargoRegistryEnv is the environment key prefix Cargo derives from an alias.
func cargoRegistryEnv(alias string) string {
	return "CARGO_REGISTRIES_" + strings.ToUpper(strings.ReplaceAll(alias, "-", "_"))
}

// cargoSettings builds the allowlisted settings of one source.
type cargoSettings struct {
	file string // defining file; empty for the process environment
	out  []cargoSetting
}

func (b *cargoSettings) add(key, display string, redacted bool) *cargoSetting {
	if len(display) > maxCargoSettingLen || strings.ContainsFunc(display, unicode.IsControl) {
		display, redacted = "", true
	}
	b.out = append(b.out, cargoSetting{CargoConfigSetting: model.CargoConfigSetting{Key: key, Display: display, Redacted: redacted}})
	return &b.out[len(b.out)-1]
}

func (b *cargoSettings) str(key string, v any) {
	switch x := v.(type) {
	case string:
		b.add(key, x, false)
	case bool, int64, float64:
		b.add(key, fmt.Sprint(x), false)
	}
}

func (b *cargoSettings) url(key string, v any) {
	if s, ok := v.(string); ok {
		display, redacted := SanitizeCargoURL(s)
		b.add(key, display, redacted).url = true
	}
}

// token records only that a token is configured.
func (b *cargoSettings) token(key string, v any) {
	if s, ok := v.(string); ok && s != "" {
		b.add(key, "configured", true).token = true
	}
}

// provider shows a built-in provider name; custom providers and any
// arguments may hold secrets and are never shown.
func (b *cargoSettings) provider(key string, v any) {
	var fields []string
	switch x := v.(type) {
	case string:
		fields = strings.Fields(x)
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok {
				fields = append(fields, s)
			}
		}
	}
	if len(fields) == 0 {
		return
	}
	switch {
	case cargoBuiltinProviders[fields[0]]:
		b.add(key, fields[0], len(fields) > 1)
	case fields[0] == "cargo:token-from-stdout":
		b.add(key, fields[0], len(fields) > 1)
	default:
		b.add(key, "custom", true)
	}
}

// path resolves a config-relative path against the parent of the directory
// holding the defining file, as Cargo does, even for an included file.
func (b *cargoSettings) path(key string, v any) {
	s, ok := v.(string)
	if !ok || s == "" {
		return
	}
	if strings.Contains(s, "{") {
		b.add(key, s, false).unresolved = true
		return
	}
	if !filepath.IsAbs(s) {
		s = filepath.Join(filepath.Dir(filepath.Dir(b.file)), filepath.FromSlash(s))
	}
	b.add(key, filepath.Clean(s), false)
}

// envPath keeps an absolute environment path; a relative one depends on the
// unknown working directory of the originating shell.
func (b *cargoSettings) envPath(key, v string) {
	if filepath.IsAbs(v) {
		b.add(key, filepath.Clean(v), false)
		return
	}
	b.add(key, v, false).unresolved = true
}

func cargoTableOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// cargoKeyPart makes a user-chosen table name safe inside a setting key. A
// patch table is named by a source URL, whose credentials are stripped like
// any other URL; redacted reports that something was removed.
func cargoKeyPart(name string) (part string, redacted, ok bool) {
	if name == "" || len(name) > maxCargoKeyPartLen || strings.ContainsFunc(name, unicode.IsControl) {
		return "", false, false
	}
	part, redacted = SanitizeCargoURL(name)
	return part, redacted, true
}

// redactFrom marks every setting added since index start as redacted.
func (b *cargoSettings) redactFrom(start int) {
	for i := start; i < len(b.out); i++ {
		b.out[i].Redacted = true
	}
}

// cargoConfigSettings extracts the allowlisted settings and include entries
// of one config document. Every other key is dropped in memory.
func cargoConfigSettings(doc map[string]any, file string) ([]cargoSetting, []cargoInclude) {
	b := &cargoSettings{file: file}
	reg := cargoTableOf(doc["registry"])
	b.str("registry.default", reg["default"])
	b.token("registry.token", reg["token"])
	b.provider("registry.credential-provider", reg["credential-provider"])
	if list, ok := reg["global-credential-providers"].([]any); ok {
		for _, p := range list {
			b.provider("registry.global-credential-providers", p)
		}
	}
	for name, raw := range cargoTableOf(doc["registries"]) {
		r := cargoTableOf(raw)
		part, redacted, ok := cargoKeyPart(name)
		if !ok || r == nil {
			continue
		}
		start, prefix := len(b.out), "registries."+part+"."
		b.url(prefix+"index", r["index"])
		b.token(prefix+"token", r["token"])
		b.provider(prefix+"credential-provider", r["credential-provider"])
		if name == "crates-io" {
			b.str(prefix+"protocol", r["protocol"])
		}
		if redacted {
			b.redactFrom(start)
		}
	}
	for name, raw := range cargoTableOf(doc["source"]) {
		src := cargoTableOf(raw)
		part, redacted, ok := cargoKeyPart(name)
		if !ok || src == nil {
			continue
		}
		start, prefix := len(b.out), "source."+part+"."
		b.str(prefix+"replace-with", src["replace-with"])
		b.url(prefix+"registry", src["registry"])
		b.path(prefix+"directory", src["directory"])
		b.path(prefix+"local-registry", src["local-registry"])
		b.url(prefix+"git", src["git"])
		for _, sel := range []string{"branch", "tag", "rev"} {
			b.str(prefix+sel, src[sel])
		}
		if redacted {
			b.redactFrom(start)
		}
	}
	http := cargoTableOf(doc["http"])
	b.url("http.proxy", http["proxy"])
	b.path("http.cainfo", http["cainfo"])
	b.path("http.proxy-cainfo", http["proxy-cainfo"])
	if ssl := cargoTableOf(http["ssl-version"]); ssl != nil {
		b.str("http.ssl-version.min", ssl["min"])
		b.str("http.ssl-version.max", ssl["max"])
	} else {
		b.str("http.ssl-version", http["ssl-version"])
	}
	b.str("http.check-revoke", http["check-revoke"])
	net := cargoTableOf(doc["net"])
	b.str("net.offline", net["offline"])
	b.str("net.git-fetch-with-cli", net["git-fetch-with-cli"])
	b.path("install.root", cargoTableOf(doc["install"])["root"])
	b.path("resolver.lockfile-path", cargoTableOf(doc["resolver"])["lockfile-path"])
	if list, ok := doc["paths"].([]any); ok {
		for _, p := range list {
			b.path("paths", p)
		}
	}
	for src, raw := range cargoTableOf(doc["patch"]) {
		srcPart, srcRedacted, srcOK := cargoKeyPart(src)
		for name, entry := range cargoTableOf(raw) {
			e := cargoTableOf(entry)
			part, redacted, ok := cargoKeyPart(name)
			if !srcOK || !ok || e == nil {
				continue
			}
			start, prefix := len(b.out), "patch."+srcPart+"."+part+"."
			b.path(prefix+"path", e["path"])
			b.url(prefix+"git", e["git"])
			if srcRedacted || redacted {
				b.redactFrom(start)
			}
		}
	}

	includes := cargoIncludes(doc["include"], file)
	for _, inc := range includes {
		b.add("include", inc.path, false)
	}
	slices.SortStableFunc(b.out, func(x, y cargoSetting) int { return strings.Compare(x.Key, y.Key) })
	return b.out, includes
}

// cargoIncludes reads include as a string, or an array of strings and
// {path, optional} tables. Paths are relative to the including file.
func cargoIncludes(v any, file string) []cargoInclude {
	var raw []any
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		raw = x
	default:
		raw = []any{x}
	}
	var out []cargoInclude
	for _, item := range raw {
		inc := cargoInclude{}
		switch x := item.(type) {
		case string:
			inc.path = x
		case map[string]any:
			inc.path, _ = x["path"].(string)
			inc.optional, _ = x["optional"].(bool)
		}
		if inc.path == "" || !strings.HasSuffix(inc.path, ".toml") || len(inc.path) > maxCargoSettingLen {
			inc.invalid = true
		}
		if !filepath.IsAbs(inc.path) {
			inc.path = filepath.Join(filepath.Dir(file), filepath.FromSlash(inc.path))
		}
		inc.path = filepath.Clean(inc.path)
		out = append(out, inc)
	}
	return out
}

// cargoFindings evaluates one source's own values; there is no merged
// effective verdict because other invocation contexts remain unknown.
func cargoFindings(f *cargoConfigFile) []model.CargoConfigFinding {
	var out []model.CargoConfigFinding
	add := func(code, severity, key, detail string) {
		out = append(out, model.CargoConfigFinding{Code: code, Severity: severity, SourceID: f.file.SourceID, Key: key, Detail: detail})
	}
	for _, s := range f.settings {
		scheme := cargoScheme(s.Display)
		switch {
		case s.url && scheme == "http" && (strings.HasSuffix(s.Key, ".index") || strings.HasSuffix(s.Key, "_INDEX") ||
			(strings.HasPrefix(s.Key, "source.") && strings.HasSuffix(s.Key, ".registry"))):
			add("cargo-001", pipSevMedium, s.Key, "registry index uses plaintext http transport")
		case s.url && (scheme == "http" || scheme == "git") && strings.HasSuffix(s.Key, ".git"):
			add("cargo-002", pipSevMedium, s.Key, "Git source uses http or unauthenticated git transport")
		case s.token && f.file.Scope != model.CargoConfigScopeProcess:
			add("cargo-003", pipSevMedium, s.Key, "registry token is written in a config file rather than a credentials file or provider")
		case s.Key == "http.check-revoke" || s.Key == "CARGO_HTTP_CHECK_REVOKE":
			if s.Display == "false" {
				add("cargo-004", pipSevLow, s.Key, "certificate revocation checking is disabled; TLS peer validation is unaffected")
			}
		}
	}
	return out
}

// cargoScheme is a URL's lowercase scheme without a sparse+ or registry+ prefix.
func cargoScheme(u string) string {
	scheme, _, ok := strings.Cut(u, "://")
	if !ok {
		return ""
	}
	scheme = strings.ToLower(scheme)
	if _, s, ok := strings.Cut(scheme, "+"); ok {
		scheme = s
	}
	return scheme
}
