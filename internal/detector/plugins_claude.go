package detector

import (
	"encoding/json"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Claude Code plugin adapter. Evidence, in authority order: the installation
// registry, the marketplace registry, the settings layers, then catalogs and
// manifests for provenance and declared components. Manifest-bearing skill
// directories and account-synced packages are separate discovery kinds that
// need no registry row.

const (
	claudeInstalledRegistry  = "installed_plugins.json"
	claudeKnownMarketplaces  = "known_marketplaces.json"
	claudeRegistrySchema     = 2
	claudeManifestRel        = ".claude-plugin/plugin.json"
	claudeCatalogRel         = ".claude-plugin/marketplace.json"
	claudeSkillsDirMarket    = "skills-dir"
	claudeSyncedMarket       = "synced"
	claudeMCPFile            = ".mcp.json"
	claudeLSPFile            = ".lsp.json"
	claudeHooksFile          = "hooks/hooks.json"
	claudeManagedSettingsMac = "/Library/Application Support/ClaudeCode/managed-settings.json"
	claudeManagedSettingsNix = "/etc/claude-code/managed-settings.json"
	claudeManagedSettingsWin = `%ProgramFiles%\ClaudeCode\managed-settings.json`
)

type claudeRegistryRecord struct {
	Scope        string `json:"scope"`
	InstallPath  string `json:"installPath"`
	Version      string `json:"version"`
	InstalledAt  string `json:"installedAt"`
	LastUpdated  string `json:"lastUpdated"`
	GitCommitSha string `json:"gitCommitSha"`
	ProjectPath  string `json:"projectPath"`
}

type claudeSourceSpec struct {
	Source      string               `json:"source"`
	SparsePaths []string             `json:"sparsePaths"`
	Plugins     []claudeCatalogEntry `json:"plugins"`
	Repo        string               `json:"repo"`
	URL         string               `json:"url"`
	Path        string               `json:"path"`
	Ref         string               `json:"ref"`
	SHA         string               `json:"sha"`
	// npm
	Package  string `json:"package"`
	Version  string `json:"version"`
	Registry string `json:"registry"`
	// archive
	SHA256 string `json:"sha256"`
	// command
	Mode string `json:"mode"`
}

type claudeKnownMarketplace struct {
	Source          claudeSourceSpec `json:"source"`
	InstallLocation string           `json:"installLocation"`
	LastUpdated     string           `json:"lastUpdated"`
}

type claudeSettingsMarketplace struct {
	Source     claudeSourceSpec `json:"source"`
	AutoUpdate *bool            `json:"autoUpdate"`
}

// claudeDecls are the component declarations a manifest and a catalog entry
// share. Catalog additions retain their own declaration origins.
type claudeDecls struct {
	Skills     json.RawMessage `json:"skills"`
	Commands   json.RawMessage `json:"commands"`
	Agents     json.RawMessage `json:"agents"`
	Hooks      json.RawMessage `json:"hooks"`
	MCPServers json.RawMessage `json:"mcpServers"`
	LSPServers json.RawMessage `json:"lspServers"`
	Apps       json.RawMessage `json:"apps"`
}

type claudeManifest struct {
	claudeDecls
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Author      json.RawMessage `json:"author"`
	Homepage    string          `json:"homepage"`
}

type claudeCatalogEntry struct {
	claudeDecls
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Author      json.RawMessage `json:"author"`
	Homepage    string          `json:"homepage"`
	Source      json.RawMessage `json:"source"`
	Strict      *bool           `json:"strict"`
	index       int
}

type claudeCatalog struct {
	Name     string `json:"name"`
	Metadata struct {
		PluginRoot string `json:"pluginRoot"`
	} `json:"metadata"`
	Plugins []claudeCatalogEntry `json:"plugins"`
}

// claudeMarket is one catalog as the adapter sees it: the observation plus the
// parsed entries that give installed plugins their provenance.
type claudeMarket struct {
	obs            model.MarketplaceObservation
	root           string // directory relative payload paths resolve under; "" when unknown
	catalogFile    string
	catalogPointer string
	catalogError   string
	seedRoot       string
	pluginRoot     string
	entries        map[string]*claudeCatalogEntry
}

// claudeSettingsLayer is one settings file's selected fields.
type claudeSettingsLayer struct {
	path, scope, projectPath string
	marketplaceKey           string
	ok                       bool
	enabled                  map[string]bool
	marketplaces             map[string]claudeSettingsMarketplace
}

type claudeAdapter struct {
	s                        *pluginScan
	gd                       *SkillsDetector
	c                        *model.AgentPluginContext
	configRoot, pluginRoot   string
	layers                   []claudeSettingsLayer
	markets                  map[string]*claudeMarket
	seeds                    []string
	marketplaceRegistryError string
}

// detectClaude inventories the Claude Code context, or returns nil when the
// agent has no configuration root on this machine.
func (s *pluginScan) detectClaude() *model.AgentPluginContext {
	cfgEnv := s.d.exec.Getenv("CLAUDE_CONFIG_DIR")
	configRoot := filepath.Join(s.home, ".claude")
	if cfgEnv != "" {
		configRoot = filepath.Clean(cfgEnv)
	}
	pluginRoot := filepath.Join(configRoot, "plugins")
	if cache := s.d.exec.Getenv("CLAUDE_CODE_PLUGIN_CACHE_DIR"); cache != "" {
		pluginRoot = filepath.Clean(cache)
	}
	if state, _, _ := s.stat(s.guarded(configRoot), configRoot); state != fileDir {
		if state != fileAbsent || cfgEnv != "" {
			return s.unresolvedContext(model.AgentClaudeCode, configRoot, pluginRoot)
		}
		return nil
	}
	if s.d.skipper.WithinProtected(pluginRoot) {
		return s.unresolvedContext(model.AgentClaudeCode, configRoot, pluginRoot)
	}

	roots := []string{configRoot, pluginRoot, filepath.Dir(s.managedSettingsPath())}
	separator := ":"
	if s.goos == model.PlatformWindows {
		separator = ";"
	}
	for _, seed := range strings.Split(s.d.exec.Getenv("CLAUDE_CODE_PLUGIN_SEED_DIR"), separator) {
		if seed = strings.TrimSpace(seed); seed != "" {
			roots = append(roots, filepath.Clean(seed))
		}
	}
	a := &claudeAdapter{s: s, gd: s.guarded(roots...), configRoot: configRoot, pluginRoot: pluginRoot, seeds: roots[3:]}

	// One coherent snapshot: if the registries change while the context is being
	// assembled, rebuild once, then report partial rather than a mixed result.
	restore := s.snapshotRetry()
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			restore()
		}
		s.reads = map[string]pluginMetadataStamp{}
		s.sourceChanged = false
		a.c = s.newContext(model.AgentClaudeCode, configRoot, pluginRoot)
		a.run()
		if !s.snapshotChanged() {
			break
		}
		if attempt == 1 {
			for i := range a.c.Plugins {
				degrade(&a.c.Plugins[i].ComponentStatus, model.AgentScanStatusPartial)
			}
			degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrSourceChanged, SourcePath: filepath.Join(pluginRoot, claudeInstalledRegistry)})
			break
		}
	}
	s.evidence.suppress(filepath.Join(pluginRoot, "cache"), filepath.Join(pluginRoot, "marketplaces"),
		filepath.Join(pluginRoot, "repos"), filepath.Join(pluginRoot, "data"), filepath.Join(pluginRoot, claudeSyncedMarket, ".trash"))
	return a.c
}

func (s *pluginScan) managedSettingsPath() string {
	switch s.goos {
	case model.PlatformDarwin:
		return claudeManagedSettingsMac
	case model.PlatformWindows:
		return resolveEnvPath(s.d.exec, claudeManagedSettingsWin)
	}
	return claudeManagedSettingsNix
}

func (a *claudeAdapter) run() {
	a.markets = map[string]*claudeMarket{}
	a.layers = a.readSettingsLayers()
	registry := a.readRegistry()
	a.readMarketplaces()
	a.readSeedMarketplaces()
	a.registryPlugins(registry)
	a.skillsDirPlugins()
	a.syncedPlugins()
	a.emitMarketplaces()
}

// ---------------------------------------------------------------------------
// Settings layers
// ---------------------------------------------------------------------------

func (a *claudeAdapter) readSettingsLayers() []claudeSettingsLayer {
	layers := []claudeSettingsLayer{
		a.readSettings(a.s.managedSettingsPath(), model.PluginScopeSystem, ""),
		a.readSettings(filepath.Join(a.configRoot, "settings.json"), model.PluginScopeUser, ""),
	}
	for _, proj := range a.s.projects {
		layers = append(layers,
			a.readSettings(filepath.Join(proj, ".claude", "settings.json"), model.PluginScopeProject, proj),
			a.readSettings(filepath.Join(proj, ".claude", "settings.local.json"), model.PluginScopeLocal, proj))
	}
	return layers
}

// readSettings reads the plugin-relevant fields of one settings file. An absent
// file is a readable layer with nothing configured; a malformed one is recorded
// and leaves every state that depends on it unknown.
func (a *claudeAdapter) readSettings(p, scope, projectPath string) claudeSettingsLayer {
	layer := claudeSettingsLayer{path: p, scope: scope, projectPath: projectPath, enabled: map[string]bool{}, marketplaces: map[string]claudeSettingsMarketplace{}}
	obj, absent, code := a.s.readJSONObject(a.gd, p)
	if absent {
		layer.ok = true
		return layer
	}
	if code != "" {
		scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: p})
		degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
		return layer
	}
	layer.ok = true
	invalid := func() {
		layer.ok = false
		degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
		scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: p})
	}
	var enabled map[string]json.RawMessage
	if raw, exists := obj["enabledPlugins"]; exists {
		if json.Unmarshal(raw, &enabled) != nil || enabled == nil {
			invalid()
		}
	}
	for key, value := range enabled {
		if b := jsonBool(value); b != nil {
			layer.enabled[key] = *b
		} else {
			invalid()
		}
	}
	layer.marketplaceKey = "extraKnownMarketplaces"
	raw, exists := obj[layer.marketplaceKey]
	if !exists {
		layer.marketplaceKey = "additionalMarketplaces"
		raw = obj[layer.marketplaceKey]
	}
	if len(raw) > 0 {
		if json.Unmarshal(raw, &layer.marketplaces) != nil || layer.marketplaces == nil {
			invalid()
		}
	}
	return layer
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

func (a *claudeAdapter) readRegistry() map[string][]claudeRegistryRecord {
	p := filepath.Join(a.pluginRoot, claudeInstalledRegistry)
	data, absent, code := a.s.readMetadata(a.gd, p)
	if absent {
		return nil
	}
	if code != "" {
		a.c.InstallationStatus = model.AgentScanStatusError
		scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: p})
		return nil
	}
	var reg struct {
		Version int                               `json:"version"`
		Plugins map[string][]claudeRegistryRecord `json:"plugins"`
	}
	if err := json.Unmarshal(data, &reg); err != nil {
		a.c.InstallationStatus = model.AgentScanStatusError
		scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: p})
		return nil
	}
	if reg.Version != claudeRegistrySchema {
		a.c.InstallationStatus = model.AgentScanStatusUnsupported
		scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrUnsupportedSchema, SourcePath: p})
		return nil
	}
	if reg.Plugins == nil {
		a.c.InstallationStatus = model.AgentScanStatusError
		scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: p})
	}
	return reg.Plugins
}

func (a *claudeAdapter) readMarketplaces() {
	p := filepath.Join(a.pluginRoot, claudeKnownMarketplaces)
	var known map[string]claudeKnownMarketplace
	data, absent, code := a.s.readMetadata(a.gd, p)
	if !absent && code == "" && (json.Unmarshal(data, &known) != nil || known == nil) {
		code = model.AgentScanErrParseFailed
	}
	a.marketplaceRegistryError = code
	if code != "" {
		known = nil
		a.c.MarketplaceStatus = model.AgentScanStatusError
		scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: p})
	}
	for _, name := range sortedMapKeys(known) {
		km := known[name]
		m := a.market(name)
		m.obs.Registered = true
		m.obs.Source = claudeCatalogSource(km.Source)
		m.obs.LastRefreshedAtMs = parseNativeTimeMs(km.LastUpdated)
		if km.InstallLocation != "" {
			m.obs.CatalogPath = cleanPluginPath(km.InstallLocation)
			a.loadCatalog(m, km.InstallLocation)
		}
	}
	// Settings-declared catalogs: an explicit auto-update preference for a
	// registered one, or a declaration Claude has not registered yet.
	settingsSources := map[string]string{}
	ambiguous := map[string]string{}
	for _, layer := range a.layers {
		for _, name := range sortedMapKeys(layer.marketplaces) {
			sm := layer.marketplaces[name]
			encoded, _ := json.Marshal(sm.Source)
			if previous, ok := settingsSources[name]; ok && previous != string(encoded) {
				ambiguous[name] = layer.path
			}
			settingsSources[name] = string(encoded)
			m := a.market(name)
			if m.obs.Source == nil {
				m.obs.Registered = true
				m.obs.Source = claudeCatalogSource(sm.Source)
				if sm.Source.Source == "file" || sm.Source.Source == "directory" {
					if isAbsPath(sm.Source.Path) {
						a.loadCatalog(m, sm.Source.Path)
					} else {
						m.catalogError, m.catalogFile = model.AgentScanErrRootUnresolved, layer.path
						degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
						scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrRootUnresolved, SourcePath: layer.path})
					}
				}
			}
			if sm.Source.Source == "settings" && m.obs.Source != nil && m.obs.Source.Kind == model.PluginSourceSettings && m.catalogFile == "" {
				m.obs.Source.Location = layer.path
				m.obs.CatalogPath, m.catalogFile = layer.path, layer.path
				m.catalogPointer = "/" + layer.marketplaceKey + "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(name) + "/source/plugins"
				m.entries = map[string]*claudeCatalogEntry{}
				for i := range sm.Source.Plugins {
					entry := &sm.Source.Plugins[i]
					entry.index = i
					if entry.Name != "" {
						m.entries[entry.Name] = entry
					}
				}
			}
			if len(m.obs.AutoUpdatePreferences) >= maxAutoUpdatePrefs {
				degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
				scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: layer.path})
				continue
			}
			if sm.AutoUpdate == nil {
				continue
			}
			m.obs.AutoUpdatePreferences = append(m.obs.AutoUpdatePreferences, model.EnablementObservation{
				Scope: layer.scope, SourcePath: layer.path, Enabled: *sm.AutoUpdate, ProjectPath: layer.projectPath,
			})
		}
	}
	for _, name := range sortedMapKeys(ambiguous) {
		file := ambiguous[name]
		m := a.markets[name]
		// One marketplace row cannot represent conflicting project settings.
		m.entries = map[string]*claudeCatalogEntry{}
		m.root, m.pluginRoot, m.catalogFile, m.obs.CatalogPath = "", "", "", ""
		m.obs.Source = nil
		m.catalogError = model.AgentScanErrRootUnresolved
		degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
		scanError(&a.c.Errors, model.AgentScanError{Code: m.catalogError, SourcePath: file})
	}
	for _, m := range a.markets {
		m.obs.AutoUpdateEnabled = autoUpdateScalar(m.obs.AutoUpdatePreferences)
	}
}

func (a *claudeAdapter) readSeedMarketplaces() {
	seen := map[string]bool{}
	for _, seed := range a.seeds {
		file := filepath.Join(seed, claudeKnownMarketplaces)
		data, absent, code := a.s.readMetadata(a.gd, file)
		if absent {
			continue
		}
		var known map[string]claudeKnownMarketplace
		if code == "" && (json.Unmarshal(data, &known) != nil || known == nil) {
			code = model.AgentScanErrParseFailed
		}
		if code != "" {
			degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
			scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: file})
			continue
		}
		for _, name := range sortedMapKeys(known) {
			if seen[name] {
				continue
			}
			if !validVersionLabel(name) {
				degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
				continue
			}
			seen[name] = true
			m := a.market(name)
			m.obs.Registered = true
			m.obs.Source = claudeCatalogSource(known[name].Source)
			m.obs.LastRefreshedAtMs = parseNativeTimeMs(known[name].LastUpdated)
			m.seedRoot = seed
			m.entries = map[string]*claudeCatalogEntry{}
			location := filepath.Join(seed, "marketplaces", name)
			m.obs.CatalogPath = location
			a.loadCatalog(m, location)
		}
	}
}

// autoUpdateScalar resolves the device-level preference: the managed layer,
// then the user layer; project layers alone count only when they agree.
func autoUpdateScalar(prefs []model.EnablementObservation) *bool {
	var agreed *bool
	for _, preference := range prefs {
		if agreed != nil && *agreed != preference.Enabled {
			return nil
		}
		agreed = boolPtr(preference.Enabled)
	}
	return agreed
}

// market returns the catalog record for name, creating an unregistered stub
// when an installation names a catalog the registry no longer lists.
func (a *claudeAdapter) market(name string) *claudeMarket {
	if m, ok := a.markets[name]; ok {
		return m
	}
	m := &claudeMarket{obs: model.MarketplaceObservation{MarketplaceID: marketplaceID(a.c.ContextID, name), Name: name}, catalogPointer: "/plugins", entries: map[string]*claudeCatalogEntry{}}
	a.markets[name] = m
	return m
}

// loadCatalog parses the marketplace.json a registration points at. The
// recorded location may be a directory holding .claude-plugin/marketplace.json
// or a hosted catalog saved as a file with no extension.
func (a *claudeAdapter) loadCatalog(m *claudeMarket, location string) {
	m.catalogError = ""
	failed := func(code, file string) {
		m.catalogError = code
		scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: file})
		degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
	}
	st, _, err := a.s.stat(a.gd, location)
	switch st {
	case fileDir:
		m.root = location
		m.catalogFile = filepath.Join(location, filepath.FromSlash(claudeCatalogRel))
	case fileRegular:
		m.catalogFile = location
	case fileRefused:
		failed(readCode(err), location)
		return
	default:
		failed(model.AgentScanErrReadFailed, location)
		return
	}
	data, absent, code := a.s.readMetadata(a.gd, m.catalogFile)
	if absent {
		failed(model.AgentScanErrReadFailed, m.catalogFile)
		return
	}
	var cat claudeCatalog
	if code == "" && (json.Unmarshal(data, &cat) != nil || cat.Plugins == nil) {
		code = model.AgentScanErrParseFailed
	}
	if code != "" {
		failed(code, m.catalogFile)
		return
	}
	m.obs.CatalogPath = m.catalogFile
	m.pluginRoot = cat.Metadata.PluginRoot
	for i := range cat.Plugins {
		e := &cat.Plugins[i]
		e.index = i
		if e.Name != "" {
			m.entries[e.Name] = e
		}
	}
}

func (a *claudeAdapter) emitMarketplaces() {
	for _, m := range a.markets {
		if len(m.obs.Name) > maxNameBytes {
			degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
			scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: m.catalogFile})
			continue
		}
		a.c.Marketplaces = append(a.c.Marketplaces, m.obs)
	}
}

// ---------------------------------------------------------------------------
// Source normalization
// ---------------------------------------------------------------------------

// claudeCatalogSource normalizes a marketplace registration source.
func claudeCatalogSource(src claudeSourceSpec) *model.SourceLocator {
	loc := &model.SourceLocator{NativeKind: src.Source, RequestedRef: src.Ref, SparsePaths: src.SparsePaths}
	switch src.Source {
	case "github":
		loc.Kind, loc.Location = model.PluginSourceGitHub, githubLocation(src.Repo)
	case "git":
		loc.Kind, loc.Location = model.PluginSourceGit, sanitizeLocation(src.URL)
	case "url":
		loc.Kind, loc.Location = model.PluginSourceURL, sanitizeLocation(src.URL)
	case "settings":
		loc.Kind = model.PluginSourceSettings
	case "file", "directory":
		loc.Kind, loc.Location = model.PluginSourceLocal, cleanPluginPath(src.Path)
	case "":
		return nil
	default:
		loc.Kind = model.PluginSourceUnknown
	}
	return loc
}

// claudePayloadSource normalizes a catalog entry's plugin source. The relative
// path form returns the declared path so the caller can resolve it under the
// catalog root; nothing here is fetched or run.
func claudePayloadSource(raw json.RawMessage) (loc *model.SourceLocator, relPath string) {
	if len(raw) == 0 {
		return nil, ""
	}
	if s := jsonString(raw); s != "" {
		return &model.SourceLocator{Kind: model.PluginSourceLocal, NativeKind: "path", Location: s}, s
	}
	var src claudeSourceSpec
	if json.Unmarshal(raw, &src) != nil {
		return &model.SourceLocator{Kind: model.PluginSourceUnknown}, ""
	}
	loc = &model.SourceLocator{NativeKind: src.Source, RequestedRef: src.Ref, RequestedSHA: src.SHA}
	switch src.Source {
	case "github":
		loc.Kind, loc.Location = model.PluginSourceGitHub, githubLocation(src.Repo)
	case "url":
		loc.Kind, loc.Location = model.PluginSourceGit, sanitizeLocation(src.URL)
	case "git-subdir":
		loc.Kind, loc.Location = model.PluginSourceGit, sanitizeLocation(src.URL)
		if src.Path != "" {
			if _, ok := insideRoot(".", src.Path); !ok {
				loc.Kind = model.PluginSourceUnknown
			} else if sub := path.Clean(src.Path); sub != "." {
				loc.Subdirectory = sub
			}
		}
	case "npm":
		loc.Kind, loc.PackageName, loc.PackageVersion, loc.Location = model.PluginSourceNPM, src.Package, src.Version, sanitizeLocation(src.Registry)
	case "archive":
		loc.Kind, loc.Location, loc.Integrity = model.PluginSourceArchive, sanitizeLocation(src.URL), src.SHA256
	case "command":
		loc.Kind = model.PluginSourceCommand
		if src.Mode == model.PluginCommandModeCopy || src.Mode == model.PluginCommandModeLink {
			loc.CommandMode = src.Mode
		}
	default:
		loc.Kind = model.PluginSourceUnknown
	}
	return loc, ""
}

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

func claudeScope(native string) string {
	switch native {
	case "user", "project", "local":
		return native
	case "managed":
		return model.PluginScopeSystem
	}
	return model.PluginScopeUnknown
}

// registryPlugins emits one observation per scoped registry record. The
// registry selects the installation; cache directories it does not name are
// stale versions, not installations.
func (a *claudeAdapter) registryPlugins(registry map[string][]claudeRegistryRecord) {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, nativeID := range ids {
		for _, rec := range registry[nativeID] {
			if a.s.ctx.Err() != nil {
				degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
				return
			}
			a.registryPlugin(nativeID, rec)
		}
	}
}

func (a *claudeAdapter) registryPlugin(nativeID string, rec claudeRegistryRecord) {
	name, marketName, hasMarket := nativeID, "", false
	if i := strings.LastIndex(nativeID, "@"); i > 0 {
		name, marketName, hasMarket = nativeID[:i], nativeID[i+1:], true
	}
	kind := model.PluginInstallUnknown
	if hasMarket {
		kind = model.PluginInstallMarketplace
	}
	p := newPlugin(nativeID, name, kind, claudeScope(rec.Scope))
	p.InstallationEvidence = model.PluginEvidenceRegistry
	p.Installed = boolPtr(true)
	p.CacheVersion = rec.Version
	p.InstalledAtMs = parseNativeTimeMs(rec.InstalledAt)
	p.LastUpdatedAtMs = parseNativeTimeMs(rec.LastUpdated)
	if p.Scope == model.PluginScopeProject || p.Scope == model.PluginScopeLocal {
		p.ProjectPath = cleanPluginPath(rec.ProjectPath)
	}
	if rec.InstallPath != "" {
		p.InstallPath = cleanPluginPath(rec.InstallPath)
	}

	var entry *claudeCatalogEntry
	var market *claudeMarket
	if hasMarket {
		market = a.market(marketName)
		p.MarketplaceID = market.obs.MarketplaceID
		entry = market.entries[name]
	}
	if entry != nil {
		loc, rel := claudePayloadSource(entry.Source)
		p.Source = loc
		if rel != "" && market.root != "" {
			if market.pluginRoot != "" && !strings.HasPrefix(rel, "./") && !strings.Contains(rel, "/") {
				rel = path.Join(market.pluginRoot, rel)
			}
			if sp, ok := insideRoot(market.root, rel); !ok {
				scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: filepath.Join(market.root, rel)})
			} else if sp != p.InstallPath {
				p.SourcePath = sp
			}
		}
	}
	if rec.GitCommitSha != "" {
		if p.Source == nil {
			p.Source = &model.SourceLocator{Kind: model.PluginSourceUnknown}
		}
		p.Source.ResolvedRevision = rec.GitCommitSha
	}

	if market != nil && market.seedRoot != "" && validVersionLabel(name) && validVersionLabel(rec.Version) {
		candidate := filepath.Join(market.seedRoot, "cache", marketName, name, rec.Version)
		if state, _, _ := a.s.stat(a.gd, candidate); state == fileDir {
			p.InstallPath = candidate
		}
	}
	if p.InstallPath != "" {
		p.FilesPresent = a.s.dirExists(a.gd, p.InstallPath)
	}
	switch {
	case p.InstallPath == "":
		p.ComponentStatus = model.AgentScanStatusError
	case p.FilesPresent == nil:
		degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
		scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: p.InstallPath})
	case !*p.FilesPresent:
		p.ComponentStatus = model.AgentScanStatusError
		if entry != nil {
			p.ManifestFormat = model.PluginManifestUnknown
		}
	}
	a.enablement(p)
	if !a.s.addPlugin(a.c, p) {
		return
	}
	if p.FilesPresent != nil && *p.FilesPresent || p.SourcePath != "" {
		a.components(&a.c.Plugins[len(a.c.Plugins)-1], entry, market)
	}
}

// skillsDirPlugins emits manifest-bearing skill directories: the user skills
// root and each discovered project's .claude/skills. No registry row exists for
// these; the manifest in the directory is the loading evidence.
func (a *claudeAdapter) skillsDirPlugins() {
	type root struct{ dir, scope, project string }
	roots := []root{{filepath.Join(a.configRoot, "skills"), model.PluginScopeUser, ""}}
	for _, proj := range a.s.projects {
		roots = append(roots, root{filepath.Join(proj, ".claude", "skills"), model.PluginScopeProject, proj})
	}
	for _, r := range roots {
		entries, code := a.s.listDir(a.gd, r.dir)
		if code != "" {
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: r.dir})
			continue
		}
		for _, name := range sortedEntryNames(entries) {
			dir := filepath.Join(r.dir, name)
			manifestPath := filepath.Join(dir, filepath.FromSlash(claudeManifestRel))
			if st, _, _ := a.s.stat(a.gd, manifestPath); st != fileRegular {
				continue
			}
			p := newPlugin(name+"@"+claudeSkillsDirMarket, name, model.PluginInstallDirectory, r.scope)
			p.InstallationEvidence = model.PluginEvidenceSkillDirectory
			p.Installed, p.FilesPresent = boolPtr(true), boolPtr(true)
			p.ProjectPath = r.project
			p.InstallPath = dir
			p.Source = &model.SourceLocator{Kind: model.PluginSourceLocal, NativeKind: "directory", Location: dir}
			a.enablement(p)
			if r.scope == model.PluginScopeProject {
				// The primary working directory and session trust are not observable here.
				p.Installed, p.EffectiveEnabled = nil, nil
			}
			if a.s.addPlugin(a.c, p) {
				a.components(&a.c.Plugins[len(a.c.Plugins)-1], nil, nil)
			}
		}
	}
}

// syncedPlugins emits account-synced packages materialized under the synced
// root. Local materialization says nothing about current account enablement.
func (a *claudeAdapter) syncedPlugins() {
	dir := filepath.Join(a.pluginRoot, claudeSyncedMarket)
	entries, code := a.s.listDir(a.gd, dir)
	if code != "" {
		degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
		scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: dir})
		return
	}
	var payloads []string
	for _, name := range sortedEntryNames(entries) {
		if strings.HasPrefix(name, ".") || !dirEntryByName(entries, name).IsDir() {
			continue
		}
		candidate := filepath.Join(dir, name)
		if state, _, _ := a.s.stat(a.gd, filepath.Join(candidate, claudeManifestRel)); state == fileRegular {
			payloads = append(payloads, candidate)
			continue
		}
		children, code := a.s.listDir(a.gd, candidate)
		if code != "" {
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			continue
		}
		for _, child := range sortedEntryNames(children) {
			if strings.HasPrefix(child, ".") || !dirEntryByName(children, child).IsDir() {
				continue
			}
			payload := filepath.Join(candidate, child)
			if state, _, _ := a.s.stat(a.gd, filepath.Join(payload, claudeManifestRel)); state == fileRegular {
				payloads = append(payloads, payload)
			}
		}
	}
	sort.Strings(payloads)
	for _, payload := range payloads {
		name := strings.SplitN(filepath.Base(payload), "@", 2)[0]
		p := newPlugin(name+"@"+claudeSyncedMarket, name, model.PluginInstallSynced, model.PluginScopeUser)
		p.InstallationEvidence = model.PluginEvidenceSyncedDirectory
		p.FilesPresent = boolPtr(true)
		p.InstallPath = payload
		p.Source = &model.SourceLocator{Kind: model.PluginSourceAccount, NativeKind: claudeSyncedMarket}
		a.enablement(p)
		if a.s.addPlugin(a.c, p) {
			a.components(&a.c.Plugins[len(a.c.Plugins)-1], nil, nil)
		}
	}

}

// enablement records every settings layer that names the plugin and resolves
// the configured and effective states for the installation's own scope. The
// effective value is claimed only when each relevant layer was readable.
func (a *claudeAdapter) enablement(p *model.PluginObservation) {
	// Precedence, lowest first; a higher layer replaces the whole entry.
	order := []string{model.PluginScopeUser, model.PluginScopeProject, model.PluginScopeLocal, model.PluginScopeSystem}
	projectScoped := p.Scope == model.PluginScopeProject || p.Scope == model.PluginScopeLocal
	allReadable := true
	var effective *bool
	for _, scope := range order {
		for _, layer := range a.layers {
			if layer.scope != scope {
				continue
			}
			if layer.projectPath != "" && (!projectScoped || layer.projectPath != p.ProjectPath) {
				continue
			}
			if !layer.ok {
				allReadable = false
			}
			v, ok := layer.enabled[p.NativeID]
			if !ok {
				continue
			}
			p.Enablement = append(p.Enablement, model.EnablementObservation{Scope: layer.scope, SourcePath: layer.path, Enabled: v, ProjectPath: layer.projectPath})
			effective = boolPtr(v)
			if layer.scope == p.Scope {
				p.ConfiguredEnabled = boolPtr(v)
			}
		}
	}
	if allReadable && p.InstallationKind != model.PluginInstallSynced {
		p.EffectiveEnabled = effective
	}
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

// declOrigin is where a declaration field came from, for the pointer a
// file-less component carries.
type declOrigin struct {
	raw          json.RawMessage
	rel, pointer string // relative path of the declaring file and pointer prefix
	file         string
}

func (a *claudeAdapter) components(p *model.PluginObservation, entry *claudeCatalogEntry, market *claudeMarket) {
	if market != nil {
		code, sourcePath := market.catalogError, market.catalogFile
		if code == "" && sourcePath == "" {
			code, sourcePath = a.marketplaceRegistryError, filepath.Join(a.pluginRoot, claudeKnownMarketplaces)
		}
		if code != "" {
			degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&p.Errors, model.AgentScanError{Code: code, SourcePath: sourcePath, InstanceID: p.InstanceID})
		}
	}
	root := p.InstallPath
	if p.SourcePath != "" && market != nil && market.obs.Source != nil && market.obs.Source.NativeKind == "directory" && market.seedRoot == "" {
		root = p.SourcePath
		if present := a.s.dirExists(a.gd, root); present == nil || !*present {
			p.ComponentStatus = model.AgentScanStatusPartial
			scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrReadFailed, SourcePath: root, InstanceID: p.InstanceID})
			return
		}
	}
	local := *a
	a = &local
	a.gd = a.gd.componentReader(root)
	a.s.evidence.suppress(root)
	manifestPath := filepath.Join(root, filepath.FromSlash(claudeManifestRel))
	var mf claudeManifest
	data, absent, code := a.s.readMetadata(a.gd, manifestPath)
	haveManifest := false
	switch {
	case absent:
	case code != "":
		p.ManifestFormat = model.PluginManifestUnknown
		p.ManifestPath = manifestPath
		p.ComponentStatus = model.AgentScanStatusError
		scanError(&p.Errors, model.AgentScanError{Code: code, SourcePath: manifestPath, InstanceID: p.InstanceID})
		return
	case json.Unmarshal(data, &mf) != nil || strings.TrimSpace(string(data)) == "null":
		p.ManifestFormat = model.PluginManifestUnknown
		p.ManifestPath = manifestPath
		p.ComponentStatus = model.AgentScanStatusError
		scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: manifestPath, InstanceID: p.InstanceID})
		return
	default:
		haveManifest = true
		p.ManifestFormat = model.PluginManifestClaude
		p.ManifestPath = manifestPath
		p.ManifestName = mf.Name
		p.ManifestVersion = mf.Version
		p.Description = truncRunes(mf.Description, maxDescriptionRunes)
		p.Publisher = truncRunes(nameField(mf.Author), maxNameBytes)
		p.Homepage = sanitizeHomepage(mf.Homepage)
	}
	if entry != nil {
		if !haveManifest {
			p.ManifestFormat = model.PluginManifestCatalog
		}
		if p.ManifestVersion == "" {
			p.ManifestVersion = entry.Version
		}
		if entry.Description != "" {
			p.Description = truncRunes(entry.Description, maxDescriptionRunes)
		}
		if author := nameField(entry.Author); author != "" {
			p.Publisher = truncRunes(author, maxNameBytes)
		}
		if hp := sanitizeHomepage(entry.Homepage); hp != "" {
			p.Homepage = hp
		}
	}
	if p.ManifestFormat == "" {
		p.ManifestFormat = model.PluginManifestNone
	}

	var ed claudeDecls
	if entry != nil {
		ed = entry.claudeDecls
	}
	if entry != nil && entry.Strict != nil && !*entry.Strict {
		if mf.Skills != nil || mf.Commands != nil || mf.Agents != nil || mf.Hooks != nil || mf.MCPServers != nil || mf.LSPServers != nil || mf.Apps != nil {
			p.ComponentStatus = model.AgentScanStatusError
			scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: manifestPath, InstanceID: p.InstanceID})
			return
		}
		mf.claudeDecls = claudeDecls{}
	}
	origins := func(manifest, catalog json.RawMessage, name string) []declOrigin {
		var out []declOrigin
		if len(manifest) > 0 {
			out = append(out, declOrigin{raw: manifest, rel: claudeManifestRel, pointer: "/" + name, file: manifestPath})
		}
		if len(catalog) > 0 && entry != nil && market != nil {
			out = append(out, declOrigin{raw: catalog, rel: ".", pointer: market.catalogPointer + "/" + strconv.Itoa(entry.index) + "/" + name, file: market.catalogFile})
		}
		return out
	}
	namespace := p.ManifestName
	if namespace == "" {
		namespace = p.Name
	}
	r := &pluginRootScan{s: a.s, gd: a.gd, p: p, root: root, attr: nestedAttr{
		agent: model.AgentClaudeCode, source: "claude_plugin", vendor: "Anthropic", scope: nestedScope(p.Scope), projectPath: p.ProjectPath,
	}}

	skillDeclarations := origins(mf.Skills, ed.Skills, "skills")
	selectedSkills := false
	for _, declaration := range skillDeclarations {
		for _, declared := range stringList(declaration.raw) {
			dir, ok := insideRoot(root, declared)
			if !ok {
				scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: declared, InstanceID: p.InstanceID})
				degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
				continue
			}
			rel, _ := relSlash(root, dir)
			if state, _, _ := a.s.stat(a.gd, dir); state != fileDir {
				r.skillComponent(dir, rel, path.Base(dir), namespace+":"+path.Base(dir))
				continue
			}
			selectedSkills = true
			a.skillsUnder(r, dir, namespace)
		}
	}
	sharedRoot := entry != nil && (jsonString(entry.Source) == "." || jsonString(entry.Source) == "./")
	if !sharedRoot || !selectedSkills {
		a.skillsUnder(r, filepath.Join(root, "skills"), namespace)
		if entries, _ := a.s.listDir(a.gd, root); entries != nil {
			if _, ok := findSkillMD(entries); ok {
				r.skillComponent(root, ".", p.Name, namespace+":"+p.Name)
			}
		}
	}

	for _, kind := range []struct {
		declarations    []declOrigin
		kind, directory string
	}{
		{origins(mf.Commands, ed.Commands, "commands"), model.PluginComponentCommand, "commands"},
		{origins(mf.Agents, ed.Agents, "agents"), model.PluginComponentAgent, "agents"},
	} {
		paths := []string{kind.directory}
		for _, d := range kind.declarations {
			paths = append(paths, stringList(d.raw)...)
		}
		for index, declared := range paths {
			dir, ok := insideRoot(root, declared)
			if !ok {
				scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: declared, InstanceID: p.InstanceID})
				degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
				continue
			}
			files := []string{dir}
			if state, _, _ := a.s.stat(a.gd, dir); state == fileDir {
				files = r.markdownFiles(dir)
			} else if state != fileRegular {
				if index > 0 || state != fileAbsent {
					a.declaredFile(r, kind.kind, path.Base(declared), declared)
				}
				continue
			}
			for _, file := range files {
				rel, ok := relSlash(root, file)
				if !ok {
					continue
				}
				inDir, _ := relSlash(dir, file)
				if inDir == "." {
					inDir = path.Base(rel)
				}
				name := strings.TrimSuffix(path.Base(rel), ".md")
				if kind.kind == model.PluginComponentCommand {
					r.commandComponent(file, rel, name, "/"+namespace+":"+commandCallable(inDir))
				} else {
					r.declared(kind.kind, name, rel, "", file, model.AgentScanStatusComplete)
				}
			}
		}
	}

	for _, d := range origins(mf.Hooks, ed.Hooks, "hooks") {
		if files := stringList(d.raw); len(files) > 0 {
			for _, file := range files {
				a.declaredFile(r, model.PluginComponentHook, "hooks", file)
			}
		} else {
			r.declared(model.PluginComponentHook, "hooks", d.rel, d.pointer, d.file, model.AgentScanStatusComplete)
		}
	}
	if st, _, _ := a.s.stat(a.gd, filepath.Join(root, filepath.FromSlash(claudeHooksFile))); st == fileRegular {
		r.declared(model.PluginComponentHook, "hooks", claudeHooksFile, "", filepath.Join(root, filepath.FromSlash(claudeHooksFile)), model.AgentScanStatusComplete)
	}

	for _, d := range origins(mf.MCPServers, ed.MCPServers, "mcpServers") {
		if files := stringList(d.raw); len(files) > 0 {
			for _, declared := range files {
				if file, ok := insideRoot(root, declared); ok {
					rel, _ := relSlash(root, file)
					r.mcpFileComponents(file, rel, true)
				} else {
					scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: declared, InstanceID: p.InstanceID})
					degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
				}
			}
		} else {
			r.mcpInlineComponents(d.raw, d.rel, d.pointer, d.file)
		}
	}
	r.mcpFileComponents(filepath.Join(root, claudeMCPFile), claudeMCPFile, false)

	for _, d := range origins(mf.LSPServers, ed.LSPServers, "lspServers") {
		if files := stringList(d.raw); len(files) > 0 {
			for _, file := range files {
				a.lspFile(r, file, true)
			}
		} else {
			for _, name := range jsonObjectKeys(d.raw) {
				r.declared(model.PluginComponentLSP, name, d.rel, d.pointer+"/"+name, d.file, model.AgentScanStatusComplete)
			}
		}
	}
	a.lspFile(r, claudeLSPFile, false)
	for _, d := range origins(mf.Apps, ed.Apps, "apps") {
		if files := stringList(d.raw); len(files) > 0 {
			for _, file := range files {
				a.declaredFile(r, model.PluginComponentApp, path.Base(file), file)
			}
		} else {
			for _, name := range jsonObjectKeys(d.raw) {
				r.declared(model.PluginComponentApp, name, d.rel, d.pointer+"/"+strings.NewReplacer("~", "~0", "/", "~1").Replace(name), d.file, model.AgentScanStatusComplete)
			}
		}
	}

}

// skillsUnder emits every skill directory found under dir with the plugin's
// callable namespace.
func (a *claudeAdapter) skillsUnder(r *pluginRootScan, dir, namespace string) {
	r.gd = r.gd.componentReader(r.root)
	if st, _, err := a.s.stat(r.gd, dir); st != fileDir {
		if st != fileAbsent {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&r.p.Errors, model.AgentScanError{Code: readCode(err), SourcePath: dir, InstanceID: r.p.InstanceID})
		}
		return
	}
	dirs := []string{dir}
	if entries, _ := a.s.listDir(r.gd, dir); entries != nil {
		if _, ok := findSkillMD(entries); !ok {
			dirs = r.skillDirs(dir, true)
		}
	}
	for _, d := range dirs {
		rel, ok := relSlash(r.root, d)
		if !ok {
			continue
		}
		name := path.Base(rel)
		r.skillComponent(d, rel, name, namespace+":"+name)
	}
}

// declaredFile emits a descriptive component for a declared file path.
func (a *claudeAdapter) declaredFile(r *pluginRootScan, kind, name, declared string) {
	file, ok := insideRoot(r.root, declared)
	if !ok {
		scanError(&r.p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: declared, InstanceID: r.p.InstanceID})
		degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
		return
	}
	rel, _ := relSlash(r.root, file)
	status := model.AgentScanStatusComplete
	if st, _, _ := a.s.stat(a.gd, file); st != fileRegular {
		status = model.AgentScanStatusError
	}
	r.declared(kind, name, rel, "", file, status)
}

// lspFile emits one lsp component per server named in a declared LSP file.
func (a *claudeAdapter) lspFile(r *pluginRootScan, declared string, required bool) {
	file, ok := insideRoot(r.root, declared)
	if !ok {
		scanError(&r.p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: declared, InstanceID: r.p.InstanceID})
		degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
		return
	}
	rel, _ := relSlash(r.root, file)
	obj, absent, code := a.s.readJSONObject(a.gd, file)
	if absent && !required {
		return
	}
	if absent {
		code = model.AgentScanErrReadFailed
	}
	if code != "" {
		c := model.PluginComponent{Kind: model.PluginComponentLSP, Name: path.Base(rel), RelativePath: rel, DefinitionPath: file}
		r.componentError(&c, code)
		r.addComponent(c)
		return
	}
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r.declared(model.PluginComponentLSP, name, rel, "", file, model.AgentScanStatusComplete)
	}
}

// jsonObjectKeys returns the sorted keys of a JSON object, or nil.
func jsonObjectKeys(raw json.RawMessage) []string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
