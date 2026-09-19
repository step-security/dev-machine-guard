package detector

import (
	"encoding/json"
	"maps"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Codex plugin adapter. Configuration comes from selected sections of
// config.toml only; installations are the configured plugins reconciled with
// the versioned store under plugins/cache; account bundles are recognized by
// their remote identity marker. Nothing here reads auth.json or any account API.

const (
	codexConfigFile         = "config.toml"
	codexMarketplaceMarker  = ".codex-marketplace-install.json"
	codexRemoteMarker       = ".codex-remote-plugin-install.json"
	codexRemoteMarkerSchema = 1
	codexPortableSchema     = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
	codexPortablePrefix     = "https://agent-plugins.org/schemas/"
	codexLocalVersion       = "local"
	codexMigratedSkillsRel  = ".codex-plugin/migrated-command-skills"
)

// codexCatalogPaths is the native catalog precedence; a malformed preferred
// catalog never falls through to the next one.
var codexCatalogPaths = []string{
	".agents/plugins/marketplace.json",
	".agents/plugins/api_marketplace.json",
	".claude-plugin/marketplace.json",
	".cursor-plugin/marketplace.json",
}

// codexLegacyManifests is the compatible-manifest precedence after the portable root.
var codexLegacyManifests = []struct{ rel, format string }{
	{".codex-plugin/plugin.json", model.PluginManifestCodex},
	{".claude-plugin/plugin.json", model.PluginManifestClaude},
	{".cursor-plugin/plugin.json", model.PluginManifestCursor},
}

type codexMarketplaceCfg struct {
	SourceType   string   `toml:"source_type"`
	Source       string   `toml:"source"`
	Ref          string   `toml:"ref"`
	SparsePaths  []string `toml:"sparse_paths"`
	LastUpdated  any      `toml:"last_updated"`
	LastRevision string   `toml:"last_revision"`
}

type codexConfig struct {
	Marketplaces map[string]codexMarketplaceCfg `toml:"marketplaces"`
	Plugins      map[string]struct {
		Enabled *bool `toml:"enabled"`
	} `toml:"plugins"`
}

type codexLayer struct {
	path, scope, project string
	config               codexConfig
}

type codexMarketplaceMarkerFile struct {
	SourceType  string   `json:"source_type"`
	Source      string   `json:"source"`
	RefName     string   `json:"ref_name"`
	SparsePaths []string `json:"sparse_paths"`
	Revision    string   `json:"revision"`
}

type codexCatalogEntry struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Author      json.RawMessage `json:"author"`
	Homepage    string          `json:"homepage"`
	Source      json.RawMessage `json:"source"`
}

// codexManifest covers the portable root manifest and the legacy formats; only
// the fields each format defines are read from it.
type codexManifest struct {
	Extensions struct {
		OpenAI json.RawMessage `json:"com.openai"`
	} `json:"extensions"`
	Schema      string          `json:"$schema"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Author      json.RawMessage `json:"author"`
	Homepage    string          `json:"homepage"`
	Skills      json.RawMessage `json:"skills"`
	MCPServers  json.RawMessage `json:"mcpServers"`
	Apps        json.RawMessage `json:"apps"`
	Hooks       json.RawMessage `json:"hooks"`
	Interface   struct {
		ShortDescription string `json:"shortDescription"`
		DeveloperName    string `json:"developerName"`
		WebsiteURL       string `json:"websiteUrl"`
		WebsiteURLAlt    string `json:"websiteURL"`
	} `json:"interface"`
}

type codexMarket struct {
	obs     model.MarketplaceObservation
	root    string
	entries map[string]*codexCatalogEntry
}

type codexAdapter struct {
	s                    *pluginScan
	gd                   *SkillsDetector
	c                    *model.AgentPluginContext
	home, cache, cfgPath string
	markets              map[string]*codexMarket
	cfg                  codexConfig
	layers               []codexLayer
}

// detectCodex inventories the Codex context, or returns nil when the agent has
// no home on this machine.
func (s *pluginScan) detectCodex() *model.AgentPluginContext {
	homeEnv := s.d.exec.Getenv("CODEX_HOME")
	codexHome := filepath.Join(s.home, ".codex")
	if homeEnv != "" {
		codexHome = filepath.Clean(homeEnv)
	}
	pluginRoot := filepath.Join(codexHome, "plugins")
	if state, _, _ := s.stat(s.guarded(codexHome), codexHome); state != fileDir {
		if state != fileAbsent || homeEnv != "" {
			return s.unresolvedContext(model.AgentCodex, codexHome, pluginRoot)
		}
		return nil
	}
	a := &codexAdapter{s: s, gd: s.guarded(codexHome, filepath.Dir(s.codexSystemConfigPath())), home: codexHome, cache: filepath.Join(pluginRoot, "cache"), cfgPath: filepath.Join(codexHome, codexConfigFile)}
	restore := s.snapshotRetry()
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			restore()
		}
		s.reads = map[string]pluginMetadataStamp{}
		s.sourceChanged = false
		a.c = s.newContext(model.AgentCodex, codexHome, pluginRoot)
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
			scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrSourceChanged, SourcePath: a.cfgPath})
			break
		}
	}
	s.evidence.suppress(filepath.Join(codexHome, ".tmp"), a.cache, filepath.Join(pluginRoot, "data"),
		filepath.Join(pluginRoot, ".marketplace-plugin-source-staging"), filepath.Join(pluginRoot, ".remote-plugin-install-staging"),
		filepath.Join(pluginRoot, ".plugin-appserver"))
	return a.c
}

func (a *codexAdapter) run() {
	a.markets = map[string]*codexMarket{}
	a.readConfigs()
	a.readMarketplaces()
	a.discoverCatalogs()
	a.plugins()
	for _, m := range a.markets {
		a.c.Marketplaces = append(a.c.Marketplaces, m.obs)
	}
}

func (s *pluginScan) codexSystemConfigPath() string {
	if s.goos == model.PlatformWindows {
		root := s.d.exec.Getenv("ProgramData")
		if root == "" {
			root = `C:\ProgramData`
		}
		return filepath.Join(root, "OpenAI", "Codex", "config.toml")
	}
	return "/etc/codex/config.toml"
}

func (a *codexAdapter) readConfigs() {
	a.cfg = codexConfig{}
	a.layers = nil
	layers := []codexLayer{{path: a.cfgPath, scope: model.PluginScopeUser}, {path: a.s.codexSystemConfigPath(), scope: model.PluginScopeSystem}}
	for _, project := range a.s.projects {
		layers = append(layers, codexLayer{path: filepath.Join(project, ".codex", "config.toml"), scope: model.PluginScopeProject, project: project})
	}
	for _, layer := range layers {
		data, absent, code := a.s.readMetadata(a.gd, layer.path)
		if absent {
			continue
		}
		if code == "" && toml.Unmarshal(data, &layer.config) != nil {
			code = model.AgentScanErrParseFailed
		}
		if code != "" {
			degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: layer.path})
			continue
		}
		if a.cfg.Marketplaces == nil {
			a.cfg.Marketplaces = maps.Clone(layer.config.Marketplaces)
		} else {
			for name, cfg := range layer.config.Marketplaces {
				if previous, exists := a.cfg.Marketplaces[name]; !exists {
					a.cfg.Marketplaces[name] = cfg
				} else if !reflect.DeepEqual(previous, cfg) {
					// A device scan has no active session to select a project override.
					a.cfg.Marketplaces[name] = codexMarketplaceCfg{}
					degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
					scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrRootUnresolved, SourcePath: layer.path})
				}
			}
		}
		if a.cfg.Plugins == nil {
			a.cfg.Plugins = maps.Clone(layer.config.Plugins)
		} else {
			for name, cfg := range layer.config.Plugins {
				if _, exists := a.cfg.Plugins[name]; !exists {
					a.cfg.Plugins[name] = cfg
				}
			}
		}
		a.layers = append(a.layers, layer)
	}
}

// ---------------------------------------------------------------------------
// Marketplaces
// ---------------------------------------------------------------------------

func (a *codexAdapter) market(name string) *codexMarket {
	if m, ok := a.markets[name]; ok {
		return m
	}
	m := &codexMarket{obs: model.MarketplaceObservation{MarketplaceID: marketplaceID(a.c.ContextID, name), Name: name}, entries: map[string]*codexCatalogEntry{}}
	a.markets[name] = m
	return m
}

func (a *codexAdapter) readMarketplaces() {
	for _, name := range sortedMapKeys(a.cfg.Marketplaces) {
		cfg := a.cfg.Marketplaces[name]
		if len(name) > maxNameBytes || !validVersionLabel(name) {
			degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
			scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: a.cfgPath})
			continue
		}
		m := a.market(name)
		m.obs.Registered = true
		m.obs.Revision = cfg.LastRevision
		m.obs.LastRefreshedAtMs = codexTimeMs(cfg.LastUpdated)
		loc := &model.SourceLocator{NativeKind: cfg.SourceType, RequestedRef: cfg.Ref}
		m.obs.Source = loc
		if len(cfg.SparsePaths) > maxSparsePaths {
			degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
			scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: a.cfgPath})
		} else if len(cfg.SparsePaths) > 0 {
			loc.SparsePaths = cfg.SparsePaths
		}
		switch cfg.SourceType {
		case "local":
			loc.Kind, loc.Location = model.PluginSourceLocal, cleanPluginPath(cfg.Source)
			if isAbsPath(cfg.Source) && !a.s.d.skipper.WithinProtected(cfg.Source) {
				m.root = filepath.Clean(cfg.Source)
			} else {
				scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: cfg.Source})
				degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
			}
		case "git":
			loc.Kind, loc.Location = model.PluginSourceGit, sanitizeLocation(cfg.Source)
			m.root = filepath.Join(a.home, ".tmp", "marketplaces", name)
			a.readMarketplaceMarker(m)
		default:
			loc.Kind = model.PluginSourceUnknown
		}
		if m.root != "" {
			m.obs.CatalogPath = m.root
			a.loadCatalog(m)
		}
	}
}

// discoverCatalogs records native personal and discovered-project catalogs without
// promoting their available entries to installed plugins.
func (a *codexAdapter) discoverCatalogs() {
	for _, root := range append([]string{a.s.home}, a.s.projects...) {
		m := &codexMarket{root: root, entries: map[string]*codexCatalogEntry{}}
		a.loadCatalog(m)
		if m.obs.Name == "" {
			continue
		}
		if existing, ok := a.markets[m.obs.Name]; ok {
			if existing.obs.CatalogPath != m.obs.CatalogPath {
				degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
				scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrRootUnresolved, SourcePath: m.obs.CatalogPath})
			}
			continue
		}
		m.obs.MarketplaceID = marketplaceID(a.c.ContextID, m.obs.Name)
		m.obs.Source = &model.SourceLocator{Kind: model.PluginSourceLocal, NativeKind: "local", Location: cleanPluginPath(root)}
		a.markets[m.obs.Name] = m
	}
}

// readMarketplaceMarker reads the Git snapshot's install marker for the
// resolved revision and the checkout selectors actually used.
func (a *codexAdapter) readMarketplaceMarker(m *codexMarket) {
	p := filepath.Join(m.root, codexMarketplaceMarker)
	data, absent, code := a.s.readMetadata(a.gd, p)
	if absent {
		return
	}
	var marker codexMarketplaceMarkerFile
	if code == "" && json.Unmarshal(data, &marker) != nil {
		code = model.AgentScanErrParseFailed
	}
	if code != "" {
		scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: p})
		degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
		return
	}
	if marker.Revision != "" {
		m.obs.Revision = marker.Revision
	}
	if m.obs.Source.RequestedRef == "" {
		m.obs.Source.RequestedRef = marker.RefName
	}
	if len(m.obs.Source.SparsePaths) == 0 && len(marker.SparsePaths) > 0 && len(marker.SparsePaths) <= maxSparsePaths {
		m.obs.Source.SparsePaths = marker.SparsePaths
	}
}

// loadCatalog selects the first catalog file in native precedence and parses it.
func (a *codexAdapter) loadCatalog(m *codexMarket) {
	for _, rel := range codexCatalogPaths {
		p := filepath.Join(m.root, filepath.FromSlash(rel))
		data, absent, code := a.s.readMetadata(a.gd, p)
		if absent {
			continue
		}
		var cat struct {
			Name    string              `json:"name"`
			Plugins []codexCatalogEntry `json:"plugins"`
		}
		if code == "" && (json.Unmarshal(data, &cat) != nil || cat.Plugins == nil) {
			code = model.AgentScanErrParseFailed
		}
		if code != "" {
			scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: p})
			degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
			return
		}
		m.obs.CatalogPath = p
		if m.obs.Name == "" {
			if cat.Name == "" || len(cat.Name) > maxNameBytes {
				degrade(&a.c.MarketplaceStatus, model.AgentScanStatusPartial)
				scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: p})
				return
			}
			m.obs.Name = cat.Name
		}
		for i := range cat.Plugins {
			if e := &cat.Plugins[i]; e.Name != "" {
				m.entries[e.Name] = e
			}
		}
		return
	}
}

// codexTimeMs accepts the TOML datetime forms go-toml produces, or a string.
func codexTimeMs(v any) *int64 {
	switch t := v.(type) {
	case time.Time:
		return parseNativeTimeMs(t.Format(time.RFC3339Nano))
	case string:
		return parseNativeTimeMs(t)
	}
	return nil
}

// codexPayloadSource normalizes a catalog entry's source. The relative path form
// returns the declared path for resolution under the catalog root.
func codexPayloadSource(raw json.RawMessage) (loc *model.SourceLocator, relPath string) {
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
	case "local":
		loc.Kind, loc.Location = model.PluginSourceLocal, src.Path
		return loc, src.Path
	case "url", "git-subdir":
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
	default:
		loc.Kind = model.PluginSourceUnknown // github, archive and command are not Codex payloads
	}
	return loc, ""
}

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

// plugins reconciles configured plugins with the store. A configured plugin
// needs a materialized store version; a store entry with a remote marker
// is an account bundle; a bare cache directory is not an installation.
func (a *codexAdapter) plugins() {
	ids := map[string]bool{}
	for id := range a.cfg.Plugins {
		ids[id] = true
	}
	markets, code := a.s.listDir(a.gd, a.cache)
	if code != "" {
		degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
		scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: a.cache})
	}
	for _, market := range sortedEntryNames(markets) {
		if !dirEntryByName(markets, market).IsDir() || strings.HasPrefix(market, ".") {
			continue
		}
		names, code := a.s.listDir(a.gd, filepath.Join(a.cache, market))
		if code != "" {
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: filepath.Join(a.cache, market)})
			continue
		}
		for _, name := range sortedEntryNames(names) {
			if dirEntryByName(names, name).IsDir() && !strings.HasPrefix(name, ".") {
				ids[name+"@"+market] = true
			}
		}
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		if a.s.ctx.Err() != nil {
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			return
		}
		a.plugin(id)
	}
}

func (a *codexAdapter) plugin(nativeID string) {
	i := strings.LastIndex(nativeID, "@")
	if i <= 0 {
		return
	}
	name, marketName := nativeID[:i], nativeID[i+1:]
	if !validVersionLabel(name) || !validVersionLabel(marketName) {
		degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
		scanError(&a.c.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: a.cfgPath})
		return
	}
	_, configured := a.cfg.Plugins[nativeID]
	base := filepath.Join(a.cache, marketName, name)
	version := a.selectVersion(base)
	if version == "" {
		return
	}

	var remote *struct {
		SchemaVersion  int    `json:"schema_version"`
		RemotePluginID string `json:"remote_plugin_id"`
	}
	markerPath := filepath.Join(base, codexRemoteMarker)
	markerData, markerAbsent, markerCode := a.s.readMetadata(a.gd, markerPath)
	if !markerAbsent && markerCode == "" && json.Unmarshal(markerData, &remote) != nil {
		markerCode = model.AgentScanErrParseFailed
	}

	var p *model.PluginObservation
	switch {
	case !markerAbsent:
		p = newPlugin(nativeID, name, model.PluginInstallAccount, model.PluginScopeUser)
		p.InstallationEvidence = model.PluginEvidenceRemoteMarker
		p.Source = &model.SourceLocator{Kind: model.PluginSourceAccount, NativeKind: "remote"}
		switch {
		case markerCode != "":
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&p.Errors, model.AgentScanError{Code: markerCode, SourcePath: markerPath})
		case remote == nil || remote.SchemaVersion != codexRemoteMarkerSchema:
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsupportedSchema, SourcePath: markerPath})
		case remote.RemotePluginID == "":
			degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: markerPath})
		default:
			p.RemotePluginID = remote.RemotePluginID
		}
	case configured:
		p = newPlugin(nativeID, name, model.PluginInstallMarketplace, model.PluginScopeUser)
		p.InstallationEvidence = model.PluginEvidenceLocalConfig
		p.Installed = boolPtr(true)
	default:
		return // cache only: a stale or interrupted store entry, not an installation
	}
	if p.InstallationKind == model.PluginInstallMarketplace {
		m := a.market(marketName)
		p.MarketplaceID = m.obs.MarketplaceID
		if entry := m.entries[name]; entry != nil {
			loc, rel := codexPayloadSource(entry.Source)
			p.Source = loc
			if loc != nil && loc.Kind == model.PluginSourceUnknown {
				p.Installed = nil
				degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
				scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsupportedSchema, SourcePath: m.obs.CatalogPath})
			}
			if rel != "" && m.root != "" {
				if sp, ok := insideRoot(m.root, rel); !ok {
					scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: filepath.Join(m.root, rel)})
				} else {
					p.SourcePath = sp
				}
			}
			p.Description = truncRunes(entry.Description, maxDescriptionRunes)
			p.Publisher = truncRunes(nameField(entry.Author), maxNameBytes)
			p.Homepage = sanitizeHomepage(entry.Homepage)
			p.ManifestVersion = entry.Version
		}
	}
	for _, layer := range a.layers {
		cfg, exists := layer.config.Plugins[nativeID]
		if !exists || cfg.Enabled == nil {
			continue
		}
		p.Enablement = append(p.Enablement, model.EnablementObservation{Scope: layer.scope, SourcePath: layer.path, ProjectPath: layer.project, Enabled: *cfg.Enabled})
		if layer.scope == p.Scope {
			p.ConfiguredEnabled = boolPtr(*cfg.Enabled)
		}
	}
	// Profiles, project trust and remote managed policy are not resolved by passive inventory.
	p.InstallPath = filepath.Join(base, version)
	p.CacheVersion = version
	p.FilesPresent = boolPtr(true)
	if p.SourcePath == p.InstallPath {
		p.SourcePath = ""
	}
	if a.s.addPlugin(a.c, p) {
		a.components(&a.c.Plugins[len(a.c.Plugins)-1])
	}
}

// selectVersion applies the native store rule to the version directories under
// base: "local" wins, then the highest semantic version, then the lexically
// greatest label. Symlinked, hidden and oddly named entries are ignored.
func (a *codexAdapter) selectVersion(base string) string {
	entries, code := a.s.listDir(a.gd, base)
	if code != "" {
		degrade(&a.c.InstallationStatus, model.AgentScanStatusPartial)
		scanError(&a.c.Errors, model.AgentScanError{Code: code, SourcePath: base})
		return ""
	}
	var best string
	for _, name := range sortedEntryNames(entries) {
		e := dirEntryByName(entries, name)
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() || !validVersionLabel(name) {
			continue
		}
		if name == "backup" || name == "staging" || name == "data" {
			continue
		}
		if name == codexLocalVersion {
			return name
		}
		if best == "" || compareVersionLabels(name, best) > 0 {
			best = name
		}
	}
	return best
}

func validVersionLabel(s string) bool {
	if s == "" || strings.HasPrefix(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '+':
		default:
			return false
		}
	}
	return true
}

// compareVersionLabels orders two labels: both semantic versions compare
// numerically, anything else compares as a string.
func compareVersionLabels(x, y string) int {
	xv, xp, xok := parseSemver(x)
	yv, yp, yok := parseSemver(y)
	if xok && yok {
		for i := range 3 {
			if xv[i] != yv[i] {
				if xv[i] < yv[i] {
					return -1
				}
				return 1
			}
		}
		if xp == yp {
			return 0
		}
		if xp == "" {
			return 1
		}
		if yp == "" {
			return -1
		}
		xs, ys := strings.Split(xp, "."), strings.Split(yp, ".")
		for i := 0; i < min(len(xs), len(ys)); i++ {
			if xs[i] == ys[i] {
				continue
			}
			xn, yn := strictUintRE.MatchString(xs[i]), strictUintRE.MatchString(ys[i])
			if xn && !yn {
				return -1
			}
			if !xn && yn {
				return 1
			}
			if xn && len(xs[i]) != len(ys[i]) {
				if len(xs[i]) < len(ys[i]) {
					return -1
				}
				return 1
			}
			return strings.Compare(xs[i], ys[i])
		}
		if len(xs) < len(ys) {
			return -1
		}
		return 1
	}
	return strings.Compare(x, y)
}

func parseSemver(s string) ([3]int, string, bool) {
	var out [3]int
	version, build, hasBuild := strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(version, "-")
	validIdentifiers := func(value string, leadingZero bool) bool {
		for _, part := range strings.Split(value, ".") {
			if part == "" {
				return false
			}
			numeric := true
			for _, ch := range part {
				if ch < '0' || ch > '9' {
					numeric = false
				}
				if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '-') {
					return false
				}
			}
			if numeric && !leadingZero && len(part) > 1 && part[0] == '0' {
				return false
			}
		}
		return true
	}
	if hasBuild && !validIdentifiers(build, true) || hasPre && !validIdentifiers(pre, false) {
		return out, "", false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, "", false
	}
	for i, part := range parts {
		if !strictUintRE.MatchString(part) {
			return out, "", false
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return out, "", false
		}
		out[i] = n
	}
	return out, pre, true
}

// ---------------------------------------------------------------------------
// Manifest and components
// ---------------------------------------------------------------------------

func (a *codexAdapter) components(p *model.PluginObservation) {
	root := p.InstallPath
	local := *a
	a = &local
	a.gd = a.gd.componentReader(root)
	format, manifestPath, mf, code := a.selectManifest(root)
	switch {
	case code == model.AgentScanErrUnsupportedSchema:
		p.ManifestFormat, p.ManifestPath = model.PluginManifestUnknown, manifestPath
		p.ComponentStatus = model.AgentScanStatusUnsupported
		scanError(&p.Errors, model.AgentScanError{Code: code, SourcePath: manifestPath, InstanceID: p.InstanceID})
		return
	case code != "":
		p.ManifestFormat, p.ManifestPath = model.PluginManifestUnknown, manifestPath
		p.ComponentStatus = model.AgentScanStatusError
		scanError(&p.Errors, model.AgentScanError{Code: code, SourcePath: manifestPath, InstanceID: p.InstanceID})
		return
	case format == "":
		p.ManifestFormat = model.PluginManifestNone
		return
	}
	p.ManifestFormat, p.ManifestPath, p.ManifestName = format, manifestPath, mf.Name
	if mf.Version != "" {
		p.ManifestVersion = mf.Version
	}
	desc, publisher, homepage := mf.Description, nameField(mf.Author), mf.Homepage
	if format != model.PluginManifestPortable {
		if desc == "" {
			desc = mf.Interface.ShortDescription
		}
		if publisher == "" {
			publisher = mf.Interface.DeveloperName
		}
		if homepage == "" {
			homepage = mf.Interface.WebsiteURL
		}
		if homepage == "" {
			homepage = mf.Interface.WebsiteURLAlt
		}
	}
	if desc != "" {
		p.Description = truncRunes(desc, maxDescriptionRunes)
	}
	if publisher != "" {
		p.Publisher = truncRunes(publisher, maxNameBytes)
	}
	if hp := sanitizeHomepage(homepage); hp != "" {
		p.Homepage = hp
	}

	r := &pluginRootScan{s: a.s, gd: a.gd, p: p, root: root, attr: nestedAttr{
		agent: model.AgentCodex, source: "codex_plugin", vendor: "OpenAI", scope: nestedScope(p.Scope), projectPath: p.ProjectPath,
	}}
	manifestRel, _ := relSlash(root, manifestPath)

	if format == model.PluginManifestPortable {
		// Portable roots are fixed by the format.
		a.skillsUnder(r, filepath.Join(root, "skills"), false)
		r.mcpFileComponents(filepath.Join(root, "mcp.json"), "mcp.json", false)
		overlay := codexManifest{}
		overlayPath, overlayRel, pointer := manifestPath, manifestRel, "/extensions/com.openai"
		data := mf.Extensions.OpenAI
		if len(data) == 0 {
			overlayRel = ".codex-plugin/plugin.json"
			overlayPath = filepath.Join(root, filepath.FromSlash(overlayRel))
			var absent bool
			var code string
			data, absent, code = a.s.readMetadata(a.gd, overlayPath)
			if absent {
				return
			}
			if code != "" {
				degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
				scanError(&p.Errors, model.AgentScanError{Code: code, SourcePath: overlayPath})
				return
			}
			pointer = ""
		}
		if json.Unmarshal(data, &overlay) != nil {
			degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: overlayPath})
			return
		}
		a.descriptiveComponents(r, overlay, overlayRel, overlayPath, pointer)
		return
	}

	// Legacy formats: declared paths, else the format defaults.
	skillRoots := []string{filepath.Join(root, "skills")}
	if declared := legacySkillPaths(mf.Skills); len(declared) > 0 {
		skillRoots = skillRoots[:0]
		for _, d := range declared {
			if dir, ok := insideRoot(root, d); ok {
				skillRoots = append(skillRoots, dir)
			} else {
				scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: d, InstanceID: p.InstanceID})
				degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
			}
		}
	}
	for _, dir := range skillRoots {
		if st, _, _ := a.s.stat(a.gd, dir); st != fileDir && len(legacySkillPaths(mf.Skills)) > 0 {
			rel, _ := relSlash(root, dir)
			r.skillComponent(dir, rel, path.Base(rel), path.Base(rel))
			continue
		}
		a.skillsUnder(r, dir, true)
	}
	a.skillsUnder(r, filepath.Join(root, filepath.FromSlash(codexMigratedSkillsRel)), false)

	if len(mf.MCPServers) > 0 {
		if s := jsonString(mf.MCPServers); s != "" {
			if file, ok := insideRoot(root, s); ok {
				rel, _ := relSlash(root, file)
				r.mcpFileComponents(file, rel, true)
			} else {
				scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: s, InstanceID: p.InstanceID})
				degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
			}
		} else {
			r.mcpInlineComponents(mf.MCPServers, manifestRel, "/mcpServers", manifestPath)
		}
	} else {
		r.mcpFileComponents(filepath.Join(root, ".mcp.json"), ".mcp.json", false)
	}

	a.descriptiveComponents(r, mf, manifestRel, manifestPath, "")
}

func (a *codexAdapter) descriptiveComponents(r *pluginRootScan, mf codexManifest, manifestRel, manifestPath, pointer string) {
	if len(mf.Hooks) > 0 {
		if files := stringList(mf.Hooks); len(files) > 0 {
			for _, file := range files {
				a.declaredFile(r, model.PluginComponentHook, "hooks", file, model.AgentScanStatusComplete)
			}
		} else {
			r.declared(model.PluginComponentHook, "hooks", manifestRel, pointer+"/hooks", manifestPath, model.AgentScanStatusComplete)
		}
	} else if state, _, _ := a.s.stat(a.gd, filepath.Join(r.root, "hooks/hooks.json")); state == fileRegular {
		r.declared(model.PluginComponentHook, "hooks", "hooks/hooks.json", "", filepath.Join(r.root, "hooks/hooks.json"), model.AgentScanStatusComplete)
	}
	declared := jsonString(mf.Apps)
	if declared == "" {
		declared = ".app.json"
	}
	file, ok := insideRoot(r.root, declared)
	if !ok {
		degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
		scanError(&r.p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: declared})
		return
	}
	rel, _ := relSlash(r.root, file)
	object, absent, code := a.s.readJSONObject(a.gd, file)
	if absent && len(mf.Apps) == 0 {
		return
	}
	if absent {
		code = model.AgentScanErrReadFailed
	}
	var apps map[string]json.RawMessage
	if code == "" && (json.Unmarshal(object["apps"], &apps) != nil || apps == nil) {
		code = model.AgentScanErrParseFailed
	}
	if code != "" {
		c := model.PluginComponent{Kind: model.PluginComponentApp, Name: path.Base(file), RelativePath: rel, DefinitionPath: file}
		r.componentError(&c, code)
		r.addComponent(c)
		return
	}
	for _, name := range sortedMapKeys(apps) {
		r.declared(model.PluginComponentApp, name, rel, "/apps/"+strings.NewReplacer("~", "~0", "/", "~1").Replace(name), file, model.AgentScanStatusComplete)
	}
}

// selectManifest applies the native precedence: a root plugin.json counts only
// when it carries the recognized portable schema, then the compatible formats.
// A malformed preferred manifest is reported, never skipped.
func (a *codexAdapter) selectManifest(root string) (format, manifestPath string, mf codexManifest, code string) {
	rootManifest := filepath.Join(root, "plugin.json")
	data, absent, code := a.s.readMetadata(a.gd, rootManifest)
	if !absent {
		if code != "" {
			return "", rootManifest, mf, code
		}
		var probe codexManifest
		if json.Unmarshal(data, &probe) != nil {
			return "", rootManifest, mf, model.AgentScanErrParseFailed
		}
		switch {
		case probe.Schema == codexPortableSchema:
			return model.PluginManifestPortable, rootManifest, probe, ""
		case strings.HasPrefix(probe.Schema, codexPortablePrefix):
			return "", rootManifest, mf, model.AgentScanErrUnsupportedSchema
		}
	}
	for _, legacy := range codexLegacyManifests {
		p := filepath.Join(root, filepath.FromSlash(legacy.rel))
		data, absent, code := a.s.readMetadata(a.gd, p)
		if absent {
			continue
		}
		if code != "" {
			return "", p, mf, code
		}
		if json.Unmarshal(data, &mf) != nil || strings.TrimSpace(string(data)) == "null" {
			return "", p, codexManifest{}, model.AgentScanErrParseFailed
		}
		return legacy.format, p, mf, ""
	}
	return "", "", mf, ""
}

// legacySkillPaths accepts the legacy skills field forms: a path, a list of
// paths, or an object with path/paths.
func legacySkillPaths(raw json.RawMessage) []string {
	if list := stringList(raw); list != nil {
		return list
	}
	var obj struct {
		Path  string   `json:"path"`
		Paths []string `json:"paths"`
	}
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	if obj.Path != "" {
		return append([]string{obj.Path}, obj.Paths...)
	}
	return obj.Paths
}

// skillsUnder emits each skill directory under dir; portable roots list direct
// children only, legacy roots are walked.
func (a *codexAdapter) skillsUnder(r *pluginRootScan, dir string, recursive bool) {
	r.gd = r.gd.componentReader(r.root)
	if st, _, err := a.s.stat(r.gd, dir); st != fileDir {
		if st != fileAbsent {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&r.p.Errors, model.AgentScanError{Code: readCode(err), SourcePath: dir, InstanceID: r.p.InstanceID})
		}
		return
	}
	dirs := r.skillDirs(dir, recursive)
	if recursive {
		if entries, _ := a.s.listDir(r.gd, dir); entries != nil {
			if _, ok := findSkillMD(entries); ok {
				dirs = []string{dir}
			}
		}
	}
	for _, d := range dirs {
		rel, ok := relSlash(r.root, d)
		if !ok {
			continue
		}
		r.skillComponent(d, rel, path.Base(rel), path.Base(rel))
	}
}

func (a *codexAdapter) declaredFile(r *pluginRootScan, kind, name, declared, status string) {
	file, ok := insideRoot(r.root, declared)
	if !ok {
		scanError(&r.p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, SourcePath: declared, InstanceID: r.p.InstanceID})
		degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
		return
	}
	rel, _ := relSlash(r.root, file)
	if st, _, _ := a.s.stat(a.gd, file); st != fileRegular {
		status = model.AgentScanStatusError
	}
	r.declared(kind, name, rel, "", file, status)
}
