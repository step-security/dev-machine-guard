package model

// Agent plugin inventory wire types. A plugin is the parent entity: one
// installation of one catalog entry, under one agent's configuration root, at one
// scope. Its components are the capabilities it declares — skills, legacy
// commands, MCP servers, agents, hooks, LSP and apps.
//
// Six facts stay separate and are never collapsed into one another: the catalog
// is registered, the plugin is installed, its files are present, a scope
// configured it enabled, the resolved configuration says enabled, and a skill it
// supplies has recorded uses. Catalog availability is not installation, cached
// files are not an installation, an enablement flag is not runtime loading, and a
// declared MCP server is not a connected one.
//
// Everything here is read from disk. Nothing in this inventory is produced by
// running an agent, resolving a Git ref, fetching a catalog or contacting an
// account: an installation whose original source is now unreachable is still
// reported from the bytes that remain on the device.

// Collector agent names, matching the existing skill vocabulary.
const (
	AgentClaudeCode = "claude-code"
	AgentCodex      = "codex"
)

// Coverage statuses. Each one answers whether an enumeration is the whole set for
// the scope it describes, not whether every attribute inside it parsed.
const (
	// The stated scope was enumerated. Zero observations is a real answer for
	// that scope — not a missing one — so a reader may retire what it no longer
	// sees. It does not claim the agent loaded any of it.
	AgentScanStatusComplete = "complete"
	// Positive observations are valid, membership is not known complete. A reader
	// merges what it sees and removes nothing.
	AgentScanStatusPartial = "partial"
	// The scope could not be read. Previously accepted facts stay, marked stale.
	AgentScanStatusError = "error"
	// The scope was recognized but its format or schema is not one this build
	// parses. Distinct from error: nothing failed, nothing is claimed.
	AgentScanStatusUnsupported = "unsupported"
)

// Reason codes for a source that could not be collected. Typed rather than free
// text because a parser's own message can quote the line it choked on, and these
// lines come from settings, catalogs and manifests that hold tokens.
const (
	AgentScanErrReadFailed        = "read_failed"
	AgentScanErrParseFailed       = "parse_failed"
	AgentScanErrUnsupportedSchema = "unsupported_schema"
	AgentScanErrLimitExceeded     = "limit_exceeded"
	AgentScanErrUnsafePath        = "unsafe_path"
	AgentScanErrSourceChanged     = "source_changed"
	AgentScanErrRootUnresolved    = "root_unresolved"
)

// Normalized delivery provenance. These describe where bytes came from, not an
// action to replay: nothing here is ever fetched, cloned, downloaded or executed.
// The native spelling is preserved separately in SourceLocator.NativeKind, so
// "url" meaning a hosted catalog JSON and "url" meaning a Git repository stay
// distinguishable after normalization.
const (
	PluginSourceLocal    = "local"
	PluginSourceGit      = "git"
	PluginSourceGitHub   = "github"
	PluginSourceURL      = "url"
	PluginSourceSettings = "settings"
	PluginSourceNPM      = "npm"
	PluginSourceArchive  = "archive"
	PluginSourceCommand  = "command"
	PluginSourceAccount  = "account"
	PluginSourceUnknown  = "unknown"
)

// Command source modes. The producing command itself is never collected or run —
// only which of the two delivery modes the native client recorded.
const (
	PluginCommandModeCopy = "copy"
	PluginCommandModeLink = "link"
)

// How a plugin came to be installed.
const (
	// Installed from a registered catalog entry.
	PluginInstallMarketplace = "marketplace"
	// Loaded from a directory that carries its own manifest, with no registry row.
	PluginInstallDirectory = "directory"
	// Materialized by account sync into the agent's synced root.
	PluginInstallSynced = "synced"
	// Materialized from an account or workspace bundle carrying a remote identity
	// marker. Current account installation state is not knowable from disk.
	PluginInstallAccount = "account"
	PluginInstallUnknown = "unknown"
)

// Installation scopes, distinct from AgentSkill.Scope.
const (
	PluginScopeUser    = "user"
	PluginScopeProject = "project"
	PluginScopeLocal   = "local"
	PluginScopeSystem  = "system"
	PluginScopeUnknown = "unknown"
)

// What proves the installation. A cache directory and an orphaned enablement flag
// are deliberately absent: neither is evidence, and neither produces a record.
const (
	PluginEvidenceRegistry        = "registry"
	PluginEvidenceLocalConfig     = "local_config"
	PluginEvidenceSkillDirectory  = "skill_directory"
	PluginEvidenceSyncedDirectory = "synced_directory"
	PluginEvidenceRemoteMarker    = "remote_marker"
)

// The manifest format actually selected for this package. A dual-format bundle
// has one selected format per host agent; the formats are never merged, and a
// filename alone never selects one.
const (
	PluginManifestClaude   = "claude"
	PluginManifestCodex    = "codex"
	PluginManifestCursor   = "cursor"
	PluginManifestPortable = "portable"
	PluginManifestCatalog  = "catalog"
	PluginManifestNone     = "none"
	PluginManifestUnknown  = "unknown"
)

// Declared component kinds. A kind that is retained but not parsed — agent, hook,
// lsp, app — is a descriptive capability: it says the package declares one, never
// that the agent activated it.
const (
	PluginComponentSkill   = "skill"
	PluginComponentCommand = "command"
	PluginComponentMCP     = "mcp"
	PluginComponentAgent   = "agent"
	PluginComponentHook    = "hook"
	PluginComponentLSP     = "lsp"
	PluginComponentApp     = "app"
)

// Definition kinds for AgentSkill.DefinitionKind. Empty also denotes SKILL.md.
const (
	AgentDefinitionSkill   = "skill"
	AgentDefinitionCommand = "command"
)

// AgentPluginScan is one device's plugin observation. Absent means unreported —
// never "this machine has no plugins" — so a reader that receives no envelope
// keeps what it already stored.
type AgentPluginScan struct {
	SchemaVersion int                  `json:"schema_version"`
	CollectedAtMs int64                `json:"collected_at_ms"` // unix ms, one instant per scan
	Contexts      []AgentPluginContext `json:"contexts"`
}

// PluginCount is the number of plugin observations across every context —
// installations, never catalog entries or stale cache versions. Nil-safe.
func (s *AgentPluginScan) PluginCount() int {
	if s == nil {
		return 0
	}
	n := 0
	for _, c := range s.Contexts {
		n += len(c.Plugins)
	}
	return n
}

// AgentPluginContext is one agent's configuration and plugin root pair. Scope and
// project coordinates live on the individual installations, so one user plugin is
// not repeated for every discovered project.
type AgentPluginContext struct {
	ContextID  string `json:"context_id"`
	Agent      string `json:"agent"`       // AgentClaudeCode | AgentCodex
	ConfigRoot string `json:"config_root"` // observed, normalized; not an instruction to read it
	PluginRoot string `json:"plugin_root"`
	// Trusted existing inventory or passive metadata only. This collector never
	// launches an agent to learn a version, so absent is normal.
	AgentVersion string `json:"agent_version,omitempty"`

	MarketplaceStatus  string `json:"marketplace_status"`
	InstallationStatus string `json:"installation_status"`

	Marketplaces []MarketplaceObservation `json:"marketplaces"`
	Plugins      []PluginObservation      `json:"plugins"`
	Errors       []AgentScanError         `json:"errors"`
}

// AgentScanError carries a code and the coordinates it applies to. It never
// carries a parser message, a settings excerpt, a source command or agent stderr.
type AgentScanError struct {
	Code        string `json:"code"`
	SourcePath  string `json:"source_path,omitempty"`
	InstanceID  string `json:"instance_id,omitempty"`
	ComponentID string `json:"component_id,omitempty"`
}

// MarketplaceObservation is one catalog registration. A catalog that supplies a
// still-installed plugin but is no longer registered is emitted with
// Registered=false and whatever provenance survives, rather than omitted.
type MarketplaceObservation struct {
	MarketplaceID string         `json:"marketplace_id"`
	Name          string         `json:"name"` // native registered name
	Source        *SourceLocator `json:"source,omitempty"`
	CatalogPath   string         `json:"catalog_path,omitempty"` // may name a file, not a directory
	Revision      string         `json:"revision,omitempty"`
	Registered    bool           `json:"registered"`

	// Native recorded catalog refresh. Separate from any plugin's update time,
	// and never a filesystem mtime.
	LastRefreshedAtMs *int64 `json:"last_refreshed_at_ms,omitempty"`
	// Explicit configured automatic-update preference. Nil is unknown, not the
	// vendor's default, and never proof an update ran.
	AutoUpdateEnabled *bool `json:"auto_update_enabled,omitempty"`
	// Contributing scoped preferences. Conflicting project values stay separate
	// rather than collapsing into one device-wide answer.
	AutoUpdatePreferences []EnablementObservation `json:"auto_update_preferences,omitempty"`
}

// SourceLocator describes where one catalog or one payload came from. A
// marketplace's source and its entries' payload sources are independent and need
// not be the same repository.
type SourceLocator struct {
	Kind string `json:"kind"`
	// The native discriminator as written — "file", "directory", "git-subdir",
	// "url" — kept because normalization is lossy, not because it is replayable.
	NativeKind string `json:"native_kind,omitempty"`
	// Sanitized repository or catalog URL, local path, registry URL or non-secret
	// account object id. Userinfo, query and fragment are stripped.
	Location     string `json:"location,omitempty"`
	Subdirectory string `json:"subdirectory,omitempty"` // slash-separated, no traversal

	// What was asked for, kept apart from what is actually installed: a pin is
	// not a verified checkout.
	RequestedRef     string `json:"requested_ref,omitempty"`
	RequestedSHA     string `json:"requested_sha,omitempty"`
	ResolvedRevision string `json:"resolved_revision,omitempty"`

	Integrity      string `json:"integrity,omitempty"`
	PackageName    string `json:"package_name,omitempty"`
	PackageVersion string `json:"package_version,omitempty"` // requested range/tag, not resolved
	// PluginCommandModeCopy | PluginCommandModeLink. The command text itself is
	// never collected: a real producer command can embed a secret.
	CommandMode string `json:"command_mode,omitempty"`
	// Declared catalog checkout selection. Records configuration; grants no reads.
	SparsePaths []string `json:"sparse_paths,omitempty"`
}

// EnablementObservation is one configuration layer's explicit boolean, with the
// file that stated it. Layers are preserved rather than resolved away, because
// user, project, local and managed can disagree and a project override is not a
// device-wide policy.
type EnablementObservation struct {
	Scope       string `json:"scope"`
	SourcePath  string `json:"source_path"`
	Enabled     bool   `json:"enabled"`
	ProjectPath string `json:"project_path,omitempty"`
}

// PluginObservation is one installation of one plugin within one context.
type PluginObservation struct {
	InstanceID string `json:"instance_id"`
	NativeID   string `json:"native_id"`
	Name       string `json:"name"` // catalog entry / native display name

	MarketplaceID string `json:"marketplace_id,omitempty"`
	// The manifest's own name, which need not equal the catalog entry name.
	ManifestName string `json:"manifest_name,omitempty"`
	// Stable non-secret account object id from a supported local marker.
	RemotePluginID string `json:"remote_plugin_id,omitempty"`

	InstallationKind string `json:"installation_kind"`
	Scope            string `json:"scope"`
	// The project a project/local installation applies to. It need not contain the
	// payload — a shared cache outside the project can supply both scopes — and a
	// user or system installation has none rather than an invented one.
	ProjectPath string `json:"project_path,omitempty"`

	InstallPath string `json:"install_path,omitempty"`
	// Original local source, retained separately from the installation's cache path.
	SourcePath   string         `json:"source_path,omitempty"`
	ManifestPath string         `json:"manifest_path,omitempty"`
	Source       *SourceLocator `json:"source,omitempty"` // payload, not catalog

	ManifestFormat  string `json:"manifest_format,omitempty"`
	ManifestVersion string `json:"manifest_version,omitempty"`
	CacheVersion    string `json:"cache_version,omitempty"` // directory label, not the manifest's version

	// Self-declared package metadata. Publisher is a name the package claims, not
	// a verified identity; homepage is a sanitized HTTP(S) URL.
	Description string `json:"description,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	Homepage    string `json:"homepage,omitempty"`

	// Native recorded times. Not catalog refresh, not first-seen, not mtime.
	InstalledAtMs   *int64 `json:"installed_at_ms,omitempty"`
	LastUpdatedAtMs *int64 `json:"last_updated_at_ms,omitempty"`

	// Tri-state. Installed=true needs positive native installation or supported
	// directory-loading evidence; a cache directory or a stray flag is neither.
	// FilesPresent=false keeps an installation that lost its payload.
	Installed            *bool  `json:"installed,omitempty"`
	FilesPresent         *bool  `json:"files_present,omitempty"`
	InstallationEvidence string `json:"installation_evidence"`

	// The preference at this installation's own scope, and the resolved result —
	// populated only when every relevant layer for that same scope was readable.
	// Neither proves the agent loaded the plugin.
	ConfiguredEnabled *bool                   `json:"configured_enabled,omitempty"`
	EffectiveEnabled  *bool                   `json:"effective_enabled,omitempty"`
	Enablement        []EnablementObservation `json:"enablement"`

	ComponentStatus string            `json:"component_status"`
	Components      []PluginComponent `json:"components"`
	Errors          []AgentScanError  `json:"errors"`
}

// PluginComponent is one declaration inside one installation. Exactly one payload
// matches Kind — Skill, Command or MCPConfig — and the remaining kinds carry
// none: they are descriptive, and their scripts, hooks and manifests are never
// uploaded.
type PluginComponent struct {
	ComponentID string `json:"component_id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"` // native declaration name, not display text
	// Relative to the selected plugin root, forward-slash, never containing "..".
	// A root declaration uses ".".
	RelativePath string `json:"relative_path"`
	Status       string `json:"status"`

	DefinitionPath string `json:"definition_path,omitempty"`
	// Symlink-resolved absolute path, when resolution succeeded. Used for
	// deduplicating one physical read; never a cross-device identity.
	ResolvedDefinitionPath string `json:"resolved_definition_path,omitempty"`
	// RFC 6901 pointer into the manifest, for a declaration that has no file of
	// its own. It never implies a file exists at RelativePath.
	DeclarationPointer string `json:"declaration_pointer,omitempty"`

	// How the agent invokes this declaration. Empty for kinds that are not invoked.
	CallableNames []string `json:"callable_names"`

	Skill     *AgentSkill             `json:"skill,omitempty"`
	Command   *AgentCommandDefinition `json:"command,omitempty"`
	MCPConfig *MCPConfigEnterprise    `json:"mcp_config,omitempty"`
}

// AgentCommandDefinition is a legacy command Markdown file — an actual file with
// an actual hash. It is never represented as a SKILL.md, and its path is never
// reported in a skill's skill_md_path.
type AgentCommandDefinition struct {
	Usage          *SkillUsage `json:"usage,omitempty"`
	Name           string      `json:"name"`
	DefinitionPath string      `json:"definition_path"`
	DefinitionHash string      `json:"definition_hash"` // hex(sha256(raw file bytes))

	Description  string   `json:"description,omitempty"`
	Version      string   `json:"version,omitempty"`
	License      string   `json:"license,omitempty"`
	AllowedTools []string `json:"allowed_tools,omitempty"`

	// Required: a false here is the positive claim that the file does not set it.
	DisableModelInvocation bool `json:"disable_model_invocation"`
	UserInvocableDisabled  bool `json:"user_invocable_disabled"`
	HasHooks               bool `json:"has_hooks"`
	HasShellInjection      bool `json:"has_shell_injection"`
}

// SkillUsage is a native cumulative counter associated with a detected skill.
// A nil count means unavailable or ambiguous, not zero uses.
type SkillUsage struct {
	Availability        string `json:"availability"`
	RecordedUses        *int64 `json:"recorded_uses,omitempty"`
	LastRecordedUseAtMs *int64 `json:"last_recorded_use_at_ms,omitempty"`
	RawKey              string `json:"raw_key,omitempty"`
	SourceID            string `json:"source_id,omitempty"`
	ObservedAtMs        int64  `json:"observed_at_ms,omitempty"`
}
