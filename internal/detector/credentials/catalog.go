// Package credentials inventories the places a developer's tools keep
// credentials.
//
// The unit of collection is a source: one file, or the one directory that
// exists for nothing but keys. A source reports where credential material sits
// and how well it is guarded. Full credential values, digests and fingerprints
// never leave this package. When the tenant opts in, eligible API keys may also
// report a bounded prefix and suffix with their credential type.
//
// A finding means material is in the file: a concrete value in a field the tool
// consumes as authentication, or a structurally valid private key. A file that
// names a credential kept elsewhere is not a finding, and neither is one this
// build could not interpret — that becomes an error, so a file the agent cannot
// read can never resolve to "this machine holds nothing".
//
// Two properties hold for every source and are what keep the phase bounded and
// consent-safe: each location is an exact path rather than a root to walk, and
// each read has a byte cap. Adding a family is a table entry plus a parser.
package credentials

import (
	"path"
	"slices"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// catalogVersion is the revision of the source list below, travelling with every
// scan so a reader can tell a list narrower than it expects from a source that ran
// and found nothing. A string because a revision is an identifier: nothing
// compares two arithmetically, and a suffix would change the type on both sides.
const catalogVersion = "3"

// Per-read byte caps. A credential file is small; anything larger is either not
// what we think it is or is hostile, and either way there is no reason to pull
// it into memory.
const (
	// A private key is validated over its complete bytes, so the cap has to
	// clear the largest key a developer plausibly holds — a header-sized read
	// cannot tell a whole container from a truncated one. A candidate longer
	// than this is reported capped rather than classified from its prefix.
	capPrivateKey = 64 << 10 // 64 KiB
	// The one source whose whole contents are the credential. Small on purpose:
	// this read exists only to tell a filled file from an emptied one, and
	// nothing about the value survives the parse.
	capToken  = 4 << 10 // 4 KiB
	capConfig = 1 << 20 // 1 MiB
	// Larger because a kubeconfig legitimately accumulates one cluster entry
	// per environment, each with an embedded CA certificate.
	capKubeconfig = 4 << 20 // 4 MiB
	// Application databases include request bodies and retained revisions.
	capInsomnia = 8 << 20 // 8 MiB
)

// Result-shape caps. Hitting either sets both `truncated` and
// `scan_complete=false`: the snapshot replaces its predecessor wholesale, so it
// carries its own incompleteness. Both match the bounds the reader applies to what
// it receives — a result the reader would refuse or shorten is not a result — and
// thirteen sources cannot reach either today, which is why exceeding them was never
// observed rather than never possible.
const (
	maxFindings = 400
	maxErrors   = 64
	// Bounds every directory listing this phase performs.
	maxKeyDirEntries = 200
	// Bounds the files the AI-tool and MCP sources take from listings and from
	// project discovery, so a home full of profiles or repositories cannot turn
	// one phase into an unbounded walk.
	maxListedCandidates = 1000
	// The most entries one AI-tool or MCP finding reports. Past it the count is
	// a lower bound and the finding says so.
	maxAICount = 10000
)

// Source identifiers. Stable strings: `errors[]` keys on them and fleet views
// group by them, so renaming one splits a source's history in two.
const (
	sourceAWSCredentials       = "aws_credentials"
	sourceAWSConfig            = "aws_config"
	sourceGCPADC               = "gcp_adc"
	sourceSSHPrivateKeys       = "ssh_private_keys"
	sourceGitCredentials       = "git_credentials"
	sourceNetrc                = "netrc"
	sourceGitHubCLIHosts       = "github_cli_hosts"
	sourceNPMRC                = "npmrc"
	sourcePypirc               = "pypirc"
	sourceDockerConfig         = "docker_config"
	sourceKubeconfig           = "kubeconfig"
	sourceTerraformCredentials = "terraform_credentials" //#nosec G101 -- the wire identifier for a source, naming a kind of file rather than holding anything read out of one.
	sourceVaultToken           = "vault_token"
	sourceInsomnia             = "insomnia"

	sourceClaudeCode      = "claude_code"
	sourceCodex           = "codex"
	sourceOpenCode        = "opencode"
	sourcePi              = "pi"
	sourceHermes          = "hermes"
	sourceCopilotCLI      = "copilot_cli"
	sourceCursor          = "cursor"
	sourceVSCode          = "vscode"
	sourceClaudeMCP       = "claude_mcp"
	sourceCodexMCP        = "codex_mcp"
	sourceOpenCodeMCP     = "opencode_mcp"
	sourcePiMCP           = "pi_mcp"
	sourceHermesMCP       = "hermes_mcp"
	sourceCopilotCLIMCP   = "copilot_cli_mcp"
	sourceCursorMCP       = "cursor_mcp"
	sourceVSCodeMCP       = "vscode_mcp"
	sourceSharedMCPConfig = "shared_mcp_config"
)

// readMode is the only filesystem operation a source performs. Declared per
// source rather than decided in the collector so that "what does this touch" is
// answerable by reading the table.
type readMode string

const (
	readFile readMode = "file"
	// One non-recursive listing followed by a bounded read of each entry. The
	// only listing this phase performs, confined to a directory whose entire
	// purpose is holding keys.
	readKeyDir readMode = "key_dir"
)

// matchPolicy decides what to do when more than one candidate location exists.
type matchPolicy string

const (
	// Report the highest-precedence location that exists, because the tool
	// reads exactly one. Reporting a superseded file would claim a credential
	// is in use when the tool never looks at it.
	matchFirst matchPolicy = "first"
	// Report every location that exists, because the tool reads all of them and
	// each is a separate file with its own mode and git status.
	matchAll matchPolicy = "all"
)

// pathRoot names the directory a location is relative to. Resolution comes from
// the OS user record, never from an inherited environment variable: the agent runs
// as root or SYSTEM, so its own home variables point at a service account.
type pathRoot string

const (
	rootHome pathRoot = "home"
	// Windows only.
	rootAppData pathRoot = "appdata"
	// $XDG_CONFIG_HOME when the developer has set it, $HOME/.config otherwise.
	// Only for tools that honour the variable: several keep files under ~/.config
	// while ignoring it, and those are rootHome paths that contain ".config".
	rootXDGConfig pathRoot = "xdg_config"
	// Windows only: the local, non-roaming application data directory.
	rootLocalAppData pathRoot = "local_appdata"
	// $XDG_DATA_HOME when the developer has set it, $HOME/.local/share otherwise,
	// on every platform: the tools that use it spell the same path on Windows.
	rootXDGData pathRoot = "xdg_data"
)

// location is one candidate path for a source.
type location struct {
	Root pathRoot
	// Slash-separated and joined with the platform separator when resolved, so
	// one string serves every platform.
	Rel string
	// Restricts this candidate. Nil means every platform.
	Platforms []string
	// The relocation group this candidate belongs to. An override replaces the
	// defaults of its own group only, because one tool can keep files under
	// roots that independent variables move.
	Group string
	// Read with the database reader rather than as text. Declared rather than
	// inferred from the name, because a relocated database can be named anything.
	SQLite bool
}

// overrideKind says how to read the value of an environment override.
type overrideKind string

const (
	// The value is the full path to the file.
	overrideFile overrideKind = "file"
	// The value is a directory the source's file sits under.
	overrideDir overrideKind = "dir"
	// The value is a separator-joined list of file paths, all of which the tool
	// reads.
	overrideList overrideKind = "list"
	// The value is the tool's active home, which may be one profile directory
	// below the root that holds every profile. The root and each of its profiles
	// are probed as well, because each keeps its own files on disk.
	overrideProfile overrideKind = "profile"
	// The value is the tool's active home, as for overrideProfile, but only the
	// root that holds it is probed: a store every profile shares.
	overrideRoot overrideKind = "root"
	// The value is appended to the name of the tool's own directory, which Base
	// names, rather than replacing it.
	overrideSuffix overrideKind = "suffix"
)

// envOverride relocates a source. Not an edge case: monorepos, CI-parity setups
// and multi-account workflows are configured this way, and probing only the
// default path reports such a machine as having no credentials at all.
type envOverride struct {
	Var  string
	Kind overrideKind
	// The path below the directory for overrideDir, overrideProfile,
	// overrideRoot and overrideSuffix, and unused for overrideFile and overrideList. A "*"
	// element is one bounded listing.
	Rel string
	// The relocation group this override replaces.
	Group string
	// Where a relative value resolves, or for overrideSuffix the directory
	// whose name is extended; its Platforms restrict the override. Zero means a
	// relative value is used as written, which the path guard then refuses.
	Base location
	// The value may start with "~", meaning the developer's home.
	Tilde bool
	// See location.SQLite.
	SQLite bool
	// The file is a configuration whatever it is called: the developer chose
	// its name, so the name says nothing about its shape.
	Config bool
}

// source is one catalog entry. Everything here is data; no entry carries
// behaviour, and none carries a protection state — protection is measured per
// file at scan time, never declared in advance.
type source struct {
	ID       string
	Category string
	Mode     readMode
	MaxBytes int64
	Match    matchPolicy
	// Ahead of Locations in precedence order.
	Overrides []envOverride
	Locations []location
	// Project-relative names probed under each project the inventory walk
	// discovered. A "*" is allowed in the final element only.
	Project []string
	// Files with this suffix are a raw secret rather than a document, so they
	// are read with the raw-secret cap.
	RawSuffix string
}

// Scope a location to platforms that spell a path differently. Written out
// rather than inferred from a "unix" pseudo-platform so the table names the
// same platform values the rest of the agent branches on.
var (
	unixOnly    = []string{model.PlatformDarwin, model.PlatformLinux}
	windowsOnly = []string{model.PlatformWindows}
	darwinOnly  = []string{model.PlatformDarwin}
	linuxOnly   = []string{model.PlatformLinux}
)

// insomniaFiles are the API client's databases that can hold credential
// material. The names are fixed by the application, so each is an exact path
// and the directory is never listed; the databases beside them hold cookies,
// responses and settings.
var insomniaFiles = []string{
	"insomnia.Request.db",
	"insomnia.RequestGroup.db",
	"insomnia.Environment.db",
	"insomnia.OAuth2Token.db",
	"insomnia.WebSocketRequest.db",
	"insomnia.SocketIORequest.db",
	"insomnia.McpRequest.db",
	"insomnia.GrpcRequest.db",
	"insomnia.ClientCertificate.db",
	"insomnia.RequestVersion.db",
	"insomnia.GitCredentials.db",
	"insomnia.GitRepository.db",
	"insomnia.CloudCredential.db",
	"insomnia.UserSession.db",
}

// insomniaLocations spells the data directory per platform for every database
// file; ten files under three roots is too many literals to read for a typo.
func insomniaLocations() []location {
	out := make([]location, 0, 3*len(insomniaFiles))
	for _, f := range insomniaFiles {
		out = append(out,
			location{Root: rootHome, Rel: "Library/Application Support/Insomnia/" + f, Platforms: darwinOnly},
			location{Root: rootAppData, Rel: "Insomnia/" + f, Platforms: windowsOnly},
			location{Root: rootXDGConfig, Rel: "Insomnia/" + f, Platforms: linuxOnly},
		)
	}
	return out
}

// insomniaOverrides relocates every database file under the one directory the
// application reads from its environment.
func insomniaOverrides() []envOverride {
	out := make([]envOverride, 0, len(insomniaFiles))
	for _, f := range insomniaFiles {
		out = append(out, envOverride{Var: "INSOMNIA_DATA_PATH", Kind: overrideDir, Rel: f})
	}
	return out
}

// sources is the catalog.
var sources = []source{
	{
		ID:        sourceAWSCredentials,
		Category:  model.CredentialCategoryCloud,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchFirst,
		Overrides: []envOverride{{Var: "AWS_SHARED_CREDENTIALS_FILE", Kind: overrideFile}},
		Locations: []location{{Root: rootHome, Rel: ".aws/credentials"}},
	},
	{
		// Separate from the credentials file because the two variables move
		// independently: a developer can relocate one and leave the other.
		ID:        sourceAWSConfig,
		Category:  model.CredentialCategoryCloud,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchFirst,
		Overrides: []envOverride{{Var: "AWS_CONFIG_FILE", Kind: overrideFile}},
		Locations: []location{{Root: rootHome, Rel: ".aws/config"}},
	},
	{
		// The only fixed-path credential in this directory: the caches beside it
		// are SQLite and the per-account files are named after the account. The
		// home is the right root — this tool ignores XDG_CONFIG_HOME.
		ID:       sourceGCPADC,
		Category: model.CredentialCategoryCloud,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchFirst,
		Locations: []location{
			{Root: rootHome, Rel: ".config/gcloud/application_default_credentials.json", Platforms: unixOnly},
			{Root: rootAppData, Rel: "gcloud/application_default_credentials.json", Platforms: windowsOnly},
		},
	},
	{
		// One finding per key file rather than one for the directory: mode is
		// per-file and materially different between keys, and a key committed
		// to a repository has to be identifiable on its own.
		ID:        sourceSSHPrivateKeys,
		Category:  model.CredentialCategorySourceControl,
		Mode:      readKeyDir,
		MaxBytes:  capPrivateKey,
		Match:     matchFirst,
		Locations: []location{{Root: rootHome, Rel: ".ssh"}},
	},
	{
		// Both files are read by the tool, so both are reported.
		ID:       sourceGitCredentials,
		Category: model.CredentialCategorySourceControl,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		Locations: []location{
			{Root: rootHome, Rel: ".git-credentials"},
			{Root: rootXDGConfig, Rel: "git/credentials"},
		},
	},
	{
		// The Windows name uses an underscore.
		ID:       sourceNetrc,
		Category: model.CredentialCategorySourceControl,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchFirst,
		Locations: []location{
			{Root: rootHome, Rel: ".netrc", Platforms: unixOnly},
			{Root: rootHome, Rel: "_netrc", Platforms: windowsOnly},
		},
	},
	{
		// XDG_CONFIG_HOME outranks the roaming profile here, on Windows too, which
		// reverses the usual assumption. An override rather than a rootXDGConfig
		// location because unset it falls back to the roaming profile on Windows,
		// not to %USERPROFILE%\.config. Note the space in the Windows name.
		ID:       sourceGitHubCLIHosts,
		Category: model.CredentialCategorySourceControl,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchFirst,
		Overrides: []envOverride{
			{Var: "GH_CONFIG_DIR", Kind: overrideDir, Rel: "hosts.yml"},
			{Var: "XDG_CONFIG_HOME", Kind: overrideDir, Rel: "gh/hosts.yml"},
		},
		Locations: []location{
			{Root: rootAppData, Rel: "GitHub CLI/hosts.yml", Platforms: windowsOnly},
			{Root: rootHome, Rel: ".config/gh/hosts.yml", Platforms: unixOnly},
		},
	},
	{
		ID:        sourceNPMRC,
		Category:  model.CredentialCategoryPackageReg,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchFirst,
		Overrides: []envOverride{{Var: "NPM_CONFIG_USERCONFIG", Kind: overrideFile}},
		Locations: []location{{Root: rootHome, Rel: ".npmrc"}},
	},
	{
		// No override: this file has no environment variable that relocates it.
		// The variable that moves the installer's own configuration points at a
		// different file, which this source does not read.
		ID:        sourcePypirc,
		Category:  model.CredentialCategoryPackageReg,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchFirst,
		Locations: []location{{Root: rootHome, Rel: ".pypirc"}},
	},
	{
		ID:        sourceDockerConfig,
		Category:  model.CredentialCategoryContainers,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchFirst,
		Overrides: []envOverride{{Var: "DOCKER_CONFIG", Kind: overrideDir, Rel: "config.json"}},
		Locations: []location{{Root: rootHome, Rel: ".docker/config.json"}},
	},
	{
		// The override is a path list and every element is live, so each one
		// that exists is its own finding.
		ID:        sourceKubeconfig,
		Category:  model.CredentialCategoryContainers,
		Mode:      readFile,
		MaxBytes:  capKubeconfig,
		Match:     matchAll,
		Overrides: []envOverride{{Var: "KUBECONFIG", Kind: overrideList}},
		Locations: []location{{Root: rootHome, Rel: ".kube/config"}},
	},
	{
		// The JSON credentials file, where this tool stores a token in a form that
		// can be read exactly. The adjacent CLI file may hold one too, but it is
		// HCL, and a partial reading would report under this same identifier.
		ID:       sourceTerraformCredentials,
		Category: model.CredentialCategoryInfrastructure,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchFirst,
		Locations: []location{
			{Root: rootHome, Rel: ".terraform.d/credentials.tfrc.json", Platforms: unixOnly},
			{Root: rootAppData, Rel: "terraform.d/credentials.tfrc.json", Platforms: windowsOnly},
		},
	},
	{
		// The one source whose whole contents are the credential, so establishing
		// that it holds material means opening it. The read is bounded to a few
		// kilobytes and the bytes are trimmed, tested for being a reference, and
		// dropped — a stat alone cannot tell a live token from an emptied file
		// carrying a placeholder or an environment reference.
		ID:        sourceVaultToken,
		Category:  model.CredentialCategoryInfrastructure,
		Mode:      readFile,
		MaxBytes:  capToken,
		Match:     matchFirst,
		Locations: []location{{Root: rootHome, Rel: ".vault-token"}},
	},
	{
		// One finding per database file that exists: each has its own mode and
		// git status, and each keeps superseded and deleted records until the
		// application compacts it.
		ID:        sourceInsomnia,
		Category:  model.CredentialCategoryAPIClients,
		Mode:      readFile,
		MaxBytes:  capInsomnia,
		Match:     matchAll,
		Overrides: insomniaOverrides(),
		Locations: insomniaLocations(),
	},
	// The AI-tool and MCP sources follow the classic ones so that, when the result
	// cap is reached, it is these project-heavy sources that are cut short. Every
	// one reports each file holding material: the inventory describes what is
	// retained on disk, not which copy a tool would pick at run time.
	{
		ID:       sourceClaudeCode,
		Category: model.CredentialCategoryAITools,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		Overrides: slices.Concat(
			dirOverrides("CLAUDE_CONFIG_DIR", "claude", ".credentials.json", "config.json", ".config.json", "settings.json", ".claude.json"),
			dirOverrides("ANTHROPIC_CONFIG_DIR", "anthropic", "credentials/*.json"),
		),
		Locations: slices.Concat(
			filesUnder(rootHome, "claude", ".claude", nil, ".credentials.json", "config.json", ".config.json", "settings.json"),
			// Read even when the configuration directory moves: the tool keeps
			// this file in the home regardless.
			filesUnder(rootHome, "home", "", nil, ".claude.json"),
			filesUnder(rootHome, "anthropic", ".config/anthropic", unixOnly, "credentials/*.json"),
			filesUnder(rootAppData, "anthropic", "Anthropic", windowsOnly, "credentials/*.json"),
		),
		Project: []string{".claude/settings.json", ".claude/settings.local.json"},
	},
	{
		ID:        sourceCodex,
		Category:  model.CredentialCategoryAITools,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Overrides: dirOverrides("CODEX_HOME", "", codexAIFiles...),
		Locations: filesUnder(rootHome, "", ".codex", nil, codexAIFiles...),
		Project:   []string{".codex/config.toml"},
	},
	{
		ID:       sourceOpenCode,
		Category: model.CredentialCategoryAITools,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		Overrides: slices.Concat(
			[]envOverride{{Var: "OPENCODE_DB", Kind: overrideFile, Group: "db", Base: location{Root: rootXDGData, Rel: "opencode"}, SQLite: true}},
			openCodeConfigOverrides,
		),
		Locations: slices.Concat(
			filesUnder(rootXDGData, "", "opencode", nil, "auth.json"),
			openCodeDatabases(),
			filesUnder(rootXDGConfig, "", "opencode", nil, openCodeConfigFiles...),
		),
		Project: openCodeProjectFiles,
	},
	{
		ID:        sourcePi,
		Category:  model.CredentialCategoryAITools,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Overrides: dirOverrides("PI_CODING_AGENT_DIR", "", "auth.json", "models.json"),
		Locations: filesUnder(rootHome, "", ".pi/agent", nil, "auth.json", "models.json"),
	},
	{
		ID:        sourceHermes,
		Category:  model.CredentialCategoryAITools,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Overrides: slices.Concat(hermesOverrides("", hermesAIFiles...), hermesOverrides("shared")),
		Locations: slices.Concat(hermesLocations("", hermesAIFiles...), hermesLocations("shared")),
	},
	{
		ID:       sourceCopilotCLI,
		Category: model.CredentialCategoryAITools,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		Overrides: slices.Concat(
			dirOverrides("COPILOT_HOME", "", "config.json"),
			[]envOverride{{Var: "COPILOT_PROVIDERS_CONFIG", Kind: overrideFile, Group: "providers"}},
			dirOverrides("COPILOT_HOME", "providers", "providers.json"),
		),
		Locations: slices.Concat(
			filesUnder(rootHome, "", ".copilot", nil, "config.json"),
			filesUnder(rootHome, "providers", ".copilot", nil, "providers.json"),
		),
	},
	{
		ID:        sourceCursor,
		Category:  model.CredentialCategoryAITools,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Locations: editorLocations("Cursor", true, editorStateDatabases...),
	},
	{
		ID:       sourceVSCode,
		Category: model.CredentialCategoryAITools,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		// The editor's own provider key storage is encrypted and has no fixed
		// slot names, so only the language model configuration is read.
		Locations: editorLocations("Code", false, "chatLanguageModels.json", "profiles/*/chatLanguageModels.json"),
	},
	{
		ID:        sourceClaudeMCP,
		Category:  model.CredentialCategoryMCPServers,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Overrides: dirOverrides("CLAUDE_CONFIG_DIR", "claude", ".credentials.json", ".config.json", ".claude.json"),
		Locations: slices.Concat(
			filesUnder(rootHome, "claude", ".claude", nil, ".credentials.json", ".config.json"),
			filesUnder(rootHome, "home", "", nil, ".claude.json"),
		),
	},
	{
		ID:        sourceCodexMCP,
		Category:  model.CredentialCategoryMCPServers,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Overrides: dirOverrides("CODEX_HOME", "", codexMCPFiles...),
		Locations: filesUnder(rootHome, "", ".codex", nil, codexMCPFiles...),
		Project:   []string{".codex/config.toml"},
	},
	{
		ID:       sourceOpenCodeMCP,
		Category: model.CredentialCategoryMCPServers,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		Overrides: slices.Concat(
			[]envOverride{{Var: "OPENCODE_DB", Kind: overrideFile, Group: "db", Base: location{Root: rootXDGData, Rel: "opencode"}, SQLite: true}},
			openCodeConfigOverrides,
		),
		Locations: slices.Concat(
			filesUnder(rootXDGData, "", "opencode", nil, "mcp-auth.json"),
			openCodeDatabases(),
			filesUnder(rootXDGConfig, "", "opencode", nil, openCodeConfigFiles...),
		),
		Project: openCodeProjectFiles,
	},
	{
		ID:        sourcePiMCP,
		Category:  model.CredentialCategoryMCPServers,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Overrides: dirOverrides("PI_CODING_AGENT_DIR", "", "mcp.json", "mcp-auth.json"),
		Locations: filesUnder(rootHome, "", ".pi/agent", nil, "mcp.json", "mcp-auth.json"),
		Project:   []string{".pi/mcp.json"},
	},
	{
		ID:        sourceHermesMCP,
		Category:  model.CredentialCategoryMCPServers,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Overrides: hermesOverrides("", hermesMCPFiles...),
		Locations: hermesLocations("", hermesMCPFiles...),
	},
	{
		ID:        sourceCopilotCLIMCP,
		Category:  model.CredentialCategoryMCPServers,
		Mode:      readFile,
		MaxBytes:  capConfig,
		Match:     matchAll,
		Overrides: dirOverrides("COPILOT_HOME", "", copilotMCPFiles...),
		Locations: filesUnder(rootHome, "", ".copilot", nil, copilotMCPFiles...),
		Project:   []string{".github/mcp.json"},
		RawSuffix: ".secret",
	},
	{
		ID:       sourceCursorMCP,
		Category: model.CredentialCategoryMCPServers,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		Locations: slices.Concat(
			filesUnder(rootHome, "", ".cursor", nil, "mcp.json"),
			editorLocations("Cursor", true, editorStateDatabases...),
		),
		Project: []string{".cursor/mcp.json"},
	},
	{
		ID:       sourceVSCodeMCP,
		Category: model.CredentialCategoryMCPServers,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		Locations: slices.Concat(
			editorLocations("Code", false, "mcp.json", "profiles/*/mcp.json"),
			editorLocations("Code", true, slices.Concat(editorStateDatabases, []string{"workspaceStorage/*/state.vscdb"})...),
		),
		Project: []string{".vscode/mcp.json", "*.code-workspace"},
	},
	{
		// Project files only: the portable configuration has no owner of its
		// own, so it is reported once here rather than under every client
		// that reads it.
		ID:       sourceSharedMCPConfig,
		Category: model.CredentialCategoryMCPServers,
		Mode:     readFile,
		MaxBytes: capConfig,
		Match:    matchAll,
		Project:  []string{".mcp.json"},
	},
}

// Codex keeps account and MCP material in one home, split by file. The encrypted
// stores are listed so an attempt is recorded: their contents cannot be read.
var (
	codexAIFiles  = []string{"auth.json", "config.toml", "*.config.toml", "secrets/gateway_oauth.json", "secrets/codex_auth.age"}
	codexMCPFiles = []string{"config.toml", "*.config.toml", ".credentials.json", "secrets/mcp_oauth.age"}
)

var (
	openCodeConfigFiles  = []string{"opencode.json", "opencode.jsonc"}
	openCodeProjectFiles = []string{"opencode.json", "opencode.jsonc", ".opencode/opencode.json", ".opencode/opencode.jsonc"}
)

// openCodeConfigOverrides are the configuration file and directory OpenCode
// loads on top of its global configuration. Each is a group of its own, so
// setting one never displaces the global files.
var openCodeConfigOverrides = slices.Concat(
	[]envOverride{{Var: "OPENCODE_CONFIG", Kind: overrideFile, Group: "config", Config: true}},
	dirOverrides("OPENCODE_CONFIG_DIR", "config-dir", openCodeConfigFiles...),
)

// openCodeDatabases names the default database and the per-channel databases
// beside it. Channel names are sanitised to the listing's own name alphabet, so
// one bounded listing of the data directory finds them without guessing which
// channels were installed.
func openCodeDatabases() []location {
	return []location{
		{Root: rootXDGData, Rel: "opencode/opencode.db", SQLite: true},
		{Root: rootXDGData, Rel: "opencode/opencode-*.db", SQLite: true},
	}
}

// Hermes keeps one home per profile below a root, each with its own files; the
// default home is the root itself.
var (
	hermesAIFiles  = []string{"auth.json", ".env", ".op.env", "config.yaml"}
	hermesMCPFiles = []string{"config.yaml", "mcp-tokens/*.json"}
)

// hermesRoots are the root directory on each platform. Its name is the one a
// suffix variable extends.
var hermesRoots = []location{
	{Root: rootHome, Rel: ".hermes", Platforms: unixOnly},
	{Root: rootLocalAppData, Rel: "hermes", Platforms: windowsOnly},
}

// hermesLocations names the files in the root and in every profile below it.
// The group is "" for the per-profile files and "shared" for the account store
// every profile shares.
func hermesLocations(group string, files ...string) []location {
	var out []location
	for _, root := range hermesRoots {
		for _, rel := range hermesRels(group, files) {
			out = append(out, location{Root: root.Root, Rel: path.Join(root.Rel, rel), Platforms: root.Platforms, Group: group})
		}
	}
	return out
}

// hermesOverrides relocates the Hermes files: a suffix renames the root, and an
// active home set in the environment adds that home, its root and the root's
// profiles without displacing the default root, whose files stay on disk.
func hermesOverrides(group string, files ...string) []envOverride {
	var out []envOverride
	if group == "shared" {
		// An active home outside the default root brings its own root, whose
		// shared store sits beside its profiles.
		out = append(out,
			envOverride{Var: "HERMES_SHARED_AUTH_DIR", Kind: overrideDir, Rel: "nous_auth.json", Group: group, Tilde: true},
			envOverride{Var: "HERMES_HOME", Kind: overrideRoot, Rel: "shared/nous_auth.json", Group: "home", Tilde: true},
		)
	}
	for _, rel := range hermesRels(group, files) {
		for _, root := range hermesRoots {
			out = append(out, envOverride{Var: "HERMES_DATA_DIR_SUFFIX", Kind: overrideSuffix, Rel: rel, Group: group, Base: root})
		}
	}
	if group == "" {
		for _, f := range files {
			out = append(out, envOverride{Var: "HERMES_HOME", Kind: overrideProfile, Rel: f, Group: "home", Tilde: true})
		}
	}
	return out
}

// hermesRels spells the files of one Hermes group relative to the root.
func hermesRels(group string, files []string) []string {
	if group == "shared" {
		return []string{"shared/nous_auth.json"}
	}
	out := make([]string, 0, 2*len(files))
	for _, f := range files {
		out = append(out, f, "profiles/*/"+f)
	}
	return out
}

var copilotMCPFiles = []string{"mcp-config.json", "mcp-oauth-config/*.json", "mcp-secrets/*.secret"}

// editorStateDatabases are the editor's own key-value stores that can hold
// provider and MCP material, globally and per named profile.
var editorStateDatabases = []string{"globalStorage/state.vscdb", "profiles/*/globalStorage/state.vscdb"}

// editorLocations spells an editor's per-user directory on each platform for
// the given files below it.
func editorLocations(product string, sqlite bool, rels ...string) []location {
	out := make([]location, 0, 3*len(rels))
	for _, rel := range rels {
		out = append(out,
			location{Root: rootHome, Rel: "Library/Application Support/" + product + "/User/" + rel, Platforms: darwinOnly, SQLite: sqlite},
			location{Root: rootXDGConfig, Rel: product + "/User/" + rel, Platforms: linuxOnly, SQLite: sqlite},
			location{Root: rootAppData, Rel: product + "/User/" + rel, Platforms: windowsOnly, SQLite: sqlite},
		)
	}
	return out
}

// filesUnder lists files below one directory of one root.
func filesUnder(root pathRoot, group, dir string, platforms []string, files ...string) []location {
	out := make([]location, 0, len(files))
	for _, f := range files {
		out = append(out, location{Root: root, Rel: path.Join(dir, f), Platforms: platforms, Group: group})
	}
	return out
}

// dirOverrides relocates the given files under the directory a variable names.
func dirOverrides(name, group string, files ...string) []envOverride {
	out := make([]envOverride, 0, len(files))
	for _, f := range files {
		out = append(out, envOverride{Var: name, Kind: overrideDir, Rel: f, Group: group})
	}
	return out
}

// rootEnvVars are the variables the path roots themselves depend on. They are
// resolved alongside the per-source overrides even though no source lists them,
// because one of them relocates whole families of files at once.
var rootEnvVars = []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME"}

// EnvVars returns every environment variable whose value the catalog needs from
// the resolved developer's session, deduplicated and in a stable order. It is what
// the one-shot probe asks for: these live in a shell session rather than a file, so
// they are collected in a single pass and never re-queried per source.
func EnvVars() []string {
	seen := make(map[string]bool, len(rootEnvVars)+len(sources))
	out := make([]string, 0, len(rootEnvVars)+len(sources))
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, name := range rootEnvVars {
		add(name)
	}
	for _, s := range sources {
		for _, o := range s.Overrides {
			add(o.Var)
		}
	}
	return out
}

// appliesTo reports whether a candidate location is spelled this way on the
// platform being scanned.
func (l location) appliesTo(platform string) bool {
	if len(l.Platforms) == 0 {
		return true
	}
	for _, p := range l.Platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// applies reports whether the source has any location on this platform. A
// source that does not apply is not a source that failed: it produces neither a
// finding nor an error, because there is nothing there to look for.
func (s source) applies(platform string) bool {
	if len(s.Project) > 0 {
		return true
	}
	for _, l := range s.Locations {
		if l.appliesTo(platform) {
			return true
		}
	}
	return false
}
