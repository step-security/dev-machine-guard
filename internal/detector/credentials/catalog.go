// Package credentials inventories the places a developer's tools keep
// credentials.
//
// The unit of collection is a source: one file, or the one directory that
// exists for nothing but keys. A source reports where credential material sits
// and how well it is guarded — never the material itself. No value, no
// substring, no digest, no fingerprint, and no classification derived from the
// secret's own characters ever leaves this package.
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

import "github.com/step-security/dev-machine-guard/internal/model"

// catalogVersion is the revision of the source list below, travelling with every
// scan so a reader can tell a list narrower than it expects from a source that ran
// and found nothing. A string because a revision is an identifier: nothing
// compares two arithmetically, and a suffix would change the type on both sides.
const catalogVersion = "2"

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
	// Bounds the single directory listing this phase performs.
	maxKeyDirEntries = 200
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
)

// location is one candidate path for a source.
type location struct {
	Root pathRoot
	// Slash-separated and joined with the platform separator when resolved, so
	// one string serves every platform.
	Rel string
	// Restricts this candidate. Nil means every platform.
	Platforms []string
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
)

// envOverride relocates a source. Not an edge case: monorepos, CI-parity setups
// and multi-account workflows are configured this way, and probing only the
// default path reports such a machine as having no credentials at all.
type envOverride struct {
	Var  string
	Kind overrideKind
	// Read according to Kind: the path below the directory for overrideDir, the
	// home-relative directory being replaced for overridePrefix, and unused for
	// overrideFile and overrideList.
	Rel string
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
}

// rootEnvVars are the variables the path roots themselves depend on. They are
// resolved alongside the per-source overrides even though no source lists them,
// because one of them relocates whole families of files at once.
var rootEnvVars = []string{"XDG_CONFIG_HOME"}

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
	for _, l := range s.Locations {
		if l.appliesTo(platform) {
			return true
		}
	}
	return false
}
