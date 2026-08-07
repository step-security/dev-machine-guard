package model

// Credential inventory wire types.
//
// A finding says which category of credential lives at a location, where it is,
// and how well protected it is. It never carries the credential — no value, no
// substring, no digest, no fingerprint, and no category derived from the
// secret's own characters. Protection state is derived by reading
// secret-bearing bytes (a key header, whether a token cache is JSON at all),
// which describes how material is guarded rather than what it is.

// Credential categories. The customer-facing grouping a finding rolls up to.
const (
	CredentialCategoryCloud          = "cloud"
	CredentialCategorySourceControl  = "source_control"
	CredentialCategoryPackageReg     = "package_registry"
	CredentialCategoryContainers     = "containers"
	CredentialCategoryAIMCP          = "ai_mcp"
	CredentialCategoryInfrastructure = "infrastructure"
)

// Protection states, worst-case per source. The fold order is
// plaintext > unknown > protected > external: `unknown` outranks `protected`
// because it means bytes were read and protection could not be determined, and
// folding it lower would let one unrecognised entry inherit a sibling's.
const (
	// A usable secret in the clear.
	CredentialProtectionPlaintext = "plaintext"
	// Present but not usable as-is — passphrase-encrypted, hardware-backed, or
	// wrapped by an OS store.
	CredentialProtectionProtected = "protected"
	// A file asserting a credential held elsewhere: a helper, an environment
	// reference, an SSO session.
	CredentialProtectionExternal = "external"
	// Bytes read, protection undetermined. Never read as safe downstream.
	CredentialProtectionUnknown = "unknown"
)

// Collection principals. AgentEffective is the agent process itself, which on
// macOS is a root daemon. UserEffective is reserved for a reader that drops
// privileges first.
const (
	CredentialPrincipalAgentEffective = "agent_effective"
	CredentialPrincipalUserEffective  = "user_effective"
)

// Reason codes for a source that could not be collected. Typed rather than free
// text because a parser's own error message can quote the line it choked on,
// which is a credential value.
const (
	CredentialReasonRefusedTCC          = "refused_tcc"
	CredentialReasonRefusedOutsideRoots = "refused_outside_user_roots"
	CredentialReasonPermissionDenied    = "permission_denied"
	CredentialReasonLocationUnresolved  = "location_unresolved"  //#nosec G101 -- a reason code on the wire; no value read from a file reaches this vocabulary.
	CredentialReasonUnsupportedEncoding = "unsupported_encoding" //#nosec G101 -- see above: a reason code, not anything read.
	CredentialReasonSkippedNoUser       = "skipped_no_user"
	CredentialReasonCapped              = "capped"
	CredentialReasonTimedOut            = "timed_out"
)

// GitHub CLI authentication outcomes, this inventory's own vocabulary rather
// than the CLI's: the tool's verdict has changed spelling across releases, and a
// reader cannot group hosts by a value it does not know. Every host carries one,
// so an absent value is never read as a verdict.
const (
	CredentialAuthAuthenticated    = "authenticated"
	CredentialAuthNotAuthenticated = "not_authenticated"
	CredentialAuthUnknown          = "unknown"
)

// Where the GitHub CLI holds a host's token. A token written into a file is the
// finding; a token in the OS keystore is not.
const (
	CredentialStorageInlineFile = "inline_file"
	CredentialStorageKeyring    = "keyring"
	CredentialStorageUnknown    = "unknown"
)

// Scope-reporting outcomes. Scopes only carries values GitHub authoritatively
// returned; every other outcome is one of these, so a caller never reads an
// empty Scopes as "this token has no permissions".
const (
	CredentialScopeObserved            = "observed"
	CredentialScopeUnavailable         = "unavailable"
	CredentialScopeUnsupportedCLI      = "unsupported_cli_version"  //#nosec G101 -- an outcome code on the wire, reported in place of permissions rather than carrying any.
	CredentialScopeAccessDenied        = "credential_access_denied" //#nosec G101 -- see above: an outcome code, not a permission or a token.
	CredentialScopeNetworkError        = "network_error"
	CredentialScopeNotReportedByGitHub = "not_reported_by_github"
)

// CurrentCredentialSchemaVersion is the credential block's own shape version,
// declared so a reader can reject or down-convert a shape it does not know
// instead of silently dropping fields.
const CurrentCredentialSchemaVersion = 1

// CredentialScanInfo is the credential inventory for one run. Its presence is
// the "scan ran" sentinel and that is load-bearing: nil means no information,
// while non-nil with zero findings means the scan ran and found nothing. The
// stored snapshot is replaced on any non-nil section, so an eagerly initialised
// struct where nil was meant erases a device's inventory in one write.
type CredentialScanInfo struct {
	Findings []CredentialFinding `json:"findings"`

	// One entry per source attempted and not read. A source absent from the
	// machine produces neither — a path name is not evidence.
	Errors []CredentialError `json:"errors"`

	// Pessimistic: false if any source could not be read, a cap was hit, or no
	// user resolved. A snapshot that replaces its predecessor wholesale has to
	// carry its own incompleteness.
	ScanComplete bool `json:"scan_complete"`

	// A cap bounded the result. Setting it also clears ScanComplete.
	Truncated bool `json:"truncated,omitempty"`

	PayloadSchemaVersion int `json:"payload_schema_version"`

	// The revision of the source list probed, so a narrower list is
	// distinguishable from a source that did not run. An identifier, not a
	// quantity.
	CatalogVersion string `json:"catalog_version"`

	CollectionPrincipal string `json:"collection_principal"`

	CollectedAt int64 `json:"collected_at"`

	DurationMs int64 `json:"duration_ms"`
}

// CredentialFinding describes one credential location.
type CredentialFinding struct {
	SourceID string `json:"source_id"`

	Category string `json:"category"`

	// The path as configured, in tokenised-root form ($HOME/..., $APPDATA/...,
	// $XDG_CONFIG_HOME/..., $VOLUME/<id>/..., $ABS/<token>/...). Display path
	// and identity path are one string: two representations become two rows.
	Location string `json:"location"`

	ResolvedLocation string `json:"resolved_location,omitempty"`

	// Credentials seen for plaintext, protected and unknown; configuration
	// references for external, which are not evidence that material exists
	// anywhere. Never total this as "credentials" without that split.
	Count int `json:"count"`

	Protection string `json:"protection"`

	// Octal POSIX bits ("0600"). Omitted on Windows, where Go synthesizes Perm()
	// from the read-only attribute regardless of the real ACL.
	Mode string `json:"mode,omitempty"`

	// Windows only: the file's own DACL carries an allow-read entry for a broad
	// trustee. Named for what is observed, not a conclusion it cannot reach —
	// effective access also depends on inherited entries, deny ordering, nested
	// groups and conditional entries. Tri-state so "not evaluated" stays
	// distinct from "absent".
	BroadReadAllowACEPresent *bool `json:"broad_read_allow_ace_present,omitempty"`

	// The highest-signal fields. Both use the resolved location, because a
	// dotfiles symlink farm is the layout that puts a credential in a repository
	// and the probed path looks innocent.
	InGitRepo  bool `json:"in_git_repo"`
	GitTracked bool `json:"git_tracked"`

	// Change detection without a whole-file hash, which for a low-entropy
	// credential would be a guessing oracle.
	Size  int64 `json:"size"`
	MTime int64 `json:"mtime"`

	CollectionPrincipal string `json:"collection_principal"`

	// Present only on the GitHub CLI hosts finding, which describes the same
	// configuration: a top-level list would force readers to re-join by host.
	GitHub []CredentialGitHubHost `json:"github,omitempty"`
}

// CredentialGitHubHost is the GitHub CLI's own account and permission report
// for one configured host.
type CredentialGitHubHost struct {
	Host                 string   `json:"host"`
	Configured           bool     `json:"configured"`
	AccountCount         int      `json:"account_count"`
	AuthenticationStatus string   `json:"authentication_status"`
	CredentialStorage    string   `json:"credential_storage"`
	Scopes               []string `json:"scopes,omitempty"`
	// An empty Scopes with ScopeStatus=observed means the token really carries
	// none; any other status means they were not obtained.
	ScopeStatus string `json:"scope_status"`
}

// CredentialError is one source attempted and not collected. Deliberately not a
// finding: before the first syscall the detector does not know whether anything
// is there, so a finding would claim a credential on the strength of a path.
type CredentialError struct {
	// Empty for exactly one reason code, skipped_no_user, which reports that no
	// account resolved and so no source was ever attempted. Every other reason
	// names the source it belongs to, and a reader is entitled to reject an
	// empty one. Naming the run here instead would put a value in this field
	// that looks like a catalog source and matches none.
	SourceID   string `json:"source_id"`
	ReasonCode string `json:"reason_code"`
}
