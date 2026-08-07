package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// The GitHub CLI probe is the one place this phase runs a program, and every
// bound on it is deliberate.
const (
	// The child makes an authenticated network call, so it can hang on a
	// black-holed proxy; the phase cannot.
	ghTimeout = 10 * time.Second
	// The report is a few hundred bytes per host, and a child that produces
	// more than this is not producing the document this parses.
	ghMaxOutput = 256 << 10
	// Output is collected through a pipe, and a grandchild that inherited the
	// write end keeps it open after its parent dies — so the wait, not the
	// child, is what would outlive the timeout and hold the phase open.
	ghWaitDelay = 2 * time.Second
)

// ghTokenVars are the variables the CLI reads a token from, removed from the
// child's environment because the agent's own service environment may carry one.
// The enterprise pair is a separate precedence path: stripping only the first two
// would leave an inherited value answering for a self-hosted host.
var ghTokenVars = []string{
	"GH_TOKEN",
	"GITHUB_TOKEN",
	"GH_ENTERPRISE_TOKEN",
	"GITHUB_ENTERPRISE_TOKEN",
}

// ghRequest is one invocation of the probe.
type ghRequest struct {
	// Absolute. The child is never located through a PATH lookup at exec time.
	Binary string
	// Points the child at the developer's configuration. Without it the child
	// reads the agent's own and reports on the wrong identity.
	ConfigDir string
	Username  string
	// The agent is running as a system account and has to become Username
	// first.
	DropPrivileges bool
}

// ghRunner executes the probe. An interface so the fence itself is testable:
// what the child is given, what is stripped from it, and what is read back are
// all assertable without a CLI installed.
type ghRunner interface {
	Run(ctx context.Context, req ghRequest) ([]byte, error)
}

// execRunner is the production runner.
type execRunner struct{}

// Run executes the probe with a constructed environment and a bounded read.
// Standard error is discarded at the pipe rather than captured and dropped later:
// the CLI's diagnostics quote the host and account, and anything captured can end
// up in a log.
func (execRunner) Run(ctx context.Context, req ghRequest) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, ghTimeout)
	defer cancel()

	name := req.Binary
	args := slices.Clone(ghStatusArgs)
	if req.DropPrivileges {
		// The environment is rebuilt inside the child rather than handed to it:
		// dropping privileges resets it on the way through, so the strip has to
		// take effect where the child can see it.
		name = "sudo"
		args = append([]string{"-H", "-u", req.Username, "--", "env"}, ghChildEnv(req.ConfigDir)...)
		args = append(args, req.Binary)
		args = append(args, ghStatusArgs...)
	}

	// #nosec G204 -- name is the path a PATH lookup returned for the CLI, or the
	// literal below it; the arguments are package constants plus that same path
	// and the account name the user enumeration produced. Nothing here is spelled
	// by a scanned file or by the environment.
	cmd := exec.CommandContext(ctx, name, args...)
	// The command is built here rather than run through the shared executor
	// because that interface returns the child's standard error and its whole
	// standard output as strings and offers no way to set the environment —
	// which would undo the discard, the cap and the token strip below. The
	// process-level safeguards are not stream or environment concerns, so they
	// come from the one place that defines them.
	executor.HardenCommand(cmd)
	if !req.DropPrivileges {
		cmd.Env = append(strippedEnv(), "GH_CONFIG_DIR="+req.ConfigDir)
	}
	out := &boundedBuffer{max: ghMaxOutput}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	// Stated here rather than left to the group teardown, which is a no-op on
	// Windows: the bound the phase depends on has to hold on every platform.
	cmd.WaitDelay = ghWaitDelay
	err := cmd.Run()
	return out.data, err
}

// ghStatusArgs asks for the host report and never for the token: there is a flag
// that prints the token itself and it is never passed. The child does the keystore
// access and the network call, so the token stays with the tool that owns it.
var ghStatusArgs = []string{"auth", "status", "--json", "hosts"}

// ghChildEnv is the environment assignment list for the privilege-dropping form.
func ghChildEnv(configDir string) []string {
	env := make([]string, 0, len(ghTokenVars)*2+1)
	for _, name := range ghTokenVars {
		env = append(env, "-u", name)
	}
	return append(env, "GH_CONFIG_DIR="+configDir)
}

// strippedEnv copies the current environment without the token variables.
func strippedEnv() []string {
	drop := make(map[string]bool, len(ghTokenVars))
	for _, name := range ghTokenVars {
		drop[name] = true
	}
	current := os.Environ()
	kept := make([]string, 0, len(current))
	for _, entry := range current {
		name, _, _ := strings.Cut(entry, "=")
		if drop[name] {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// boundedBuffer accumulates up to max bytes and discards the rest, bounding the
// child's output at the pipe so a runaway child cannot grow the agent's memory
// while the read is in progress.
type boundedBuffer struct {
	max  int
	data []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.max - len(b.data); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		b.data = append(b.data, p[:room]...)
	}
	// The full length is reported so the child is never signalled to stop
	// writing; the bound is on what is kept, not on what it may produce.
	return len(p), nil
}

// ghStatusDoc is the probe's report. Hosts are decoded loosely because the value
// shape has varied across releases and a decode failure here would discard a
// report the machine did produce.
type ghStatusDoc struct {
	Hosts map[string]json.RawMessage `json:"hosts"`
}

// ghAccount is one account record. login is deliberately absent: accounts are
// counted from the configuration file, and the account name is not part of this
// inventory.
type ghAccount struct {
	Active bool `json:"active"`
	// Arrives as one comma-separated string rather than a list.
	Scopes string `json:"scopes"`
	// The CLI's own verdict, which decides success: the command exits zero even
	// when authentication failed, so reading the exit code would record a
	// failure as a successful observation.
	State       string `json:"state"`
	TokenSource string `json:"tokenSource"`
}

// parseGHStatus reads the probe's report into the active account per host.
func parseGHStatus(data []byte) (map[string]ghAccount, bool) {
	var doc ghStatusDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	byHost := make(map[string]ghAccount, len(doc.Hosts))
	for host, raw := range doc.Hosts {
		accounts, ok := decodeGHAccounts(raw)
		if !ok || len(accounts) == 0 {
			continue
		}
		chosen := accounts[0]
		for _, account := range accounts {
			if account.Active {
				chosen = account
				break
			}
		}
		byHost[host] = chosen
	}
	return byHost, true
}

// decodeGHAccounts accepts either a list of accounts or a single account, which the
// tool has spelled both ways across versions. The shape comes from the first
// meaningful byte rather than from a failed decode and a fallback: a fallback cannot
// tell the other shape from a malformed one, and would re-read a corrupt list.
func decodeGHAccounts(raw json.RawMessage) ([]ghAccount, bool) {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, false
	}
	if trimmed[0] == '[' {
		var list []ghAccount
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, false
		}
		return list, true
	}
	var single ghAccount
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, false
	}
	return []ghAccount{single}, true
}

// parseGHScopes splits the comma-separated scope string.
func parseGHScopes(value string) []string {
	var scopes []string
	for field := range strings.SplitSeq(value, ",") {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	return scopes
}

// githubHostReports merges what the configuration file established with what the
// CLI reported, one entry per configured host. fallbackStatus covers a host the CLI
// said nothing about, including every host when the probe did not run: scopes and
// their status travel together, so an empty list never reads as no permissions.
func githubHostReports(configs []githubHostConfig, byHost map[string]ghAccount, fallbackStatus string) []model.CredentialGitHubHost {
	reports := make([]model.CredentialGitHubHost, 0, len(configs))
	for _, cfg := range configs {
		report := model.CredentialGitHubHost{
			Host:         cfg.Host,
			Configured:   true,
			AccountCount: cfg.AccountCount,
			// Both start at the value that says nothing was established, so a
			// host the probe never reached is described rather than left blank.
			AuthenticationStatus: model.CredentialAuthUnknown,
			CredentialStorage:    model.CredentialStorageUnknown,
			ScopeStatus:          fallbackStatus,
		}
		// The one thing needing no probe: a token written into the file is in it
		// whatever the tool says afterwards.
		if cfg.InlineToken {
			report.CredentialStorage = model.CredentialStorageInlineFile
		}

		account, reported := byHost[cfg.Host]
		if !reported {
			reports = append(reports, report)
			continue
		}
		report.AuthenticationStatus = authenticationStatus(account.State)

		// A token source naming one of the stripped variables means the child
		// was answering for whatever identity the agent's environment carries.
		// The report would be about the wrong account, so none of it is kept.
		if isStrippedTokenVar(account.TokenSource) {
			report.ScopeStatus = model.CredentialScopeUnavailable
			reports = append(reports, report)
			continue
		}
		if storage := credentialStorage(account.TokenSource); storage != "" {
			report.CredentialStorage = storage
		}

		switch {
		case report.AuthenticationStatus != model.CredentialAuthAuthenticated:
			report.ScopeStatus = model.CredentialScopeUnavailable
		default:
			report.Scopes = parseGHScopes(account.Scopes)
			if len(report.Scopes) == 0 {
				// The permissions of a fine-grained token are not expressible
				// as scopes, so the service reports none for one. That is an
				// absence of information, not a token without permissions.
				report.ScopeStatus = model.CredentialScopeNotReportedByGitHub
			} else {
				report.ScopeStatus = model.CredentialScopeObserved
			}
		}
		reports = append(reports, report)
	}
	return reports
}

// ghStateAuthenticated is the tool's own word for an account that authenticates,
// named once here to keep its spelling out of the record. The command exits
// successfully even when authentication failed, so this is the verdict.
const ghStateAuthenticated = "success"

// The tool's own names for where it keeps a token. A token in the CLI's
// configuration is spelled after the grant that produced it rather than after
// the file it sits in.
const (
	ghTokenSourceInline  = "oauth_token" //#nosec G101 -- the CLI's own word for where it keeps a token; the value read from the tool is compared against it and never stored.
	ghTokenSourceKeyring = "keyring"
)

// authenticationStatus translates the tool's verdict into this inventory's own.
// Anything not reported as authenticating is reported as not authenticating; a
// verdict that is absent altogether is not a verdict.
func authenticationStatus(state string) string {
	switch state {
	case ghStateAuthenticated:
		return model.CredentialAuthAuthenticated
	case "":
		return model.CredentialAuthUnknown
	default:
		return model.CredentialAuthNotAuthenticated
	}
}

// credentialStorage translates the tool's token source, returning "" when it names
// something unrecognised. An empty answer leaves what the configuration file
// established standing: the file is direct evidence, and a source spelled in a way
// this does not know is not evidence against it.
func credentialStorage(tokenSource string) string {
	switch tokenSource {
	case ghTokenSourceInline:
		return model.CredentialStorageInlineFile
	case ghTokenSourceKeyring:
		return model.CredentialStorageKeyring
	default:
		return ""
	}
}

func isStrippedTokenVar(name string) bool {
	for _, v := range ghTokenVars {
		if name == v {
			return true
		}
	}
	return false
}

// validEnvName bounds what may be interpolated into the probe command: a leading
// letter or underscore, then letters, digits and underscores. The names come from
// the catalog, so nothing reaching here is attacker-supplied today — and this check
// is what keeps that true when an entry is added later.
func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// resolveEnv reads the developer's values for the variables that can relocate a
// credential file. The second return says whether the read succeeded, which is not
// the same as finding nothing: a machine can genuinely have none set, but a probe
// that failed has established nothing, and reporting the default path as an
// authoritative absence would hide a relocated credential.
func (d *Detector) resolveEnv(ctx context.Context, paths userPaths) (userEnv, bool) {
	declared := EnvVars()
	names := make([]string, 0, len(declared))
	for _, name := range declared {
		if validEnvName(name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return userEnv{Values: map[string]string{}}, true
	}
	if d.exec.GOOS() == model.PlatformWindows {
		return readUserEnvironment(paths.Username, names)
	}
	return d.readShellEnvironment(ctx, paths, names)
}

// readShellEnvironment asks the developer's login shell for the values in one
// invocation. One is the whole design: the agent cannot read another account's
// session, so the values have to come from a shell started as that account, and one
// per variable would multiply the most expensive thing this phase does. Only the
// named variables are printed, so nothing else from that session — including any
// secret it exports — enters this process. Values arrive already expanded.
func (d *Detector) readShellEnvironment(ctx context.Context, paths userPaths, names []string) (userEnv, bool) {
	if paths.Username == "" {
		return userEnv{}, false
	}
	out, err := d.exec.RunAsUser(ctx, paths.Username, envProbeCommand(names))
	if err != nil {
		// The error text is discarded rather than reported: it carries the
		// shell's own diagnostics, which can quote the session it came from.
		return userEnv{}, false
	}
	return userEnv{Values: parseEnvProbeOutput(out, names)}, true
}

// envProbeCommand builds the one-shot print. The format string is reused for
// each pair, so one command prints every value.
func envProbeCommand(names []string) string {
	var b strings.Builder
	b.WriteString(`printf '%s=%s\n'`)
	for _, name := range names {
		b.WriteString(" ")
		b.WriteString(name)
		b.WriteString(` "$`)
		b.WriteString(name)
		b.WriteString(`"`)
	}
	return b.String()
}

// parseEnvProbeOutput keeps only the values that were asked for. A variable set
// to an empty value and a variable that is unset are indistinguishable here and
// mean the same thing to every caller: no relocation.
func parseEnvProbeOutput(out string, names []string) map[string]string {
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	values := make(map[string]string, len(names))
	for line := range strings.SplitSeq(out, "\n") {
		name, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok || !wanted[name] {
			continue
		}
		if value = strings.TrimSpace(value); value != "" {
			values[name] = value
		}
	}
	return values
}
