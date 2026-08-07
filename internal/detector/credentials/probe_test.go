package credentials

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// TestGHStatusArgs_NeverAsksForTheToken is the first half of the fence: the command
// has a flag that prints the token itself, and the whole design is that the child
// does the keystore access while the token stays with the tool that owns it.
func TestGHStatusArgs_NeverAsksForTheToken(t *testing.T) {
	args := ghStatusArgs
	for _, arg := range args {
		if strings.Contains(arg, "show-token") || strings.Contains(arg, "token") {
			t.Fatalf("argv %v asks for the token", args)
		}
	}
	if !slices.Contains(args, "--json") || !slices.Contains(args, "hosts") {
		t.Errorf("argv = %v, want the host report requested as a document", args)
	}
}

// TestGHChildEnv_StripsEveryTokenVariable is the second half. The agent's own
// service environment may carry a token, and the enterprise pair is a separate
// precedence path — either left in place has the child answer for the wrong one.
func TestGHChildEnv_StripsEveryTokenVariable(t *testing.T) {
	env := ghChildEnv("/home/octocat/.config/gh")

	for _, name := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"} {
		if !slices.Contains(ghTokenVars, name) {
			t.Errorf("%s is not in the strip list", name)
		}
		removed := false
		for i := 0; i+1 < len(env); i++ {
			if env[i] == "-u" && env[i+1] == name {
				removed = true
				break
			}
		}
		if !removed {
			t.Errorf("child environment does not unset %s: %v", name, env)
		}
	}
	if got := env[len(env)-1]; got != "GH_CONFIG_DIR=/home/octocat/.config/gh" {
		t.Errorf("last assignment = %q, want the developer's configuration directory", got)
	}
}

// TestStrippedEnv_DropsATokenFromThisProcess covers the non-privilege-dropping
// form, where the environment is handed to the child directly.
func TestStrippedEnv_DropsATokenFromThisProcess(t *testing.T) {
	t.Setenv("GH_TOKEN", "value")
	t.Setenv("GITHUB_ENTERPRISE_TOKEN", "value")
	t.Setenv("STEPSEC_CREDENTIALS_PROBE_MARKER", "kept")

	var sawMarker bool
	for _, entry := range strippedEnv() {
		name, _, _ := strings.Cut(entry, "=")
		if isStrippedTokenVar(name) {
			t.Errorf("%s survived the strip", name)
		}
		if name == "STEPSEC_CREDENTIALS_PROBE_MARKER" {
			sawMarker = true
		}
	}
	if !sawMarker {
		t.Error("the strip must remove the token variables and keep everything else")
	}
	// The process environment itself is untouched — the strip builds a copy.
	if os.Getenv("GH_TOKEN") == "" {
		t.Error("strippedEnv must not modify this process's environment")
	}
}

func TestBoundedBuffer_KeepsAtMostItsCap(t *testing.T) {
	b := &boundedBuffer{max: 8}
	n, err := b.Write([]byte("0123456789"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	// The full length is reported so the child is never signalled to stop writing;
	// the bound is on what is kept, not on what it may produce.
	if n != 10 {
		t.Errorf("n = %d, want the full length reported", n)
	}
	if string(b.data) != "01234567" {
		t.Errorf("data = %q, want the first 8 bytes", b.data)
	}
	if _, err := b.Write([]byte("more")); err != nil {
		t.Fatalf("write past the cap: %v", err)
	}
	if len(b.data) != 8 {
		t.Errorf("data grew past the cap to %d bytes", len(b.data))
	}
}

func TestParseGHStatus(t *testing.T) {
	t.Run("account list picks the active account", func(t *testing.T) {
		doc := `{"hosts":{"github.com":[
			{"active":false,"login":"hubot","state":"success","scopes":"repo","tokenSource":"keyring"},
			{"active":true,"login":"octocat","state":"success","scopes":"repo, read:org","tokenSource":"keyring"}
		]}}`
		byHost, ok := parseGHStatus([]byte(doc))
		if !ok {
			t.Fatal("document must parse")
		}
		account := byHost["github.com"]
		if !account.Active || account.Scopes != "repo, read:org" {
			t.Errorf("account = %+v, want the active one", account)
		}
	})

	t.Run("single account object", func(t *testing.T) {
		// The value shape has varied across releases, so both are accepted rather
		// than discarding a report the machine did produce.
		doc := `{"hosts":{"github.com":{"active":true,"state":"success","scopes":"repo","tokenSource":"keyring"}}}`
		byHost, ok := parseGHStatus([]byte(doc))
		if !ok {
			t.Fatal("document must parse")
		}
		if byHost["github.com"].State != "success" {
			t.Errorf("account = %+v, want the single object decoded", byHost["github.com"])
		}
	})

	t.Run("no active account falls back to the first", func(t *testing.T) {
		doc := `{"hosts":{"github.com":[{"active":false,"state":"error"}]}}`
		byHost, _ := parseGHStatus([]byte(doc))
		if byHost["github.com"].State != "error" {
			t.Errorf("account = %+v, want the first entry", byHost["github.com"])
		}
	})

	t.Run("a document that is not the report", func(t *testing.T) {
		if _, ok := parseGHStatus([]byte("unknown flag: --json\n")); ok {
			t.Error("output that is not the document must not parse")
		}
	})

	t.Run("empty output", func(t *testing.T) {
		if _, ok := parseGHStatus(nil); ok {
			t.Error("no output must not parse")
		}
	})
}

func TestParseGHScopes(t *testing.T) {
	// Scopes arrive as one comma-separated string rather than a list.
	got := parseGHScopes("repo, read:org , gist")
	want := []string{"repo", "read:org", "gist"}
	if !slices.Equal(got, want) {
		t.Errorf("scopes = %v, want %v", got, want)
	}
	if parseGHScopes("") != nil {
		t.Error("an empty string must yield no scopes")
	}
	if parseGHScopes(" , ") != nil {
		t.Error("separators alone must yield no scopes")
	}
}

func TestGitHubHostReports(t *testing.T) {
	configs := []githubHostConfig{{Host: "github.com", AccountCount: 1, InlineToken: true}}

	t.Run("the probe said nothing about this host", func(t *testing.T) {
		reports := githubHostReports(configs, nil, model.CredentialScopeUnavailable)
		if len(reports) != 1 {
			t.Fatalf("reports = %+v, want one per configured host", reports)
		}
		got := reports[0]
		if !got.Configured || got.Host != "github.com" || got.AccountCount != 1 {
			t.Errorf("report = %+v, want the configuration carried through", got)
		}
		if got.CredentialStorage != model.CredentialStorageInlineFile {
			t.Errorf("storage = %q, want the inline token reported", got.CredentialStorage)
		}
		// Both enumerated fields carry a value even here, so an absent one never has
		// to be read as a verdict.
		if got.AuthenticationStatus != model.CredentialAuthUnknown {
			t.Errorf("authentication status = %q, want %q", got.AuthenticationStatus, model.CredentialAuthUnknown)
		}
		// Scopes and their status always travel together, so an empty list is never
		// left to be read as a token with no permissions.
		if got.ScopeStatus != model.CredentialScopeUnavailable || len(got.Scopes) != 0 {
			t.Errorf("scopes = %v/%q, want none with a status", got.Scopes, got.ScopeStatus)
		}
	})

	t.Run("scopes observed", func(t *testing.T) {
		byHost := map[string]ghAccount{"github.com": {Active: true, State: "success", Scopes: "repo,read:org", TokenSource: "keyring"}}
		got := githubHostReports(configs, byHost, model.CredentialScopeUnavailable)[0]
		if got.ScopeStatus != model.CredentialScopeObserved {
			t.Errorf("status = %q, want %q", got.ScopeStatus, model.CredentialScopeObserved)
		}
		if !slices.Equal(got.Scopes, []string{"repo", "read:org"}) {
			t.Errorf("scopes = %v", got.Scopes)
		}
		if got.CredentialStorage != model.CredentialStorageKeyring {
			t.Errorf("storage = %q, want what the probe reported", got.CredentialStorage)
		}
		if got.AuthenticationStatus != model.CredentialAuthAuthenticated {
			t.Errorf("authentication status = %q", got.AuthenticationStatus)
		}
	})

	t.Run("authenticated with no scopes to report", func(t *testing.T) {
		// A fine-grained token's permissions are not expressible as scopes, so the
		// service reports none: an absence of information, not of permissions.
		byHost := map[string]ghAccount{"github.com": {Active: true, State: "success", Scopes: "", TokenSource: "keyring"}}
		got := githubHostReports(configs, byHost, model.CredentialScopeUnavailable)[0]
		if got.ScopeStatus != model.CredentialScopeNotReportedByGitHub {
			t.Errorf("status = %q, want %q", got.ScopeStatus, model.CredentialScopeNotReportedByGitHub)
		}
		if len(got.Scopes) != 0 {
			t.Errorf("scopes = %v, want none", got.Scopes)
		}
	})

	t.Run("the command succeeded and authentication did not", func(t *testing.T) {
		// The command exits zero even when authentication failed, so success is
		// judged on what the document says.
		byHost := map[string]ghAccount{"github.com": {Active: true, State: "error", Scopes: "repo", TokenSource: "keyring"}}
		got := githubHostReports(configs, byHost, model.CredentialScopeUnavailable)[0]
		if got.ScopeStatus != model.CredentialScopeUnavailable {
			t.Errorf("status = %q, want %q", got.ScopeStatus, model.CredentialScopeUnavailable)
		}
		if len(got.Scopes) != 0 {
			t.Errorf("scopes = %v, want none for a failed authentication", got.Scopes)
		}
		if got.AuthenticationStatus != model.CredentialAuthNotAuthenticated {
			t.Errorf("authentication status = %q, want a failed authentication", got.AuthenticationStatus)
		}
	})

	t.Run("a token source naming a stripped variable is discarded", func(t *testing.T) {
		// The child was answering for whatever identity the agent's environment
		// carries, so the report is about the wrong account and none of it is kept.
		for _, name := range ghTokenVars {
			byHost := map[string]ghAccount{"github.com": {Active: true, State: "success", Scopes: "repo", TokenSource: name}}
			got := githubHostReports(configs, byHost, model.CredentialScopeObserved)[0]
			if got.ScopeStatus != model.CredentialScopeUnavailable {
				t.Errorf("%s: status = %q, want %q", name, got.ScopeStatus, model.CredentialScopeUnavailable)
			}
			if len(got.Scopes) != 0 {
				t.Errorf("%s: scopes = %v, want none", name, got.Scopes)
			}
			if got.CredentialStorage == name {
				t.Errorf("%s: storage names the stripped variable", name)
			}
		}
	})

	t.Run("a host the probe reported but the file did not is not invented", func(t *testing.T) {
		byHost := map[string]ghAccount{"ghe.example.com": {Active: true, State: "success", Scopes: "repo"}}
		reports := githubHostReports(configs, byHost, model.CredentialScopeUnavailable)
		if len(reports) != 1 || reports[0].Host != "github.com" {
			t.Errorf("reports = %+v, want one entry per configured host", reports)
		}
	})
}

func TestValidEnvName(t *testing.T) {
	tests := map[string]bool{
		"XDG_CONFIG_HOME":   true,
		"KUBECONFIG":        true,
		"_LEADING":          true,
		"WITH1DIGIT":        true,
		"1LEADING":          false,
		"":                  false,
		"HAS-DASH":          false,
		"HAS SPACE":         false,
		"HAS;SEMICOLON":     false,
		"HAS$DOLLAR":        false,
		"HAS`BACKTICK":      false,
		"HAS\nNEWLINE":      false,
		"HAS(PAREN)":        false,
		"HAS/SLASH":         false,
		"$(id)":             false,
		"NAME\"WITH\"QUOTE": false,
	}
	for name, want := range tests {
		if got := validEnvName(name); got != want {
			t.Errorf("validEnvName(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestEnvProbeCommand_AsksOnlyForTheNamedVariables holds the reason this is one
// invocation printing a fixed list rather than a dump: nothing else from that
// session, including any secret it exports, enters this process.
func TestEnvProbeCommand_AsksOnlyForTheNamedVariables(t *testing.T) {
	got := envProbeCommand([]string{"XDG_CONFIG_HOME", "KUBECONFIG"})
	want := `printf '%s=%s\n' XDG_CONFIG_HOME "$XDG_CONFIG_HOME" KUBECONFIG "$KUBECONFIG"`
	if got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
	for _, forbidden := range []string{"env", "set", "export", "printenv"} {
		if strings.Contains(got, forbidden+" ") {
			t.Errorf("command dumps the environment: %q", got)
		}
	}
}

func TestParseEnvProbeOutput(t *testing.T) {
	names := []string{"XDG_CONFIG_HOME", "KUBECONFIG"}
	out := "XDG_CONFIG_HOME=/opt/config\r\n" +
		"KUBECONFIG=\n" +
		"GH_TOKEN=a-token-this-probe-never-asked-for\n" +
		"not a pair\n"

	got := parseEnvProbeOutput(out, names)
	if got["XDG_CONFIG_HOME"] != "/opt/config" {
		t.Errorf("value = %q, want the carriage return trimmed", got["XDG_CONFIG_HOME"])
	}
	// A variable set to an empty value and one that is unset mean the same thing to
	// every caller: no relocation.
	if _, ok := got["KUBECONFIG"]; ok {
		t.Error("an empty value must not be recorded")
	}
	// Only what was asked for is kept, so a shell that prints more cannot smuggle a
	// value into the map.
	if _, ok := got["GH_TOKEN"]; ok {
		t.Error("a variable that was not asked for must not be kept")
	}
	if len(got) != 1 {
		t.Errorf("values = %v, want one entry", got)
	}
}

func TestParseEnvProbeOutput_ValueContainingASeparator(t *testing.T) {
	got := parseEnvProbeOutput("KUBECONFIG=/a/config=1:/b/config\n", []string{"KUBECONFIG"})
	if got["KUBECONFIG"] != "/a/config=1:/b/config" {
		t.Errorf("value = %q, want everything after the first separator", got["KUBECONFIG"])
	}
}
