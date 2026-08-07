package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/safepath"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// canary is planted in every fixture that carries a value. No payload this phase
// produces may contain it: the inventory reports where credentials live, never
// the material itself.
const canary = "CANARY-b6f4c2e1-DO-NOT-EMIT"

// Fixture bodies shared across the tables below.
var (
	awsBody    = "[default]\naws_secret_access_key = " + canary + "\n"
	gitBody    = "https://octocat:" + canary + "@github.com\n"
	kubeBody   = "users:\n  - name: dev\n    user:\n      token: " + canary + "\n"
	ghBody     = "github.com:\n    oauth_token: " + canary + "\n    user: octocat\n"
	dockerBody = `{"auths":{"registry.example.com":{"auth":"` + canary + `"}}}`

	awsTree = map[string]string{".aws/credentials": awsBody}
	gitTree = map[string]string{".git-credentials": gitBody}
)

// fakeRunner stands in for the one child process this phase starts, so the fence
// around it is assertable without a CLI installed.
type fakeRunner struct {
	out   []byte
	err   error
	calls int
	last  ghRequest
}

func (f *fakeRunner) Run(_ context.Context, req ghRequest) ([]byte, error) {
	f.calls++
	f.last = req
	return f.out, f.err
}

// testHome returns a temporary directory with its symlinks resolved, which is the
// form the operating system's own record of an account would carry.
func testHome(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return resolved
}

// writeTree materialises slash-relative paths below home.
func writeTree(t *testing.T, home string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		path := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// newMock builds an executor for a machine whose console user owns home.
func newMock(t *testing.T, home string) *executor.Mock {
	t.Helper()
	m := executor.NewMock()
	m.SetUsername("octocat")
	m.SetHomeDir(home)
	m.SetGOOS(runtime.GOOS)
	m.SetPath("gh", filepath.Join(string(filepath.Separator), "usr", "local", "bin", "gh"))
	return m
}

// staticEnv stands in for a login session exporting these values, so a case is
// about the catalog rather than about whether a host can enter another session.
func staticEnv(values map[string]string) envProbe {
	return func(context.Context, userPaths) (userEnv, bool) { return userEnv{Values: values}, true }
}

// unreadableEnv stands in for a probe that failed. That is not the same as a
// machine with nothing set: nothing has been established either way.
func unreadableEnv() envProbe {
	return func(context.Context, userPaths) (userEnv, bool) { return userEnv{}, false }
}

// unexpandedEnv stands in for a probe that reached the account's stored values and
// found one it could not resolve — the Windows case, where a value may defer to
// another variable meaningful only inside that session.
func unexpandedEnv(names ...string) envProbe {
	unresolved := make(map[string]bool, len(names))
	for _, name := range names {
		unresolved[name] = true
	}
	return func(context.Context, userPaths) (userEnv, bool) {
		return userEnv{Values: map[string]string{}, Unresolved: unresolved}, true
	}
}

// detect scans home for a machine that exports nothing and whose CLI reports
// nothing.
func detect(t *testing.T, home string) *model.CredentialScanInfo {
	t.Helper()
	return New(newMock(t, home)).withRunner(&fakeRunner{}).withEnv(staticEnv(nil)).Detect(context.Background())
}

func findingFor(info *model.CredentialScanInfo, sourceID string) (model.CredentialFinding, bool) {
	for _, f := range info.Findings {
		if f.SourceID == sourceID {
			return f, true
		}
	}
	return model.CredentialFinding{}, false
}

func findingsFor(info *model.CredentialScanInfo, sourceID string) []model.CredentialFinding {
	var out []model.CredentialFinding
	for _, f := range info.Findings {
		if f.SourceID == sourceID {
			out = append(out, f)
		}
	}
	return out
}

// errorFor returns the error reported against sourceID, or the first error of the
// run when sourceID is empty.
func errorFor(info *model.CredentialScanInfo, sourceID string) (model.CredentialError, bool) {
	for _, e := range info.Errors {
		if sourceID == "" || e.SourceID == sourceID {
			return e, true
		}
	}
	return model.CredentialError{}, false
}

// detectCase is one scan of a home built for the case, stating what a single
// source must have reported. An expectation left at its zero value is not
// asserted, except scan_complete and truncated, which every case states.
type detectCase struct {
	name string
	// only runs the case on that platform alone; skip runs it everywhere else.
	only, skip string
	tree       map[string]string
	// outside is a second tree beyond the account's roots. Every env value is
	// slash-spelled and expands {home} and {out} to the two trees.
	outside map[string]string
	env     map[string]string
	// unresolved names variables the probe reached but could not expand; noEnv
	// stands in for a probe that failed outright; noUser for a machine whose
	// console account could not be resolved at all.
	unresolved            []string
	noEnv, noUser         bool
	guard, expired        bool
	source                string // what the expectations are about; empty means the run
	want                  observation
	location              string   // where the single finding must be
	locations             []string // one per live location where a source reports several
	noFinding, noError    bool
	reason                string // the error code the source must carry
	errors                int    // the exact number of errors the run may report
	incomplete, truncated bool
}

func runDetectCases(t *testing.T, cases []detectCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.only != "" && runtime.GOOS != tc.only {
				t.Skipf("the behaviour under test is %s-specific", tc.only)
			}
			if tc.skip != "" && runtime.GOOS == tc.skip {
				t.Skipf("not reachable on %s", tc.skip)
			}

			home := testHome(t)
			writeTree(t, home, tc.tree)
			outside := ""
			if len(tc.outside) > 0 {
				outside = testHome(t)
				writeTree(t, outside, tc.outside)
			}
			expand := strings.NewReplacer("{home}", home, "{out}", outside)
			env := map[string]string{}
			for name, value := range tc.env {
				env[name] = filepath.FromSlash(expand.Replace(value))
			}

			m := newMock(t, home)
			if tc.noUser {
				m = executor.NewMock()
				m.SetLoggedInUserError(os.ErrNotExist)
			}
			d := New(m).withRunner(&fakeRunner{}).withEnv(staticEnv(env))
			switch {
			case tc.noEnv:
				d = d.withEnv(unreadableEnv())
			case len(tc.unresolved) > 0:
				d = d.withEnv(unexpandedEnv(tc.unresolved...))
			}
			if tc.guard {
				d = d.WithSkipper(tcc.New(home))
			}
			ctx := context.Background()
			if tc.expired {
				spent, cancel := context.WithCancel(ctx)
				cancel()
				ctx = spent
			}
			info := d.Detect(ctx)

			if info == nil || info.Findings == nil || info.Errors == nil {
				t.Fatalf("both lists must always render rather than serialise as null: %+v", info)
			}
			// A guarded case names a location that was never created: a refusal
			// reported for a path that is not there proves the decision came
			// before any access, since probing first would have found silence.
			if tc.guard {
				for name, path := range env {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("%s names %s, which exists; the case proves nothing", name, path)
					}
				}
			}
			// A path with no root to strip carries the opaque token, so its
			// absence is the containment guarantee, stated once for every case.
			for _, f := range info.Findings {
				if strings.HasPrefix(f.Location, "$ABS/") || strings.HasPrefix(f.ResolvedLocation, "$ABS/") {
					t.Errorf("finding at %q resolved to %q, outside the account's tree", f.Location, f.ResolvedLocation)
				}
			}

			found := info.Findings
			if tc.source != "" {
				found = findingsFor(info, tc.source)
			}
			if tc.noFinding && len(found) != 0 {
				t.Errorf("findings = %+v, want none", found)
			}
			if tc.want != obsNone || tc.location != "" {
				if len(found) != 1 {
					t.Fatalf("findings = %+v, want exactly one; errors = %+v", found, info.Errors)
				}
				if tc.want != obsNone && (found[0].Count != tc.want.Count || found[0].Protection != tc.want.Protection) {
					t.Errorf("finding = %d/%q, want %d/%q", found[0].Count, found[0].Protection, tc.want.Count, tc.want.Protection)
				}
				if tc.location != "" && found[0].Location != tc.location {
					t.Errorf("location = %q, want %q", found[0].Location, tc.location)
				}
			}
			if len(tc.locations) > 0 {
				at := map[string]bool{}
				for _, f := range found {
					at[f.Location] = true
				}
				for _, want := range tc.locations {
					if !at[want] {
						t.Errorf("locations = %v, want %q among them", at, want)
					}
				}
				if len(found) != len(tc.locations) {
					t.Errorf("findings = %+v, want one per live location", found)
				}
			}

			reported, ok := errorFor(info, tc.source)
			if tc.reason != "" && (!ok || reported.ReasonCode != tc.reason) {
				t.Errorf("errors = %+v, want %q for %q", info.Errors, tc.reason, tc.source)
			}
			if tc.noError && ok {
				t.Errorf("errors = %+v, want nothing for %q", info.Errors, tc.source)
			}
			if tc.errors > 0 && len(info.Errors) != tc.errors {
				t.Errorf("errors = %+v, want exactly %d", info.Errors, tc.errors)
			}
			if info.ScanComplete == tc.incomplete {
				t.Errorf("scan_complete = %v with errors %+v", info.ScanComplete, info.Errors)
			}
			if info.Truncated != tc.truncated {
				t.Errorf("truncated = %v, want %v", info.Truncated, tc.truncated)
			}
		})
	}
}

// TestDetect_InventoriesTheKnownLocations is the end-to-end shape: a machine with
// a credential in each family produces one finding per source, located by its
// tokenised path and classified by how it is held.
func TestDetect_InventoriesTheKnownLocations(t *testing.T) {
	home := testHome(t)

	// Several of these files are spelled or rooted differently per platform, so
	// each fixture goes where this platform reads it.
	perPlatform := func(windows, unix string) string {
		if runtime.GOOS == model.PlatformWindows {
			return windows
		}
		return unix
	}
	netrc := perPlatform("_netrc", ".netrc")
	terraform := perPlatform("AppData/Roaming/terraform.d/credentials.tfrc.json", ".terraform.d/credentials.tfrc.json")
	gcloud := perPlatform("AppData/Roaming/gcloud/application_default_credentials.json", ".config/gcloud/application_default_credentials.json")

	writeTree(t, home, map[string]string{
		".aws/credentials":    awsBody,
		".aws/config":         "[profile work]\nsso_start_url = https://example.awsapps.com/start\n",
		".git-credentials":    gitBody,
		".gitconfig":          "[credential]\n\thelper = store\n",
		".npmrc":              "//registry.example.com/:_authToken=" + canary + "\n",
		".pypirc":             "[pypi]\nusername = __token__\npassword = " + canary + "\n",
		".docker/config.json": `{"auths":{"registry.example.com":{"auth":"` + canary + `"}}}`,
		".kube/config":        kubeBody,
		".vault-token":        canary,
		".cursor/mcp.json":    `{"mcpServers":{"demo":{"command":"npx","env":{"GITHUB_TOKEN":"` + canary + `"}}}}`,
		netrc:                 "machine example.com login octocat password " + canary + "\n",
		terraform:             `{"credentials":{"app.terraform.io":{"token":"` + canary + `"}}}`,
		gcloud:                `{"type":"authorized_user","client_secret":"` + canary + `","refresh_token":"` + canary + `"}`,
	})

	info := detect(t, home)

	if !info.ScanComplete || len(info.Errors) != 0 {
		t.Errorf("scan_complete = %v with errors %+v", info.ScanComplete, info.Errors)
	}
	if info.PayloadSchemaVersion != model.CurrentCredentialSchemaVersion || info.CatalogVersion != catalogVersion {
		t.Errorf("schema/catalog = %d/%q, want %d/%q", info.PayloadSchemaVersion, info.CatalogVersion, model.CurrentCredentialSchemaVersion, catalogVersion)
	}
	// The principal is stated on the run as well as on each finding, and a reader
	// that rejects a snapshot it cannot honour has only the run in front of it.
	if info.CollectionPrincipal != model.CredentialPrincipalAgentEffective {
		t.Errorf("collection_principal = %q, want %q", info.CollectionPrincipal, model.CredentialPrincipalAgentEffective)
	}
	if info.CollectedAt == 0 {
		t.Error("collected_at must be stamped")
	}

	want := map[string]struct {
		want     observation
		location string
	}{
		sourceAWSCredentials:       {obsPlain(1), "$HOME/.aws/credentials"},
		sourceAWSConfig:            {obsExt(1), "$HOME/.aws/config"},
		sourceGitCredentials:       {obsPlain(1), "$HOME/.git-credentials"},
		sourceGitconfigHelper:      {obsPlain(1), "$HOME/.gitconfig"},
		sourceNPMRC:                {obsPlain(1), "$HOME/.npmrc"},
		sourcePypirc:               {obsPlain(1), "$HOME/.pypirc"},
		sourceDockerConfig:         {obsPlain(1), "$HOME/.docker/config.json"},
		sourceKubeconfig:           {obsPlain(1), "$HOME/.kube/config"},
		sourceVaultToken:           {obsPlain(1), "$HOME/.vault-token"},
		sourceMCPConfig:            {obsPlain(1), "$HOME/.cursor/mcp.json"},
		sourceNetrc:                {obsPlain(1), "$HOME/" + netrc},
		sourceTerraformCredentials: {obsPlain(1), perPlatform("$APPDATA/terraform.d/credentials.tfrc.json", "$HOME/.terraform.d/credentials.tfrc.json")},
		sourceGCPADC:               {obsPlain(1), perPlatform("$APPDATA/gcloud/application_default_credentials.json", "$HOME/.config/gcloud/application_default_credentials.json")},
	}
	for id, expect := range want {
		got, ok := findingFor(info, id)
		if !ok {
			t.Errorf("%s: no finding", id)
			continue
		}
		if got.Count != expect.want.Count || got.Protection != expect.want.Protection || got.Location != expect.location {
			t.Errorf("%s: %d/%q at %q, want %d/%q at %q", id, got.Count, got.Protection, got.Location, expect.want.Count, expect.want.Protection, expect.location)
		}
		// Every read is made by the agent's own process, and a record silent on that
		// would mean two things on the same machine.
		if got.CollectionPrincipal != model.CredentialPrincipalAgentEffective {
			t.Errorf("%s: principal = %q, want %q", id, got.CollectionPrincipal, model.CredentialPrincipalAgentEffective)
		}
		if got.Size <= 0 || got.MTime <= 0 {
			t.Errorf("%s: size/mtime = %d/%d, want both stamped", id, got.Size, got.MTime)
		}
		if runtime.GOOS != model.PlatformWindows && got.Mode != "0600" {
			t.Errorf("%s: mode = %q, want %q", id, got.Mode, "0600")
		}
		if got.InGitRepo {
			t.Errorf("%s: reported inside a repository", id)
		}
	}
}

// TestDetect_NeverEmitsCredentialMaterial is the property the whole phase exists
// under. Every fixture carries the same distinctive value, so a parser leaking a
// value, a substring or a digest surfaces here whatever field it chose.
func TestDetect_NeverEmitsCredentialMaterial(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".aws/credentials":     "[default]\naws_access_key_id = AKIA" + canary + "\naws_secret_access_key = " + canary + "\n",
		".git-credentials":     gitBody,
		".npmrc":               "//registry.example.com/:_authToken=" + canary + "\n",
		".docker/config.json":  `{"auths":{"registry.example.com":{"auth":"` + canary + `"}}}`,
		".kube/config":         kubeBody,
		".vault-token":         canary,
		".cursor/mcp.json":     `{"mcpServers":{"demo":{"env":{"GITHUB_TOKEN":"` + canary + `"}}}}`,
		".ssh/id_ed25519":      string(opensshKey("none", "none", "ssh-ed25519", 512)),
		".config/gh/hosts.yml": ghBody,
	})

	runner := &fakeRunner{out: []byte(`{"hosts":{"github.com":[{"active":true,"login":"octocat","state":"success","scopes":"repo","tokenSource":"keyring"}]}}`)}
	info := New(newMock(t, home)).withRunner(runner).withEnv(staticEnv(nil)).Detect(context.Background())

	payload, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(payload), canary) {
		t.Errorf("payload carries credential material: %s", payload)
	}
	// The account name is counted, never stored — and neither is the login the
	// probe reported.
	if strings.Contains(string(payload), "octocat") {
		t.Errorf("payload names an account: %s", payload)
	}
	if len(info.Findings) == 0 {
		t.Fatal("the fixtures must produce findings for this to prove anything")
	}
}

// TestDetect_RoundTripsThroughTheWire holds the shape a reader depends on: the
// lists always render, and every finding lands back identical.
func TestDetect_RoundTripsThroughTheWire(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, awsTree)

	info := detect(t, home)
	payload, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{`"findings"`, `"errors"`, `"scan_complete"`, `"payload_schema_version"`, `"catalog_version"`, `"collected_at"`} {
		if !strings.Contains(string(payload), field) {
			t.Errorf("payload omits %s: %s", field, payload)
		}
	}

	var back model.CredentialScanInfo
	if err := json.Unmarshal(payload, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Findings) != len(info.Findings) {
		t.Fatalf("findings = %d, want %d", len(back.Findings), len(info.Findings))
	}
	if !reflect.DeepEqual(back.Findings[0], info.Findings[0]) {
		t.Errorf("finding changed across the wire:\n got %+v\nwant %+v", back.Findings[0], info.Findings[0])
	}
	if !back.ScanComplete {
		t.Error("scan_complete must survive the round trip")
	}
}

func TestDetect_Findings(t *testing.T) {
	runDetectCases(t, []detectCase{
		// A section with no findings asserts that nothing was found, which is not
		// the same as no section at all.
		{name: "a machine holding nothing", noFinding: true},
		// The three ways a source yields nothing without failing: the file is
		// absent, empty, or holds no credential and no reference to one. A path
		// name is not evidence, and a finding would assert one is in the file.
		{name: "an empty file", tree: map[string]string{".vault-token": ""}, source: sourceVaultToken, noFinding: true, noError: true},
		// The probed source is absent; the sibling that is present keeps the case
		// from passing vacuously.
		{name: "a file that is not there", tree: map[string]string{".aws/config": "[profile work]\nsso_session = corp\n"}, source: sourceAWSCredentials, noFinding: true, noError: true},
		{name: "files holding no credential", tree: map[string]string{".gitconfig": "[user]\n\tname = Octocat\n", ".npmrc": "registry=https://registry.example.com/\n"}, noFinding: true},
		// That file is the credential: nothing to interpret, so its contents never
		// reach a parser. The body is deliberately valid in no format here.
		{name: "a token file is classified without parsing", tree: map[string]string{".vault-token": "\x00\x01\x02" + canary}, source: sourceVaultToken, want: obsPlain(1)},
		// Both files are real and only one is read. Reporting the superseded one as
		// well would claim a credential is in use where the tool never looks.
		{
			name: "a relocated file is reported and the default is not", source: sourceAWSCredentials,
			tree:     map[string]string{"relocated/credentials": awsBody, ".aws/credentials": awsBody},
			env:      map[string]string{"AWS_SHARED_CREDENTIALS_FILE": "{home}/relocated/credentials"},
			want:     obsPlain(1),
			location: "$HOME/relocated/credentials",
		},
		// This tool reads every element of the list instead, and each element is a
		// separate file with its own mode and version-control status. The default is
		// not among them: setting the variable is what stops the tool reading it, so
		// a live file there is one nothing consults.
		{
			name: "all match reports every live location", source: sourceKubeconfig,
			tree:      map[string]string{"clusters/a": kubeBody, "clusters/b": "users:\n  - name: b\n    user:\n      tokenFile: /var/run/secrets/token\n", ".kube/config": kubeBody},
			env:       map[string]string{"KUBECONFIG": "{home}/clusters/a" + string(os.PathListSeparator) + "{home}/clusters/b"},
			locations: []string{"$HOME/clusters/a", "$HOME/clusters/b"},
		},
		// A list holding nothing but separators is set, so it is still the answer.
		// The tool splits any non-empty value and then ignores the empty elements
		// without restoring its default, which comes back only when the variable is
		// unset — so the file at the default is one it has stopped opening.
		{
			name: "a list naming nowhere reports nothing", source: sourceKubeconfig,
			tree:      map[string]string{".kube/config": kubeBody},
			env:       map[string]string{"KUBECONFIG": strings.Repeat(string(os.PathListSeparator), 3)},
			noFinding: true, noError: true,
		},
		// The relocation is the whole answer even when it names nowhere. A default
		// left standing here would be the one over-report a reader cannot detect:
		// a real file, at a real path, that its tool has stopped opening.
		{
			name: "a relocation naming nowhere reports nothing", source: sourceAWSCredentials,
			tree:      map[string]string{".aws/credentials": awsBody},
			env:       map[string]string{"AWS_SHARED_CREDENTIALS_FILE": "{home}/relocated/credentials"},
			noFinding: true, noError: true,
		},
		{
			name: "a relocated directory naming nowhere reports nothing", source: sourceDockerConfig,
			tree:      map[string]string{".docker/config.json": dockerBody},
			env:       map[string]string{"DOCKER_CONFIG": "{home}/relocated/docker"},
			noFinding: true, noError: true,
		},
		// This tool reads the first variable in preference to the second, so the
		// second's target is a file it has stopped reading even though it is there.
		{
			name: "the lower-precedence relocation is not consulted", source: sourceGitHubCLIHosts,
			tree:     map[string]string{"gh-dir/hosts.yml": ghBody, "cfg/gh/hosts.yml": ghBody},
			env:      map[string]string{"GH_CONFIG_DIR": "{home}/gh-dir", "XDG_CONFIG_HOME": "{home}/cfg"},
			want:     obsPlain(1),
			location: "$HOME/gh-dir/hosts.yml",
		},
		// The family that does honour the configuration variable. Its default is not
		// a separate place, so a path below it stays home-relative.
		{name: "a configuration directory at its default", tree: map[string]string{".config/git/credentials": gitBody}, source: sourceGitCredentials, want: obsPlain(1), location: "$HOME/.config/git/credentials"},
		{name: "a relocated configuration directory", tree: map[string]string{"cfg/git/credentials": gitBody}, env: map[string]string{"XDG_CONFIG_HOME": "{home}/cfg"}, source: sourceGitCredentials, want: obsPlain(1), location: "$XDG_CONFIG_HOME/git/credentials"},
		// The one catalog location below a directory this agent's policy declines as
		// a group while the platform serves it unprompted.
		//
		// This is the deliberate exception, and it is worth stating plainly because
		// the two halves look contradictory next to each other: a predefined
		// location under ~/Library is read despite the guard being active, while a
		// location a variable moved into a gated directory is refused — see
		// "a delegated path a variable moved is guarded too" below. The guard is
		// about traversal, not about the byte. Walking ~/Library is what trips the
		// services that fire a prompt, and each macOS release adds more of them, so
		// the walk declines the tree wholesale; opening one named file in a reviewed
		// set is not that walk. What makes the distinction safe is that the reviewed
		// set is fixed in this repository, whereas a rewritten path has its leading
		// directory chosen in the session being scanned.
		{
			name: "the application configuration directory", only: model.PlatformDarwin, guard: true,
			tree:     map[string]string{"Library/Application Support/Code/User/mcp.json": `{"servers":{"demo":{"env":{"API_KEY":"` + canary + `"}}}}`},
			source:   sourceMCPConfig,
			want:     obsPlain(1),
			location: "$HOME/Library/Application Support/Code/User/mcp.json",
		},
	})
}

// TestDetect_PredefinedMCPPathBypassesGuardButRelocatedPathDoesNot pins which
// resolver each half of the delegated source reaches, so the one deliberate
// exception to the consent guard cannot be widened or removed by accident: a
// predefined location under the declined `~/Library` tree is read, and a path a
// variable moved into a declined tree is refused untouched.
//
// This is a mechanical policy test, not a background-launch test. It runs in the
// test process against a temporary tree with a mock executor, so it exercises
// neither launchd attribution nor the real consent machinery, and the root flag it
// sets only selects the console-user path — no privilege is held and `tccd` is never
// consulted. Whether a scheduled run under a system account with no session to
// prompt in still returns is a claim about the platform, and only a LaunchAgent or
// LaunchDaemon run can settle it: that stays external validation until such a test
// exists. The deadline below is a hang guard for this process, nothing more.
func TestDetect_PredefinedMCPPathBypassesGuardButRelocatedPathDoesNot(t *testing.T) {
	if runtime.GOOS != model.PlatformDarwin {
		t.Skipf("the behaviour under test is %s-specific", model.PlatformDarwin)
	}
	home := testHome(t)
	writeTree(t, home, map[string]string{
		"Library/Application Support/Code/User/mcp.json": `{"servers":{"demo":{"env":{"API_KEY":"` + canary + `"}}}}`,
	})

	m := newMock(t, home)
	// The shape of a scheduled run: describing a console account that is not the
	// account this runs as. It selects the branch, it does not reproduce the context.
	m.SetIsRoot(true)
	relocated := filepath.Join(home, "Documents", "claude")
	d := New(m).withRunner(&fakeRunner{}).
		withEnv(staticEnv(map[string]string{"CLAUDE_CONFIG_DIR": relocated})).
		WithSkipper(tcc.New(home))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	info := d.Detect(ctx)
	if ctx.Err() != nil {
		t.Fatal("the phase did not return before the deadline")
	}

	// The refusal is for a path that was never created, so the decision came before
	// any access: probing first would have found silence, not a reason to refuse.
	if _, err := os.Stat(relocated); !os.IsNotExist(err) {
		t.Fatalf("%s exists; the case proves nothing", relocated)
	}
	e, ok := errorFor(info, sourceMCPConfig)
	if !ok || e.ReasonCode != model.CredentialReasonRefusedTCC {
		t.Errorf("errors = %+v, want %q for the relocated path", info.Errors, model.CredentialReasonRefusedTCC)
	}

	f, ok := findingFor(info, sourceMCPConfig)
	if !ok {
		t.Fatalf("the predefined location under the declined tree was not read: %+v", info)
	}
	if want := "$HOME/Library/Application Support/Code/User/mcp.json"; f.Location != want {
		t.Errorf("location = %q, want %q", f.Location, want)
	}
}

func TestDetect_Refusals(t *testing.T) {
	runDetectCases(t, []detectCase{
		// A home guessed from the agent's own environment would put the containment
		// boundary under the control of whatever the agent inherited.
		{name: "the console account could not be resolved", noUser: true, noFinding: true, reason: model.CredentialReasonSkippedNoUser, errors: 1, incomplete: true},
		// A relocation variable is developer-controlled input and the boundary comes
		// from the account record, so a value pointing elsewhere is declined.
		{
			name: "a location outside the user roots", source: sourceKubeconfig,
			outside: map[string]string{"elsewhere/config": kubeBody},
			env:     map[string]string{"KUBECONFIG": "{out}/elsewhere/config"},
			reason:  model.CredentialReasonRefusedOutsideRoots, noFinding: true, incomplete: true,
		},
		// The root set is deliberately not derived from the channel being bounded.
		// The file at the default location is real, so the source is still collected
		// and the refusal is visibly about the relocated path.
		{
			name: "a relocated configuration root outside the user roots", source: sourceGitCredentials,
			tree: gitTree, outside: map[string]string{"git/credentials": gitBody},
			env:        map[string]string{"XDG_CONFIG_HOME": "{out}"},
			reason:     model.CredentialReasonRefusedOutsideRoots,
			want:       obsPlain(1),
			location:   "$HOME/.git-credentials",
			incomplete: true,
		},
		// Traversing into a consent-gated directory is itself the consent event, and
		// a background process gets no prompt it can answer — it blocks, and no
		// deadline interrupts a blocked open.
		{
			name: "a consent-gated location is refused untouched", only: model.PlatformDarwin, guard: true,
			env:    map[string]string{"KUBECONFIG": "{home}/Documents/kubeconfig"},
			source: sourceKubeconfig, reason: model.CredentialReasonRefusedTCC, incomplete: true,
		},
		// The boundary between the two resolvers, and the one an attacker reaches. A
		// delegated location is a named file in a reviewed set; a location a variable
		// moved has its directory chosen in the scanned session, and a value naming a
		// gated tree would block past this phase's whole budget.
		{
			name: "a delegated path a variable moved is guarded too", only: model.PlatformDarwin, guard: true,
			env:    map[string]string{"CLAUDE_CONFIG_DIR": "{home}/Documents/claude"},
			source: sourceMCPConfig, reason: model.CredentialReasonRefusedTCC, incomplete: true,
		},
		// The default path is still worth probing, but not as an authoritative
		// absence while the setting that could have moved the file is unknown. A
		// source with no relocation variable is unaffected.
		{name: "an unreadable environment marks a relocatable source", noEnv: true, source: sourceAWSCredentials, reason: model.CredentialReasonLocationUnresolved, incomplete: true},
		{name: "an unreadable environment spares a fixed source", noEnv: true, source: sourcePypirc, noError: true, incomplete: true},
		// Why the probe reports unresolved names rather than one flag for the run:
		// the source reading the variable may be somewhere this run never looked,
		// while marking the rest would spend the snapshot's completeness on sources
		// read exactly as configured.
		{name: "an unresolved variable marks the source that reads it", tree: gitTree, unresolved: []string{"KUBECONFIG"}, source: sourceKubeconfig, reason: model.CredentialReasonLocationUnresolved, incomplete: true},
		{name: "an unresolved variable spares a source whose own variables resolved", tree: gitTree, unresolved: []string{"KUBECONFIG"}, source: sourceAWSCredentials, noError: true, incomplete: true},
		{name: "an unresolved variable does not stop the sources it does not govern", tree: gitTree, unresolved: []string{"KUBECONFIG"}, source: sourceGitCredentials, want: obsPlain(1), noError: true, incomplete: true},
		// A file read does not observe a context, so the budget check happens between
		// sources and the source it stops has to say why.
		{name: "the phase budget is spent", tree: awsTree, expired: true, noFinding: true, reason: model.CredentialReasonTimedOut, errors: 1, incomplete: true},
	})
}

func TestDetect_PartialReads(t *testing.T) {
	// Profiles holding no credential fill the whole readable span, so the prefix
	// parses cleanly and counts nothing — the case a truncation check placed after
	// the count never sees. The one credential-bearing profile sits past the cap.
	var padding strings.Builder
	for i := 0; padding.Len() < capConfig; i++ {
		fmt.Fprintf(&padding, "[profile p%d]\nregion = us-east-1\noutput = json\n", i)
	}
	// One entry, then padding past the cap for this source.
	cut := awsBody + strings.Repeat("# padding\n", (capConfig/10)+16)
	// A two-byte encoding parses to almost nothing rather than failing, so the only
	// answer that does not under-report is to report the encoding.
	utf16 := []byte{0xFF, 0xFE}
	for _, r := range awsBody {
		utf16 = append(utf16, byte(r), 0x00)
	}

	runDetectCases(t, []detectCase{
		// The under-report direction, the one that matters: a file whose credentials
		// sit past the cap parses to nothing, and calling that read-and-empty would
		// drop a real exposed credential while still claiming completeness.
		{
			name: "a capped parse is not a clean file", source: sourceAWSCredentials,
			tree:   map[string]string{".aws/credentials": padding.String() + "[real]\naws_secret_access_key = " + canary + "\n"},
			reason: model.CredentialReasonCapped, noFinding: true, incomplete: true, truncated: true,
		},
		// The snapshot replaces its predecessor wholesale, so it is the only thing
		// left to carry the fact that a cap bounded it.
		{name: "a truncated read marks the snapshot incomplete", tree: map[string]string{".aws/credentials": cut}, source: sourceAWSCredentials, want: obsPlain(1), incomplete: true, truncated: true},
		// The flag says a bound was hit somewhere, the entry says where. The finding
		// still stands: what it counted is a lower bound, not nothing.
		{name: "the byte cap reports which source it cut", tree: map[string]string{".aws/credentials": cut}, source: sourceAWSCredentials, want: obsPlain(1), reason: model.CredentialReasonCapped, incomplete: true, truncated: true},
		// This is what separates a file this build cannot read from a file holding
		// nothing.
		{name: "an unsupported encoding is reported, not dropped", tree: map[string]string{".aws/credentials": string(utf16)}, source: sourceAWSCredentials, noFinding: true, reason: model.CredentialReasonUnsupportedEncoding, incomplete: true},
	})
}

// TestDetect_ReadsRelocationFromTheLoginSession exercises the probe itself rather
// than a stand-in. These values live in a session the agent cannot enter, so they
// come from one shell started as that account, and its output picks the path.
func TestDetect_ReadsRelocationFromTheLoginSession(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("the values come from the account's registry hive on Windows")
	}
	home := testHome(t)
	relocated := filepath.Join(home, "relocated", "credentials")
	writeTree(t, home, map[string]string{"relocated/credentials": awsBody})

	m := newMock(t, home)
	m.SetCommand("AWS_SHARED_CREDENTIALS_FILE="+relocated+"\n", "", 0, "bash", "-c", envProbeCommand(EnvVars()))

	info := New(m).withRunner(&fakeRunner{}).Detect(context.Background())
	got, ok := findingFor(info, sourceAWSCredentials)
	if !ok {
		t.Fatalf("no finding; errors = %+v", info.Errors)
	}
	if got.Location != "$HOME/relocated/credentials" {
		t.Errorf("location = %q, want the relocated file", got.Location)
	}
	if !info.ScanComplete {
		t.Errorf("scan_complete = false with errors %+v", info.Errors)
	}
}

// TestDetect_KeyDirectoryReportsOnePerKey holds because two keys in one directory
// routinely differ in the only two things a customer acts on — file mode and
// repository status — and one row for the directory would have to pick one.
func TestDetect_KeyDirectoryReportsOnePerKey(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".ssh/id_ed25519":       string(opensshKey("none", "none", "ssh-ed25519", 0)),
		".ssh/id_rsa_protected": string(opensshKey("aes256-ctr", "bcrypt", "ssh-rsa", 0)),
		".ssh/id_sk":            string(opensshKey("none", "none", "sk-ssh-ed25519@openssh.com", 0)),
		".ssh/id_ed25519.pub":   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample octocat@example.com\n",
		".ssh/known_hosts":      "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample\n",
		".ssh/config":           "Host *\n  AddKeysToAgent yes\n",
		".ssh/authorized_keys":  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample octocat@example.com\n",
	})

	info := detect(t, home)
	got := findingsFor(info, sourceSSHPrivateKeys)
	if len(got) != 3 {
		t.Fatalf("findings = %d, want one per private key; got %+v", len(got), got)
	}
	states := map[string]string{}
	for _, f := range got {
		states[filepath.Base(f.Location)] = f.Protection
		if f.Count != 1 {
			t.Errorf("%s: count = %d, want 1", f.Location, f.Count)
		}
	}
	// A hardware-backed key holds a handle rather than the secret.
	want := map[string]string{
		"id_ed25519":       model.CredentialProtectionPlaintext,
		"id_rsa_protected": model.CredentialProtectionProtected,
		"id_sk":            model.CredentialProtectionProtected,
	}
	for name, expect := range want {
		if states[name] != expect {
			t.Errorf("%s: protection = %q, want %q", name, states[name], expect)
		}
	}
	if !info.ScanComplete {
		t.Errorf("scan_complete = false with errors %+v", info.Errors)
	}
}

// TestDetect_KeyLargerThanTheHeaderCapIsStillAWholeObservation holds because the cap
// for that source is the header, not the file. Every usable key exceeds it, so
// treating that as a partial read would leave the flag meaning nothing.
func TestDetect_KeyLargerThanTheHeaderCapIsStillAWholeObservation(t *testing.T) {
	home := testHome(t)
	key := opensshKey("aes256-ctr", "bcrypt", "ssh-rsa", 4096)
	if int64(len(key)) <= capKeyHeader {
		t.Fatalf("key of %d bytes does not exceed the cap; the test proves nothing", len(key))
	}
	writeTree(t, home, map[string]string{".ssh/id_rsa": string(key)})

	info := detect(t, home)
	got := findingsFor(info, sourceSSHPrivateKeys)
	if len(got) != 1 || got[0].Protection != model.CredentialProtectionProtected {
		t.Fatalf("findings = %+v, want one protected key", got)
	}
	if info.Truncated || !info.ScanComplete {
		t.Errorf("truncated = %v, scan_complete = %v; reading only the header is a whole result", info.Truncated, info.ScanComplete)
	}
	// The whole file is reported even though only its head was read.
	if got[0].Size != int64(len(key)) {
		t.Errorf("size = %d, want the file's own size %d", got[0].Size, len(key))
	}
}

// TestDetect_GitHubHostsCarryTheProbeReport covers the fenced child process: pointed
// at the developer's own configuration and run as that account, its report lands on
// the host entries of the finding describing the same file.
func TestDetect_GitHubHostsCarryTheProbeReport(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("the probe does not run on Windows under a service account")
	}
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".config/gh/hosts.yml": "github.com:\n    user: octocat\n    users:\n        octocat:\n            git_protocol: ssh\n",
	})

	runner := &fakeRunner{out: []byte(`{"hosts":{"github.com":[{"active":true,"login":"octocat","state":"success","scopes":"repo, read:org","tokenSource":"keyring"}]}}`)}
	info := New(newMock(t, home)).withRunner(runner).withEnv(staticEnv(nil)).Detect(context.Background())

	got, ok := findingFor(info, sourceGitHubCLIHosts)
	if !ok {
		t.Fatalf("no finding; errors = %+v", info.Errors)
	}
	if got.Protection != model.CredentialProtectionExternal {
		t.Errorf("protection = %q, want %q for a token held outside the file", got.Protection, model.CredentialProtectionExternal)
	}
	if len(got.GitHub) != 1 {
		t.Fatalf("hosts = %+v, want one per configured host", got.GitHub)
	}
	host := got.GitHub[0]
	if host.Host != "github.com" || !host.Configured || host.AccountCount != 1 {
		t.Errorf("host = %+v, want the configuration carried through", host)
	}
	if host.ScopeStatus != model.CredentialScopeObserved || len(host.Scopes) != 2 {
		t.Errorf("scope status = %q with scopes %v, want %q and the comma-separated string split", host.ScopeStatus, host.Scopes, model.CredentialScopeObserved)
	}
	if host.CredentialStorage != "keyring" {
		t.Errorf("storage = %q, want what the probe reported", host.CredentialStorage)
	}
	if runner.calls != 1 {
		t.Fatalf("probe ran %d times, want once", runner.calls)
	}
	// The child reads the developer's configuration, not the agent's.
	if runner.last.ConfigDir != filepath.Join(home, ".config", "gh") || runner.last.Username != "octocat" {
		t.Errorf("child given %q as %q, want the developer's directory and account", runner.last.ConfigDir, runner.last.Username)
	}
	// A finding is never withheld because the probe was unavailable, so it must be
	// reported as a status rather than as an error on the source.
	if _, ok := errorFor(info, sourceGitHubCLIStatus); ok {
		t.Errorf("errors = %+v, want the probe's outcome carried as a scope status", info.Errors)
	}
}

// TestDetect_GitHubHostsSurviveAProbeThatCannotRun holds because the
// configuration was read successfully; what the tool could or could not add to it
// does not change that.
func TestDetect_GitHubHostsSurviveAProbeThatCannotRun(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("the probe does not run on Windows under a service account")
	}
	home := testHome(t)
	writeTree(t, home, map[string]string{".config/gh/hosts.yml": ghBody})

	cases := map[string]*fakeRunner{
		"the child failed":             {err: os.ErrDeadlineExceeded},
		"the child produced no report": {out: []byte("unknown flag: --json\n")},
		"the child produced nothing":   {},
	}
	for name, runner := range cases {
		t.Run(name, func(t *testing.T) {
			info := New(newMock(t, home)).withRunner(runner).withEnv(staticEnv(nil)).Detect(context.Background())
			got, ok := findingFor(info, sourceGitHubCLIHosts)
			if !ok {
				t.Fatalf("no finding; errors = %+v", info.Errors)
			}
			if got.Protection != model.CredentialProtectionPlaintext {
				t.Errorf("protection = %q, want the on-disk reading kept", got.Protection)
			}
			if len(got.GitHub) != 1 {
				t.Fatalf("hosts = %+v, want one per configured host", got.GitHub)
			}
			host := got.GitHub[0]
			if host.ScopeStatus == model.CredentialScopeObserved || len(host.Scopes) != 0 {
				t.Errorf("scope status = %q with scopes %v, want an outcome other than observed and no scopes", host.ScopeStatus, host.Scopes)
			}
			// The inline token is on-disk evidence and survives regardless.
			if host.CredentialStorage != model.CredentialStorageInlineFile {
				t.Errorf("storage = %q, want the inline token reported", host.CredentialStorage)
			}
			if _, ok := errorFor(info, sourceGitHubCLIHosts); ok {
				t.Errorf("errors = %+v, want nothing on a source that was read", info.Errors)
			}
		})
	}
}

// TestDetect_ProbeDoesNotRunAsAServiceAccountOnWindows holds because privilege
// dropping there ignores the requested account: a child started that way would
// report the service identity's credential state as the developer's.
func TestDetect_ProbeDoesNotRunAsAServiceAccountOnWindows(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{"AppData/Roaming/GitHub CLI/hosts.yml": ghBody})

	m := newMock(t, home)
	m.SetGOOS(model.PlatformWindows)
	m.SetIsRoot(true)

	runner := &fakeRunner{out: []byte(`{"hosts":{"github.com":[{"active":true,"state":"success","scopes":"repo"}]}}`)}
	info := New(m).withRunner(runner).withEnv(staticEnv(nil)).Detect(context.Background())

	if runner.calls != 0 {
		t.Errorf("probe ran %d times, want never", runner.calls)
	}
	got, ok := findingFor(info, sourceGitHubCLIHosts)
	if !ok {
		t.Fatalf("no finding; errors = %+v", info.Errors)
	}
	if got.Mode != "" {
		t.Errorf("mode = %q, want it omitted on Windows", got.Mode)
	}
	if len(got.GitHub) != 1 || got.GitHub[0].ScopeStatus != model.CredentialScopeUnavailable {
		t.Errorf("hosts = %+v, want the outcome reported as unavailable", got.GitHub)
	}
}

// TestDetect_ProbeFollowsTheRelocatedConfiguration holds because the child is
// pointed at a directory: at the relocated one, since that is the configuration the
// tool reads, and at none at all when the relocation leaves the account's tree.
//
// The uncontained half is the one worth stating. The default directory is not a
// fallback here even though a configuration is sitting in it: the variable is set,
// so the tool has stopped reading that file, and reporting it would name the wrong
// identity while asking the child about a directory the tool is not using. The
// refusal is the whole answer, and it costs the run its completeness.
func TestDetect_ProbeFollowsTheRelocatedConfiguration(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("the probe does not run on Windows under a service account")
	}
	status := []byte(`{"hosts":{"github.com":[{"active":true,"state":"success","scopes":"repo"}]}}`)

	t.Run("outside the roots", func(t *testing.T) {
		home := testHome(t)
		elsewhere := testHome(t)
		writeTree(t, elsewhere, map[string]string{"gh/hosts.yml": ghBody})
		// The default holds a configuration of its own, so the case fails loudly if
		// the uncontained relocation ever falls back to it.
		writeTree(t, home, map[string]string{".config/gh/hosts.yml": "github.com:\n    user: octocat\n"})

		env := staticEnv(map[string]string{"GH_CONFIG_DIR": filepath.Join(elsewhere, "gh")})
		runner := &fakeRunner{out: status}
		info := New(newMock(t, home)).withRunner(runner).withEnv(env).Detect(context.Background())

		if got, ok := errorFor(info, sourceGitHubCLIHosts); !ok || got.ReasonCode != model.CredentialReasonRefusedOutsideRoots {
			t.Errorf("errors = %+v, want %q", info.Errors, model.CredentialReasonRefusedOutsideRoots)
		}
		if f, ok := findingFor(info, sourceGitHubCLIHosts); ok {
			t.Errorf("finding at %q: the default is not a fallback once the variable is set", f.Location)
		}
		if runner.calls != 0 {
			t.Errorf("probe ran %d times against %q, want never", runner.calls, runner.last.ConfigDir)
		}
		if info.ScanComplete {
			t.Error("a refused source leaves the run incomplete")
		}
	})

	// The positive control: without it the assertion above passes even for a probe
	// that never runs at all.
	t.Run("inside the roots", func(t *testing.T) {
		home := testHome(t)
		writeTree(t, home, map[string]string{"gh-dir/hosts.yml": ghBody})

		env := staticEnv(map[string]string{"GH_CONFIG_DIR": filepath.Join(home, "gh-dir")})
		runner := &fakeRunner{out: status}
		info := New(newMock(t, home)).withRunner(runner).withEnv(env).Detect(context.Background())

		f, ok := findingFor(info, sourceGitHubCLIHosts)
		if !ok {
			t.Fatalf("no finding; errors = %+v", info.Errors)
		}
		if want := "$HOME/gh-dir/hosts.yml"; f.Location != want {
			t.Errorf("location = %q, want %q", f.Location, want)
		}
		if runner.calls != 1 {
			t.Errorf("probe ran %d times, want once for the relocated configuration", runner.calls)
		}
		if runner.last.ConfigDir != filepath.Join(home, "gh-dir") {
			t.Errorf("configuration directory = %q, want the relocated one", runner.last.ConfigDir)
		}
	})
}

// TestDetect_WritesNothingToStandardError holds because enterprise runs tee this
// process's standard error into a buffer that ships with the telemetry, unredacted:
// a parser naming the file it choked on would put a credential location there.
func TestDetect_WritesNothingToStandardError(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".aws/credentials":    awsBody,
		".docker/config.json": `{"auths":{"registry.example.com":{"auth":"` + canary,
		".kube/config":        "users: [ unterminated " + canary + "\n",
		".npmrc":              "//registry.example.com/:_authToken=" + canary + "\n",
		".ssh/id_ed25519":     string(opensshKey("none", "none", "ssh-ed25519", 0)),
		".cursor/mcp.json":    `{"mcpServers":{"demo":{"env":{"API_KEY":"` + canary,
	})

	captured := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(captured)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	original := os.Stderr
	os.Stderr = f
	info := detect(t, home)
	os.Stderr = original
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	written, err := os.ReadFile(captured)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(written) != 0 {
		t.Errorf("the phase wrote to standard error: %q", written)
	}
	if len(info.Findings) == 0 && len(info.Errors) == 0 {
		t.Fatal("the fixtures must produce a result for this to prove anything")
	}
}

// TestDetect_ReportsAFindingInsideARepository is the field a customer acts on first,
// evaluated against the resolved location because a dotfiles symlink farm is exactly
// the layout that version-controls a credential while the probed path looks innocent.
func TestDetect_ReportsAFindingInsideARepository(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{"dotfiles/aws/credentials": awsBody})
	for _, dir := range []string{filepath.Join(home, "dotfiles", ".git"), filepath.Join(home, ".aws")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	link := filepath.Join(home, ".aws", "credentials")
	if err := os.Symlink(filepath.Join(home, "dotfiles", "aws", "credentials"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	info := detect(t, home)
	got, ok := findingFor(info, sourceAWSCredentials)
	if !ok {
		t.Fatalf("no finding; errors = %+v", info.Errors)
	}
	if got.Location != "$HOME/.aws/credentials" || got.ResolvedLocation != "$HOME/dotfiles/aws/credentials" {
		t.Errorf("location = %q resolving to %q, want the path as configured and where the bytes were", got.Location, got.ResolvedLocation)
	}
	if !got.InGitRepo {
		t.Error("a credential resolving into a working tree must be reported as such")
	}
}

// TestRefusalReason_CarriesTheResolverVocabularyUnchanged is what makes the mapping
// an identity rather than a translation. The resolver's own reason codes and the
// wire's are the same strings, which is why a refusal travels straight through — and
// it is exactly the agreement that breaks silently, since a renamed constant on
// either side keeps compiling and starts emitting a code no reader has seen.
func TestRefusalReason_CarriesTheResolverVocabularyUnchanged(t *testing.T) {
	pairs := map[string]string{
		safepath.ReasonOutsideRoots: model.CredentialReasonRefusedOutsideRoots,
		safepath.ReasonDenied:       model.CredentialReasonPermissionDenied,
		safepath.ReasonUnresolved:   model.CredentialReasonLocationUnresolved,
	}
	for resolverReason, wireReason := range pairs {
		if resolverReason != wireReason {
			t.Errorf("resolver reports %q where the wire says %q", resolverReason, wireReason)
		}
		if got := refusalReason(&safepath.Refusal{Reason: resolverReason}); got != wireReason {
			t.Errorf("refusalReason(%q) = %q, want %q", resolverReason, got, wireReason)
		}
	}
	// The consent refusal comes from the guard this package installs, so it is a
	// wire code from the start.
	if got := refusalReason(&safepath.Refusal{Reason: model.CredentialReasonRefusedTCC}); got != model.CredentialReasonRefusedTCC {
		t.Errorf("refusalReason of a guard refusal = %q, want %q", got, model.CredentialReasonRefusedTCC)
	}
	// Anything that is not a refusal at all still has to land inside the closed set
	// rather than travelling as a library's own message.
	if got := refusalReason(errors.New("read /home/octocat/.aws/credentials: some library detail")); got != model.CredentialReasonLocationUnresolved {
		t.Errorf("an unrecognised error mapped to %q, want %q", got, model.CredentialReasonLocationUnresolved)
	}
}
