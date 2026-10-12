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
	"sync"
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
	gitBody    = "https://a-user:" + canary + "@example.invalid\n"
	kubeBody   = "users:\n  - name: dev\n    user:\n      token: " + canary + "\n"
	ghBody     = "example.invalid:\n    oauth_token: " + canary + "\n    user: a-user\n"
	dockerBody = `{"auths":{"registry.example.invalid":{"auth":"` + canary + `"}}}`

	awsTree = map[string]string{".aws/credentials": awsBody}
	gitTree = map[string]string{".git-credentials": gitBody}
)

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
	m.SetUsername("a-user")
	m.SetHomeDir(home)
	m.SetGOOS(runtime.GOOS)
	m.SetPath("gh", filepath.Join(string(filepath.Separator), "usr", "local", "bin", "gh"))
	return m
}

// recordingExec notes every program this phase asks for or starts, so "reads
// files and nothing else" is assertable rather than asserted by reading the code.
type recordingExec struct {
	executor.Executor
	mu  sync.Mutex
	ran []string
}

func (r *recordingExec) note(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ran = append(r.ran, filepath.Base(name))
}

func (r *recordingExec) started() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ran...)
}

func (r *recordingExec) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	r.note(name)
	return r.Executor.Run(ctx, name, args...)
}

func (r *recordingExec) RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (string, string, int, error) {
	r.note(name)
	return r.Executor.RunWithTimeout(ctx, timeout, name, args...)
}

func (r *recordingExec) RunInDir(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) (string, string, int, error) {
	r.note(name)
	return r.Executor.RunInDir(ctx, dir, timeout, name, args...)
}

func (r *recordingExec) RunAsUser(ctx context.Context, username, command string) (string, error) {
	r.note(command)
	return r.Executor.RunAsUser(ctx, username, command)
}

func (r *recordingExec) LookPath(name string) (string, error) {
	r.note("lookpath:" + name)
	return r.Executor.LookPath(name)
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

// detect scans home for a machine that exports nothing.
func detect(t *testing.T, home string) *model.CredentialScanInfo {
	t.Helper()
	return New(newMock(t, home)).withEnv(staticEnv(nil)).Detect(context.Background())
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

// hasScanError reports whether one source carries one reason code.
func hasScanError(errs []model.CredentialError, sourceID, reason string) bool {
	return countScanErrors(errs, sourceID, reason) > 0
}

func countScanErrors(errs []model.CredentialError, sourceID, reason string) (n int) {
	for _, e := range errs {
		if e.SourceID == sourceID && e.ReasonCode == reason {
			n++
		}
	}
	return n
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

			var m executor.Executor = newMock(t, home)
			if tc.noUser {
				mock := executor.NewMock()
				mock.SetLoggedInUserError(os.ErrNotExist)
				m = mock
			}
			d := New(m).withEnv(staticEnv(env))
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
			if tc.guard && tc.noFinding {
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
			// Every finding is material, so there is no third protection state a
			// reader could be handed.
			for _, f := range info.Findings {
				if f.Protection != model.CredentialProtectionPlaintext && f.Protection != model.CredentialProtectionProtected {
					t.Errorf("finding %+v carries protection %q", f, f.Protection)
				}
				if f.Count <= 0 {
					t.Errorf("finding %+v counts no credential", f)
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
// credential material in each family produces one finding per source, located by
// its tokenised path and classified by how it is held.
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
	ghHosts := perPlatform("AppData/Roaming/GitHub CLI/hosts.yml", ".config/gh/hosts.yml")
	insomnia := insomniaRel("insomnia.Request.db")

	writeTree(t, home, map[string]string{
		".aws/credentials":    awsBody,
		".aws/config":         "[profile work]\naws_session_token = " + canary + "\n",
		".git-credentials":    gitBody,
		".npmrc":              "//registry.example.invalid/:_authToken=" + canary + "\n",
		".pypirc":             "[pypi]\nusername = __token__\npassword = " + canary + "\n",
		".docker/config.json": dockerBody,
		".kube/config":        kubeBody,
		".vault-token":        canary,
		".ssh/id_ed25519":     string(opensshKey("none", "none", "ssh-ed25519")),
		netrc:                 "machine example.invalid login a-user password " + canary + "\n",
		terraform:             `{"credentials":{"app.terraform.io":{"token":"` + canary + `"}}}`,
		gcloud:                `{"type":"authorized_user","client_secret":"` + canary + `","refresh_token":"` + canary + `"}`,
		ghHosts:               ghBody,
		insomnia:              insomniaBody,
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
		sourceAWSConfig:            {obsPlain(1), "$HOME/.aws/config"},
		sourceGitCredentials:       {obsPlain(1), "$HOME/.git-credentials"},
		sourceNPMRC:                {obsPlain(1), "$HOME/.npmrc"},
		sourcePypirc:               {obsPlain(1), "$HOME/.pypirc"},
		sourceDockerConfig:         {obsPlain(1), "$HOME/.docker/config.json"},
		sourceKubeconfig:           {obsPlain(1), "$HOME/.kube/config"},
		sourceVaultToken:           {obsPlain(1), "$HOME/.vault-token"},
		sourceSSHPrivateKeys:       {obsPlain(1), "$HOME/.ssh/id_ed25519"},
		sourceNetrc:                {obsPlain(1), "$HOME/" + netrc},
		sourceGitHubCLIHosts:       {obsPlain(1), perPlatform("$APPDATA/GitHub CLI/hosts.yml", "$HOME/.config/gh/hosts.yml")},
		sourceTerraformCredentials: {obsPlain(1), perPlatform("$APPDATA/terraform.d/credentials.tfrc.json", "$HOME/.terraform.d/credentials.tfrc.json")},
		sourceGCPADC:               {obsPlain(1), perPlatform("$APPDATA/gcloud/application_default_credentials.json", "$HOME/.config/gcloud/application_default_credentials.json")},
		sourceInsomnia:             {obsPlain(2), insomniaLocation("insomnia.Request.db")},
	}
	// Every catalog source is covered, so a source added without a fixture fails
	// here rather than going untested end to end.
	if len(want) != len(sources) {
		t.Fatalf("fixtures cover %d sources, catalog has %d", len(want), len(sources))
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

// TestDetect_ReportsOnlyMaterial is the correction this catalog was rebuilt
// around. Every file here is a real, fully configured credential mechanism, and
// not one of them puts material where the agent can read it — so a machine
// configured exactly this way holds nothing to report and is not incomplete
// either, since each file was read and understood.
func TestDetect_ReportsOnlyMaterial(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".gitconfig":           "[credential]\n\thelper = store\n",
		".aws/config":          "[profile work]\nsso_start_url = https://example.awsapps.com/start\nsso_account_id = 123456789012\n",
		".aws/credentials":     "[default]\naws_access_key_id = AKIAEXAMPLE\n",
		".docker/config.json":  `{"credsStore":"desktop","credHelpers":{"registry.example.invalid":"ecr-login"}}`,
		".kube/config":         "users:\n  - name: dev\n    user:\n      exec:\n        command: aws\n",
		".config/gh/hosts.yml": "example.invalid:\n    user: a-user\n    git_protocol: ssh\n",
		".npmrc":               "//registry.example.invalid/:_authToken=${NPM_TOKEN}\n",
		".git-credentials":     "https://a-user@example.invalid\n",
		".vault-token":         "${VAULT_TOKEN}\n",
		".ssh/id_ed25519.pub":  sshPublicKeyLine() + "\n",
	})

	info := detect(t, home)
	if len(info.Findings) != 0 {
		t.Errorf("findings = %+v, want none: none of these files holds material", info.Findings)
	}
	if !info.ScanComplete || len(info.Errors) != 0 {
		t.Errorf("scan_complete = %v with errors %+v; every file here was read and understood", info.ScanComplete, info.Errors)
	}
}

// TestDetect_AsksNoToolAboutItsCredentials holds the removal of the one program
// this phase used to run for an answer about a secret. What a tool reports about a
// credential it holds in a keystore is not material in a file, so asking is
// neither evidence nor this agent's business — and a question never put cannot
// leak through a child's arguments, environment or diagnostics. The environment
// probe is the one command a run still makes, and it is told nothing about what is
// being looked for.
func TestDetect_AsksNoToolAboutItsCredentials(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".config/gh/hosts.yml":                 ghBody,
		"AppData/Roaming/GitHub CLI/hosts.yml": ghBody,
		".aws/credentials":                     awsBody,
	})

	rec := &recordingExec{Executor: newMock(t, home)}
	info := New(rec).withEnv(staticEnv(nil)).Detect(context.Background())

	for _, name := range rec.started() {
		if strings.Contains(name, "gh") {
			t.Errorf("the phase reached for %q; commands run were %v", name, rec.started())
		}
	}
	if _, ok := findingFor(info, sourceGitHubCLIHosts); !ok {
		t.Fatalf("the inline token must still be reported without asking the tool: %+v", info)
	}
}

// TestDetect_NeverEmitsCredentialMaterial is the property the whole phase exists
// under. Every fixture carries the same distinctive value, so a parser leaking a
// value, a substring or a digest surfaces here whatever field it chose. The token
// file is the case worth naming: its whole contents are the credential and this
// build now opens it, so the canary is in the read buffer by construction.
func TestDetect_NeverEmitsCredentialMaterial(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".aws/credentials":                     "[default]\naws_access_key_id = AKIA" + canary + "\naws_secret_access_key = " + canary + "\n",
		".git-credentials":                     gitBody,
		".npmrc":                               "//registry.example.invalid/:_authToken=" + canary + "\n",
		".docker/config.json":                  dockerBody,
		".kube/config":                         kubeBody,
		".vault-token":                         canary,
		".ssh/id_ed25519":                      string(opensshKey("none", "none", "ssh-ed25519")),
		".config/gh/hosts.yml":                 ghBody,
		insomniaRel("insomnia.Request.db"):     insomniaBody,
		insomniaRel("insomnia.Environment.db"): `{"_id":"env_1","type":"Environment","data":{"token":"` + canary + `"},"kvPairData":[{"name":"` + canary + `","value":"` + canary + `","type":"secret"}]}` + "\n",
	})

	info := New(newMock(t, home)).withEnv(staticEnv(nil)).Detect(context.Background())

	payload, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(payload), canary) {
		t.Errorf("payload carries credential material: %s", payload)
	}
	// Account and host names are read to iterate entries and never stored.
	for _, named := range []string{"a-user", "example.invalid"} {
		if strings.Contains(string(payload), named) {
			t.Errorf("payload names %q: %s", named, payload)
		}
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
		// absent, empty, or holds no material. A path name is not evidence, and a
		// finding would assert something is in the file.
		{name: "an empty file", tree: map[string]string{".vault-token": ""}, source: sourceVaultToken, noFinding: true, noError: true},
		// The probed source is absent; the sibling that is present keeps the case
		// from passing vacuously.
		{name: "a file that is not there", tree: map[string]string{".aws/config": "[profile work]\naws_session_token = " + canary + "\n"}, source: sourceAWSCredentials, noFinding: true, noError: true},
		{name: "files holding no material", tree: map[string]string{".gitconfig": "[user]\n\tname = A User\n", ".npmrc": "registry=https://registry.example.invalid/\n"}, noFinding: true},
		{name: "a token file holds material", tree: map[string]string{".vault-token": canary}, source: sourceVaultToken, want: obsPlain(1)},
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
			tree:      map[string]string{"clusters/a": kubeBody, "clusters/b": kubeBody, ".kube/config": kubeBody},
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
	})
}

// TestDetect_MalformedSourcesAreIncomplete is the outcome that replaced counting a
// parse failure as a credential. A file the agent cannot interpret produces no
// finding — there is no evidence one is in it — and costs the snapshot its
// completeness, so it can never be read as a clean machine.
func TestDetect_MalformedSourcesAreIncomplete(t *testing.T) {
	runDetectCases(t, []detectCase{
		{
			name: "a malformed document", source: sourceKubeconfig,
			tree:   map[string]string{".kube/config": "users: [ unterminated " + canary + "\n"},
			reason: model.CredentialReasonUnrecognizedFormat, noFinding: true, incomplete: true,
		},
		{
			name: "a malformed settings file", source: sourceAWSCredentials,
			tree:   map[string]string{".aws/credentials": "[default]\naws_secret_access_key " + canary + "\n"},
			reason: model.CredentialReasonUnrecognizedFormat, noFinding: true, incomplete: true,
		},
		// The line-oriented sources are where partial interpretation is possible,
		// so the confirmed credential stands and the source is still incomplete.
		{
			name: "material beside a line that is not one", source: sourceGitCredentials,
			tree:   map[string]string{".git-credentials": gitBody + "not a credential url\n"},
			reason: model.CredentialReasonUnrecognizedFormat, want: obsPlain(1), incomplete: true,
		},
		{
			name: "an unterminated login entry", source: sourceNetrc, skip: model.PlatformWindows,
			tree:   map[string]string{".netrc": "machine example.invalid login a-user password"},
			reason: model.CredentialReasonUnrecognizedFormat, noFinding: true, incomplete: true,
		},
	})
}

// TestDetect_KeyDirectoryReportsOnePerKey holds because two keys in one directory
// routinely differ in the only two things a customer acts on — file mode and
// repository status — and one row for the directory would have to pick one.
func TestDetect_KeyDirectoryReportsOnePerKey(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".ssh/id_ed25519":       string(opensshKey("none", "none", "ssh-ed25519")),
		".ssh/id_rsa_protected": string(opensshKey("aes256-ctr", "bcrypt", "ssh-rsa")),
		".ssh/id_sk":            string(hardwareKey("sk-ssh-ed25519@openssh.com", 1, 0x01, deviceHandle)),
		".ssh/id_ed25519.pub":   sshPublicKeyLine() + "\n",
		".ssh/known_hosts":      "example.invalid " + sshPublicKeyLine() + "\n",
		".ssh/config":           "Host *\n  AddKeysToAgent yes\n",
		".ssh/authorized_keys":  sshPublicKeyLine() + "\n",
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

// TestDetect_KeyDirectoryKeepsGoingPastADamagedKey covers the mixed result for the
// one source that is a directory: a candidate this build cannot confirm costs the
// scan its completeness without taking the readable keys beside it out of the
// inventory, and never becomes a finding of its own.
func TestDetect_KeyDirectoryKeepsGoingPastADamagedKey(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".ssh/id_ed25519":   string(opensshKey("none", "none", "ssh-ed25519")),
		".ssh/id_damaged":   "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA",
		".ssh/id_damaged_2": "-----BEGIN PRIVATE KEY-----\ndmFsdWU=\n-----END PRIVATE KEY-----\n",
	})

	info := detect(t, home)
	got := findingsFor(info, sourceSSHPrivateKeys)
	if len(got) != 1 || filepath.Base(got[0].Location) != "id_ed25519" {
		t.Fatalf("findings = %+v, want only the key that was confirmed", got)
	}
	if !hasScanError(info.Errors, sourceSSHPrivateKeys, model.CredentialReasonUnrecognizedFormat) {
		t.Errorf("errors = %+v, want the damaged candidate reported", info.Errors)
	}
	// An error names its source and nothing else, so a second copy of this one
	// says nothing further and spends a budget a different failure needs.
	if n := countScanErrors(info.Errors, sourceSSHPrivateKeys, model.CredentialReasonUnrecognizedFormat); n != 1 {
		t.Errorf("errors = %+v, want one entry for the source however many candidates are damaged, got %d", info.Errors, n)
	}
	if info.ScanComplete {
		t.Error("a candidate that could not be confirmed leaves the run incomplete")
	}
}

// TestDetect_KeyDirectoryReportsOneRefusalHowManyKeysItTurnedAway holds because an
// error names its source and no file: a directory whose entries the account cannot
// open would otherwise report the same refusal once per key, filling a budget the
// sources read after it need to report anything at all.
func TestDetect_KeyDirectoryReportsOneRefusalHowManyKeysItTurnedAway(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("a mode of zero does not deny the owner a read on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("the superuser is refused by no file mode")
	}
	home := testHome(t)
	unreadable := map[string]string{}
	for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"} {
		unreadable[".ssh/"+name] = string(opensshKey("none", "none", "ssh-ed25519"))
	}
	unreadable[".ssh/id_readable"] = string(opensshKey("none", "none", "ssh-ed25519"))
	writeTree(t, home, unreadable)
	for rel := range unreadable {
		if filepath.Base(rel) == "id_readable" {
			continue
		}
		if err := os.Chmod(filepath.Join(home, filepath.FromSlash(rel)), 0); err != nil {
			t.Fatalf("chmod %s: %v", rel, err)
		}
	}

	info := detect(t, home)
	got := findingsFor(info, sourceSSHPrivateKeys)
	if len(got) != 1 || filepath.Base(got[0].Location) != "id_readable" {
		t.Fatalf("findings = %+v, want only the key that could be opened", got)
	}
	if n := countScanErrors(info.Errors, sourceSSHPrivateKeys, model.CredentialReasonPermissionDenied); n != 1 {
		t.Errorf("errors = %+v, want one refusal for the source however many keys it turned away, got %d", info.Errors, n)
	}
	if info.ScanComplete {
		t.Error("a key that could not be read leaves the run incomplete")
	}
}

// TestDetect_KeyLargerThanItsCapIsNotClassified holds because a key is validated
// over its complete bytes: a prefix is indistinguishable from the truncated
// container that validation exists to reject, so the read is reported as capped
// rather than guessed at.
func TestDetect_KeyLargerThanItsCapIsNotClassified(t *testing.T) {
	home := testHome(t)
	oversized := string(opensshKey("none", "none", "ssh-ed25519")) + strings.Repeat("# padding\n", capPrivateKey/10+16)
	writeTree(t, home, map[string]string{".ssh/id_ed25519": oversized})

	info := detect(t, home)
	if got := findingsFor(info, sourceSSHPrivateKeys); len(got) != 0 {
		t.Fatalf("findings = %+v, want none for a candidate read only in part", got)
	}
	if !hasScanError(info.Errors, sourceSSHPrivateKeys, model.CredentialReasonCapped) {
		t.Errorf("errors = %+v, want the cap reported", info.Errors)
	}
	if info.ScanComplete || !info.Truncated {
		t.Errorf("scan_complete = %v, truncated = %v", info.ScanComplete, info.Truncated)
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

	info := New(m).Detect(context.Background())
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

// TestDetect_WritesNothingToStandardError holds because enterprise runs tee this
// process's standard error into a buffer that ships with the telemetry, unredacted:
// a parser naming the file it choked on would put a credential location there.
func TestDetect_WritesNothingToStandardError(t *testing.T) {
	home := testHome(t)
	writeTree(t, home, map[string]string{
		".aws/credentials":                        awsBody,
		".docker/config.json":                     `{"auths":{"registry.example.invalid":{"auth":"` + canary,
		".kube/config":                            "users: [ unterminated " + canary + "\n",
		".npmrc":                                  "//registry.example.invalid/:_authToken=" + canary + "\n",
		".ssh/id_ed25519":                         string(opensshKey("none", "none", "ssh-ed25519")),
		".ssh/id_damaged":                         "-----BEGIN OPENSSH PRIVATE KEY-----\n" + canary,
		insomniaRel("insomnia.Environment.db"):    `{"_id":"env_1","type":"Environment","data":{"token":"` + canary,
		insomniaRel("insomnia.RequestVersion.db"): `{"_id":"rv_1","type":"RequestVersion","compressedRequest":"` + canary + `"}` + "\n",
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
	if got := refusalReason(errors.New("read /home/a-user/.aws/credentials: some library detail")); got != model.CredentialReasonLocationUnresolved {
		t.Errorf("an unrecognised error mapped to %q, want %q", got, model.CredentialReasonLocationUnresolved)
	}
}

// insomniaBody is one live request holding a token and an authorization header.
var insomniaBody = `{"_id":"req_1","type":"Request","authentication":{"type":"bearer","token":"` + canary + `"},"headers":[{"name":"Authorization","value":"` + canary + `"}]}` + "\n"

// insomniaRel is where this platform keeps one of the API client's databases,
// relative to the home.
func insomniaRel(file string) string {
	switch runtime.GOOS {
	case model.PlatformWindows:
		return "AppData/Roaming/Insomnia/" + file
	case model.PlatformDarwin:
		return "Library/Application Support/Insomnia/" + file
	}
	return ".config/Insomnia/" + file
}

// insomniaLocation is the tokenised spelling of the same path.
func insomniaLocation(file string) string {
	if runtime.GOOS == model.PlatformWindows {
		return "$APPDATA/Insomnia/" + file
	}
	return "$HOME/" + insomniaRel(file)
}

// TestDetect_InsomniaDatabases covers the one source that spans several files:
// each database that exists is its own finding, one variable relocates all of
// them, and the store's habit of keeping deleted records means a file is read
// whole rather than for its current records.
func TestDetect_InsomniaDatabases(t *testing.T) {
	secret := `{"_id":"env_1","type":"Environment","data":{"__insomnia_vault":{"k":"` + envelope() + `"}},"kvPairData":[{"name":"k","value":"` + envelope() + `","type":"secret"}]}` + "\n"
	runDetectCases(t, []detectCase{
		{
			name: "each database is its own finding", source: sourceInsomnia,
			tree: map[string]string{
				insomniaRel("insomnia.Request.db"):     insomniaBody,
				insomniaRel("insomnia.Environment.db"): secret,
				insomniaRel("insomnia.OAuth2Token.db"): `{"_id":"tok_1","type":"OAuth2Token","accessToken":"` + canary + `"}` + "\n",
			},
			locations: []string{insomniaLocation("insomnia.Request.db"), insomniaLocation("insomnia.Environment.db"), insomniaLocation("insomnia.OAuth2Token.db")},
		},
		{
			name: "a database of secrets alone is protected", source: sourceInsomnia,
			tree: map[string]string{insomniaRel("insomnia.Environment.db"): secret},
			want: obsProt(1), location: insomniaLocation("insomnia.Environment.db"),
		},
		{
			name: "a secret beside a plain variable is in the clear", source: sourceInsomnia,
			tree: map[string]string{insomniaRel("insomnia.Environment.db"): secret + `{"_id":"env_2","type":"Environment","data":{"token":"` + canary + `"}}` + "\n"},
			want: obsPlain(2),
		},
		{
			name: "the data directory variable relocates every file", source: sourceInsomnia,
			tree: map[string]string{
				"elsewhere/insomnia.Request.db":        insomniaBody,
				"elsewhere/insomnia.OAuth2Token.db":    `{"_id":"tok_1","type":"OAuth2Token","refreshToken":"` + canary + `"}` + "\n",
				insomniaRel("insomnia.Environment.db"): secret,
			},
			env:       map[string]string{"INSOMNIA_DATA_PATH": "{home}/elsewhere"},
			locations: []string{"$HOME/elsewhere/insomnia.Request.db", "$HOME/elsewhere/insomnia.OAuth2Token.db"},
		},
		{
			name: "the configuration directory variable moves the linux root", only: model.PlatformLinux, source: sourceInsomnia,
			tree:     map[string]string{"xdg/Insomnia/insomnia.Request.db": insomniaBody},
			env:      map[string]string{"XDG_CONFIG_HOME": "{home}/xdg"},
			want:     obsPlain(2),
			location: "$XDG_CONFIG_HOME/Insomnia/insomnia.Request.db",
		},
		// Ten relocated files outside the roots are one refusal, not ten.
		{
			name: "a data directory outside the user roots", source: sourceInsomnia,
			outside: map[string]string{"data/insomnia.Request.db": insomniaBody},
			env:     map[string]string{"INSOMNIA_DATA_PATH": "{out}/data"},
			reason:  model.CredentialReasonRefusedOutsideRoots, noFinding: true, errors: 1, incomplete: true,
		},
		// Blank lines parse to nothing, so the prefix is clean and only the cap
		// says the count is a lower bound.
		{
			name: "a database past the byte cap", source: sourceInsomnia,
			tree: map[string]string{insomniaRel("insomnia.Request.db"): insomniaBody + strings.Repeat("\n", capInsomnia)},
			want: obsPlain(2), reason: model.CredentialReasonCapped, incomplete: true, truncated: true,
		},
		{
			name: "a database of tombstones holds nothing", source: sourceInsomnia,
			tree:      map[string]string{insomniaRel("insomnia.Request.db"): `{"_id":"req_1","$$deleted":true}` + "\n"},
			noFinding: true, noError: true,
		},
		{
			name: "a deleted record is still material until compaction", source: sourceInsomnia,
			tree: map[string]string{insomniaRel("insomnia.Request.db"): insomniaBody + `{"_id":"req_1","$$deleted":true}` + "\n"},
			want: obsPlain(2),
		},
		{
			name: "a damaged database is incomplete", source: sourceInsomnia,
			tree:   map[string]string{insomniaRel("insomnia.Request.db"): `{"_id":"req_1","type":"Request","authentication":{`},
			reason: model.CredentialReasonUnrecognizedFormat, noFinding: true, incomplete: true,
		},
	})
}

func TestDetect_InsomniaAccountStores(t *testing.T) {
	for _, tc := range []struct {
		file, body string
		want       observation
	}{
		{"insomnia.GitCredentials.db", `{"_id":"git_1","type":"GitCredentials","credentials":{"token":"` + canary + `"}}`, obsPlain(1)},
		{"insomnia.GitRepository.db", `{"_id":"repo_1","type":"GitRepository","credentials":{"password":"` + canary + `"}}`, obsPlain(1)},
		{"insomnia.CloudCredential.db", `{"_id":"cloud_1","type":"CloudCredential","provider":"aws","credentials":{"secretAccessKey":"` + canary + `"}}`, obsPlain(1)},
		{"insomnia.UserSession.db", `{"_id":"usr_1","type":"UserSession","id":"` + canary + `","symmetricKey":{"kty":"oct","k":"` + canary + `"}}`, obsPlain(2)},
	} {
		t.Run(tc.file, func(t *testing.T) {
			runDetectCases(t, []detectCase{
				{name: "default location", source: sourceInsomnia, guard: runtime.GOOS == model.PlatformDarwin,
					tree: map[string]string{insomniaRel(tc.file): tc.body}, want: tc.want, location: insomniaLocation(tc.file), noError: true},
				{name: "relocated data directory", source: sourceInsomnia,
					tree: map[string]string{"elsewhere/" + tc.file: tc.body}, want: tc.want,
					env: map[string]string{"INSOMNIA_DATA_PATH": "{home}/elsewhere"}, location: "$HOME/elsewhere/" + tc.file, noError: true},
			})
		})
	}
}

func TestDetect_InsomniaLibraryGuard(t *testing.T) {
	if runtime.GOOS != model.PlatformDarwin {
		t.Skip("macOS consent guard")
	}
	runDetectCases(t, []detectCase{
		{name: "default database", guard: true, source: sourceInsomnia,
			tree: map[string]string{insomniaRel("insomnia.Request.db"): insomniaBody}, want: obsPlain(2), noError: true},
		{name: "override to default directory", guard: true, source: sourceInsomnia,
			tree: map[string]string{insomniaRel("insomnia.Request.db"): insomniaBody},
			env:  map[string]string{"INSOMNIA_DATA_PATH": "{home}/Library/Application Support/Insomnia"}, want: obsPlain(2), noError: true},
		{name: "safe override", guard: true, source: sourceInsomnia,
			tree: map[string]string{"custom/insomnia.Request.db": insomniaBody},
			env:  map[string]string{"INSOMNIA_DATA_PATH": "{home}/custom"}, want: obsPlain(2), noError: true},
		{name: "sibling override", guard: true, source: sourceInsomnia,
			env:       map[string]string{"INSOMNIA_DATA_PATH": "{home}/Library/Application Support/Insomnia-backup"},
			noFinding: true, reason: model.CredentialReasonRefusedTCC, incomplete: true},
		{name: "nested override", guard: true, source: sourceInsomnia,
			env:       map[string]string{"INSOMNIA_DATA_PATH": "{home}/Library/Application Support/Insomnia/backup"},
			noFinding: true, reason: model.CredentialReasonRefusedTCC, incomplete: true},
		{name: "protected override", guard: true, source: sourceInsomnia,
			env:       map[string]string{"INSOMNIA_DATA_PATH": "{home}/Documents"},
			noFinding: true, reason: model.CredentialReasonRefusedTCC, incomplete: true},
		{name: "other source retains guard", guard: true, source: sourceAWSCredentials,
			env:       map[string]string{"AWS_SHARED_CREDENTIALS_FILE": "{home}/Library/Application Support/Insomnia/insomnia.Request.db"},
			noFinding: true, reason: model.CredentialReasonRefusedTCC, incomplete: true},
	})
	for _, tc := range []struct {
		name, target string
		directory    bool
	}{
		{"file to Mail", "Library/Mail/credential", false},
		{"file to sibling", "Library/Application Support/Insomnia-backup/credential", false},
		{"file to unlisted database", "Library/Application Support/Insomnia/insomnia.Settings.db", false},
		{"directory to Documents", "Documents", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := testHome(t)
			link := filepath.Join(home, insomniaRel("insomnia.Request.db"))
			if tc.directory {
				link = filepath.Dir(link)
			}
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			// The target is absent: a refusal proves the guard ran before its stat.
			if err := os.Symlink(filepath.Join(home, tc.target), link); err != nil {
				t.Fatal(err)
			}
			info := New(newMock(t, home)).withEnv(staticEnv(nil)).WithSkipper(tcc.New(home)).Detect(context.Background())
			if len(info.Findings) != 0 || !hasScanError(info.Errors, sourceInsomnia, model.CredentialReasonRefusedTCC) || info.ScanComplete {
				t.Fatalf("got %+v, want guarded refusal without findings", info)
			}
		})
	}
}

func TestDetect_InsomniaLargerDatabases(t *testing.T) {
	for _, tc := range []struct {
		name, file       string
		records, padding int
		history          bool
	}{
		{"requests", "insomnia.Request.db", 2000, 2048, false},
		{"environments", "insomnia.Environment.db", 2000, 2048, false},
		{"history", "insomnia.RequestVersion.db", 1000, 4096, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body strings.Builder
			padding := strings.Repeat("x", tc.padding)
			packed := compressed(`{"type":"Request","body":{"text":"` + padding + `"}}`)
			for i := range tc.records {
				switch {
				case tc.history:
					fmt.Fprintf(&body, "{\"_id\":\"rev_%d\",\"type\":\"RequestVersion\",\"compressedRequest\":\"%s\"}\n", i, packed)
				case tc.name == "environments":
					fmt.Fprintf(&body, "{\"_id\":\"env_%d\",\"type\":\"Environment\",\"data\":{\"description\":\"%s\"}}\n", i, padding)
				default:
					fmt.Fprintf(&body, "{\"_id\":\"req_%d\",\"type\":\"Request\",\"body\":{\"text\":\"%s\"}}\n", i, padding)
				}
			}
			// Material only at the tail: reading a prefix cannot pass this test.
			if tc.history {
				fmt.Fprintf(&body, "{\"_id\":\"last\",\"type\":\"RequestVersion\",\"compressedRequest\":\"%s\"}\n", compressed(insomniaBody))
			} else if tc.name == "environments" {
				fmt.Fprintf(&body, "{\"_id\":\"last\",\"type\":\"Environment\",\"data\":{\"token\":\"%s\",\"password\":\"%s\"}}\n", canary, canary)
			} else {
				body.WriteString(insomniaBody)
			}
			t.Logf("records=%d file_bytes=%d expanded_padding_bytes=%d", tc.records+1, body.Len(), tc.records*tc.padding)
			runDetectCases(t, []detectCase{{name: "tail found", source: sourceInsomnia,
				tree: map[string]string{insomniaRel(tc.file): body.String()}, want: obsPlain(2), noError: true}})
		})
	}
}
