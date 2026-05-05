package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// fakeAudit returns a representative NPMRCAudit covering all the verbose
// view's branches: a missing scope, a present file with auth + env-ref + a
// security-relevant key, a git-tracked project file, and an env var that
// must come out redacted.
func fakeAudit() *model.NPMRCAudit {
	return &model.NPMRCAudit{
		Available:  true,
		NPMVersion: "10.9.4",
		NPMPath:    "/usr/bin/npm",
		Files: []model.NPMRCFile{
			{
				Path:   "/etc/npmrc",
				Scope:  "global",
				Exists: false,
			},
			{
				Path:        "/home/test/.npmrc",
				Scope:       "user",
				Exists:      true,
				Readable:    true,
				SizeBytes:   200,
				ModTimeUnix: 1730000000,
				Mode:        "0600",
				OwnerName:   "test",
				GroupName:   "test",
				SHA256:      "deadbeefcafebabe0123456789abcdef",
				Entries: []model.NPMRCEntry{
					{Key: "registry", DisplayValue: "https://registry.npmjs.org/", LineNum: 1},
					{Key: "//registry.npmjs.org/:_authToken", DisplayValue: "***1234", LineNum: 2, IsAuth: true},
					{Key: "//npm.mycompany.com/:_authToken", DisplayValue: "${COMPANY_TOKEN}", LineNum: 3, IsAuth: true, IsEnvRef: true, EnvRefVars: []string{"COMPANY_TOKEN"}},
					{Key: "strict-ssl", DisplayValue: "false", LineNum: 4},
				},
			},
			{
				Path:        "/home/test/proj/.npmrc",
				Scope:       "project",
				Exists:      true,
				Readable:    true,
				SizeBytes:   80,
				Mode:        "0644",
				OwnerName:   "test",
				GroupName:   "test",
				SHA256:      "abc123",
				InGitRepo:   true,
				GitTracked:  true,
				Entries: []model.NPMRCEntry{
					{Key: "ignore-scripts", DisplayValue: "true", LineNum: 1},
				},
			},
		},
		Effective: &model.NPMRCEffective{
			Config: map[string]any{
				"registry":       "https://registry.npmjs.org/",
				"strict-ssl":     false,
				"ignore-scripts": true,
				"audit-level":    "moderate",
				"long":           true, // not security-relevant; should hide if from default
			},
			SourceByKey: map[string]string{
				"registry":       "user",
				"strict-ssl":     "user",
				"ignore-scripts": "user",
				"audit-level":    "global",
				"long":           "default",
			},
		},
		Env: []model.NPMRCEnvVar{
			{Name: "NPM_TOKEN", Set: true, DisplayValue: "***f00d"},
			{Name: "NPM_CONFIG_USERCONFIG", Set: false},
		},
	}
}

func TestPrettyNPMRC_RedactsAuthAndShowsEnvRef(t *testing.T) {
	var buf bytes.Buffer
	PrettyNPMRC(&buf, fakeAudit(), model.Device{Hostname: "h", UserIdentity: "u", Platform: "linux"}, "never")
	out := buf.String()

	// Auth-hardcoded should NEVER print the raw token; should print the
	// already-redacted DisplayValue plus the AUTH:hardcoded badge.
	if !strings.Contains(out, "***1234") {
		t.Errorf("expected redacted display ***1234 in output")
	}
	if !strings.Contains(out, "AUTH:hardcoded") {
		t.Errorf("expected AUTH:hardcoded badge")
	}
	if !strings.Contains(out, "AUTH:env-ref") {
		t.Errorf("expected AUTH:env-ref badge for ${VAR} reference")
	}
	if !strings.Contains(out, "${COMPANY_TOKEN}") {
		t.Errorf("env-ref literal should be preserved verbatim")
	}
	if !strings.Contains(out, "resolves from env: COMPANY_TOKEN") {
		t.Errorf("expected env var name in resolves-from line")
	}
}

func TestPrettyNPMRC_HighlightsGitTracked(t *testing.T) {
	var buf bytes.Buffer
	PrettyNPMRC(&buf, fakeAudit(), model.Device{}, "never")
	out := buf.String()

	if !strings.Contains(out, "GIT-TRACKED") {
		t.Errorf("git-tracked file should surface a GIT-TRACKED warning, got:\n%s", out)
	}
}

func TestPrettyNPMRC_GroupsEffectiveBySource(t *testing.T) {
	var buf bytes.Buffer
	PrettyNPMRC(&buf, fakeAudit(), model.Device{}, "never")
	out := buf.String()

	for _, want := range []string{"from user", "from global", "from default"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected effective view to include %q grouping", want)
		}
	}

	// Security-relevant keys from non-default sources are always shown.
	for _, key := range []string{"registry", "strict-ssl", "ignore-scripts", "audit-level"} {
		if !strings.Contains(out, key) {
			t.Errorf("expected security-relevant key %q in effective view", key)
		}
	}

	// Default-section non-security keys should be hidden behind the
	// "+N default values not shown" line.
	if strings.Contains(out, "long ") && !strings.Contains(out, "default values not shown") {
		t.Errorf("non-security default key 'long' should not be expanded")
	}
}

func TestPrettyNPMRC_ShowsMissingFiles(t *testing.T) {
	var buf bytes.Buffer
	PrettyNPMRC(&buf, fakeAudit(), model.Device{}, "never")
	out := buf.String()

	if !strings.Contains(out, "/etc/npmrc") {
		t.Errorf("missing global file should still be listed")
	}
	if !strings.Contains(out, "file does not exist") {
		t.Errorf("missing files should be marked clearly")
	}
}

func TestPrettyNPMRC_HandlesNoNPM(t *testing.T) {
	a := fakeAudit()
	a.Available = false
	a.NPMVersion = ""
	a.NPMPath = ""

	var buf bytes.Buffer
	PrettyNPMRC(&buf, a, model.Device{}, "never")
	out := buf.String()

	if !strings.Contains(out, "not found in PATH") {
		t.Errorf("expected fallback message when npm missing")
	}
}
