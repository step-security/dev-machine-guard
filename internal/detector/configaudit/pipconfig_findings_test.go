package configaudit

import (
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

const at = "@" // dodge editor auto-link rewriting on literal user@host forms

// findingsByID extracts a quick map of present finding IDs for a test
// audit. Multiple findings with the same ID collapse into one entry —
// counts can be inspected via the slice indexing on findings[i].
func findingsByID(findings []model.PipFinding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[f.ID]++
	}
	return out
}

// makeAuditWithUserFile constructs a minimal PipAudit with one
// already-parsed file containing the given sections+entries.
func makeAuditWithUserFile(path, mode string, gitTracked bool, sections []model.PipSection) *model.PipAudit {
	return &model.PipAudit{
		Files: []model.PipConfigFile{
			{
				Path:       path,
				Layer:      "user",
				Exists:     true,
				Readable:   true,
				Mode:       mode,
				SHA256:     "deadbeef",
				GitTracked: gitTracked,
				Sections:   sections,
			},
		},
	}
}

// section helper for terser test fixtures.
func sec(name string, entries ...model.PipKeyValue) model.PipSection {
	return model.PipSection{Name: name, Entries: entries}
}

func kv(key string, values ...string) model.PipKeyValue {
	return model.PipKeyValue{Key: key, Values: values, Display: strings.Join(values, ", ")}
}

func TestFindings_EmbeddedCredsInURL_pip001(t *testing.T) {
	audit := makeAuditWithUserFile("/u/.config/pip/pip.conf", "0644", false, []model.PipSection{
		sec("global", kv("extra-index-url", "https://__token__:pypi-AgEI..."+at+"my-private.example.com/simple")),
	})
	findings := evaluatePipFindings(audit)
	ids := findingsByID(findings)
	for _, want := range []string{"pip-001", "pip-005"} {
		if ids[want] == 0 {
			t.Errorf("expected %s, got %v", want, ids)
		}
	}
	// pip-001 must be CRITICAL.
	for _, f := range findings {
		if f.ID == "pip-001" && f.Severity != "CRITICAL" {
			t.Errorf("pip-001 severity %q, want CRITICAL", f.Severity)
		}
		if f.ID == "pip-001" && strings.Contains(f.ValueShown, "pypi-AgEI") {
			t.Errorf("pip-001 leaked credential in ValueShown: %q", f.ValueShown)
		}
	}
}

func TestFindings_GitTrackedEscalation_pip004(t *testing.T) {
	audit := makeAuditWithUserFile("/u/code/repo/.pip/pip.conf", "0644", true /* git-tracked */, []model.PipSection{
		sec("global", kv("extra-index-url", "https://alice:secret"+at+"internal.example.com/simple")),
	})
	findings := evaluatePipFindings(audit)
	ids := findingsByID(findings)
	if ids["pip-004"] == 0 {
		t.Errorf("expected pip-004 escalation, got %v", ids)
	}
	for _, f := range findings {
		if f.ID == "pip-004" && f.Severity != "CRITICAL" {
			t.Errorf("pip-004 severity %q, want CRITICAL", f.Severity)
		}
	}
}

func TestFindings_HTTPScheme_pip002_pip006_pip008(t *testing.T) {
	audit := makeAuditWithUserFile("/u/.config/pip/pip.conf", "0644", false, []model.PipSection{
		sec("global",
			kv("index-url", "http://internal.example.com/simple"),
			kv("extra-index-url", "http://other.example.com/simple"),
			kv("find-links", "http://mirror.example.com"),
		),
	})
	findings := evaluatePipFindings(audit)
	ids := findingsByID(findings)
	for _, want := range []string{"pip-002", "pip-006", "pip-008"} {
		if ids[want] == 0 {
			t.Errorf("expected %s, got %v", want, ids)
		}
	}
}

func TestFindings_TrustedHost_pip007(t *testing.T) {
	audit := makeAuditWithUserFile("/u/.config/pip/pip.conf", "0644", false, []model.PipSection{
		sec("global", kv("trusted-host", "a.example.com", "b.example.com")),
	})
	findings := evaluatePipFindings(audit)
	count := 0
	for _, f := range findings {
		if f.ID == "pip-007" {
			count++
			if f.Severity != "HIGH" {
				t.Errorf("pip-007 severity %q, want HIGH", f.Severity)
			}
		}
	}
	if count != 2 {
		t.Errorf("expected 2 pip-007 findings (one per host), got %d", count)
	}
}

func TestFindings_NoBuildIsolation_pip011(t *testing.T) {
	audit := makeAuditWithUserFile("/u/.config/pip/pip.conf", "0644", false, []model.PipSection{
		sec("global", kv("no-build-isolation", "true")),
	})
	ids := findingsByID(evaluatePipFindings(audit))
	if ids["pip-011"] == 0 {
		t.Errorf("expected pip-011, got %v", ids)
	}
}

func TestFindings_RequireHashesPositive_pip023(t *testing.T) {
	audit := makeAuditWithUserFile("/u/.config/pip/pip.conf", "0644", false, []model.PipSection{
		sec("install", kv("require-hashes", "true"), kv("only-binary", ":all:")),
	})
	findings := evaluatePipFindings(audit)
	ids := findingsByID(findings)
	if ids["pip-023"] == 0 {
		t.Errorf("expected positive pip-023, got %v", ids)
	}
	if ids["pip-024"] == 0 {
		t.Errorf("expected positive pip-024, got %v", ids)
	}
	for _, f := range findings {
		if f.ID == "pip-023" || f.ID == "pip-024" {
			if f.Severity != "INFO" {
				t.Errorf("%s should be INFO, got %s", f.ID, f.Severity)
			}
		}
	}
}

func TestFindings_PipConfigFileDevNull_pip021(t *testing.T) {
	audit := &model.PipAudit{
		EnvVars: []model.PipEnvVar{
			{Name: "PIP_CONFIG_FILE", Value: "/dev/null", Display: "/dev/null"},
		},
	}
	ids := findingsByID(evaluatePipFindings(audit))
	if ids["pip-021"] == 0 {
		t.Errorf("expected pip-021, got %v", ids)
	}
	if ids["pip-020"] != 0 {
		t.Errorf("pip-020 should NOT fire when devnull is present (different rule path), got %v", ids)
	}
}

func TestFindings_PipConfigFileRedirected_pip020(t *testing.T) {
	audit := &model.PipAudit{
		EnvVars: []model.PipEnvVar{
			{Name: "PIP_CONFIG_FILE", Value: "/tmp/attacker.conf", Display: "/tmp/attacker.conf"},
		},
	}
	ids := findingsByID(evaluatePipFindings(audit))
	if ids["pip-020"] == 0 {
		t.Errorf("expected pip-020, got %v", ids)
	}
}

func TestFindings_LegacyPath_pip019(t *testing.T) {
	audit := &model.PipAudit{
		Files: []model.PipConfigFile{
			{Path: "/home/u/.pip/pip.conf", Layer: "user-legacy", Exists: true, Readable: true, Mode: "0644"},
		},
	}
	ids := findingsByID(evaluatePipFindings(audit))
	if ids["pip-019"] == 0 {
		t.Errorf("expected pip-019, got %v", ids)
	}
}

func TestFindings_FilePermissions_pip022(t *testing.T) {
	// Plain mode > 0644 → MEDIUM, no creds.
	a1 := &model.PipAudit{
		Files: []model.PipConfigFile{{
			Path: "/u/.config/pip/pip.conf", Layer: "user", Exists: true, Readable: true, Mode: "0666",
			Sections: []model.PipSection{},
		}},
	}
	for _, f := range evaluatePipFindings(a1) {
		if f.ID == "pip-022" && f.Severity != "MEDIUM" {
			t.Errorf("plain mode > 0644 should be MEDIUM, got %s", f.Severity)
		}
	}

	// Contains creds + mode > 0600 → HIGH.
	a2 := makeAuditWithUserFile("/u/.config/pip/pip.conf", "0644", false, []model.PipSection{
		sec("global", kv("extra-index-url", "https://alice:secret"+at+"internal.example.com/simple")),
	})
	for _, f := range evaluatePipFindings(a2) {
		if f.ID == "pip-022" && f.Severity != "HIGH" {
			t.Errorf("creds + mode 0644 should be HIGH, got %s", f.Severity)
		}
	}

	// Global + group/other writable → HIGH.
	a3 := &model.PipAudit{
		Files: []model.PipConfigFile{{
			Path: "/etc/pip.conf", Layer: "global", Exists: true, Readable: true, Mode: "0666",
			Sections: []model.PipSection{},
		}},
	}
	sawHigh := false
	for _, f := range evaluatePipFindings(a3) {
		if f.ID == "pip-022" && f.Severity == "HIGH" {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Errorf("global + world-writable should escalate to HIGH")
	}
}

func TestFindings_NetrcLoosePerms(t *testing.T) {
	audit := &model.PipAudit{
		Netrc: &model.PipNetrcStatus{Path: "/u/.netrc", Exists: true, Mode: "0644"},
	}
	sawNetrc := false
	for _, f := range evaluatePipFindings(audit) {
		if f.ID == "pip-netrc-perms" {
			sawNetrc = true
			if f.Severity != "MEDIUM" {
				t.Errorf("netrc perms severity %q, want MEDIUM", f.Severity)
			}
		}
	}
	if !sawNetrc {
		t.Errorf("expected pip-netrc-perms finding")
	}
}

func TestFindings_StableOrdering_severityFirst(t *testing.T) {
	audit := makeAuditWithUserFile("/u/.config/pip/pip.conf", "0644", false, []model.PipSection{
		sec("global",
			kv("pre", "true"), // LOW
			kv("extra-index-url", "https://alice:secret"+at+"internal.example.com/simple"), // CRITICAL
			kv("trusted-host", "x.example.com"),                                            // HIGH
		),
	})
	findings := evaluatePipFindings(audit)
	if findings[0].Severity != "CRITICAL" {
		t.Errorf("expected first finding to be CRITICAL, got %+v", findings[0])
	}
	last := findings[len(findings)-1]
	if last.Severity != "LOW" && last.Severity != "INFO" {
		t.Errorf("expected last finding to be LOW/INFO, got %+v", last)
	}
}

func TestParseTruthy(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want bool
	}{
		{"true", true}, {"TRUE", true}, {"yes", true}, {"1", true}, {"on", true},
		{"false", false}, {"no", false}, {"0", false}, {"", false}, {" ", false},
	} {
		if got := parseTruthy(tt.in); got != tt.want {
			t.Errorf("parseTruthy(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseModeOctal(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"0644", 0o644, true},
		{"0o644", 0o644, true},
		{"600", 0o600, true},
		{"abc", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := parseModeOctal(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseModeOctal(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestIsLegacyPipConfigPath(t *testing.T) {
	cases := map[string]bool{
		// Unix legacy
		"/home/alice/.pip/pip.conf": true,
		"/Users/bob/.pip/pip.conf":  true,
		// Unix current
		"/home/alice/.config/pip/pip.conf": false,
		"/etc/pip.conf":                    false,
		"/etc/xdg/pip/pip.conf":            false,
		// macOS user
		"/Users/bob/Library/Application Support/pip/pip.conf": false,
		// Windows legacy (HOME-rooted, no AppData component)
		`C:\Users\Carol\pip\pip.ini`: true,
		// Windows current (under AppData)
		`C:\Users\Carol\AppData\Roaming\pip\pip.ini`: false,
		// Windows global
		`C:\ProgramData\pip\pip.ini`: false,
		// Random path
		"/tmp/something/pip.conf": false,
	}
	for in, want := range cases {
		if got := isLegacyPipConfigPath(in); got != want {
			t.Errorf("isLegacyPipConfigPath(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestEvaluateFileLevel_Pip019_FiresOnLegacyPathRegardlessOfLayer locks
// in the bug fix: when pip is installed, `pip config debug` reports the
// legacy path under the `user` layer (not `user-legacy`), so the rule
// must detect by path suffix, not by Layer field. Validated end-to-end
// on Fedora EC2.
func TestEvaluateFileLevel_Pip019_FiresOnLegacyPathRegardlessOfLayer(t *testing.T) {
	for _, layer := range []string{"user", "user-legacy"} {
		f := model.PipConfigFile{
			Path:   "/home/test/.pip/pip.conf",
			Layer:  layer,
			Exists: true,
			Mode:   "0644",
		}
		var fired bool
		evaluateFileLevelFindings(f, func(fnd model.PipFinding) {
			if fnd.ID == "pip-019" {
				fired = true
			}
		})
		if !fired {
			t.Errorf("pip-019 must fire for legacy path under layer=%q (was missed when pip-debug reports the legacy file as 'user')", layer)
		}
	}
}
