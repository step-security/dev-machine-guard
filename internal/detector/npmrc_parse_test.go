package detector

import (
	"strings"
	"testing"
)

func TestParseNPMRC_Basic(t *testing.T) {
	input := `
; this is a comment
# also a comment
registry = https://registry.npmjs.org/
@mycompany:registry=https://npm.mycompany.com/
strict-ssl=false
`
	entries := parseNPMRC([]byte(input))
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	want := map[string]string{
		"registry":             "https://registry.npmjs.org/",
		"@mycompany:registry":  "https://npm.mycompany.com/",
		"strict-ssl":           "false",
	}
	for _, e := range entries {
		if got := want[e.Key]; got != e.DisplayValue {
			t.Errorf("key %q: want %q, got %q", e.Key, got, e.DisplayValue)
		}
		if e.IsAuth {
			t.Errorf("key %q should not be auth", e.Key)
		}
	}
}

func TestParseNPMRC_AuthRedaction(t *testing.T) {
	input := `//registry.npmjs.org/:_authToken=npm_AbCdEfGhIjKlMnOpQrStUv1234WXYZ
//npm.mycompany.com/:_authToken=short
//registry.yarnpkg.com/:_password=plainpassword123
`
	entries := parseNPMRC([]byte(input))
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	for _, e := range entries {
		if !e.IsAuth {
			t.Errorf("key %q should be auth", e.Key)
		}
		if strings.Contains(e.DisplayValue, "AbCdEf") || strings.Contains(e.DisplayValue, "plainpassword") {
			t.Errorf("key %q: raw secret leaked through DisplayValue=%q", e.Key, e.DisplayValue)
		}
		if !strings.HasPrefix(e.DisplayValue, "***") {
			t.Errorf("key %q: expected redacted prefix, got %q", e.Key, e.DisplayValue)
		}
		if e.ValueSHA256 == "" {
			t.Errorf("key %q: expected ValueSHA256 to be populated", e.Key)
		}
	}

	// The "short" token should collapse to plain "***" with no last-4 leak.
	for _, e := range entries {
		if e.Key == "//npm.mycompany.com/:_authToken" && e.DisplayValue != "***" {
			t.Errorf("short secret should redact to ***, got %q", e.DisplayValue)
		}
	}
}

func TestParseNPMRC_EnvRefPreserved(t *testing.T) {
	input := `//registry.npmjs.org/:_authToken=${NPM_TOKEN}
//npm.mycompany.com/:_authToken=${COMPANY_TOKEN:-fallback}
cache = ${HOME}/.npm-packages
`
	entries := parseNPMRC([]byte(input))
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	for _, e := range entries {
		if !e.IsEnvRef {
			t.Errorf("key %q: IsEnvRef should be true (value=%q)", e.Key, e.DisplayValue)
		}
		// For env-ref auth values, we KEEP the literal — that's the whole
		// point. Hardcoded vs ${VAR} is the most important distinction in
		// the audit.
		if !strings.Contains(e.DisplayValue, "${") {
			t.Errorf("key %q: env-ref form should be preserved, got %q", e.Key, e.DisplayValue)
		}
	}

	// Auth + env-ref should still record the var name.
	for _, e := range entries {
		if e.Key == "//registry.npmjs.org/:_authToken" {
			if len(e.EnvRefVars) != 1 || e.EnvRefVars[0] != "NPM_TOKEN" {
				t.Errorf("EnvRefVars: want [NPM_TOKEN], got %v", e.EnvRefVars)
			}
		}
	}
}

func TestParseNPMRC_ArraySyntax(t *testing.T) {
	input := `ca[]=cert1
ca[]=cert2
`
	entries := parseNPMRC([]byte(input))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Key != "ca" {
			t.Errorf("expected key=ca, got %q", e.Key)
		}
		if !e.IsArray {
			t.Errorf("expected IsArray=true")
		}
	}
}

func TestParseNPMRC_QuotedValue(t *testing.T) {
	input := `node-options = "--max-old-space-size=4096 --require=/tmp/x.js"`
	entries := parseNPMRC([]byte(input))
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].Quoted {
		t.Errorf("expected Quoted=true")
	}
	if strings.HasPrefix(entries[0].DisplayValue, `"`) || strings.HasSuffix(entries[0].DisplayValue, `"`) {
		t.Errorf("quotes should be stripped from DisplayValue, got %q", entries[0].DisplayValue)
	}
}

func TestParseNPMRC_Comments(t *testing.T) {
	// Both `;` and `#` at start of line are comments; inline `;` is NOT.
	input := `; pure comment
# pure comment
key1 = value1 ; this stays in the value (npm/ini behavior)
# trailing comment line
`
	entries := parseNPMRC([]byte(input))
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (only key1), got %d: %+v", len(entries), entries)
	}
	if !strings.Contains(entries[0].DisplayValue, ";") {
		t.Errorf("inline ; should remain in value, got %q", entries[0].DisplayValue)
	}
}

func TestParseNPMRC_BOM(t *testing.T) {
	input := "\xEF\xBB\xBFregistry=https://registry.npmjs.org/"
	entries := parseNPMRC([]byte(input))
	if len(entries) != 1 || entries[0].Key != "registry" {
		t.Fatalf("BOM not stripped; got entries=%+v", entries)
	}
}

func TestParseNPMRC_EmptyAndMalformed(t *testing.T) {
	input := `
=novalue
keyonly
key=

[section]
key2=value2
`
	entries := parseNPMRC([]byte(input))
	// Expect: keyonly (empty value), key (empty value), key2=value2.
	// `=novalue` has empty key so it's skipped. `[section]` is skipped.
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	wantKeys := []string{"keyonly", "key", "key2"}
	if len(keys) != len(wantKeys) {
		t.Fatalf("want keys %v, got %v", wantKeys, keys)
	}
	for i, k := range wantKeys {
		if keys[i] != k {
			t.Errorf("position %d: want %q, got %q", i, k, keys[i])
		}
	}
}

func TestIsAuthKey(t *testing.T) {
	cases := map[string]bool{
		"//registry.npmjs.org/:_authToken":     true,
		"//npm.com/path/:_password":            true,
		"//registry.npmjs.org/:_AUTHTOKEN":     true, // case-insensitive
		"_auth":                                true, // legacy unscoped
		"username":                             true,
		"email":                                true,
		"cafile":                               true,
		"cert":                                 true, // deprecated but still flagged
		"registry":                             false,
		"@scope:registry":                      false,
		"strict-ssl":                           false,
		"ignore-scripts":                       false,
	}
	for k, want := range cases {
		if got := isAuthKey(k); got != want {
			t.Errorf("isAuthKey(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestExtractEnvRefs(t *testing.T) {
	cases := []struct {
		in       string
		wantEnv  bool
		wantVars []string
	}{
		{"plain", false, nil},
		{"${VAR}", true, []string{"VAR"}},
		{"${A}/${B}", true, []string{"A", "B"}},
		{"${VAR:-default}", true, []string{"VAR"}},
		{"${VAR?missing}", true, []string{"VAR"}},
		{"${SAME}/${SAME}", true, []string{"SAME"}}, // dedup
		{"$VAR", false, nil},                         // we only match ${...}
	}
	for _, c := range cases {
		gotVars, gotIs := extractEnvRefs(c.in)
		if gotIs != c.wantEnv {
			t.Errorf("extractEnvRefs(%q) is=%v want=%v", c.in, gotIs, c.wantEnv)
		}
		if len(gotVars) != len(c.wantVars) {
			t.Errorf("extractEnvRefs(%q) vars=%v want=%v", c.in, gotVars, c.wantVars)
			continue
		}
		for i, v := range c.wantVars {
			if gotVars[i] != v {
				t.Errorf("extractEnvRefs(%q) var[%d]=%q want %q", c.in, i, gotVars[i], v)
			}
		}
	}
}

func TestRedactSecret(t *testing.T) {
	cases := map[string]string{
		"":              "***",   // empty stays *** (defensive; redactSecret isn't called for empty in practice)
		"abc":           "***",
		"abcdefgh":      "***",   // exactly 8 chars: still ***
		"abcdefghi":     "***fghi", // 9+ chars: ***last4
		"npm_xxxxxxXYZ1234": "***1234",
	}
	for in, want := range cases {
		if got := redactSecret(in); got != want {
			t.Errorf("redactSecret(%q) = %q, want %q", in, got, want)
		}
	}
}
