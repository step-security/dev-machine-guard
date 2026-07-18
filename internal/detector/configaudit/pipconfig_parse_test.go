package configaudit

import (
	"strings"
	"testing"
)

func TestParsePipConfig_BasicSections(t *testing.T) {
	in := `[global]
index-url = https://pypi.org/simple
timeout = 60

[install]
no-build-isolation = true
`
	secs := parsePipConfig([]byte(in))
	if len(secs) != 2 {
		t.Fatalf("expected 2 sections, got %d: %+v", len(secs), secs)
	}
	if secs[0].Name != "global" || secs[1].Name != "install" {
		t.Errorf("section names wrong: %+v", []string{secs[0].Name, secs[1].Name})
	}
	if len(secs[0].Entries) != 2 {
		t.Errorf("expected 2 entries in [global], got %+v", secs[0].Entries)
	}
	// Spot-check a value.
	for _, e := range secs[0].Entries {
		if e.Key == "index-url" {
			if len(e.Values) != 1 || e.Values[0] != "https://pypi.org/simple" {
				t.Errorf("index-url value wrong: %+v", e)
			}
		}
	}
}

func TestParsePipConfig_MultiValue(t *testing.T) {
	in := `[global]
trusted-host =
    a.example.com
    b.example.com
    c.example.com
find-links =
    https://mirror1.example.com
    https://mirror2.example.com
`
	secs := parsePipConfig([]byte(in))
	if len(secs) != 1 || len(secs[0].Entries) != 2 {
		t.Fatalf("unexpected structure: %+v", secs)
	}
	for _, e := range secs[0].Entries {
		switch e.Key {
		case "trusted-host":
			if len(e.Values) != 3 {
				t.Errorf("trusted-host: want 3 values, got %v", e.Values)
			}
			if e.Values[0] != "a.example.com" || e.Values[2] != "c.example.com" {
				t.Errorf("trusted-host values wrong: %v", e.Values)
			}
		case "find-links":
			if len(e.Values) != 2 {
				t.Errorf("find-links: want 2 values, got %v", e.Values)
			}
		}
	}
}

func TestParsePipConfig_CommentsBoth(t *testing.T) {
	in := `; comment 1
[global]
# comment 2
index-url = https://pypi.org/simple
`
	secs := parsePipConfig([]byte(in))
	if len(secs) != 1 || len(secs[0].Entries) != 1 {
		t.Fatalf("comments not skipped correctly: %+v", secs)
	}
}

func TestParsePipConfig_NoEnvInterpolation(t *testing.T) {
	// pip does NOT expand ${VAR}. Our parser must propagate it verbatim.
	in := `[global]
index-url = https://${INTERNAL_INDEX_HOST}/simple
`
	secs := parsePipConfig([]byte(in))
	if len(secs) != 1 || len(secs[0].Entries) != 1 {
		t.Fatalf("structure: %+v", secs)
	}
	if !strings.Contains(secs[0].Entries[0].Values[0], "${INTERNAL_INDEX_HOST}") {
		t.Errorf("env-ref form not preserved: %v", secs[0].Entries[0])
	}
}

func TestParsePipConfig_ColonSeparator(t *testing.T) {
	// configparser supports `key: value` as well as `key = value`.
	in := `[global]
index-url: https://pypi.org/simple
`
	secs := parsePipConfig([]byte(in))
	if len(secs) != 1 || len(secs[0].Entries) != 1 || secs[0].Entries[0].Values[0] != "https://pypi.org/simple" {
		t.Fatalf("colon separator not handled: %+v", secs)
	}
}

func TestParsePipConfig_BOMStrippedAndDisplayRedacts(t *testing.T) {
	// NB: editor tooling auto-rewrites the literal string "user@host" forms
	// into markdown email-protection links. Build the input via fmt to
	// dodge that.
	const at = "@"
	in := "\xEF\xBB\xBF[global]\nextra-index-url = https://user:secret" + at + "internal.example.com/simple\n"
	secs := parsePipConfig([]byte(in))
	if len(secs) != 1 || len(secs[0].Entries) != 1 {
		t.Fatalf("BOM/sections wrong: %+v", secs)
	}
	d := secs[0].Entries[0].Display
	if strings.Contains(d, "secret") {
		t.Errorf("Display leaks credential: %q", d)
	}
	if !strings.Contains(d, "user:****"+at+"internal.example.com") {
		t.Errorf("Display should redact to user:****%shost form, got %q", at, d)
	}
}

func TestRedactCredsInValue(t *testing.T) {
	const at = "@"
	cases := []struct{ in, want string }{
		{"https://pypi.org/simple", "https://pypi.org/simple"},
		{"https://alice" + at + "internal.example.com/simple", "https://****" + at + "internal.example.com/simple"},
		{"https://alice:secret" + at + "internal.example.com/simple", "https://alice:****" + at + "internal.example.com/simple"},
		{"http://__token__:pypi-AgEI..." + at + "upload.pypi.org/", "http://__token__:****" + at + "upload.pypi.org/"},
		// Malformed value with several user:pass@host runs concatenated
		// before the real host (a real customer had this shape in a pip
		// index-url, with a live Azure DevOps PAT as the last segment). The
		// userinfo is everything up to the *last* @, and because it contains
		// extra @s we can't safely pick out a username, so the whole run is
		// masked — no segment survives into the output.
		{"https://user" + at + "corp.com:pass1" + at + "corp.com:TOKENabc123" + at + "corp.pkgs.visualstudio.com/_packaging/feed/pypi/simple/",
			"https://****" + at + "corp.pkgs.visualstudio.com/_packaging/feed/pypi/simple/"},
		// An @ in the path or query is not userinfo and must be left alone.
		{"https://pypi.org/simple?contact=me" + at + "corp.com", "https://pypi.org/simple?contact=me" + at + "corp.com"},
		{"not-a-url", "not-a-url"},
	}
	for _, c := range cases {
		got := redactCredsInValue(c.in)
		if got != c.want {
			t.Errorf("redactCredsInValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRedactCredsInValue_MultiAtNoLeak is a focused regression guard for the
// credential leak where a malformed multi-@ authority left every segment after
// the first @ verbatim in the "safe" output. No credential run may appear
// anywhere in the redacted string.
func TestRedactCredsInValue_MultiAtNoLeak(t *testing.T) {
	const at = "@"
	in := "https://user" + at + "corp.com:pass1" + at + "corp.com:TOKENabc123" + at + "corp.pkgs.visualstudio.com/_packaging/feed/pypi/simple/"
	got := redactCredsInValue(in)
	for _, secret := range []string{"pass1", "TOKENabc123"} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted value leaks %q: got %q", secret, got)
		}
	}
	if !strings.HasPrefix(got, "https://****"+at+"corp.pkgs.visualstudio.com/") {
		t.Errorf("real host not preserved after redaction: got %q", got)
	}
}

func TestUrlIsHTTP(t *testing.T) {
	cases := map[string]bool{
		"http://example.com":  true,
		"https://example.com": false,
		"file:///etc/x":       false,
		"not-a-url":           false,
		"HTTP://EXAMPLE.COM":  true, // case-insensitive scheme
	}
	for in, want := range cases {
		if got := urlIsHTTP(in); got != want {
			t.Errorf("urlIsHTTP(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPipKeyEnvNameRoundTrip(t *testing.T) {
	cases := []struct{ key, env string }{
		{"index-url", "PIP_INDEX_URL"},
		{"no-build-isolation", "PIP_NO_BUILD_ISOLATION"},
		{"trusted-host", "PIP_TRUSTED_HOST"},
	}
	for _, c := range cases {
		if got := pipEnvNameForKey(c.key); got != c.env {
			t.Errorf("pipEnvNameForKey(%q) = %q, want %q", c.key, got, c.env)
		}
		if got := pipKeyForEnvName(c.env); got != c.key {
			t.Errorf("pipKeyForEnvName(%q) = %q, want %q", c.env, got, c.key)
		}
	}
	// Non-PIP_ env name returns unchanged.
	if got := pipKeyForEnvName("HTTP_PROXY"); got != "HTTP_PROXY" {
		t.Errorf("non-PIP_ name should round-trip unchanged, got %q", got)
	}
}
