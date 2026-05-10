package redact

import (
	"strings"
	"testing"
)

// High-entropy values sitting on KEY=VALUE / YAML / JSON shaped lines
// must be redacted even when no specific vendor prefix matches.
func TestEntropyPassRedactsHighEntropyTokens(t *testing.T) {
	cases := []string{
		"OPAQUE_TOKEN=Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3",
		`opaque_token: Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3`,
		`{"opaque": "Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3"}`,
	}
	for _, in := range cases {
		out := String(in)
		if strings.Contains(out, "Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3") {
			t.Errorf("high-entropy token leaked: %q", out)
		}
		if !strings.Contains(out, Placeholder) {
			t.Errorf("expected placeholder, got %q", out)
		}
	}
}

// Word-like English values must pass through. Random-looking tokens
// composed of real bigrams (like brand names) are the trickiest case.
func TestEntropyPassPreservesEnglishText(t *testing.T) {
	in := "description: this is a perfectly normal English sentence with several words"
	if got := String(in); got != in {
		t.Errorf("English value over-redacted:\n  in  = %q\n  out = %q", in, got)
	}
}

// URLs and absolute paths must pass through even when they sit on a YAML
// line and are >= entropyMinLen long.
func TestEntropyPassPreservesURLsAndPaths(t *testing.T) {
	cases := []string{
		"path: /Users/foo/bar/baz.go",
		"url: https://example.com/api/v1/things",
		"home: ~/projects/dev-machine-guard/internal",
	}
	for _, in := range cases {
		if got := String(in); got != in {
			t.Errorf("path/url over-redacted:\n  in  = %q\n  out = %q", in, got)
		}
	}
}

// Array and object literals are structured non-secret payloads.
func TestEntropyPassPreservesArrayLiterals(t *testing.T) {
	cases := []string{
		`tags: ["alpha", "beta", "gamma"]`,
		`config: {host: localhost, port: 8080}`,
	}
	for _, in := range cases {
		if got := String(in); got != in {
			t.Errorf("literal over-redacted:\n  in  = %q\n  out = %q", in, got)
		}
	}
}

// Comment lines are author prose, not config values, so the entropy pass
// leaves them alone. (Specific vendor-prefix rules still apply at the rule
// pipeline, but those don't trigger on a generic high-entropy blob.)
func TestEntropyPassSkipsComments(t *testing.T) {
	cases := []string{
		"# example: OPAQUE=Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3",
		"// example: OPAQUE=Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3",
	}
	for _, in := range cases {
		if got := String(in); got != in {
			t.Errorf("comment over-redacted:\n  in  = %q\n  out = %q", in, got)
		}
	}
}

func TestEntropyPassIdempotent(t *testing.T) {
	inputs := []string{
		"OPAQUE_TOKEN=Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3",
		"description: this is a perfectly normal English sentence with several words",
		"path: /Users/foo/bar/baz.go",
		`tags: ["alpha", "beta", "gamma"]`,
	}
	for _, in := range inputs {
		once := String(in)
		twice := String(once)
		if once != twice {
			t.Errorf("entropy pass not idempotent for %q:\n  once  = %q\n  twice = %q", in, once, twice)
		}
	}
}

// Spot-check the building blocks. Keeps a regression in the heuristic
// pinpointable when the integration tests light up.
func TestEntropyHelpers(t *testing.T) {
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("entropy(empty) = %v, want 0", e)
	}
	if e := shannonEntropy("aaaaaa"); e != 0 {
		t.Errorf("entropy(constant) = %v, want 0", e)
	}
	// Mixed alphanumeric strings are well above 3 bits/char.
	if e := shannonEntropy("Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3"); e < entropyMin {
		t.Errorf("entropy(random) = %v, want >= %v", e, entropyMin)
	}

	if !looksLikeEnglish("hello") {
		t.Error("'hello' should look English")
	}
	if looksLikeEnglish("xqzkvb") {
		t.Error("'xqzkvb' should NOT look English")
	}

	if !looksLikeNonSecret("https://example.com/foo") {
		t.Error("URL must look non-secret")
	}
	if !looksLikeNonSecret("/Users/foo/bar") {
		t.Error("absolute path must look non-secret")
	}
	if !looksLikeNonSecret(`["alpha", "beta"]`) {
		t.Error("array literal must look non-secret")
	}
	if looksLikeNonSecret("Z9k2M7q4N1p8W3r6T0y5J8h2L4d7G1a3") {
		t.Error("random alnum blob must NOT look non-secret")
	}
}
