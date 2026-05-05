package redact

import (
	"strings"
	"testing"
)

func TestStringRedactsCommonSecrets(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// substrings that must NOT appear in the redacted output.
		mustNotContain []string
	}{
		{
			name:           "stepsecurity api key",
			in:             `STEPSECURITY_API_KEY=ss_live_AbCdEfGhIjKlMnOp`,
			mustNotContain: []string{"ss_live_AbCdEfGhIjKlMnOp"},
		},
		{
			name:           "npm authToken",
			in:             "//registry.npmjs.org/:_authToken=npm_xyzabc1234567890",
			mustNotContain: []string{"npm_xyzabc1234567890"},
		},
		{
			name:           "npm _auth",
			in:             "_auth=dXNlcjpwYXNzd29yZA==",
			mustNotContain: []string{"dXNlcjpwYXNzd29yZA=="},
		},
		{
			name:           "bearer header",
			in:             "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
			mustNotContain: []string{"eyJhbGciOiJIUzI1NiJ9.payload.sig"},
		},
		{
			name:           "aws access key",
			in:             "key AKIAIOSFODNN7EXAMPLE here",
			mustNotContain: []string{"AKIAIOSFODNN7EXAMPLE"},
		},
		{
			name:           "aws secret key",
			in:             `AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			mustNotContain: []string{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		},
		{
			name:           "password assignment",
			in:             "DB_PASSWORD=hunter2",
			mustNotContain: []string{"hunter2"},
		},
		{
			name:           "token assignment",
			in:             "GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			mustNotContain: []string{"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
		{
			name:           "secret assignment",
			in:             "JWT_SECRET=topsecretvalue",
			mustNotContain: []string{"topsecretvalue"},
		},
		{
			name:           "api key assignment",
			in:             "OPENAI_API_KEY=sk-proj-1234567890abcdef",
			mustNotContain: []string{"sk-proj-1234567890abcdef"},
		},
		{
			name:           "bare password assignment",
			in:             "PASSWORD=hunter2",
			mustNotContain: []string{"hunter2"},
		},
		{
			name:           "bare token assignment",
			in:             "TOKEN=abc123def456",
			mustNotContain: []string{"abc123def456"},
		},
		{
			name:           "bare api key assignment",
			in:             "API_KEY=sk-proj-bare123456",
			mustNotContain: []string{"sk-proj-bare123456"},
		},
		{
			name: "private key block",
			in: "-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIBOgIBAAJBAKj\n" +
				"-----END RSA PRIVATE KEY-----",
			mustNotContain: []string{"MIIBOgIBAAJBAKj"},
		},
		{
			name:           "url userinfo",
			in:             "fetched https://alice:s3cret@api.example.com:8443/users",
			mustNotContain: []string{"alice:s3cret", "s3cret"},
		},
		{
			name:           "url query token",
			in:             "redirect to https://example.com/cb?token=abc123def456 then proceed",
			mustNotContain: []string{"abc123def456"},
		},
		{
			name:           "url query access_token",
			in:             "https://api.example.com/me?access_token=zzzzz&user=alice",
			mustNotContain: []string{"zzzzz"},
		},
		{
			name:           "url query refresh_token",
			in:             "https://api.example.com/cb?refresh_token=rrrrr",
			mustNotContain: []string{"rrrrr"},
		},
		{
			name:           "url query id_token",
			in:             "https://idp.example.com/cb?id_token=jjjjj",
			mustNotContain: []string{"jjjjj"},
		},
		{
			name:           "url query client_secret",
			in:             "https://idp.example.com/token?client_id=app&client_secret=ssssss",
			mustNotContain: []string{"ssssss"},
		},
		{
			name:           "url query oauth code",
			in:             "https://app.example.com/cb?code=AUTHCODEABC&state=xyz",
			mustNotContain: []string{"AUTHCODEABC"},
		},
		{
			name:           "url query oauth state",
			in:             "https://app.example.com/cb?state=opaqueSESSION123",
			mustNotContain: []string{"opaqueSESSION123"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := String(tc.in)
			if !strings.Contains(out, Placeholder) {
				t.Fatalf("expected redaction placeholder in output; got %q", out)
			}
			for _, banned := range tc.mustNotContain {
				if strings.Contains(out, banned) {
					t.Fatalf("redacted output still contains %q: %q", banned, out)
				}
			}
		})
	}
}

func TestStringPreservesNonSecrets(t *testing.T) {
	cases := []string{
		"user ran: npm install lodash",
		// URL with no userinfo or credential query params must pass through.
		"https://api.example.com:8443/v1/users?user=alice&limit=10",
		// Param names that merely *contain* a keyword fragment but do not
		// end on it must NOT be redacted (e.g. statefulservice contains
		// "state", client_id is public).
		"https://api.example.com/v1?statefulservice=true",
		"https://idp.example.com/authorize?client_id=public_app_id",
	}
	for _, in := range cases {
		if got := String(in); got != in {
			t.Errorf("expected unchanged, got %q", got)
		}
	}
}

// URL userinfo redaction must keep the host portion intact so the
// audit log still shows where traffic went.
func TestStringRedactsURLUserinfoKeepsHost(t *testing.T) {
	got := String("https://user:secret@mcp.example.com:8443/path")
	if !strings.Contains(got, "mcp.example.com:8443") {
		t.Errorf("host stripped: %q", got)
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "user:") {
		t.Errorf("userinfo leaked: %q", got)
	}
}

func TestValueRedactsNestedSecrets(t *testing.T) {
	in := map[string]any{
		"command": "git push",
		"env": map[string]any{
			"GITHUB_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"USER":         "alice",
		},
		"headers": []any{
			"Authorization: Bearer eyJ.payload.sig",
		},
	}
	out := Value(in).(map[string]any)
	env := out["env"].(map[string]any)
	if env["GITHUB_TOKEN"] != Placeholder {
		t.Fatalf("expected GITHUB_TOKEN redacted by key, got %v", env["GITHUB_TOKEN"])
	}
	if env["USER"] != "alice" {
		t.Fatalf("expected USER preserved, got %v", env["USER"])
	}
	hdr := out["headers"].([]any)[0].(string)
	if strings.Contains(hdr, "eyJ.payload.sig") {
		t.Fatalf("bearer not redacted in nested array: %q", hdr)
	}
}

func TestStringIsIdempotent(t *testing.T) {
	// Running redaction twice must produce the same output as running it
	// once. Re-running is the simplest way for a caller (e.g., the error
	// logger) to be sure a previously-redacted string isn't double-mangled.
	inputs := []string{
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"https://alice:s3cret@api.example.com/users",
		"plain log line with no secrets",
		"",
	}
	for _, in := range inputs {
		once := String(in)
		twice := String(once)
		if once != twice {
			t.Errorf("not idempotent for %q:\n  once  = %q\n  twice = %q", in, once, twice)
		}
	}
}

func TestStringRedactsMultipleSecretsInOneInput(t *testing.T) {
	in := "AKIAIOSFODNN7EXAMPLE then ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa then bearer eyJ.payload.sig.AAAAAAAAAAA"
	out := String(in)
	for _, banned := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"eyJ.payload.sig.AAAAAAAAAAA",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("multi-secret line still contains %q: %q", banned, out)
		}
	}
}

func TestStringRedactsGitHubFineGrainedPAT(t *testing.T) {
	// Fine-grained PATs use a different prefix from classic ghp_ tokens
	// and contain an inner underscore between the prefix and body.
	in := "GH_TOKEN=github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"
	out := String(in)
	if strings.Contains(out, "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN") {
		t.Errorf("github fine-grained PAT not redacted: %q", out)
	}
}

func TestStringRedactsPrivateKeyVariants(t *testing.T) {
	// All four PEM/armor variants the audit pipeline can plausibly see
	// must redact the whole block, not just one BEGIN/END line.
	cases := []struct {
		name    string
		in      string
		mustOut string // body content that must NOT appear after redaction
	}{
		{
			name:    "RSA",
			in:      "-----BEGIN RSA PRIVATE KEY-----\nBODYRSA\n-----END RSA PRIVATE KEY-----",
			mustOut: "BODYRSA",
		},
		{
			name:    "PKCS8",
			in:      "-----BEGIN PRIVATE KEY-----\nBODYPKCS8\n-----END PRIVATE KEY-----",
			mustOut: "BODYPKCS8",
		},
		{
			name:    "OPENSSH",
			in:      "-----BEGIN OPENSSH PRIVATE KEY-----\nBODYSSH\n-----END OPENSSH PRIVATE KEY-----",
			mustOut: "BODYSSH",
		},
		{
			name:    "PGP",
			in:      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nBODYPGP\n-----END PGP PRIVATE KEY BLOCK-----",
			mustOut: "BODYPGP",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := String(tc.in)
			if strings.Contains(out, tc.mustOut) {
				t.Errorf("%s body leaked: %q", tc.name, out)
			}
			if !strings.Contains(out, Placeholder) {
				t.Errorf("%s missing placeholder: %q", tc.name, out)
			}
		})
	}
}

func TestBytesWrapsString(t *testing.T) {
	// Bytes is a thin wrapper. Test the three input shapes a caller can
	// hand it: nil, empty slice, populated.
	if got := Bytes(nil); got != nil {
		t.Errorf("Bytes(nil) = %v, want nil", got)
	}
	if got := Bytes([]byte{}); len(got) != 0 {
		t.Errorf("Bytes(empty) = %v, want empty", got)
	}
	in := []byte("Authorization: Bearer eyJ.payload.sig.AAAAAAAAAAA")
	out := Bytes(in)
	if strings.Contains(string(out), "eyJ.payload.sig.AAAAAAAAAAA") {
		t.Errorf("Bytes did not redact: %q", string(out))
	}
}

func TestValueHandlesNonStringLeaves(t *testing.T) {
	// Numbers, booleans, and nil must pass through untouched. Only string
	// leaves get redacted.
	in := map[string]any{
		"count":   42,
		"ratio":   0.5,
		"flag":    true,
		"missing": nil,
		"note":    "no secret here",
	}
	out := Value(in).(map[string]any)
	if out["count"] != 42 {
		t.Errorf("int leaf mutated: %v", out["count"])
	}
	if out["ratio"] != 0.5 {
		t.Errorf("float leaf mutated: %v", out["ratio"])
	}
	if out["flag"] != true {
		t.Errorf("bool leaf mutated: %v", out["flag"])
	}
	if out["missing"] != nil {
		t.Errorf("nil leaf mutated: %v", out["missing"])
	}
	if out["note"] != "no secret here" {
		t.Errorf("clean string leaf mutated: %v", out["note"])
	}
}

func TestValueRedactsSecretKeyEvenWithNonStringValue(t *testing.T) {
	// A secret-looking key replaces the value with [REDACTED] regardless
	// of value type — a numeric token is still a token.
	in := map[string]any{
		"token":  12345,
		"secret": []any{"a", "b"},
		"safe":   "ok",
	}
	out := Value(in).(map[string]any)
	if out["token"] != Placeholder {
		t.Errorf("numeric token not redacted: %v", out["token"])
	}
	if out["secret"] != Placeholder {
		t.Errorf("array under secret key not redacted: %v", out["secret"])
	}
	if out["safe"] != "ok" {
		t.Errorf("safe leaf mutated: %v", out["safe"])
	}
}

func TestValueDeeplyNested(t *testing.T) {
	// Three-level nesting through both maps and slices. Redaction must
	// reach the innermost string.
	in := map[string]any{
		"l1": map[string]any{
			"l2": []any{
				map[string]any{
					"headers": []any{
						"Authorization: Bearer eyJ.payload.sig.AAAAAAAAAAA",
					},
				},
			},
		},
	}
	out := Value(in).(map[string]any)
	l1 := out["l1"].(map[string]any)
	l2 := l1["l2"].([]any)
	l3 := l2[0].(map[string]any)
	hdr := l3["headers"].([]any)[0].(string)
	if strings.Contains(hdr, "eyJ.payload.sig.AAAAAAAAAAA") {
		t.Errorf("deeply nested bearer not redacted: %q", hdr)
	}
}

func TestIsSensitivePathWindowsBackslash(t *testing.T) {
	// IsSensitivePath normalizes backslashes so a Windows path hits the
	// same regexes as the POSIX equivalent.
	for _, p := range []string{
		`C:\Users\x\.env`,
		`C:\Users\x\.aws\credentials`,
		`C:\Users\x\.ssh\id_rsa`,
		`secrets\db.yaml`,
	} {
		if !IsSensitivePath(p) {
			t.Errorf("expected %q (Windows-style) to be sensitive", p)
		}
	}
}

func TestIsSensitivePathEmpty(t *testing.T) {
	if IsSensitivePath("") {
		t.Error("empty path must not be flagged sensitive")
	}
}

func TestIsSensitivePath(t *testing.T) {
	yes := []string{
		"/Users/x/.env",
		"./.env.production",
		"app/secrets/db.yaml",
		"keys/server.pem",
		"id_rsa.key",
		"cert.p12",
		"/home/x/.ssh/id_rsa",
		"/Users/x/.aws/credentials",
		"./.npmrc",
		"./.pypirc",
	}
	for _, p := range yes {
		if !IsSensitivePath(p) {
			t.Errorf("expected %q to be sensitive", p)
		}
	}
	no := []string{"README.md", "src/main.go", "config.json"}
	for _, p := range no {
		if IsSensitivePath(p) {
			t.Errorf("expected %q to NOT be sensitive", p)
		}
	}
}
