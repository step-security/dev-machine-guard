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
