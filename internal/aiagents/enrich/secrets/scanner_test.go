package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanTranscriptFindsKnownSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transcript.txt")
	body := strings.Join([]string{
		"hello world",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"_authToken=npm_xyz1234567890",
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIBOgIBAAJBAKj",
		"-----END RSA PRIVATE KEY-----",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := ScanTranscript(context.Background(), path)
	if info == nil || !info.Scanned {
		t.Fatal("expected scan result")
	}
	rules := map[string]bool{}
	for _, f := range info.Findings {
		rules[f.RuleID] = true
		// Findings must never carry the raw value.
		if strings.Contains(f.MaskedPreview, "wJalrXUtnFEMI/K7MDENG") {
			t.Errorf("masked preview leaks secret: %q", f.MaskedPreview)
		}
		if f.Fingerprint == "" {
			t.Errorf("missing fingerprint for %s", f.RuleID)
		}
	}
	for _, want := range []string{"aws_access_key_id", "aws_secret_access_key", "github_token", "npm_auth_token", "private_key_block"} {
		if !rules[want] {
			t.Errorf("expected rule %q to fire; got %v", want, rules)
		}
	}
}

func TestScanTranscriptDeduplicatesByFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transcript.txt")
	line := "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
	body := strings.Repeat(line, 10)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := ScanTranscript(context.Background(), path)
	hits := 0
	for _, f := range info.Findings {
		if f.RuleID == "github_token" {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("expected dedup to leave 1 github_token finding, got %d", hits)
	}
}

func TestScanTranscriptMissingFileNoError(t *testing.T) {
	info, timedOut := ScanTranscript(context.Background(), "/nonexistent/transcript.txt")
	if info != nil || timedOut {
		t.Fatalf("expected nil result for missing file, got %+v timedOut=%v", info, timedOut)
	}
}
