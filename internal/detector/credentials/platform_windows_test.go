//go:build windows

package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

// TestContainsExpansion decides which stored values are usable as they are:
// expansion would resolve against this process, a system account, so a value
// referencing another variable would name the wrong account's directories.
func TestContainsExpansion(t *testing.T) {
	tests := map[string]bool{
		`%USERPROFILE%\.kube\config`: true,
		`C:\Users\octocat\.kube`:     false,
		`50%`:                        false,
		`50%%`:                       false,
		`%`:                          false,
		``:                           false,
		`%A%`:                        true,
		`a%b%c`:                      true,
	}
	for value, want := range tests {
		if got := containsExpansion(value); got != want {
			t.Errorf("containsExpansion(%q) = %v, want %v", value, got, want)
		}
	}
}

// TestReadUserEnvironment_RefusesWithoutAnAccount holds because the hive is keyed by
// account identifier: with none there is nothing to open, and an empty result would
// look like a machine with nothing set.
func TestReadUserEnvironment_RefusesWithoutAnAccount(t *testing.T) {
	if _, ok := readUserEnvironment("", []string{"XDG_CONFIG_HOME"}); ok {
		t.Error("a read with no account must not report success")
	}
	if _, ok := readUserEnvironment("no-such-account-b6f4c2e1", []string{"XDG_CONFIG_HOME"}); ok {
		t.Error("a read for an unknown account must not report success")
	}
}

// TestBroadReadAllowACE_ReadsARealFile covers the three-valued result: a readable
// file reports a verdict, an unreadable path reports that nothing was established
// rather than that nothing was granted.
func TestBroadReadAllowACE_ReadsARealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := broadReadAllowACE(path); got == nil {
		t.Error("a readable file must produce a verdict")
	}
	if got := broadReadAllowACE(filepath.Join(dir, "absent")); got != nil {
		t.Errorf("verdict = %v, want nil when the list could not be read", *got)
	}
}
