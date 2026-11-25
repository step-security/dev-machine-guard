//go:build selfupdate_testkeys

package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/fwpath"
)

// In a test-key build DMG_TEST_FIREWALL_UNSIGNED=1 skips the signed checksum
// and Authenticode (with a warning each time); sha256, the zip shape and the
// exe's version are still enforced. Without it nothing is skipped.
func TestTestKeys_UnsignedOverride(t *testing.T) {
	if !testkeysBuild {
		t.Fatal("testkeys_on.go not compiled in")
	}
	exe := exeContent("0.2.0", "42", false)
	for _, tc := range []struct {
		name  string
		env   string
		zip   func(t *testing.T) []byte
		sum   string
		want  Outcome
		code  string
		warns int
	}{
		{"unsigned build accepted", "1", func(t *testing.T) []byte { return makeZip(t, map[string][]byte{fwpath.ExeName: exe}) }, "", OutcomeInstalled, "", 2},
		{"override off", "", func(t *testing.T) []byte { return makeZip(t, map[string][]byte{fwpath.ExeName: exe}) }, "", OutcomeFailed, CodeResponseInvalid, 0},
		{"other value", "true", func(t *testing.T) []byte { return makeZip(t, map[string][]byte{fwpath.ExeName: exe}) }, "", OutcomeFailed, CodeResponseInvalid, 0},
		{"sha256 still checked", "1", func(t *testing.T) []byte { return makeZip(t, map[string][]byte{fwpath.ExeName: exe}) }, strings.Repeat("0", 64), OutcomeFailed, CodeChecksumMismatch, 1},
		{"zip shape still checked", "1", func(t *testing.T) []byte {
			return makeZip(t, map[string][]byte{fwpath.ExeName: exe, "extra.txt": []byte("x")})
		}, "", OutcomeFailed, CodeUnpackFailed, 1},
		{"version still checked", "1", func(t *testing.T) []byte {
			return makeZip(t, map[string][]byte{fwpath.ExeName: exeContent("0.2.0", "41", false)})
		}, "", OutcomeFailed, CodeBuildMismatch, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DMG_TEST_FIREWALL_UNSIGNED", tc.env)
			h := newHarness(t, testEndpoint)
			h.m.WantInstall = true
			h.sigErr, h.pubErr = errors.New("bad signature"), errors.New("not signed")
			h.serve("0.2.0", "42", tc.zip(t), "") // unsigned: no signed_checksum
			if tc.sum != "" {
				inner := h.api.latest
				h.api.latest = func() (int, any) {
					_, r := inner()
					r.(map[string]any)["checksum"] = tc.sum
					return 200, r
				}
			}
			if got := h.m.Reconcile(context.Background()); got != tc.want {
				t.Fatalf("Reconcile = %s, reports %q", got, h.reports)
			}
			if tc.code == "" {
				h.wantReports()
			} else {
				h.wantReports(tc.code)
			}
			warns := 0
			for _, l := range h.logs {
				if strings.Contains(l, "WARNING: test-key build with DMG_TEST_FIREWALL_UNSIGNED=1") {
					warns++
				}
			}
			if warns != tc.warns {
				t.Errorf("%d warning lines, want %d: %q", warns, tc.warns, h.logs)
			}
			if tc.want != OutcomeInstalled && fileExists(h.m.exe()) {
				t.Error("a rejected exe was installed")
			}
		})
	}
}
