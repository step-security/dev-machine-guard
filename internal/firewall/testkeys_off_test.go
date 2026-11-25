//go:build !selfupdate_testkeys

package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/fwpath"
)

// A release build ignores DMG_TEST_FIREWALL_UNSIGNED: the hook is a constant
// false, and an unsigned release or a wrong publisher is still refused.
func TestTestKeys_ReleaseBuildCannotSkip(t *testing.T) {
	t.Setenv("DMG_TEST_FIREWALL_UNSIGNED", "1")
	if testkeysBuild || testFirewallUnsigned() {
		t.Fatal("a release build can skip the firewall signature checks")
	}
	for _, tc := range []struct {
		name, signed string
		pubErr       error
		code         string
	}{
		{"no signed checksum", "", nil, CodeResponseInvalid},
		{"unsigned exe", testSigned, errors.New("not signed"), CodeAuthenticodeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, testEndpoint)
			h.m.WantInstall = true
			h.pubErr = tc.pubErr
			h.serve("0.2.0", "42", makeZip(t, map[string][]byte{fwpath.ExeName: exeContent("0.2.0", "42", false)}), tc.signed)
			if got := h.m.Reconcile(context.Background()); got != OutcomeFailed {
				t.Fatalf("Reconcile = %s", got)
			}
			h.wantReports(tc.code)
			for _, l := range h.logs {
				if strings.Contains(l, "DMG_TEST_FIREWALL_UNSIGNED") {
					t.Errorf("release build logged the test override: %q", l)
				}
			}
		})
	}
}
