//go:build selfupdate_testkeys

package selfupdate

import (
	"os"
	"strings"
	"time"
)

// Test-key builds (spec Contracts, build tag selfupdate_testkeys) take the
// SSHSIG key, the GitHub release base and the time constants from DMG_TEST_*
// env. Release builds use testkeys_off.go.

// testSSHSIGKey accepts the base64 wire blob or a whole
// "ssh-ed25519 <blob> [comment]" public-key line.
func testSSHSIGKey() string {
	v := strings.TrimSpace(os.Getenv("DMG_TEST_SSHSIG_PUBKEY"))
	if f := strings.Fields(v); len(f) >= 2 && f[0] == keyTypeEd {
		return f[1]
	}
	return v
}

func testReleaseBaseURL() string { return strings.TrimSpace(os.Getenv("DMG_TEST_RELEASE_BASE_URL")) }

// testAllowInsecureMirror lets a fake mirror on http://127.0.0.1 serve assets.
func testAllowInsecureMirror() bool { return os.Getenv("DMG_TEST_ALLOW_HTTP_MIRROR") == "1" }

var knobEnv = map[knob]string{
	knobProbationWindow: "DMG_TEST_PROBATION_WINDOW",
	knobSwitchWait:      "DMG_TEST_SWITCH_WAIT",
	knobDedupeWindow:    "DMG_TEST_DEDUPE_WINDOW",
	knobCheckInterval:   "DMG_TEST_CHECK_INTERVAL",
	knobSmokeTimeout:    "DMG_TEST_SMOKE_TIMEOUT",
	knobSendBackoff:     "DMG_TEST_SEND_BACKOFF",
}

// testDuration reads a Go duration knob such as DMG_TEST_PROBATION_WINDOW.
func testDuration(k knob) (time.Duration, bool) {
	v := strings.TrimSpace(os.Getenv(knobEnv[k]))
	if v == "" {
		return 0, false
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, false
	}
	return d, true
}
