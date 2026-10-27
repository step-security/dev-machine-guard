//go:build !selfupdate_testkeys

package selfupdate

import "time"

// Release builds: every test-key and time-knob override is absent, so none
// of the DMG_TEST_* names exist in the binary.

func testSSHSIGKey() string                   { return "" }
func testReleaseBaseURL() string              { return "" }
func testAllowInsecureMirror() bool           { return false }
func testDuration(knob) (time.Duration, bool) { return 0, false }
