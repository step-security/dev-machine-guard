//go:build selfupdate_testkeys

package authenticode

import (
	"os"
	"strings"
)

// testPinnedSubject is the expected publisher subject for test-signed
// fixtures (spec Contracts: test keys).
func testPinnedSubject() string {
	return strings.TrimSpace(os.Getenv("DMG_TEST_AUTHENTICODE_SUBJECT"))
}
