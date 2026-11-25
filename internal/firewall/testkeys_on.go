//go:build selfupdate_testkeys

package firewall

import "os"

// Test-key builds only (build tag selfupdate_testkeys, never a release):
// DMG_TEST_FIREWALL_UNSIGNED=1 accepts firewall builds that carry no signed
// checksum and no Authenticode signature, for end-to-end tests against
// unsigned firewall builds. The sha256, the zip shape and the version the exe
// reports are still checked. Release builds use testkeys_off.go.

// testkeysBuild reports a selfupdate_testkeys build.
const testkeysBuild = true

func testFirewallUnsigned() bool { return os.Getenv("DMG_TEST_FIREWALL_UNSIGNED") == "1" }
