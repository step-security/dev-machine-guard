//go:build !selfupdate_testkeys

package firewall

// Release builds: the signature checks can never be skipped, and the
// DMG_TEST_FIREWALL_UNSIGNED name does not exist in the binary.

const testkeysBuild = false

func testFirewallUnsigned() bool { return false }
