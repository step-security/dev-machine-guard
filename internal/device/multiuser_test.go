package device

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// withMachineStateDir points the shared-host files at a temp dir and stubs
// the Windows edition probe for the test's duration.
func withMachineStateDir(t *testing.T, edition string, tsAppCompat bool) string {
	t.Helper()
	dir := t.TempDir()
	restore := SetMachineStateDirForTest(dir)
	prevProbe := probeWindowsEdition
	probeWindowsEdition = func() (string, bool) { return edition, tsAppCompat }
	t.Cleanup(func() { restore(); probeWindowsEdition = prevProbe })
	return dir
}

func windowsMock(username string) *executor.Mock {
	m := executor.NewMock()
	m.SetGOOS(model.PlatformWindows)
	m.SetHostname("AVD-HOST-07")
	m.SetUsername(username)
	return m
}

func TestMultiUserHost(t *testing.T) {
	tests := []struct {
		name        string
		edition     string
		tsAppCompat bool
		seen        []string
		marker      bool
		want        bool
		wantReason  string
	}{
		{"plain pro, one user", "Professional", false, []string{"jdoe"}, false, false, ""},
		{"plain pro, nobody seen", "Professional", false, nil, false, false, ""},
		{"enterprise multi-session", "EnterpriseMultiSession", false, nil, false, true, "edition"},
		{"server rdsh, case-insensitive", "serverrdsh", false, nil, false, true, "edition"},
		{"rd session host role", "ServerStandard", true, nil, false, true, "edition"},
		{"second user seen", "Professional", false, []string{"jdoe", "asmith"}, false, true, "users"},
		{"marker already set wins", "Professional", false, nil, true, true, "marker"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := multiUserHost(tc.edition, tc.tsAppCompat, tc.seen, tc.marker)
			if got != tc.want || reason != tc.wantReason {
				t.Errorf("multiUserHost() = %v, %q; want %v, %q", got, reason, tc.want, tc.wantReason)
			}
		})
	}
}

func TestSeenUsers_AppendDedupAndBounds(t *testing.T) {
	dir := t.TempDir()
	for _, u := range []string{"jdoe", "JDoe", "  jdoe ", "asmith"} {
		if err := appendSeenUser(dir, u); err != nil {
			t.Fatal(err)
		}
	}
	if got := readSeenUsers(dir); strings.Join(got, ",") != "jdoe,asmith" {
		t.Errorf("readSeenUsers = %v, want [jdoe asmith]", got)
	}
	if err := appendSeenUser(dir, ""); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, seenUsersFile))
	if strings.Count(string(data), "\n") != 2 {
		t.Errorf("file must hold exactly the two distinct tokens:\n%s", data)
	}
	// Oversized file reads as empty rather than being parsed.
	if err := os.WriteFile(filepath.Join(dir, seenUsersFile), []byte(strings.Repeat("x\n", maxSeenUsersBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readSeenUsers(dir); len(got) != 0 {
		t.Errorf("oversized file must read as empty, got %d users", len(got))
	}
	if got := readSeenUsers(""); got != nil {
		t.Errorf("empty dir must read as nil, got %v", got)
	}
}

func TestMultiUserMarker_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok := readMultiUserMarker(dir); ok {
		t.Fatal("no marker yet")
	}
	if err := writeMultiUserMarker(dir, multiUserMarker{Since: 42, Reason: autoReasonUsers}); err != nil {
		t.Fatal(err)
	}
	m, ok := readMultiUserMarker(dir)
	if !ok || m.Since != 42 || m.Reason != autoReasonUsers || m.RetiredSerialID != "" {
		t.Fatalf("marker round trip = %+v, %v", m, ok)
	}
	// Garbage is ignored, never fatal.
	if err := os.WriteFile(filepath.Join(dir, multiUserMarkerFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readMultiUserMarker(dir); ok {
		t.Error("corrupt marker must read as absent")
	}
}

func TestAutoIdentity_MultiSessionEditionFromFirstScan(t *testing.T) {
	dir := withMachineStateDir(t, "EnterpriseMultiSession", false)
	withConfigDeviceID(t, "")
	mock := windowsMock(`AVD-HOST-07\jdoe`)

	id := ResolveIdentity(mock, "SER1", "AVD-HOST-07", `AVD-HOST-07\jdoe`)
	if id.Source != IdentitySourceAuto || id.DeviceID != "avd-host-07-jdoe" || !id.PerUser || id.UserScope != "jdoe" {
		t.Fatalf("auto identity = %+v", id)
	}
	if id.AutoReason != "multi-session edition" {
		t.Errorf("AutoReason = %q", id.AutoReason)
	}
	if _, ok := readMultiUserMarker(dir); !ok {
		t.Error("first positive decision must write the sticky marker")
	}
	if scope := IdentityUserScope(mock); scope != "jdoe" {
		t.Errorf("IdentityUserScope = %q, want jdoe", scope)
	}
	if reason := AutoIdentityReason(mock); reason != "multi-session edition" {
		t.Errorf("AutoIdentityReason = %q", reason)
	}
}

func TestAutoIdentity_SecondUserFlipsAndSticks(t *testing.T) {
	dir := withMachineStateDir(t, "Professional", false)
	withConfigDeviceID(t, "")

	first := windowsMock(`HOST\jdoe`)
	RecordScanUser(first)
	if id := ResolveIdentity(first, "SER1", "HOST", `HOST\jdoe`); id.Source != IdentitySourceSerial || id.DeviceID != "SER1" {
		t.Fatalf("single user must keep the serial identity: %+v", id)
	}

	second := windowsMock(`HOST\asmith`)
	RecordScanUser(second)
	id := ResolveIdentity(second, "SER1", "HOST", `HOST\asmith`)
	if id.Source != IdentitySourceAuto || id.DeviceID != "host-asmith" || id.AutoReason != "2+ users seen" {
		t.Fatalf("second user must flip to per-user: %+v", id)
	}
	m, ok := readMultiUserMarker(dir)
	if !ok || m.Reason != autoReasonUsers {
		t.Fatalf("marker = %+v, %v", m, ok)
	}

	// Sticky: even with the seen-users file gone, the marker keeps it on.
	if err := os.Remove(filepath.Join(dir, seenUsersFile)); err != nil {
		t.Fatal(err)
	}
	if id := ResolveIdentity(first, "SER1", "HOST", `HOST\jdoe`); id.Source != IdentitySourceAuto || id.DeviceID != "host-jdoe" {
		t.Fatalf("marker must keep the host multi-user: %+v", id)
	}
}

func TestAutoIdentity_PrecedenceAndEscapes(t *testing.T) {
	withMachineStateDir(t, "EnterpriseMultiSession", false)
	mock := windowsMock(`HOST\jdoe`)

	withConfigDeviceID(t, "{serial}")
	if id := ResolveIdentity(mock, "SER1", "HOST", `HOST\jdoe`); id.Source != IdentitySourceConfig || id.DeviceID != "SER1" {
		t.Errorf("{serial} must force the serial identity: %+v", id)
	}
	withConfigDeviceID(t, "fleet-123")
	if id := ResolveIdentity(mock, "SER1", "HOST", `HOST\jdoe`); id.Source != IdentitySourceConfig || id.DeviceID != "fleet-123" {
		t.Errorf("config literal must beat auto: %+v", id)
	}
	withConfigDeviceID(t, "")
	mock.SetEnv(EnvDeviceID, "{hostname}")
	if id := ResolveIdentity(mock, "SER1", "HOST", `HOST\jdoe`); id.Source != IdentitySourceEnv || id.DeviceID != "host" {
		t.Errorf("env must beat auto: %+v", id)
	}
}

func TestAutoIdentity_OffOutsideWindowsAndWithoutMachineDir(t *testing.T) {
	withMachineStateDir(t, "EnterpriseMultiSession", false)
	withConfigDeviceID(t, "")
	mac := executor.NewMock()
	mac.SetGOOS(model.PlatformDarwin)
	mac.SetUsername("jdoe")
	if id := ResolveIdentity(mac, "C02XYZ", "mbp", "jdoe"); id.Source != IdentitySourceSerial || id.DeviceID != "C02XYZ" {
		t.Errorf("auto must be off on macOS: %+v", id)
	}
	restore := SetMachineStateDirForTest("")
	t.Cleanup(restore)
	win := windowsMock(`HOST\jdoe`)
	if id := ResolveIdentity(win, "SER1", "HOST", `HOST\jdoe`); id.Source != IdentitySourceSerial {
		t.Errorf("auto must be off without a machine-wide state dir: %+v", id)
	}
}

func TestRecordScanUser_SkipsServiceAccounts(t *testing.T) {
	dir := withMachineStateDir(t, "Professional", false)
	RecordScanUser(windowsMock(`NT AUTHORITY\SYSTEM`))
	RecordScanUser(windowsMock(`HOST\HOST$`))
	if got := readSeenUsers(dir); len(got) != 0 {
		t.Errorf("service accounts must not be recorded, got %v", got)
	}
	RecordScanUser(windowsMock(`CONTOSO\JDoe`))
	if got := readSeenUsers(dir); strings.Join(got, ",") != "jdoe" {
		t.Errorf("readSeenUsers = %v", got)
	}
}

func TestSerialRowRetirePending_AndMark(t *testing.T) {
	dir := withMachineStateDir(t, "Professional", false)
	if SerialRowRetirePending("SER1", "") {
		t.Error("no marker: nothing pending")
	}
	if err := writeMultiUserMarker(dir, multiUserMarker{Since: 1, Reason: autoReasonEdition}); err != nil {
		t.Fatal(err)
	}
	if SerialRowRetirePending("SER1", "") {
		t.Error("edition switch with no prior serial run: nothing to retire")
	}
	if !SerialRowRetirePending("SER1", "SER1") {
		t.Error("machine last-run under the serial proves a row exists")
	}
	if err := writeMultiUserMarker(dir, multiUserMarker{Since: 1, Reason: autoReasonUsers}); err != nil {
		t.Fatal(err)
	}
	if !SerialRowRetirePending("SER1", "") {
		t.Error("a second user implies the first scanned under the serial")
	}
	if SerialRowRetirePending("unknown", "") {
		t.Error("an unusable serial has no row to retire")
	}
	if err := MarkSerialRowRetired("SER1"); err != nil {
		t.Fatal(err)
	}
	if SerialRowRetirePending("SER1", "SER1") {
		t.Error("retire must happen once")
	}
}
