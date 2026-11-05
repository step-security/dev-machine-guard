package device

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/paths"
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

// withMultiUserDetection sets config.MultiUserDetection for the test.
func withMultiUserDetection(t *testing.T, mode string) {
	t.Helper()
	prev := config.MultiUserDetection
	config.MultiUserDetection = mode
	t.Cleanup(func() { config.MultiUserDetection = prev })
}

// withSeenUserDay pins the day RecordScanUser stamps.
func withSeenUserDay(t *testing.T, day int64) {
	t.Helper()
	prev := seenUserDay
	seenUserDay = func() int64 { return day }
	t.Cleanup(func() { seenUserDay = prev })
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
		usersRule   bool
		want        bool
		wantReason  string
	}{
		{"plain pro, one user", "Professional", false, []string{"jdoe"}, false, true, false, ""},
		{"plain pro, nobody seen", "Professional", false, nil, false, true, false, ""},
		{"enterprise multi-session", "EnterpriseMultiSession", false, nil, false, false, true, "edition"},
		{"server rdsh, case-insensitive", "serverrdsh", false, nil, false, false, true, "edition"},
		{"rd session host role", "ServerStandard", true, nil, false, false, true, "edition"},
		{"second established user, users rule on", "Professional", false, []string{"jdoe", "asmith"}, false, true, true, "users"},
		{"second established user, users rule off", "Professional", false, []string{"jdoe", "asmith"}, false, false, false, ""},
		{"marker already set wins", "Professional", false, nil, true, false, true, "marker"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := multiUserHost(tc.edition, tc.tsAppCompat, tc.seen, tc.marker, tc.usersRule)
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
	jdoe := "jdoe-" + UserTokenFingerprint(`avd-host-07\jdoe`)
	if id.Source != IdentitySourceAuto || id.DeviceID != "avd-host-07-"+jdoe || !id.PerUser || id.UserScope != jdoe {
		t.Fatalf("auto identity = %+v", id)
	}
	if id.AutoReason != "multi-session edition" {
		t.Errorf("AutoReason = %q", id.AutoReason)
	}
	if _, ok := readMultiUserMarker(dir); !ok {
		t.Error("first positive decision must write the sticky marker")
	}
	if scope := IdentityUserScope(mock); scope != jdoe {
		t.Errorf("IdentityUserScope = %q, want %q", scope, jdoe)
	}
	if reason := AutoIdentityReason(mock); reason != "multi-session edition" {
		t.Errorf("AutoIdentityReason = %q", reason)
	}
}

// With multi_user_detection = "users", two developers who have each scanned
// on two different days flip an ordinary edition to per-user identities; the
// decision then sticks.
func TestAutoIdentity_SecondUserFlipsAndSticks(t *testing.T) {
	dir := withMachineStateDir(t, "Professional", false)
	withConfigDeviceID(t, "")
	withMultiUserDetection(t, config.MultiUserDetectionUsers)
	first := windowsMock(`HOST\jdoe`)
	second := windowsMock(`HOST\asmith`)
	scan := func(m *executor.Mock, user string, day int64) Identity {
		withSeenUserDay(t, day)
		ResetAutoIdentityForTest()
		RecordScanUser(m)
		return ResolveIdentity(m, "SER1", "HOST", user)
	}
	// Day 1: both scan; neither is established yet.
	if id := scan(first, `HOST\jdoe`, 100); id.Source != IdentitySourceSerial || id.DeviceID != "SER1" {
		t.Fatalf("single user must keep the serial identity: %+v", id)
	}
	if id := scan(second, `HOST\asmith`, 100); id.Source != IdentitySourceSerial {
		t.Fatalf("a second user's first visit must not flip the host: %+v", id)
	}
	// Day 2: jdoe is established, asmith's second day establishes them too.
	if id := scan(first, `HOST\jdoe`, 101); id.Source != IdentitySourceSerial {
		t.Fatalf("one established user is not enough: %+v", id)
	}
	id := scan(second, `HOST\asmith`, 101)
	asmith := "asmith-" + UserTokenFingerprint(`host\asmith`)
	if id.Source != IdentitySourceAuto || id.DeviceID != "host-"+asmith || id.AutoReason != "2+ users seen" {
		t.Fatalf("second established user must flip to per-user: %+v", id)
	}
	m, ok := readMultiUserMarker(dir)
	if !ok || m.Reason != autoReasonUsers {
		t.Fatalf("marker = %+v, %v", m, ok)
	}

	// Sticky: even with the seen-users file gone, the marker keeps it on.
	if err := os.Remove(filepath.Join(dir, seenUsersFile)); err != nil {
		t.Fatal(err)
	}
	ResetAutoIdentityForTest()
	if id := ResolveIdentity(first, "SER1", "HOST", `HOST\jdoe`); id.Source != IdentitySourceAuto || id.DeviceID != "host-jdoe-"+UserTokenFingerprint(`host\jdoe`) {
		t.Fatalf("marker must keep the host multi-user: %+v", id)
	}
}

// The users rule is opt-in: with the default mode a second developer's scans
// never change an ordinary workstation's identity, and "off" keeps even a
// multi-session edition on the machine identity.
func TestAutoIdentity_DetectionModes(t *testing.T) {
	withMachineStateDir(t, "Professional", false)
	withConfigDeviceID(t, "")
	for _, day := range []int64{100, 101} {
		withSeenUserDay(t, day)
		for _, u := range []string{`HOST\jdoe`, `HOST\asmith`} {
			ResetAutoIdentityForTest()
			RecordScanUser(windowsMock(u))
		}
	}
	ResetAutoIdentityForTest()
	if id := ResolveIdentity(windowsMock(`HOST\asmith`), "SER1", "HOST", `HOST\asmith`); id.Source != IdentitySourceSerial {
		t.Fatalf("default mode must ignore seen users: %+v", id)
	}
	if got := readSeenUsers(t.TempDir()); len(got) != 0 {
		t.Fatalf("nothing recorded without the users rule, got %v", got)
	}

	withMachineStateDir(t, "EnterpriseMultiSession", false)
	withMultiUserDetection(t, config.MultiUserDetectionOff)
	if id := ResolveIdentity(windowsMock(`AVD\jdoe`), "SER1", "AVD", `AVD\jdoe`); id.Source != IdentitySourceSerial || id.DeviceID != "SER1" {
		t.Fatalf("off must keep the machine identity even on a multi-session edition: %+v", id)
	}
}

// seen-users.txt written by an earlier agent holds bare short names. A
// returning developer's new, fingerprinted token inherits that visit when it
// is unambiguous (one legacy line, no other fingerprinted account with the
// same short name), so one more day establishes them; an ambiguous legacy
// name is never credited to anyone.
func TestRecordScanUser_CarriesAnUnambiguousLegacyVisit(t *testing.T) {
	dir := withMachineStateDir(t, "Professional", false)
	withMultiUserDetection(t, config.MultiUserDetectionUsers)
	if err := os.WriteFile(filepath.Join(dir, seenUsersFile), []byte("jdoe\nasmith\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := establishedSeenUsers(dir); len(got) != 0 {
		t.Fatalf("legacy lines alone are one visit each, got %v", got)
	}
	withSeenUserDay(t, 200)
	RecordScanUser(windowsMock(`CONTOSO\JDoe`))
	jdoe := "jdoe-" + UserTokenFingerprint(`contoso\jdoe`)
	if got := establishedSeenUsers(dir); strings.Join(got, ",") != jdoe {
		t.Fatalf("established = %v, want [%s] (legacy visit carried over)", got, jdoe)
	}
	// A third day appends nothing: the token is established.
	withSeenUserDay(t, 201)
	RecordScanUser(windowsMock(`CONTOSO\JDoe`))
	data, _ := os.ReadFile(filepath.Join(dir, seenUsersFile))
	if want := "jdoe\nasmith\n" + jdoe + " 0\n" + jdoe + " 200\n"; string(data) != want {
		t.Fatalf("file = %q, want %q", data, want)
	}
	// The first fingerprinted "asmith" to appear inherits the legacy visit
	// (nothing else can claim it then); once it exists the legacy name is
	// ambiguous and a second "asmith" account starts over.
	other := "asmith-" + UserTokenFingerprint(`other\asmith`)
	if err := appendSeenUser(dir, other); err != nil {
		t.Fatal(err)
	}
	RecordScanUser(windowsMock(`CONTOSO\ASmith`))
	contoso := "asmith-" + UserTokenFingerprint(`contoso\asmith`)
	for _, u := range readSeenUserRecords(dir) {
		switch u.token {
		case other:
			if !hasDay(u.days, legacySeenDay) {
				t.Fatalf("the first fingerprinted account inherits the legacy visit: %v", u.days)
			}
		case contoso:
			if hasDay(u.days, legacySeenDay) {
				t.Fatalf("a second account with the same short name must not inherit it: %v", u.days)
			}
		}
	}
}

// Two sessions recording their visits at the same moment never lose one:
// the file is append-only.
func TestSeenUsers_ConcurrentAppendsKeepEveryVisit(t *testing.T) {
	dir := t.TempDir()
	withSeenUserDay(t, 300)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = appendSeenUser(dir, "user"+strconv.Itoa(i)+"-0123456789ab")
		}(i)
	}
	wg.Wait()
	if got := len(readSeenUsers(dir)); got != 8 {
		t.Fatalf("recorded %d of 8 concurrent visits", got)
	}
}

// An oversized append-only file is compacted to one line per token, keeping
// every token's days.
func TestSeenUsers_CompactsWhenLarge(t *testing.T) {
	dir := t.TempDir()
	paths.SetOverride(dir)
	t.Cleanup(func() { paths.SetOverride("") })
	var b strings.Builder
	for b.Len() <= compactSeenUsersBytes {
		b.WriteString("jdoe-0123456789ab 100\njdoe-0123456789ab 101\n")
	}
	if err := os.WriteFile(filepath.Join(dir, seenUsersFile), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	withSeenUserDay(t, 102)
	if err := appendSeenUser(dir, "asmith-0123456789ab"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, seenUsersFile))
	if string(data) != "jdoe-0123456789ab 100,101\nasmith-0123456789ab 102\n" {
		t.Fatalf("compacted file = %q", data)
	}
}

// Turning detection off on a host that already switched must restore
// machine-level scanning, not skip every run because the marker exists.
func TestAutoIdentitySuperseded_OffNeverSkips(t *testing.T) {
	dir := withMachineStateDir(t, "Professional", false)
	withConfigDeviceID(t, "")
	withMultiUserDetection(t, config.MultiUserDetectionOff)
	if err := writeMultiUserMarker(dir, multiUserMarker{Since: 1, Reason: autoReasonEdition, RetiredSerialID: "SER1"}); err != nil {
		t.Fatal(err)
	}
	mock := windowsMock(`HOST\jdoe`)
	if tpl, _ := autoIdentity(mock); tpl != "" {
		t.Fatalf("off must snapshot the machine identity, got %q", tpl)
	}
	if AutoIdentitySuperseded(mock) {
		t.Fatal("off must never supersede a run")
	}
	if id := ResolveIdentity(mock, "SER1", "HOST", `HOST\jdoe`); id.Source != IdentitySourceSerial || id.DeviceID != "SER1" {
		t.Fatalf("off must report the machine identity: %+v", id)
	}
}

// `identity` must answer what the scan that follows would do: on the day the
// second developer becomes established, the scan records today's visit before
// deciding, so the diagnostic query assumes that visit without recording it.
func TestProspectiveScanUser_MatchesTheScanDecision(t *testing.T) {
	dir := withMachineStateDir(t, "Professional", false)
	withConfigDeviceID(t, "")
	withMultiUserDetection(t, config.MultiUserDetectionUsers)
	t.Cleanup(resetPendingVisitForTest)
	jdoe := "jdoe-" + UserTokenFingerprint(`host\jdoe`)
	asmith := "asmith-" + UserTokenFingerprint(`host\asmith`)
	if err := os.WriteFile(filepath.Join(dir, seenUsersFile), []byte(jdoe+" 100\n"+jdoe+" 101\n"+asmith+" 100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withSeenUserDay(t, 101)
	mock := windowsMock(`HOST\asmith`)
	if id := ResolveIdentity(mock, "SER1", "HOST", `HOST\asmith`); id.Source != IdentitySourceSerial {
		t.Fatalf("without today's visit asmith is not established yet: %+v", id)
	}
	ResetAutoIdentityForTest()
	ProspectiveScanUser(mock)
	if id := ResolveIdentity(mock, "SER1", "HOST", `HOST\asmith`); id.Source != IdentitySourceAuto || id.DeviceID != "host-"+asmith {
		t.Fatalf("the prospective visit must give the scan's answer: %+v", id)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, seenUsersFile)); strings.Count(string(data), "\n") != 3 {
		t.Fatalf("a prospective visit must not be recorded:\n%s", data)
	}
	// The scan itself records the visit and reaches the same answer.
	resetPendingVisitForTest()
	ResetAutoIdentityForTest()
	RecordScanUser(mock)
	if id := ResolveIdentity(mock, "SER1", "HOST", `HOST\asmith`); id.Source != IdentitySourceAuto {
		t.Fatalf("the scan must flip: %+v", id)
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
	withMultiUserDetection(t, config.MultiUserDetectionUsers)
	RecordScanUser(windowsMock(`NT AUTHORITY\SYSTEM`))
	RecordScanUser(windowsMock(`HOST\HOST$`))
	if got := readSeenUsers(dir); len(got) != 0 {
		t.Errorf("service accounts must not be recorded, got %v", got)
	}
	RecordScanUser(windowsMock(`CONTOSO\JDoe`))
	if got, want := strings.Join(readSeenUsers(dir), ","), "jdoe-"+UserTokenFingerprint(`contoso\jdoe`); got != want {
		t.Errorf("readSeenUsers = %v, want %v", got, want)
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

func TestAutoIdentitySuperseded(t *testing.T) {
	dir := withMachineStateDir(t, "Professional", false)
	withConfigDeviceID(t, "")
	mock := windowsMock(`AVD-HOST-07\jdoe`)
	// The snapshot of a single-user host: machine identity.
	if tpl, _ := autoIdentity(mock); tpl != "" {
		t.Fatalf("single-user host must snapshot the machine identity, got %q", tpl)
	}
	if AutoIdentitySuperseded(mock) {
		t.Fatal("no switch happened yet")
	}
	// Another user's run flips the host after the snapshot was taken.
	if err := writeMultiUserMarker(dir, multiUserMarker{Since: 1, Reason: autoReasonUsers}); err != nil {
		t.Fatal(err)
	}
	if !AutoIdentitySuperseded(mock) {
		t.Fatal("a marker written after a serial-mode snapshot must supersede it")
	}
	// A snapshot already in automatic mode is never superseded.
	ResetAutoIdentityForTest()
	if tpl, _ := autoIdentity(mock); tpl == "" {
		t.Fatal("the marker must switch a fresh snapshot")
	}
	if AutoIdentitySuperseded(mock) {
		t.Fatal("an automatic-mode snapshot is not superseded")
	}
}
