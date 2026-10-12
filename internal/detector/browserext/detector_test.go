package browserext

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// The fixtures run as the Linux catalog because its paths are the shortest; the
// platform only selects which catalog rows apply, so the parsers under test are
// the same ones every platform runs.

// tempHome returns a home directory with every symlink already resolved. The
// detector refuses a path with a link anywhere on it, and the system temporary
// directory is reached through one on macOS.
func tempHome(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return home
}

func testUser(home string) *user.User {
	return &user.User{Username: "dev", Uid: "501", HomeDir: home}
}

// newDetector builds a detector for a platform, with the session probe answering
// "there is an interactive user" so a test host's own context cannot decide it.
func newDetector(platform string) *Detector {
	mock := executor.NewMock()
	mock.SetGOOS(platform)
	d := New(mock)
	d.serviceSession = func() bool { return false }
	return d
}

// scanHome runs one scan over a prepared home.
func scanHome(t *testing.T, home string) *model.BrowserExtensionScanInfo {
	t.Helper()
	info := newDetector(model.PlatformLinux).Detect(context.Background(), testUser(home))
	if info == nil {
		t.Fatal("Detect returned the did-not-run sentinel for a resolved user")
	}
	return info
}

func chromeRoot(home string) string  { return filepath.Join(home, ".config", "google-chrome") }
func firefoxRoot(home string) string { return filepath.Join(home, ".mozilla", "firefox") }

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

// localState writes the file the profile list comes from.
func localState(t *testing.T, root string, profiles ...string) {
	t.Helper()
	quoted := make([]string, 0, len(profiles))
	for _, p := range profiles {
		// The values carry the profile label and the signed-in account's e-mail
		// address in real life; the fixture keeps them so the test proves they
		// are never read.
		quoted = append(quoted, `"`+p+`": {"name": "Person 1", "user_name": "dev@example.internal"}`)
	}
	writeFile(t, filepath.Join(root, "Local State"),
		`{"profile": {"info_cache": {`+strings.Join(quoted, ",")+`}}}`)
}

// securePrefs writes one profile's authoritative extension map.
func securePrefs(t *testing.T, root, profile, settings string) {
	t.Helper()
	writeFile(t, filepath.Join(root, profile, "Secure Preferences"),
		`{"extensions": {"settings": {`+settings+`}}}`)
}

func coverageFor(t *testing.T, info *model.BrowserExtensionScanInfo, browserID string) model.BrowserCoverage {
	t.Helper()
	for _, b := range info.Browsers {
		if b.BrowserID == browserID {
			return b
		}
	}
	t.Fatalf("no coverage entry for %s", browserID)
	return model.BrowserCoverage{}
}

func findingsFor(info *model.BrowserExtensionScanInfo, browserID string) []model.BrowserExtensionFinding {
	var out []model.BrowserExtensionFinding
	for _, f := range info.Findings {
		if f.BrowserID == browserID {
			out = append(out, f)
		}
	}
	return out
}

// assertPayloadInvariants checks the rules a reader rejects a whole payload over.
// Every scan in this suite goes through it: a fixture that violates one would be
// accepted here and refused on arrival.
func assertPayloadInvariants(t *testing.T, info *model.BrowserExtensionScanInfo) {
	t.Helper()
	if info.PayloadSchemaVersion != model.CurrentBrowserExtensionSchemaVersion {
		t.Errorf("payload_schema_version = %d", info.PayloadSchemaVersion)
	}
	if info.CatalogVersion == "" {
		t.Error("catalog_version is empty")
	}
	if info.CollectedAt <= 0 {
		t.Error("collected_at is not set")
	}
	if info.Truncated != (info.TruncatedReason != "") {
		t.Errorf("truncated = %v with reason %q", info.Truncated, info.TruncatedReason)
	}

	failed := false
	seen := map[string]bool{}
	counts := map[string]int{}
	for _, f := range info.Findings {
		counts[f.BrowserID]++
		if (f.EnabledState == model.BrowserExtDisabled) != (f.DisabledBy != "") {
			t.Errorf("%s: enabled_state %q with disabled_by %q", f.ExtensionID, f.EnabledState, f.DisabledBy)
		}
		if f.ExtensionID == "" {
			t.Error("finding with no identity")
		}
	}
	for _, b := range info.Browsers {
		if seen[b.BrowserID] {
			t.Errorf("%s: duplicate coverage entry", b.BrowserID)
		}
		seen[b.BrowserID] = true
		switch b.Status {
		case model.BrowserCoveragePartial, model.BrowserCoverageFailed:
			if b.ReasonCode == "" {
				t.Errorf("%s: status %q with no reason_code", b.BrowserID, b.Status)
			}
		default:
			if b.ReasonCode != "" {
				t.Errorf("%s: status %q with reason_code %q", b.BrowserID, b.Status, b.ReasonCode)
			}
		}
		if b.Status == model.BrowserCoverageFailed {
			failed = true
		}
		if b.Status == model.BrowserCoverageFailed || b.Status == model.BrowserCoverageNotPresent {
			if b.ExtensionCount != 0 || counts[b.BrowserID] != 0 {
				t.Errorf("%s: status %q ships %d findings", b.BrowserID, b.Status, counts[b.BrowserID])
			}
		} else if b.ExtensionCount != counts[b.BrowserID] {
			t.Errorf("%s: extension_count = %d, findings = %d", b.BrowserID, b.ExtensionCount, counts[b.BrowserID])
		}
		if b.ProfileCount < 0 || b.ProfileCount > maxProfilesPerBrowser {
			t.Errorf("%s: profile_count = %d", b.BrowserID, b.ProfileCount)
		}
	}
	for _, f := range info.Findings {
		if !seen[f.BrowserID] {
			t.Errorf("%s: finding for a browser with no coverage entry", f.BrowserID)
		}
	}
	if want := !(failed || info.Truncated); info.ScanComplete != want {
		t.Errorf("scan_complete = %v, want %v (failed=%v truncated=%v)",
			info.ScanComplete, want, failed, info.Truncated)
	}
}

// TestDetect_DeclinesWithoutADeveloper is the wipe guard. A scan of an account
// with no browsers finds none and says so authoritatively, so scanning the wrong
// account would tell a reader this machine has no extensions — and it would act
// on that. The refusal has to happen before any path is built.
func TestDetect_DeclinesWithoutADeveloper(t *testing.T) {
	home := tempHome(t)
	// A real installation, so a scan that ran would certainly report findings.
	localState(t, chromeRoot(home), "Default")
	securePrefs(t, chromeRoot(home), "Default", `"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)

	tests := []struct {
		name     string
		platform string
		target   *user.User
		session0 bool
	}{
		{name: "no user resolved", platform: model.PlatformLinux, target: nil},
		{name: "empty username", platform: model.PlatformLinux, target: &user.User{HomeDir: home}},
		{name: "root", platform: model.PlatformLinux, target: &user.User{Username: "root", Uid: "0", HomeDir: home}},
		{
			name:     "windows local system",
			platform: model.PlatformWindows,
			target:   &user.User{Username: "SYSTEM", Uid: "S-1-5-18", HomeDir: home},
		},
		{
			// The predicate that catches a service under a custom account, whose
			// SID no allowlist can enumerate.
			name:     "windows service session with an ordinary account",
			platform: model.PlatformWindows,
			target:   &user.User{Username: "svc-scanner", Uid: "S-1-5-21-1-2-3-1104", HomeDir: home},
			session0: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newDetector(tc.platform)
			d.serviceSession = func() bool { return tc.session0 }
			if info := d.Detect(context.Background(), tc.target); info != nil {
				t.Errorf("Detect returned a %d-browser section, want the did-not-run sentinel", len(info.Browsers))
			}
		})
	}
}

// TestDetect_CleanMachineIsAnAuthoritativeEmpty pins the case an earlier
// two-directional reading of the invariants got wrong: zero findings is the
// normal result for a machine with no browsers, and it must not read as a
// failure.
func TestDetect_CleanMachineIsAnAuthoritativeEmpty(t *testing.T) {
	info := scanHome(t, tempHome(t))
	assertPayloadInvariants(t, info)

	if !info.ScanComplete || info.Truncated {
		t.Errorf("scan_complete = %v truncated = %v, want a complete untruncated scan", info.ScanComplete, info.Truncated)
	}
	if len(info.Findings) != 0 {
		t.Errorf("findings = %d, want none", len(info.Findings))
	}
	if len(info.Browsers) != len(catalog) {
		t.Errorf("browsers = %d, want one entry per catalog browser (%d)", len(info.Browsers), len(catalog))
	}
	for _, b := range info.Browsers {
		if b.Status != model.BrowserCoverageNotPresent {
			t.Errorf("%s: status = %q, want %q", b.BrowserID, b.Status, model.BrowserCoverageNotPresent)
		}
	}
}

// TestDetect_ExistingRootWithNoInstallation separates the two ways a directory
// can hold no extensions. Installers leave a data directory behind holding
// nothing; calling that a failure paints a permanent red row for a browser nobody
// installed. A directory with a profile but no profile list is the opposite case
// and must stay a failure — the two must not collapse into one answer.
func TestDetect_ExistingRootWithNoInstallation(t *testing.T) {
	t.Run("leftover directory is not present", func(t *testing.T) {
		home := tempHome(t)
		mkdir(t, filepath.Join(chromeRoot(home), "NativeMessagingHosts"))

		info := scanHome(t, home)
		assertPayloadInvariants(t, info)
		got := coverageFor(t, info, browserChrome)
		if got.Status != model.BrowserCoverageNotPresent || got.ReasonCode != "" {
			t.Errorf("status = %q/%q, want %q with no reason", got.Status, got.ReasonCode, model.BrowserCoverageNotPresent)
		}
	})

	t.Run("profile with an unreadable profile list fails", func(t *testing.T) {
		home := tempHome(t)
		mkdir(t, filepath.Join(chromeRoot(home), "Default"))
		writeFile(t, filepath.Join(chromeRoot(home), "Local State"), `{"profile": {`)

		info := scanHome(t, home)
		assertPayloadInvariants(t, info)
		got := coverageFor(t, info, browserChrome)
		if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonParseError {
			t.Errorf("status = %q/%q, want %q/%q", got.Status, got.ReasonCode,
				model.BrowserCoverageFailed, model.BrowserExtReasonParseError)
		}
	})
}

// TestDetect_SymlinksRefuse covers the rule that has no exceptions: a link
// anywhere on a path refuses, above or below the data directory, and the browser
// fails rather than reporting an absence. Failing retains the browser's stored
// rows; reporting an absence would delete them, and following the link would read
// somewhere this has no business being.
func TestDetect_SymlinksRefuse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege the test host may not hold")
	}
	settings := `"` + idA + `": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example Elsewhere", "version": "1.0"}}`

	tests := []struct {
		name string
		// setup prepares a home whose chrome data directory is reached through a
		// link, and returns the directory a read must never enter.
		setup func(t *testing.T, home string) string
	}{
		{
			name: "the data directory itself is a link",
			setup: func(t *testing.T, home string) string {
				elsewhere := filepath.Join(home, "elsewhere")
				localState(t, elsewhere, "Default")
				securePrefs(t, elsewhere, "Default", settings)
				mkdir(t, filepath.Dir(chromeRoot(home)))
				if err := os.Symlink(elsewhere, chromeRoot(home)); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return elsewhere
			},
		},
		{
			name: "a profile directory below it is a link",
			setup: func(t *testing.T, home string) string {
				elsewhere := filepath.Join(home, "elsewhere")
				securePrefs(t, elsewhere, "Default", settings)
				localState(t, chromeRoot(home), "Default")
				if err := os.Symlink(filepath.Join(elsewhere, "Default"), filepath.Join(chromeRoot(home), "Default")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return elsewhere
			},
		},
		{
			name: "a state file is a link",
			setup: func(t *testing.T, home string) string {
				elsewhere := filepath.Join(home, "elsewhere")
				writeFile(t, filepath.Join(elsewhere, "Local State"), `{"profile": {"info_cache": {"Default": {}}}}`)
				mkdir(t, chromeRoot(home))
				if err := os.Symlink(filepath.Join(elsewhere, "Local State"), filepath.Join(chromeRoot(home), "Local State")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return elsewhere
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := tempHome(t)
			tc.setup(t, home)

			info := scanHome(t, home)
			assertPayloadInvariants(t, info)
			got := coverageFor(t, info, browserChrome)
			if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonSymlinkRejected {
				t.Errorf("status = %q/%q, want %q/%q", got.Status, got.ReasonCode,
					model.BrowserCoverageFailed, model.BrowserExtReasonSymlinkRejected)
			}
			// Nothing behind the link may appear in the payload: a refusal that
			// still read the target would be no refusal at all.
			for _, f := range info.Findings {
				if strings.Contains(f.Name, "Elsewhere") {
					t.Errorf("read through the link: %q", f.Name)
				}
			}
		})
	}
}

// TestDetect_NonRegularStateFileFails plants a pipe where a state file belongs.
// Opening one without asking not to block would hang the phase for ever, and no
// deadline interrupts a blocked open — so the test's own completion is half the
// assertion.
func TestDetect_NonRegularStateFileFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no in-directory pipes on this platform")
	}
	home := tempHome(t)
	mkdir(t, chromeRoot(home))
	if err := mkfifo(filepath.Join(chromeRoot(home), "Local State")); err != nil {
		t.Skipf("cannot create a fifo here: %v", err)
	}

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := coverageFor(t, info, browserChrome)
	if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonParseError {
		t.Errorf("status = %q/%q, want %q/%q", got.Status, got.ReasonCode,
			model.BrowserCoverageFailed, model.BrowserExtReasonParseError)
	}
}

// TestDetect_OversizeStateFileIsNotParsedFromItsPrefix covers the read that grew
// past its cap. A prefix of a JSON document is not a shorter version of it: parsed
// as one it would report a fraction of the extensions as the complete set, which
// is the one thing a coverage status must never say wrongly.
func TestDetect_OversizeStateFileIsNotParsedFromItsPrefix(t *testing.T) {
	home := tempHome(t)
	padding := strings.Repeat(" ", maxLocalStateBytes)
	writeFile(t, filepath.Join(chromeRoot(home), "Local State"),
		`{"profile": {"info_cache": {"Default": {}}}}`+padding)
	securePrefs(t, chromeRoot(home), "Default",
		`"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)
	got := coverageFor(t, info, browserChrome)
	if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonCapped {
		t.Errorf("status = %q/%q, want %q/%q", got.Status, got.ReasonCode,
			model.BrowserCoverageFailed, model.BrowserExtReasonCapped)
	}
	if len(info.Findings) != 0 {
		t.Errorf("findings = %d, want none from a browser that failed", len(info.Findings))
	}
	if info.Truncated {
		// The payload was not cut short; one browser failed. Saying otherwise
		// would describe a bounded result when the bound was on a file.
		t.Error("truncated is set for a file that failed its own cap")
	}
}

// TestDetect_DeadlineFailsTheRemainingBrowsers checks the other polarity: a
// deadline does bound the payload, so it fails the browsers it did not reach and
// says the result was cut short.
func TestDetect_DeadlineFailsTheRemainingBrowsers(t *testing.T) {
	home := tempHome(t)
	localState(t, chromeRoot(home), "Default")
	securePrefs(t, chromeRoot(home), "Default",
		`"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	info := newDetector(model.PlatformLinux).Detect(ctx, testUser(home))
	if info == nil {
		t.Fatal("Detect returned the did-not-run sentinel")
	}
	assertPayloadInvariants(t, info)

	if !info.Truncated || info.TruncatedReason != model.BrowserExtTruncatedDeadline {
		t.Errorf("truncated = %v/%q, want a deadline", info.Truncated, info.TruncatedReason)
	}
	for _, b := range info.Browsers {
		if b.Status != model.BrowserCoverageFailed || b.ReasonCode != model.BrowserExtReasonTimedOut {
			t.Errorf("%s: status = %q/%q, want every browser failed and timed out",
				b.BrowserID, b.Status, b.ReasonCode)
		}
	}
	if len(info.Findings) != 0 {
		t.Errorf("findings = %d, want none", len(info.Findings))
	}
}

// TestDetect_ConsentGuardRefusesADerivedPath covers the one location class the
// catalog does not fix: a profile directory named by the browser's own config
// file. It is a string an attacker can write, so it is refused before it is
// touched rather than after — the browsers' own directories stay readable under
// the same guard, which is the whole point of the exemption.
func TestDetect_ConsentGuardRefusesADerivedPath(t *testing.T) {
	home := tempHome(t)
	guarded := filepath.Join(home, "Documents", "hidden-profile")
	writeFile(t, filepath.Join(guarded, "extensions.json"),
		`{"addons": [{"id": "guarded@example-org", "type": "extension", "active": true}]}`)
	writeFile(t, filepath.Join(firefoxRoot(home), "profiles.ini"),
		"[Profile0]\nIsRelative=0\nPath="+filepath.ToSlash(guarded)+"\n")

	d := newDetector(model.PlatformLinux).WithSkipper(tcc.New(home))
	info := d.Detect(context.Background(), testUser(home))
	if info == nil {
		t.Fatal("Detect returned the did-not-run sentinel")
	}
	assertPayloadInvariants(t, info)

	got := coverageFor(t, info, browserFirefox)
	if runtime.GOOS != "darwin" {
		// The consent layer only exists on macOS, so elsewhere the path is read
		// and the add-on reported. The assertion that travels is the negative
		// one below: nothing may be refused for the browsers' own directories.
		if got.Status == model.BrowserCoverageFailed && got.ReasonCode == model.BrowserExtReasonRefusedTCC {
			t.Errorf("%s refused a readable path on a platform with no consent layer", browserFirefox)
		}
		return
	}
	if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonRefusedTCC {
		t.Errorf("status = %q/%q, want %q/%q", got.Status, got.ReasonCode,
			model.BrowserCoverageFailed, model.BrowserExtReasonRefusedTCC)
	}
}

// TestDetect_GuardExemptsTheBrowsersOwnDirectories is the other half of the
// consent rule. The macOS skipper declines the whole Library directory, which is
// where three of the four browsers keep their state — filtering candidates
// through it unmodified would report every one of them unreadable.
func TestDetect_GuardExemptsTheBrowsersOwnDirectories(t *testing.T) {
	home := tempHome(t)
	root := filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	localState(t, root, "Default")
	securePrefs(t, root, "Default",
		`"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)

	d := newDetector(model.PlatformDarwin).WithOSVersion("26.5.1").WithSkipper(tcc.New(home))
	info := d.Detect(context.Background(), testUser(home))
	if info == nil {
		t.Fatal("Detect returned the did-not-run sentinel")
	}
	assertPayloadInvariants(t, info)

	got := coverageFor(t, info, browserChrome)
	if got.Status != model.BrowserCoverageScanned {
		t.Fatalf("status = %q/%q, want %q", got.Status, got.ReasonCode, model.BrowserCoverageScanned)
	}
	if len(findingsFor(info, browserChrome)) != 1 {
		t.Errorf("findings = %d, want the one installed extension", len(findingsFor(info, browserChrome)))
	}
}

// TestDetect_CapFailsOnlyTheOverflowingBrowser pins where a cap cuts, in both
// directions. Mid-browser truncation is banned: a browser's reported list is read
// as complete, so a list cut in half would retire the extensions below the cut. But
// the bound belongs to that browser's own list, so the browsers on either side of
// it are answered normally — one browser with too many profiles must not blind the
// scan to the rest of the machine. The per-browser bound is the reachable one:
// three browsers cannot fill the whole-run budget.
func TestDetect_CapFailsOnlyTheOverflowingBrowser(t *testing.T) {
	home := tempHome(t)
	// One extension for the browser before the cap and one for the browser after
	// it, with the overflowing browser between them.
	localState(t, chromeRoot(home), "Default")
	securePrefs(t, chromeRoot(home), "Default",
		`"`+idA+`": {"location": 1, "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}}`)

	edgeRoot := filepath.Join(home, ".config", "microsoft-edge")
	localState(t, edgeRoot, "Default")
	securePrefs(t, edgeRoot, "Default", manySettings(maxExtensionsPerBrowser+1))

	// The browser after the cap is on the other engine, which is the stronger
	// version of the same claim: the bound belongs to one browser's list, not to
	// the parser family that produced it.
	ffRoot := firefoxRoot(home)
	writeFile(t, filepath.Join(ffRoot, "profiles.ini"), "[Profile0]\nIsRelative=1\nPath=abcd1234.default-release\n")
	geckoAddonJSON(t, filepath.Join(ffRoot, "abcd1234.default-release"),
		`{"id": "notes@example-org", "type": "extension", "active": true}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)

	if got := coverageFor(t, info, browserChrome); got.Status != model.BrowserCoverageScanned {
		t.Errorf("chrome: status = %q, want the browser scanned before the cap to survive", got.Status)
	}
	got := coverageFor(t, info, browserEdge)
	if got.Status != model.BrowserCoverageFailed || got.ReasonCode != model.BrowserExtReasonCapped {
		t.Errorf("edge: status = %q/%q, want failed and capped", got.Status, got.ReasonCode)
	}
	if got := coverageFor(t, info, browserFirefox); got.Status != model.BrowserCoverageScanned {
		t.Errorf("firefox: status = %q, want the browser after the cap scanned on its own merits", got.Status)
	}
	if len(findingsFor(info, browserFirefox)) != 1 {
		t.Errorf("firefox findings = %d, want the one installed extension", len(findingsFor(info, browserFirefox)))
	}
	if !info.Truncated || info.TruncatedReason != model.BrowserExtTruncatedFindingCap {
		t.Errorf("truncated = %v/%q, want the finding cap", info.Truncated, info.TruncatedReason)
	}
	if info.ScanComplete {
		t.Error("scan_complete = true, want a cut payload to say so")
	}
}

// TestDetect_FoldsOneExtensionSeenInTwoProfiles covers the reduction. Enabled
// anywhere means the extension can run on this machine; the rest of the record
// comes from one profile as a block, because pairing one profile's version with
// another's permissions would describe an extension that exists nowhere.
func TestDetect_FoldsOneExtensionSeenInTwoProfiles(t *testing.T) {
	home := tempHome(t)
	localState(t, chromeRoot(home), "Default", "Profile 1")
	securePrefs(t, chromeRoot(home), "Default", `"`+idA+`": {
		"location": 1, "disable_reasons": [1],
		"manifest": {"name": "Example Reader", "version": "1.0.0"},
		"active_permissions": {"api": ["storage"]}
	}`)
	securePrefs(t, chromeRoot(home), "Profile 1", `"`+idA+`": {
		"location": 1,
		"manifest": {"name": "Example Reader", "version": "2.0.0"},
		"active_permissions": {"api": ["tabs"]}
	}`)

	info := scanHome(t, home)
	assertPayloadInvariants(t, info)

	got := findingsFor(info, browserChrome)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want one per extension however many profiles hold it", len(got))
	}
	f := got[0]
	if f.EnabledState != model.BrowserExtEnabled {
		t.Errorf("enabled_state = %q, want enabled: it runs in the second profile", f.EnabledState)
	}
	if f.DisabledBy != "" {
		t.Errorf("disabled_by = %q, want none on an enabled extension", f.DisabledBy)
	}
	// The block comes from the profile the state describes, not from the
	// first-sorting one, so both fields come from the enabled profile.
	if f.Version != "2.0.0" || len(f.Permissions) != 1 || f.Permissions[0] != "tabs" {
		t.Errorf("version/permissions = %q/%v, want the enabled profile's whole record", f.Version, f.Permissions)
	}
	if got := coverageFor(t, info, browserChrome); got.ProfileCount != 2 {
		t.Errorf("profile_count = %d, want 2", got.ProfileCount)
	}
}

// TestDetect_GrantedProfileOwnsTheAccessLists is the shape that made the ranking
// necessary: the same extension in two profiles, host access withheld in the
// first-sorting one and granted in the other. Reporting the withheld profile
// says the machine has no broad access when it does, which is the wrong
// direction for the reader to be wrong in.
func TestDetect_GrantedProfileOwnsTheAccessLists(t *testing.T) {
	home := tempHome(t)
	localState(t, chromeRoot(home), "Default", "Profile 1")
	securePrefs(t, chromeRoot(home), "Default", `"`+idA+`": {
		"location": 1, "withholding_permissions": true,
		"manifest": {"name": "Example Blocker", "version": "1.0.0"},
		"active_permissions": {"api": ["storage"], "explicit_host": ["<all_urls>"]}
	}`)
	securePrefs(t, chromeRoot(home), "Profile 1", `"`+idA+`": {
		"location": 1,
		"manifest": {"name": "Example Blocker", "version": "1.0.0"},
		"active_permissions": {"api": ["storage"], "explicit_host": ["<all_urls>"]}
	}`)

	got := findingsFor(scanHome(t, home), browserChrome)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want one", len(got))
	}
	if len(got[0].HostPermissions) != 1 || got[0].HostPermissions[0] != "<all_urls>" {
		t.Errorf("host_permissions = %v, want the granted profile's access", got[0].HostPermissions)
	}
	// It declares no content scripts in either profile, so an empty list here is
	// the right answer and a filled one would be a different wrong one.
	if got[0].ScriptableHostPermissions == nil || len(*got[0].ScriptableHostPermissions) != 0 {
		t.Errorf("scriptable_host_permissions = %v, want the empty list it declared", got[0].ScriptableHostPermissions)
	}
}

// TestLessOccurrence covers the ranking that decides which profile's record one
// finding carries, key by key. State first, then breadth of access, and the path
// only once nothing about the access itself separates them.
func TestLessOccurrence(t *testing.T) {
	list := func(entries ...string) *[]string { return &entries }
	occ := func(sortKey, state string, hosts []string, scriptable *[]string, perms ...string) occurrence {
		return occurrence{sortKey: sortKey, enabled: state, block: model.BrowserExtensionFinding{
			Permissions:               perms,
			HostPermissions:           hosts,
			ScriptableHostPermissions: scriptable,
		}}
	}
	specific := []string{"https://a.internal/*", "https://b.internal/*", "https://c.internal/*"}

	// In every row the first occurrence is the one that should own the block, and
	// it sorts second by path so the old rule would have picked the other.
	tests := []struct {
		name   string
		first  occurrence
		second occurrence
	}{{
		name:   "enabled wins however narrow, because the row says enabled",
		first:  occ("b", model.BrowserExtEnabled, nil, nil),
		second: occ("a", model.BrowserExtDisabled, []string{"<all_urls>"}, nil),
	}, {
		name:   "a disabled profile still beats one whose state could not be read",
		first:  occ("b", model.BrowserExtDisabled, nil, nil),
		second: occ("a", model.BrowserExtStateUnknown, []string{"<all_urls>"}, nil),
	}, {
		name:   "breadth is not count",
		first:  occ("b", model.BrowserExtEnabled, []string{"<all_urls>"}, nil),
		second: occ("a", model.BrowserExtEnabled, specific, nil),
	}, {
		name:   "http and https together are the whole web",
		first:  occ("b", model.BrowserExtEnabled, []string{"http://*/*", "https://*/*"}, nil),
		second: occ("a", model.BrowserExtEnabled, specific, nil),
	}, {
		name:   "one half of the pair is not broad, so count decides",
		first:  occ("b", model.BrowserExtEnabled, specific, nil),
		second: occ("a", model.BrowserExtEnabled, []string{"https://*/*"}, nil),
	}, {
		// Reading local files is not reading websites, and the browser gates it
		// behind a per-extension setting of its own, so the profile with three
		// real sites describes more web access than the one holding it.
		name:   "file access is not web breadth, so count decides",
		first:  occ("b", model.BrowserExtEnabled, specific, nil),
		second: occ("a", model.BrowserExtEnabled, []string{"file://*/*"}, nil),
	}, {
		name:   "all disabled: breadth still decides, so a broad grant is reported",
		first:  occ("b", model.BrowserExtDisabled, []string{"<all_urls>"}, nil),
		second: occ("a", model.BrowserExtDisabled, specific, nil),
	}, {
		name:   "broad content scripts break a tie the host lists do not",
		first:  occ("b", model.BrowserExtEnabled, []string{"<all_urls>"}, list("<all_urls>")),
		second: occ("a", model.BrowserExtEnabled, []string{"<all_urls>"}, list()),
	}, {
		name:   "an unrecorded scriptable list is not a broad one",
		first:  occ("b", model.BrowserExtEnabled, []string{"<all_urls>"}, list("<all_urls>")),
		second: occ("a", model.BrowserExtEnabled, []string{"<all_urls>"}, nil),
	}, {
		name:   "with neither broad, the wider host list wins",
		first:  occ("b", model.BrowserExtEnabled, specific, nil),
		second: occ("a", model.BrowserExtEnabled, specific[:1], nil),
	}, {
		name:   "a runtime-granted API permission beats a path comparison",
		first:  occ("b", model.BrowserExtEnabled, specific, nil, "storage", "tabs"),
		second: occ("a", model.BrowserExtEnabled, specific, nil, "storage"),
	}, {
		name:   "everything equal: the path decides, and it is total",
		first:  occ("a", model.BrowserExtEnabled, specific, nil),
		second: occ("b", model.BrowserExtEnabled, specific, nil),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !lessOccurrence(tt.first, tt.second) {
				t.Error("the occurrence that describes the machine's access did not sort first")
			}
			if lessOccurrence(tt.second, tt.first) {
				t.Error("both orderings compared less, so the ordering is not a strict one")
			}

			// The invariant: whichever way round the two arrive, the block the
			// fold takes belongs to a profile in the state the fold resolves.
			// It is what stops this comparator and that union loop drifting.
			for _, occs := range [][]occurrence{{tt.first, tt.second}, {tt.second, tt.first}} {
				b := &browserScan{occurrences: map[string][]occurrence{idA: occs}}
				out := b.fold(browserChrome)
				if len(out) != 1 {
					t.Fatalf("findings = %d, want one", len(out))
				}
				if winner := b.occurrences[idA][0]; winner.enabled != out[0].EnabledState {
					t.Errorf("block came from a %q profile on a %q row", winner.enabled, out[0].EnabledState)
				}
			}
		})
	}
}

// TestDetect_DisabledCauseComesFromADisabledProfile is the trap in the reduction:
// the profile that owns the record may be an enabled one, and reading the cause
// off it would attach an enabled profile's empty cause to a disabled row.
func TestDetect_DisabledCauseComesFromADisabledProfile(t *testing.T) {
	home := tempHome(t)
	localState(t, chromeRoot(home), "Default", "Profile 1")
	// The first-sorting profile is disabled by the user, the second by the
	// browser; neither is enabled, so the row is disabled and needs one cause.
	securePrefs(t, chromeRoot(home), "Default", `"`+idA+`": {
		"location": 1, "disable_reasons": [1], "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}
	}`)
	securePrefs(t, chromeRoot(home), "Profile 1", `"`+idA+`": {
		"location": 1, "disable_reasons": [512], "active_permissions": {}, "manifest": {"name": "Example", "version": "1.0"}
	}`)

	got := findingsFor(scanHome(t, home), browserChrome)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want one", len(got))
	}
	if got[0].EnabledState != model.BrowserExtDisabled || got[0].DisabledBy != model.BrowserExtDisabledByUser {
		t.Errorf("state/cause = %q/%q, want disabled by the user", got[0].EnabledState, got[0].DisabledBy)
	}
}

// TestDetect_IsDeterministic asserts what a fixed ordering rule is for: two runs
// over an unchanged machine produce the same payload, so a reader never sees a
// change that is only this detector's map iteration.
func TestDetect_IsDeterministic(t *testing.T) {
	home := tempHome(t)
	localState(t, chromeRoot(home), "Default", "Profile 1", "Profile 2")
	settings := `"` + idA + `": {"location": 1, "active_permissions": {}, "manifest": {"name": "A", "version": "1.0"}},` +
		`"` + idB + `": {"location": 4, "active_permissions": {}, "manifest": {"name": "B", "version": "2.0"}},` +
		`"` + idC + `": {"location": 2, "active_permissions": {}, "manifest": {"name": "C", "version": "3.0"}}`
	for _, profile := range []string{"Default", "Profile 1", "Profile 2"} {
		securePrefs(t, chromeRoot(home), profile, settings)
	}

	want := marshalFindings(t, scanHome(t, home))
	for run := range 4 {
		if got := marshalFindings(t, scanHome(t, home)); got != want {
			t.Fatalf("run %d produced different findings\n got: %s\nwant: %s", run+1, got, want)
		}
	}
}

// marshalFindings renders the findings list, which is what a reader compares two
// scans by. Timings differ between runs and are not part of the question.
func marshalFindings(t *testing.T, info *model.BrowserExtensionScanInfo) string {
	t.Helper()
	raw, err := json.Marshal(info.Findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	return string(raw)
}

type panicOnSecondGOOSExecutor struct {
	executor.Executor
	calls int
}

func (e *panicOnSecondGOOSExecutor) GOOS() string {
	e.calls++
	if e.calls == 2 {
		panic("test panic")
	}
	return model.PlatformLinux
}

// TestDetect_PanicPropagates pins the recovery policy: a panic in a detector
// travels to the one top-level handler that reports it, rather than being
// swallowed here into a partial payload or a nil section that reads as "this
// machine has no browsers".
func TestDetect_PanicPropagates(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformLinux)

	d := New(&panicOnSecondGOOSExecutor{Executor: mock})
	d.serviceSession = func() bool { return false }

	defer func() {
		if recover() == nil {
			t.Error("Detect recovered the panic, want it to propagate")
		}
	}()
	d.Detect(context.Background(), testUser(tempHome(t)))
}
