package selfupdate

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// stage is a fake install with every package seam wired to it.
type stage struct {
	exe      string
	launcher string // windows only; "" elsewhere
	// downloads / launcherDownloads count hits on the agent and launcher
	// release assets separately, so a test can assert which artifact moved.
	downloads         *atomic.Int32
	launcherDownloads *atomic.Int32
}

// stageSeams is the agent-only view of stageAll, kept for the tests that only
// care about the agent artifact.
func stageSeams(t *testing.T, metaJSON, assetBody string) (string, *atomic.Int32) {
	t.Helper()
	st := stageAll(t, metaJSON, assetBody)
	return st.exe, st.downloads
}

// stageAll wires every package seam at a fake install: a scratch "current
// binary", an httptest server serving the latest-binary metadata and the
// release assets, the throwaway fixture signing key, and enterprise config.
//
// On Windows the install is the two-artifact layout the loader produces — an
// agent plus the GUI launcher beside it. The launcher is staged ALREADY
// up-to-date so the shared tests below observe the agent artifact alone; the
// launcher's own update path is covered in selfupdate_windows_test.go.
func stageAll(t *testing.T, metaJSON, assetBody string) *stage {
	t.Helper()

	dir := t.TempDir()
	exeName := binaryName
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	exe := filepath.Join(dir, exeName)
	if err := os.WriteFile(exe, []byte("old-binary-content\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := &stage{exe: exe, downloads: &atomic.Int32{}, launcherDownloads: &atomic.Int32{}}
	if runtime.GOOS == "windows" {
		st.launcher = launcherPath(exe)
		if err := os.WriteFile(st.launcher, []byte(fixturePayload), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	downloads := st.downloads
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/testcust/developer-mdm-agent/latest-binary", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(metaJSON))
	})
	mux.HandleFunc("/v9.9.9/"+assetName("9.9.9"), func(w http.ResponseWriter, _ *http.Request) {
		downloads.Add(1)
		_, _ = w.Write([]byte(assetBody))
	})
	if runtime.GOOS == "windows" {
		mux.HandleFunc("/v9.9.9/"+launcherAssetName("9.9.9"), func(w http.ResponseWriter, _ *http.Request) {
			st.launcherDownloads.Add(1)
			_, _ = w.Write([]byte(fixturePayload))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origBase, origExe, origKey := releaseBaseURL, executablePath, allowedReleaseKeyB64
	origEndpoint, origKeyCfg, origCust := config.APIEndpoint, config.APIKey, config.CustomerID
	origAuto := config.AutoUpdate
	releaseBaseURL = srv.URL
	executablePath = func() (string, error) { return exe, nil }
	allowedReleaseKeyB64 = fixtureKeyB64
	config.APIEndpoint = srv.URL
	config.APIKey = "test-key"
	config.CustomerID = "testcust"
	config.AutoUpdate = true
	t.Setenv("STEPSECURITY_HOME", dir) // version marker lands in the temp dir
	t.Cleanup(func() {
		releaseBaseURL, executablePath, allowedReleaseKeyB64 = origBase, origExe, origKey
		config.APIEndpoint, config.APIKey, config.CustomerID = origEndpoint, origKeyCfg, origCust
		config.AutoUpdate = origAuto
	})
	return st
}

func validMeta() string {
	// signed_checksum is base64-wrapped on the wire (single-line JSON
	// transport of the multi-line armored block), matching the real API.
	wrapped := base64.StdEncoding.EncodeToString([]byte(fixturePayloadSig))
	return metaJSON("9.9.9", fixturePayloadChecksum, `"`+wrapped+`"`)
}

// metaJSON builds a latest-binary response body. signedChecksum arrives
// pre-encoded as a JSON value (the tests pass both a quoted base64 wrapper
// and a raw armored block). On Windows the launcher fields are always
// included — the real endpoint requires them above v1.11.4 and
// fetchLatestBinary rejects a response without them. The fixture payload
// backs both artifacts, so they share a checksum and signature.
func metaJSON(version, checksum, signedChecksum string) string {
	out := `{"version":"` + version + `","checksum":"` + checksum + `","signed_checksum":` + signedChecksum
	if runtime.GOOS == "windows" {
		out += `,"launcher_checksum":"` + fixturePayloadChecksum + `","signed_launcher_checksum":"` +
			base64.StdEncoding.EncodeToString([]byte(fixturePayloadSig)) + `"`
	}
	return out + `}`
}

// jsonString encodes s as a JSON string literal (the signature is multi-line).
func jsonString(s string) string {
	out := `"`
	for _, r := range s {
		switch r {
		case '\n':
			out += `\n`
		case '"':
			out += `\"`
		case '\\':
			out += `\\`
		default:
			out += string(r)
		}
	}
	return out + `"`
}

func TestRun_InstallsVerifiedUpdate(t *testing.T) {
	exe, downloads := stageSeams(t, validMeta(), fixturePayload)

	updated := Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo))
	if !updated {
		t.Fatal("Run() = false, want an installed update")
	}
	got, err := os.ReadFile(exe)
	if err != nil || string(got) != fixturePayload {
		t.Errorf("binary content = %q err=%v, want the downloaded payload", got, err)
	}
	fi, _ := os.Stat(exe)
	if fi.Mode()&0o111 == 0 {
		t.Error("installed binary is not executable")
	}
	if downloads.Load() != 1 {
		t.Errorf("downloads = %d, want 1", downloads.Load())
	}
	marker, err := os.ReadFile(filepath.Join(filepath.Dir(exe), ".current_version"))
	if err != nil || string(marker) != "9.9.9\n" {
		t.Errorf("version marker = %q err=%v, want 9.9.9", marker, err)
	}
}

func TestRun_ChecksumMismatchDiscardsDownload(t *testing.T) {
	exe, _ := stageSeams(t, validMeta(), "tampered-payload-not-matching-checksum\n")

	if Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = true despite checksum mismatch")
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old-binary-content\n" {
		t.Errorf("binary was replaced by a checksum-mismatched download: %q", got)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "."+filepath.Base(exe)+".new-*"))
	if len(leftovers) != 0 {
		t.Errorf("temp download not cleaned up: %v", leftovers)
	}
}

func TestRun_BadSignatureAbortsBeforeDownload(t *testing.T) {
	// Signature is valid SSHSIG but over a DIFFERENT message than the
	// advertised checksum — verification must fail and nothing downloads.
	meta := metaJSON("9.9.9", fixturePayloadChecksum, jsonString(fixtureSig))
	exe, downloads := stageSeams(t, meta, fixturePayload)

	if Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = true despite bad checksum signature")
	}
	if downloads.Load() != 0 {
		t.Errorf("downloads = %d, want 0 (signature must gate the download)", downloads.Load())
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old-binary-content\n" {
		t.Error("binary was replaced despite bad signature")
	}
}

func TestRun_UpToDateIsNoOp(t *testing.T) {
	exe, downloads := stageSeams(t, validMeta(), fixturePayload)
	// Make the "current" binary already match the advertised checksum.
	if err := os.WriteFile(exe, []byte(fixturePayload), 0o755); err != nil {
		t.Fatal(err)
	}
	if Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = true for an up-to-date binary")
	}
	if downloads.Load() != 0 {
		t.Errorf("downloads = %d, want 0 for up-to-date", downloads.Load())
	}
}

func TestRun_RequiresOptInAndHonorsKillSwitch(t *testing.T) {
	_, downloads := stageSeams(t, validMeta(), fixturePayload)

	config.AutoUpdate = false
	if Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = true without auto_update opt-in")
	}

	config.AutoUpdate = true
	mock := executor.NewMock()
	mock.SetEnv(EnvDisable, "1")
	if Run(context.Background(), mock, progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = true despite kill switch")
	}
	if downloads.Load() != 0 {
		t.Errorf("downloads = %d, want 0 when disabled", downloads.Load())
	}
}

func TestRun_RefusesDowngradeBelowSelfUpdateFloor(t *testing.T) {
	// A release gate capping the tenant below minSelfUpdateVersion must not
	// let a binary-periodic install downgrade itself into a binary with no
	// self-update code (= no update path at all). The floor check runs
	// before signature verification and before any download.
	meta := metaJSON("1.16.0", fixturePayloadChecksum, `"ZHVtbXk="`)
	exe, downloads := stageSeams(t, meta, fixturePayload)

	if Run(context.Background(), executor.NewMock(), progress.NewLogger(progress.LevelInfo)) {
		t.Fatal("Run() = true for a below-floor downgrade")
	}
	if downloads.Load() != 0 {
		t.Errorf("downloads = %d, want 0 (floor must gate the download)", downloads.Load())
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old-binary-content\n" {
		t.Error("binary was replaced despite the self-update floor")
	}
}

// Asset names must match the release pipeline's output byte for byte (and
// windowsBinaryAssetName / windowsLauncherAssetName on the agent-api side) —
// a typo here 404s every update on the affected platform. Asserted for the
// host platform, so the CI matrix covers all three.
func TestAssetNames(t *testing.T) {
	const version = "1.17.0"
	want := map[string]string{
		"darwin":  "stepsecurity-dev-machine-guard-1.17.0-darwin",
		"linux":   "stepsecurity-dev-machine-guard-1.17.0-linux_" + runtime.GOARCH,
		"windows": "stepsecurity-dev-machine-guard-1.17.0-windows_" + runtime.GOARCH + ".exe",
	}
	if got := assetName(version); got != want[runtime.GOOS] {
		t.Errorf("assetName() = %q, want %q", got, want[runtime.GOOS])
	}
	if runtime.GOOS != "windows" {
		return
	}
	wantLauncher := "stepsecurity-dev-machine-guard-task-1.17.0-windows_" + runtime.GOARCH + ".exe"
	if got := launcherAssetName(version); got != wantLauncher {
		t.Errorf("launcherAssetName() = %q, want %q", got, wantLauncher)
	}
}

func TestVersionBelow(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.16.0", "1.17.0", true},
		{"1.17.0", "1.17.0", false},
		{"1.17.1", "1.17.0", false},
		{"1.18.0", "1.17.0", false},
		{"2.0.0", "1.17.0", false},
		{"1.9.9", "1.17.0", true},
		{"v1.16.0", "1.17.0", true},
		{"1.17.0-rc1", "1.17.0", false},
		{"1.17", "1.17.0", false},
		{"garbage", "1.17.0", true}, // unparseable = 0.0.0 = refuse (fail safe)
		{"", "1.17.0", true},
	}
	for _, tc := range cases {
		if got := versionBelow(tc.a, tc.b); got != tc.want {
			t.Errorf("versionBelow(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVerifySSHSig_OverlappingArmorMarkersDoNotPanic(t *testing.T) {
	// Regression: the END marker can match INSIDE the BEGIN marker's
	// trailing dashes ("-----BEGIN SSH SIGNATURE-----END SSH SIGNATURE-----"
	// finds END at offset 24 < len(BEGIN)); slicing with that index paniced.
	crafted := []string{
		"-----BEGIN SSH SIGNATURE-----END SSH SIGNATURE-----",
		"-----BEGIN SSH SIGNATUREEND SSH SIGNATURE-----",
		"-----END SSH SIGNATURE---------BEGIN SSH SIGNATURE-----",
	}
	for _, s := range crafted {
		if err := verifySSHSig(s, []byte("msg"), fixtureKeyB64, signatureNamespace); err == nil {
			t.Errorf("verifySSHSig(%q) = nil error, want rejection", s)
		}
	}
}
