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

// stageSeams wires every package seam at a fake install: a scratch "current
// binary", an httptest server serving both the latest-binary metadata and the
// release asset, the throwaway fixture signing key, and enterprise config.
// Returns the scratch exe path and a download-hit counter.
func stageSeams(t *testing.T, metaJSON, assetBody string) (string, *atomic.Int32) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("self-update is darwin/linux only (windows uses the task.exe + loader architecture)")
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, binaryName)
	if err := os.WriteFile(exe, []byte("old-binary-content\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var downloads atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/testcust/developer-mdm-agent/latest-binary", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(metaJSON))
	})
	mux.HandleFunc("/v9.9.9/"+assetName("9.9.9"), func(w http.ResponseWriter, _ *http.Request) {
		downloads.Add(1)
		_, _ = w.Write([]byte(assetBody))
	})
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
	return exe, &downloads
}

func validMeta() string {
	// signed_checksum is base64-wrapped on the wire (single-line JSON
	// transport of the multi-line armored block), matching the real API.
	wrapped := base64.StdEncoding.EncodeToString([]byte(fixturePayloadSig))
	return `{"version":"9.9.9","checksum":"` + fixturePayloadChecksum + `","signed_checksum":"` + wrapped + `"}`
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
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "."+binaryName+".new-*"))
	if len(leftovers) != 0 {
		t.Errorf("temp download not cleaned up: %v", leftovers)
	}
}

func TestRun_BadSignatureAbortsBeforeDownload(t *testing.T) {
	// Signature is valid SSHSIG but over a DIFFERENT message than the
	// advertised checksum — verification must fail and nothing downloads.
	meta := `{"version":"9.9.9","checksum":"` + fixturePayloadChecksum + `","signed_checksum":` + jsonString(fixtureSig) + `}`
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
	meta := `{"version":"1.16.0","checksum":"` + fixturePayloadChecksum + `","signed_checksum":"ZHVtbXk="}`
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
