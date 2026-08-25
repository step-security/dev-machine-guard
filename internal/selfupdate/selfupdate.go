// Package selfupdate keeps a scheduler-launched binary current without the
// loader script: it asks the backend's latest-binary endpoint for the release
// the tenant should run, verifies the checksum's Ed25519 SSHSIG natively,
// downloads the asset, verifies its sha256, and atomically swaps its own
// executable. The running process keeps executing the old image; the NEW
// binary takes effect on the next scheduled fire (deliberate: no re-exec
// edge cases).
//
// Enabled only when config.AutoUpdate is true — the auto-loader install flow
// writes `auto_update: true` into config.json when it registers the scheduler
// to launch the binary directly. Version-pinned installs and manual runs
// never set it, so they can never drift off their pin. Best-effort by
// contract: every failure logs and returns; a scan is never blocked by an
// update problem. Kill switch: STEPSEC_DISABLE_SELF_UPDATE=1.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// EnvDisable is the per-device kill switch, mirroring the other STEPSEC_
// escapes (run gate, background priority).
const EnvDisable = "STEPSEC_DISABLE_SELF_UPDATE"

const (
	metaTimeout     = 30 * time.Second
	downloadTimeout = 5 * time.Minute
	maxMetaBytes    = 64 << 10
	binaryName      = "stepsecurity-dev-machine-guard"
)

// releaseBaseURL / executablePath / allowedReleaseKeyB64 are vars so tests
// can point downloads at an httptest server, swap a scratch file in for the
// real executable, and verify against a throwaway signing key.
var (
	releaseBaseURL       = "https://github.com/step-security/dev-machine-guard/releases/download"
	executablePath       = os.Executable
	allowedReleaseKeyB64 = releasePublicKeyB64
)

type latestBinaryResponse struct {
	Version        string `json:"version"`
	Checksum       string `json:"checksum"`
	SignedChecksum string `json:"signed_checksum"`
}

// assetName returns the release asset for this platform, matching the
// loaders' naming: darwin ships a single universal binary, linux is
// per-arch. Windows is never self-updated (its task.exe launcher + loader
// architecture owns updates there); callers gate on GOOS first.
func assetName(version string) string {
	if runtime.GOOS == model.PlatformDarwin {
		return fmt.Sprintf("%s-%s-darwin", binaryName, version)
	}
	return fmt.Sprintf("%s-%s-linux_%s", binaryName, version, runtime.GOARCH)
}

// Run performs one self-update check. Returns true only when a new binary
// was installed (taking effect next run). Never returns an error: all
// failures are logged and swallowed so the scan proceeds regardless.
func Run(ctx context.Context, exec executor.Executor, log *progress.Logger) bool {
	if !config.AutoUpdate {
		return false
	}
	if runtime.GOOS == model.PlatformWindows {
		return false
	}
	if exec.Getenv(EnvDisable) == "1" {
		log.Debug("self-update: disabled via %s", EnvDisable)
		return false
	}

	exe, err := executablePath()
	if err != nil {
		log.Warn("self-update: cannot resolve own executable: %v", err)
		return false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}

	meta, err := fetchLatestBinary(ctx)
	if err != nil {
		log.Warn("self-update: check failed (%v) — continuing on v%s", err, buildinfo.Version)
		return false
	}

	// The signature covers the checksum string exactly as the release
	// pipeline signed it (no trailing newline; the loaders verify the same
	// bytes). A bad or missing signature aborts BEFORE any download.
	if err := verifySSHSig(meta.SignedChecksum, []byte(meta.Checksum), allowedReleaseKeyB64, signatureNamespace); err != nil {
		log.Warn("self-update: checksum signature verification failed for v%s: %v", meta.Version, err)
		return false
	}

	current, err := fileSHA256(exe)
	if err != nil {
		log.Warn("self-update: cannot hash current binary: %v", err)
		return false
	}
	if current == meta.Checksum {
		log.Debug("self-update: binary is current (v%s)", meta.Version)
		return false
	}

	log.Progress("Self-update: v%s available (checksum differs from installed binary), downloading...", meta.Version)
	tmp, err := downloadAsset(ctx, meta.Version, exe)
	if err != nil {
		log.Warn("self-update: download failed: %v", err)
		return false
	}
	defer os.Remove(tmp) // no-op after the successful rename

	got, err := fileSHA256(tmp)
	if err != nil || got != meta.Checksum {
		log.Warn("self-update: downloaded binary checksum mismatch (got %.12s, want %.12s) — discarding", got, meta.Checksum)
		return false
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		log.Warn("self-update: chmod failed: %v", err)
		return false
	}
	// Atomic same-directory rename: the running process keeps its (now
	// unlinked) old image; the next scheduled fire executes the new one.
	if err := os.Rename(tmp, exe); err != nil {
		log.Warn("self-update: install failed: %v", err)
		return false
	}
	writeVersionMarker(meta.Version)
	log.Progress("Self-update: installed v%s (replacing v%s); it takes effect on the next scheduled run", meta.Version, buildinfo.Version)
	return true
}

func fetchLatestBinary(ctx context.Context) (*latestBinaryResponse, error) {
	q := url.Values{}
	if runtime.GOOS == model.PlatformLinux {
		q.Set("os", "linux")
		q.Set("arch", runtime.GOARCH)
	}
	// Script-baked update-policy overrides ride config.json in the
	// binary-periodic flow (the loader persists them at install); send them
	// exactly like the loader's policy_query_string so the backend resolves
	// the same version either way.
	if config.UpdateLagBehind > 0 || config.UpdateCooldownHours > 0 {
		q.Set("lag_behind", fmt.Sprintf("%d", config.UpdateLagBehind))
		q.Set("cooldown_hours", fmt.Sprintf("%d", config.UpdateCooldownHours))
	}
	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/latest-binary", config.APIEndpoint, config.CustomerID)
	if enc := q.Encode(); enc != "" {
		endpoint += "?" + enc
	}

	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+config.APIKey)
	req.Header.Set("X-Agent-Version", buildinfo.Version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("latest-binary returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetaBytes))
	if err != nil {
		return nil, err
	}
	var meta latestBinaryResponse
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("parse latest-binary response: %w", err)
	}
	if meta.Version == "" || meta.Checksum == "" || meta.SignedChecksum == "" {
		return nil, fmt.Errorf("latest-binary response missing version/checksum/signed_checksum")
	}
	return &meta, nil
}

// downloadAsset streams the release asset to a temp file in the same
// directory as the target executable (same filesystem, so the final rename
// is atomic). Returns the temp path.
func downloadAsset(ctx context.Context, version, exe string) (string, error) {
	assetURL := fmt.Sprintf("%s/v%s/%s", releaseBaseURL, version, assetName(version))

	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s returned HTTP %d", assetURL, resp.StatusCode)
	}

	f, err := os.CreateTemp(filepath.Dir(exe), "."+binaryName+".new-*")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeVersionMarker refreshes the loader-compatible .current_version file in
// the install dir. Best-effort: the marker is diagnostic (scheduler_info and
// the loaders read it), never load-bearing for the update itself.
func writeVersionMarker(version string) {
	home := paths.Home()
	if home == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(home, ".current_version"), []byte(version+"\n"), 0o644)
}
