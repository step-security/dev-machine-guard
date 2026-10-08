// Package selfupdate keeps a scheduler-launched binary current without the
// loader script: it asks the backend's latest-binary endpoint for the release
// the tenant should run, verifies the checksum's Ed25519 SSHSIG natively,
// downloads the asset, verifies its sha256, and swaps its own executable in
// place (see swapBinary — one atomic rename on Unix, rename-aside on
// Windows, whose loader also owns the GUI launcher next to the agent). The
// running process keeps executing the old image; the NEW binary takes effect
// on the next scheduled fire (deliberate: no re-exec edge cases).
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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	// launcherName is the Windows GUI-subsystem launcher that the scheduled
	// task actually invokes; it spawns the agent with no console flash (see
	// internal/launcher). Windows-only, and updated in lockstep with the
	// agent so a tick never runs a mixed-version pair.
	launcherName = "stepsecurity-dev-machine-guard-task"

	// minSelfUpdateVersion is the first release that ships this package.
	// Self-update refuses to install anything OLDER: on a binary-periodic
	// install (scheduler fires the binary directly, no loader tick) a
	// downgrade below this floor would land a binary with no self-update
	// code and no other update mechanism — permanently frozen. A backend
	// that wants such a fleet on an older release must go through a loader
	// re-push, which re-installs script-periodic scheduling for it.
	//
	// Every platform shares one floor because every platform's arm of this
	// package ships in the same release. If the Windows arm ever slips to a
	// later release than the Unix one, Windows needs its own (higher) floor —
	// otherwise a Windows box could be updated down onto a release whose
	// binary has no Windows self-update code.
	minSelfUpdateVersion = "1.17.0"
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
	// Launcher fields are present only on windows responses whose resolved
	// version ships a launcher artifact (v1.11.4+). The self-update floor is
	// far above that, so on Windows both are required — see
	// fetchLatestBinary.
	LauncherChecksum       string `json:"launcher_checksum"`
	SignedLauncherChecksum string `json:"signed_launcher_checksum"`
}

// assetName returns the agent's release asset for this platform, matching
// the loaders' naming: darwin ships a single universal binary; linux and
// windows are per-arch. The windows form is the Authenticode-signed
// `.exe` — the older `_signed.exe` spelling only exists below v1.11.4, far
// under minSelfUpdateVersion, so it can never be selected here. Mirrors
// windowsBinaryAssetName in agent-api.
func assetName(version string) string {
	switch runtime.GOOS {
	case model.PlatformDarwin:
		return fmt.Sprintf("%s-%s-darwin", binaryName, version)
	case model.PlatformWindows:
		return fmt.Sprintf("%s-%s-windows_%s.exe", binaryName, version, runtime.GOARCH)
	}
	return fmt.Sprintf("%s-%s-linux_%s", binaryName, version, runtime.GOARCH)
}

// launcherAssetName returns the Windows launcher's release asset. Mirrors
// windowsLauncherAssetName in agent-api.
func launcherAssetName(version string) string {
	return fmt.Sprintf("%s-%s-windows_%s.exe", launcherName, version, runtime.GOARCH)
}

// launcherPath returns the launcher that sits beside the agent executable.
// The loader installs both into the same <install_dir>/bin, and the
// scheduled task's action references the launcher by that path.
func launcherPath(exe string) string {
	return filepath.Join(filepath.Dir(exe), launcherName+".exe")
}

// Run performs one self-update check. Returns true only when a new binary
// was installed (taking effect next run). Never returns an error: all
// failures are logged and swallowed so the scan proceeds regardless.
func Run(ctx context.Context, exec executor.Executor, log *progress.Logger) bool {
	if !config.AutoUpdate {
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

	// Windows also keeps the launcher current: the scheduled task's action
	// invokes it, not the agent, so leaving it on the old release would run a
	// mixed-version pair indefinitely.
	onWindows := runtime.GOOS == model.PlatformWindows
	launcher := ""
	if onWindows {
		launcher = launcherPath(exe)
		// Clear the images previous updates renamed aside before adding
		// another one.
		sweepLeftovers(exe, launcher)
	}

	meta, err := fetchLatestBinary(ctx)
	if err != nil {
		log.Warn("self-update: check failed (%v) — continuing on v%s", err, buildinfo.Version)
		return false
	}

	if versionBelow(meta.Version, minSelfUpdateVersion) {
		log.Warn("self-update: backend resolves v%s, below the self-update floor v%s — refusing (a downgrade past the floor would strand this install with no update path); staying on v%s",
			meta.Version, minSelfUpdateVersion, buildinfo.Version)
		return false
	}

	// The launcher is installed FIRST so the agent — the one artifact that
	// can retry on the next tick — is the last thing swapped.
	var targets []target
	if onWindows {
		targets = append(targets, target{
			label: "launcher", path: launcher, asset: launcherAssetName,
			checksum: meta.LauncherChecksum, signed: meta.SignedLauncherChecksum,
		})
	}
	targets = append(targets, target{
		label: "binary", path: exe, asset: assetName,
		checksum: meta.Checksum, signed: meta.SignedChecksum,
	})

	// Verify every signature BEFORE any download: one unverifiable artifact
	// rejects the whole release rather than landing half of it.
	for _, t := range targets {
		if err := verifyChecksumSignature(t.checksum, t.signed); err != nil {
			log.Warn("self-update: %s checksum signature verification failed for v%s: %v", t.label, meta.Version, err)
			return false
		}
	}

	installed := false
	for _, t := range targets {
		current, err := fileSHA256(t.path)
		// A target that isn't there yet is installed, not an error: it is how
		// a half-finished earlier update recovers.
		if err != nil && !os.IsNotExist(err) {
			log.Warn("self-update: cannot hash current %s: %v", t.label, err)
			return false
		}
		if err == nil && current == t.checksum {
			log.Debug("self-update: %s is current (v%s)", t.label, meta.Version)
			continue
		}
		if !install(ctx, log, t, meta.Version) {
			return false
		}
		installed = true
	}
	if !installed {
		return false
	}

	writeVersionMarker(meta.Version)
	log.Progress("Self-update: installed v%s (replacing v%s); it takes effect on the next scheduled run", meta.Version, buildinfo.Version)
	return true
}

// target is one artifact self-update keeps current: where it lives on disk,
// which release asset supplies it, and the signed checksum it must match.
type target struct {
	label    string
	path     string
	asset    func(version string) string
	checksum string
	signed   string
}

// verifyChecksumSignature checks that checksum carries a valid release
// signature. The signature covers the checksum string exactly as the release
// pipeline signed it (no trailing newline; the loaders verify the same
// bytes).
func verifyChecksumSignature(checksum, signed string) error {
	if checksum == "" {
		return fmt.Errorf("checksum is empty")
	}
	armored, err := decodeSignedChecksum(signed)
	if err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	return verifySSHSig(armored, []byte(checksum), allowedReleaseKeyB64, signatureNamespace)
}

// install downloads one target, verifies its sha256 against the (already
// signature-verified) expected checksum, and swaps it into place. Returns
// false on any failure, having left the on-disk artifact untouched.
func install(ctx context.Context, log *progress.Logger, t target, version string) bool {
	log.Progress("Self-update: v%s available (installed %s does not match it), downloading...", version, t.label)
	tmp, err := downloadAsset(ctx, version, t.asset(version), t.path)
	if err != nil {
		log.Warn("self-update: %s download failed: %v", t.label, err)
		return false
	}
	defer os.Remove(tmp) // no-op after a successful swap

	got, err := fileSHA256(tmp)
	if err != nil || got != t.checksum {
		log.Warn("self-update: downloaded %s checksum mismatch (got %.12s, want %.12s) — discarding", t.label, got, t.checksum)
		return false
	}
	// #nosec G302 -- this IS an agent executable being installed; it must
	// carry the same 0755 the loaders have always set on the binary.
	if err := os.Chmod(tmp, 0o755); err != nil {
		log.Warn("self-update: %s chmod failed: %v", t.label, err)
		return false
	}
	if err := swapBinary(tmp, t.path); err != nil {
		log.Warn("self-update: %s install failed: %v", t.label, err)
		return false
	}
	return true
}

func fetchLatestBinary(ctx context.Context) (*latestBinaryResponse, error) {
	q := url.Values{}
	// darwin is the endpoint's default (universal binary, no params); the
	// per-arch platforms must ask for their own artifact or they would get
	// the macOS checksum and reject every download.
	if runtime.GOOS == model.PlatformLinux || runtime.GOOS == model.PlatformWindows {
		q.Set("os", runtime.GOOS)
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
	// A windows response without both launcher fields is a hard error, not a
	// degraded install: the scheduled task's action references the launcher,
	// so updating the agent alone would leave the pair out of step. The
	// endpoint omits them only below v1.11.4 (impossible here — that is well
	// under minSelfUpdateVersion) and leaves them empty on a transient
	// signature-sidecar fetch failure, which the next tick retries.
	if runtime.GOOS == model.PlatformWindows && (meta.LauncherChecksum == "" || meta.SignedLauncherChecksum == "") {
		return nil, fmt.Errorf("latest-binary response for v%s is missing launcher_checksum/signed_launcher_checksum", meta.Version)
	}
	return &meta, nil
}

// downloadAsset streams a release asset to a temp file beside dst — the
// target executable's own directory, so it lands on the same filesystem and
// the swap that follows is a rename rather than a copy. Returns the temp path.
func downloadAsset(ctx context.Context, version, asset, dst string) (string, error) {
	assetURL := fmt.Sprintf("%s/v%s/%s", releaseBaseURL, version, asset)

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

	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".new-*")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	// Flush data blocks to disk before the caller swaps this in for the live
	// executable: on a power loss, journaled-metadata filesystems can persist
	// the rename without the data, leaving a truncated binary that the
	// scheduler then execs directly (no loader tick exists to re-download).
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// versionBelow reports whether semver a is strictly lower than b. Plain
// numeric field-by-field compare; missing fields count as 0, non-numeric
// suffixes are ignored ("1.17.0-rc1" compares as 1.17.0). Unparseable
// versions compare as 0.0.0 — i.e. below the floor, which fails safe (the
// update is refused, the current binary keeps running and polling).
func versionBelow(a, b string) bool {
	parse := func(s string) [3]int {
		var out [3]int
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		for i, part := range strings.SplitN(s, ".", 3) {
			n := 0
			for _, r := range part {
				if r < '0' || r > '9' {
					break
				}
				n = n*10 + int(r-'0')
			}
			out[i] = n
		}
		return out
	}
	va, vb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			return va[i] < vb[i]
		}
	}
	return false
}

// decodeSignedChecksum recovers the multi-line armored SSHSIG block from the
// API's signed_checksum field, which is base64-wrapped so the armored block
// survives single-line JSON transport (the shell loaders undo the same layer
// with `base64 -D` before handing it to ssh-keygen). A value that already
// carries the armor header is accepted as-is, so a future backend that stops
// double-encoding keeps working.
func decodeSignedChecksum(s string) (string, error) {
	if strings.Contains(s, sigArmorBegin) {
		return s, nil
	}
	compact := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return "", fmt.Errorf("base64-decode transport wrapper: %w", err)
	}
	armored := string(decoded)
	if !strings.Contains(armored, sigArmorBegin) {
		return "", fmt.Errorf("decoded signed_checksum is not an armored SSH signature block")
	}
	return armored, nil
}

func fileSHA256(path string) (string, error) {
	// #nosec G304 -- path is the agent's own resolved executable or the
	// temp download it just created; never user or network input.
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
	_ = os.WriteFile(filepath.Join(home, ".current_version"), []byte(version+"\n"), 0o600)
}
