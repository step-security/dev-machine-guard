package firewall

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/fwpath"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
)

// exeVersion is what `<exe> version --json` prints.
type exeVersion struct {
	Version string `json:"version"`
	Build   string `json:"build"`
}

func (v *exeVersion) String() string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprintf("%s (%s)", v.Version, v.Build)
}

// matches reports whether v is rel: the same build, and the same version or
// the version without its prerelease suffix (a 0.1.0-rc.5 release tags an
// exe that reports 0.1.0), the loader's Test-OnDeviceFirewallVersionMatch.
func (v *exeVersion) matches(rel release) bool {
	if v == nil || v.Build != rel.Build {
		return false
	}
	base, _, _ := strings.Cut(rel.Version, "-")
	return v.Version == rel.Version || v.Version == base
}

// exeVersionOf runs `<path> version --json`; nil when the exe is missing or
// cannot say (a build from before --json).
func (m *Manager) exeVersionOf(ctx context.Context, path string) *exeVersion {
	if !fileExists(path) {
		return nil
	}
	stdout, _, code, err := m.Sys.Run(ctx, exeVersionTimeout, path, "version", "--json")
	if err != nil || code != 0 {
		return nil
	}
	var v exeVersion
	if json.Unmarshal([]byte(strings.TrimSpace(stdout)), &v) != nil {
		return nil
	}
	v.Version, v.Build = strings.TrimSpace(v.Version), strings.TrimSpace(v.Build)
	if v.Version == "" || v.Build == "" {
		return nil
	}
	return &v
}

// verifySignature checks latest-firewall's signed checksum with the release
// key before anything is downloaded. A response without one is invalid.
func (m *Manager) verifySignature(ctx context.Context, rel release) bool {
	if testFirewallUnsigned() {
		m.Logf("firewall: WARNING: test-key build with DMG_TEST_FIREWALL_UNSIGNED=1: skipping the signed-checksum check of on-device firewall %s", rel)
		return true
	}
	if rel.Signed == "" {
		msg := fmt.Sprintf("Invalid latest-firewall response for %s: no signed_checksum", rel)
		m.Logf("firewall: %s", msg)
		m.fail(ctx, CodeResponseInvalid, rel.key(), msg)
		return false
	}
	signed := strings.TrimSpace(rel.Signed)
	if !strings.HasPrefix(signed, "-----BEGIN") {
		decoded, err := base64.StdEncoding.DecodeString(signed)
		if err != nil || len(decoded) == 0 {
			msg := fmt.Sprintf("Failed to base64-decode signed_checksum for on-device firewall %s", rel)
			m.Logf("firewall: %s", msg)
			m.fail(ctx, CodeSignatureDecodeFailed, rel.key(), msg)
			return false
		}
	}
	if err := m.verifyChecksum(rel.Checksum, []byte(signed)); err != nil {
		msg := fmt.Sprintf("Checksum signature verification failed for on-device firewall %s: %v", rel, err)
		m.Logf("firewall: %s; not installing", msg)
		m.fail(ctx, CodeSignatureInvalid, rel.key(), msg)
		return false
	}
	return true
}

// stage downloads, verifies and unpacks rel into a new private dir under
// StateDir and returns the staged exe and that dir (the caller removes it).
// Nothing on the system is touched until it returns.
func (m *Manager) stage(ctx context.Context, rel release) (exe, dir string, ok bool) {
	dir, err := os.MkdirTemp(m.StateDir, "fw-staging-")
	if err != nil {
		msg := fmt.Sprintf("Failed to create a staging dir: %v", err)
		m.Logf("firewall: %s", msg)
		m.fail(ctx, CodeMktempFailed, rel.key(), msg)
		return "", "", false
	}
	zipPath := filepath.Join(dir, rel.Asset)
	m.Logf("firewall: downloading the on-device firewall %s...", rel)
	source, err := m.download(ctx, rel, zipPath)
	if err != nil {
		msg := fmt.Sprintf("Failed to download the on-device firewall %s: %v", rel.Version, err)
		m.Logf("firewall: %s", msg)
		m.fail(ctx, CodeDownloadFailed, rel.key(), msg)
		return "", dir, false
	}
	if got, err := fileSHA256(zipPath); err != nil || got != rel.Checksum {
		msg := fmt.Sprintf("On-device firewall %s checksum mismatch (source: %s)", rel.Version, source)
		m.Logf("firewall: %s (expected %s, got %s)", msg, rel.Checksum, got)
		m.fail(ctx, CodeChecksumMismatch, rel.key(), msg)
		return "", dir, false
	}
	exe = filepath.Join(dir, "unpacked", fwpath.ExeName)
	if err := unpackExe(zipPath, exe); err != nil {
		msg := fmt.Sprintf("%s: %v", rel.Asset, err)
		m.Logf("firewall: failed to unpack the on-device firewall: %s", msg)
		m.fail(ctx, CodeUnpackFailed, rel.key(), msg)
		return "", dir, false
	}
	// The signature before the exe is run for its version.
	if testFirewallUnsigned() {
		m.Logf("firewall: WARNING: test-key build with DMG_TEST_FIREWALL_UNSIGNED=1: skipping the Authenticode check of on-device firewall %s", rel)
	} else if err := m.Sys.VerifyPublisher(exe, m.SelfExe); err != nil {
		msg := fmt.Sprintf("On-device firewall %s: %v", rel, err)
		m.Logf("firewall: Authenticode check failed: %s", msg)
		m.fail(ctx, CodeAuthenticodeFailed, rel.key(), msg)
		return "", dir, false
	}
	if got := m.exeVersionOf(ctx, exe); !got.matches(rel) {
		msg := fmt.Sprintf("On-device firewall %s: exe reports %s, release build %s", rel.Version, got, rel.Build)
		m.Logf("firewall: %s", msg)
		m.fail(ctx, CodeBuildMismatch, rel.key(), msg)
		return "", dir, false
	}
	m.Logf("firewall: on-device firewall %s downloaded and verified (source: %s)", rel, source)
	return exe, dir, true
}

// download fetches the package: download_url when it is a github.com https
// URL, else (or when that fails) packages_url, the same asset on the packages
// mirror (validated in validate). It returns the source used.
func (m *Manager) download(ctx context.Context, rel release, dst string) (string, error) {
	var githubErr error
	if githubURLRe.MatchString(rel.DownloadURL) {
		if githubErr = m.fetchTo(ctx, rel.DownloadURL, dst); githubErr == nil {
			return rel.DownloadURL, nil
		}
	} else {
		githubErr = fmt.Errorf("no GitHub download_url in the latest-firewall response (%q)", rel.DownloadURL)
	}
	if rel.PackagesURL == "" {
		return "", fmt.Errorf("github (%s) -> %w; no packages_url in the latest-firewall response", rel.DownloadURL, githubErr)
	}
	m.Logf("firewall: GitHub download unavailable or failed (%v); trying the packages mirror...", githubErr)
	if err := m.fetchTo(ctx, rel.PackagesURL, dst); err != nil {
		return "", fmt.Errorf("github (%s) -> %v; packages (%s) -> %w", rel.DownloadURL, githubErr, rel.PackagesURL, err)
	}
	return rel.PackagesURL, nil
}

// fetchTo downloads u to dst, at most maxPackageBytes within downloadTimeout.
func (m *Manager) fetchTo(ctx context.Context, u, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "dmg/"+m.AgentVersion+" (firewall)")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("[%s] %w", telemetry.NetErrorCode(err), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("[%s] HTTP %d", telemetry.HTTPStatusCode(resp.StatusCode), resp.StatusCode)
	}
	if resp.ContentLength > maxPackageBytes {
		return errors.New("the package exceeds the size limit")
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- inside our private staging dir
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, maxPackageBytes+1))
	closeErr := f.Close()
	switch {
	case copyErr != nil:
		return fmt.Errorf("[%s] %w", telemetry.NetErrorCode(copyErr), copyErr)
	case n > maxPackageBytes:
		return errors.New("the package exceeds the size limit")
	}
	return closeErr
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- inside our private staging dir
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

// unpackExe extracts the package's one entry, the firewall exe at the zip's
// root, to dst. Any other shape (more entries, a folder, another name, a
// link, an oversized file) is refused.
func unpackExe(zipPath, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) != 1 {
		return fmt.Errorf("the zip holds %d entries; want only %s at its root", len(zr.File), fwpath.ExeName)
	}
	f := zr.File[0]
	if f.Name != fwpath.ExeName || !f.Mode().IsRegular() {
		return fmt.Errorf("the zip holds %q; want only %s at its root", f.Name, fwpath.ExeName)
	}
	if f.UncompressedSize64 > maxPackageBytes {
		return fmt.Errorf("%s exceeds the size limit", fwpath.ExeName)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700) // #nosec G302 G304 -- an exe in our private staging dir
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(rc, maxPackageBytes+1))
	closeErr := out.Close()
	switch {
	case copyErr != nil:
		return copyErr
	case n > maxPackageBytes:
		return fmt.Errorf("%s exceeds the size limit", fwpath.ExeName)
	}
	return closeErr
}
