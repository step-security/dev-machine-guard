// Package selfupdate is the Windows MSI self-updater (`agent self-update
// --system`, run by the SYSTEM update task through the bootstrap). It asks
// agent-api latest-binary for the tenant's target, verifies every artefact
// (SSHSIG over the checksum before download, sha256 after, Authenticode
// publisher), stages it as an immutable versions\<v> directory and switches
// the state.json pointer the bootstrap reads. See internal/updatestate for
// the on-disk contract.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

const (
	metaTimeout     = 30 * time.Second
	maxMetaBytes    = 64 << 10
	downloadTimeout = 5 * time.Minute
	maxAssetBytes   = 128 << 20

	agentAssetBase    = "stepsecurity-dev-machine-guard"
	launcherAssetBase = "stepsecurity-dev-machine-guard-task"

	defaultReleaseBaseURL = "https://github.com/step-security/dev-machine-guard/releases/download"
)

// minWindowsSelfUpdateVersion is the floor F (spec §6): the first release
// that contains this updater. A target below it would land a version with no
// SYSTEM updater, freezing the device, so it is refused. Set at release cut.
const minWindowsSelfUpdateVersion = "1.18.0"

// Floor returns F.
func Floor() updatestate.Version {
	v, err := updatestate.ParseVersion(minWindowsSelfUpdateVersion)
	if err != nil {
		panic(err)
	}
	return v
}

// Asset is one file of a release: the name it gets in versions\<v>, the
// release asset name, and its signed checksum.
type Asset struct {
	File     string // updatestate.AgentFile etc.
	Remote   string // release asset name
	Checksum string // lowercase hex sha256
	Signed   string // signed_checksum transport value
}

// Release is a latest-binary target with all three assets.
type Release struct {
	Version updatestate.Version
	Assets  []Asset
}

// Client talks to latest-binary and downloads release assets.
type Client struct {
	HTTP          *http.Client
	APIEndpoint   string
	CustomerID    string
	APIKey        string
	AgentVersion  string
	Arch          string // native windows arch: amd64 | arm64
	LagBehind     int
	CooldownHours int
	MirrorURL     string // optional HTTPS mirror (config update_mirror_url)
	// ReleaseBaseURL and SigningKey default to the GitHub releases and the
	// pinned release key; only tests and selfupdate_testkeys builds change them.
	ReleaseBaseURL string
	SigningKey     string
}

func (c *Client) releaseBase() string {
	if c.ReleaseBaseURL != "" {
		return c.ReleaseBaseURL
	}
	if v := testReleaseBaseURL(); v != "" {
		return v
	}
	return defaultReleaseBaseURL
}

// errDowngrade refuses an https -> http redirect.
var errDowngrade = errors.New("refusing a redirect from https to http")

// httpClient is c.HTTP with redirects that downgrade https to http refused
// (on top of any redirect policy the client already has).
func (c *Client) httpClient() *http.Client {
	hc := *c.HTTP
	hc.CheckRedirect = refuseDowngrade(hc.CheckRedirect)
	return &hc
}

func refuseDowngrade(prev func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		for _, v := range via {
			if v.URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errDowngrade
			}
		}
		if prev != nil {
			return prev(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
}

func (c *Client) signingKey() string {
	if c.SigningKey != "" {
		return c.SigningKey
	}
	if v := testSSHSIGKey(); v != "" {
		return v
	}
	return releasePublicKeyB64
}

type latestBinaryResponse struct {
	Version                string `json:"version"`
	Checksum               string `json:"checksum"`
	SignedChecksum         string `json:"signed_checksum"`
	LauncherChecksum       string `json:"launcher_checksum"`
	SignedLauncherChecksum string `json:"signed_launcher_checksum"`
	LinuxChecksum          string `json:"linux_checksum"`
	SignedLinuxChecksum    string `json:"signed_linux_checksum"`
}

// ErrCheck wraps every latest-binary failure (update_check_failed).
var ErrCheck = errors.New("latest-binary check failed")

// Latest resolves the target from one windows latest-binary response:
// agent, launcher and dmg-linux all come from the same resolution, so they
// always name one version. A missing checksum or signature for any asset is
// left empty for VerifySignatures to reject (update_verify_failed) before
// anything is downloaded.
func (c *Client) Latest(ctx context.Context) (*Release, error) {
	win, err := c.fetch(ctx, "windows")
	if err != nil {
		return nil, err
	}
	v, err := updatestate.ParseVersion(win.Version)
	if err != nil {
		return nil, fmt.Errorf("%w: target %q is not a strict x.y.z release", ErrCheck, win.Version)
	}
	vs := v.String()
	return &Release{Version: v, Assets: []Asset{
		{File: updatestate.AgentFile, Remote: fmt.Sprintf("%s-%s-windows_%s.exe", agentAssetBase, vs, c.Arch),
			Checksum: strings.ToLower(win.Checksum), Signed: win.SignedChecksum},
		{File: updatestate.LauncherFile, Remote: fmt.Sprintf("%s-%s-windows_%s.exe", launcherAssetBase, vs, c.Arch),
			Checksum: strings.ToLower(win.LauncherChecksum), Signed: win.SignedLauncherChecksum},
		{File: updatestate.LinuxFile, Remote: fmt.Sprintf("%s-%s-linux_%s", agentAssetBase, vs, c.Arch),
			Checksum: strings.ToLower(win.LinuxChecksum), Signed: win.SignedLinuxChecksum},
	}}, nil
}

func (c *Client) fetch(ctx context.Context, goos string) (*latestBinaryResponse, error) {
	q := url.Values{}
	q.Set("os", goos)
	q.Set("arch", c.Arch)
	if c.LagBehind > 0 || c.CooldownHours > 0 {
		q.Set("lag_behind", fmt.Sprint(c.LagBehind))
		q.Set("cooldown_hours", fmt.Sprint(c.CooldownHours))
	}
	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/latest-binary?%s",
		strings.TrimRight(c.APIEndpoint, "/"), url.PathEscape(c.CustomerID), q.Encode())

	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCheck, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("X-Agent-Version", c.AgentVersion)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCheck, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: latest-binary (%s) returned HTTP %d", ErrCheck, goos, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetaBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCheck, err)
	}
	if len(body) > maxMetaBytes {
		return nil, fmt.Errorf("%w: latest-binary response too large", ErrCheck)
	}
	var meta latestBinaryResponse
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("%w: parse latest-binary response: %w", ErrCheck, err)
	}
	return &meta, nil
}

// ErrVerify wraps every signature, checksum or publisher failure
// (update_verify_failed).
var ErrVerify = errors.New("verification failed")

// VerifySignatures checks every asset's SSHSIG before anything is
// downloaded: one unverifiable asset rejects the whole release.
func (c *Client) VerifySignatures(r *Release) error {
	for _, a := range r.Assets {
		if a.Checksum == "" || a.Signed == "" {
			return fmt.Errorf("%w: latest-binary gave no checksum or signature for %s", ErrVerify, a.File)
		}
		if !isHexSHA256(a.Checksum) {
			return fmt.Errorf("%w: %s checksum is not a sha256", ErrVerify, a.File)
		}
		armored, err := decodeSignedChecksum(a.Signed)
		if err != nil {
			return fmt.Errorf("%w: %s signature: %w", ErrVerify, a.File, err)
		}
		if err := verifySSHSig(armored, []byte(a.Checksum), c.signingKey(), signatureNamespace); err != nil {
			return fmt.Errorf("%w: %s signature: %w", ErrVerify, a.File, err)
		}
	}
	return nil
}

func isHexSHA256(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

// ErrDownload wraps a download that failed from every source
// (update_download_failed).
var ErrDownload = errors.New("download failed")

// Download fetches asset a of version v into dir\<a.File>: GitHub first,
// then the mirror. The written file's sha256 must equal the signed checksum.
// Local write failures (disk full) are returned unwrapped by ErrDownload so
// the caller reports them as stage failures.
func (c *Client) Download(ctx context.Context, v updatestate.Version, a Asset, dir string) error {
	dst := filepath.Join(dir, a.File)
	primary := fmt.Sprintf("%s/v%s/%s", strings.TrimRight(c.releaseBase(), "/"), v, a.Remote)
	err := c.downloadURL(ctx, primary, dst, a.Checksum)
	if err == nil || !errors.Is(err, ErrDownload) || c.MirrorURL == "" {
		return err
	}
	mirror, merr := c.mirrorAssetURL(v, a)
	if merr != nil {
		return fmt.Errorf("%w: %w (mirror: %w)", ErrDownload, err, merr)
	}
	if err2 := c.downloadURL(ctx, mirror, dst, a.Checksum); err2 != nil {
		if !errors.Is(err2, ErrDownload) {
			return err2
		}
		return fmt.Errorf("%w: github: %w; mirror: %w", ErrDownload, err, err2)
	}
	return nil
}

func (c *Client) mirrorAssetURL(v updatestate.Version, a Asset) (string, error) {
	u, err := url.Parse(c.MirrorURL)
	insecureOK := testAllowInsecureMirror() && u != nil && u.Scheme == "http"
	if err != nil || (u.Scheme != "https" && !insecureOK) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid HTTPS update mirror")
	}
	return strings.TrimRight(u.String(), "/") + "/" + v.String() + "/" + a.Remote, nil
}

func (c *Client) downloadURL(ctx context.Context, assetURL, dst, want string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDownload, err)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDownload, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned HTTP %d", ErrDownload, assetURL, resp.StatusCode)
	}
	if resp.ContentLength > maxAssetBytes {
		return fmt.Errorf("%w: %s exceeds the size limit", ErrDownload, assetURL)
	}
	// #nosec G302 G304 -- dst is inside the updater's own staging directory; release executables are 0755.
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxAssetBytes+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	switch {
	case copyErr != nil && isLocalWriteErr(copyErr):
		return copyErr
	case copyErr != nil:
		return fmt.Errorf("%w: %s: %w", ErrDownload, assetURL, copyErr)
	case n > maxAssetBytes:
		return fmt.Errorf("%w: %s exceeds the size limit", ErrDownload, assetURL)
	case syncErr != nil:
		return syncErr
	case closeErr != nil:
		return closeErr
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: %s sha256 %s, want %s", ErrVerify, filepath.Base(dst), got, want)
	}
	return nil
}

// isLocalWriteErr tells a failed write to the staging file (disk full,
// quota) from a failed read of the response body.
func isLocalWriteErr(err error) bool {
	var pe *os.PathError
	return errors.As(err, &pe)
}

// decodeSignedChecksum recovers the armored SSHSIG block from the API's
// signed_checksum field, which is base64-wrapped for single-line JSON. A
// value that already carries the armor header is accepted as is.
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
		return "", errors.New("decoded signed_checksum is not an armored SSH signature block")
	}
	return armored, nil
}
