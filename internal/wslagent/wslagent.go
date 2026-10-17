// Package wslagent keeps the Linux agent binary that the Windows agent runs
// inside WSL distributions next to the Windows agent.
//
// The MSI and the PowerShell loader both install that binary (as dmg-linux).
// Installs that have neither, such as a binary run with `install`, an old
// loader, or a loader run that skipped it, otherwise never get WSL telemetry.
// Ensure fills that gap: it downloads the linux_<arch> asset for the running
// agent's version from the GitHub release and accepts it only if its
// checksum carries a valid release signature (see internal/releasesig).
//
// A copy this package did not install belongs to whoever did (MSI, loader)
// and is used as is. A copy it did install is tracked by a marker file and
// replaced when the agent version changes.
package wslagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/releasesig"
)

// BinaryName is the file name the Windows agent looks for next to itself.
// The MSI and the loader install the Linux agent under the same name.
const BinaryName = "dmg-linux"

// markerSuffix names the file that records a copy this package installed:
// "<version> <sha256>". Without it, a dmg-linux is treated as managed by
// someone else.
const markerSuffix = ".fetched"

// pendingSuffix names the claim written before a new binary is moved into
// place and renamed to the marker after it. If a run stops between the two,
// the next run finds the claim and settles it (recoverPending) instead of
// mistaking our copy for an installer's.
const pendingSuffix = ".fetched.pending"

// DefaultReleaseBase is where release assets are downloaded from.
const DefaultReleaseBase = "https://github.com/step-security/dev-machine-guard/releases/download"

// maxBinaryBytes bounds the download. Release Linux binaries are well under
// this; anything larger is not one of them.
const maxBinaryBytes = 256 << 20

// maxSigBytes bounds the signature download.
const maxSigBytes = 64 << 10

// DefaultTimeout bounds one download, so a slow network cannot hold the
// host's scheduled run open. Under the wsl_scan phase budget, leaving time
// to launch the distros afterwards.
const DefaultTimeout = 90 * time.Second

// Fetcher downloads and installs the Linux agent. The zero value is not
// usable; use New.
type Fetcher struct {
	HTTP        *http.Client
	ReleaseBase string
	// Verify checks a release signature over a hex checksum. Replaceable in
	// tests; production uses releasesig.VerifyChecksum.
	Verify func(checksum string, sig []byte) error
}

// New returns a Fetcher that downloads from the GitHub release.
func New() *Fetcher {
	return &Fetcher{
		HTTP:        &http.Client{Timeout: DefaultTimeout},
		ReleaseBase: DefaultReleaseBase,
		Verify:      releasesig.VerifyChecksum,
	}
}

// AssetName is the release asset for the Linux agent of version and arch.
// Must match linuxBinaryAssetName in agent-api's release sync.
func AssetName(version, arch string) string {
	return "stepsecurity-dev-machine-guard-" + version + "-linux_" + arch
}

// Ensure returns the path of a Linux agent binary in dir that is safe to run
// for agent version, downloading one when needed. downloaded reports whether
// this call installed a new copy.
//
// When replacing an older copy of our own fails (offline, GitHub blocked),
// Ensure returns that older copy together with the error: a guest from a
// recent release still scans, and the next run tries again.
func (f *Fetcher) Ensure(ctx context.Context, dir, version, arch string) (path string, downloaded bool, err error) {
	if arch != "amd64" && arch != "arm64" {
		return "", false, fmt.Errorf("no Linux agent is published for arch %q", arch)
	}
	if version == "" {
		return "", false, errors.New("agent version unknown")
	}

	path = filepath.Join(dir, BinaryName)
	marker := path + markerSuffix
	recoverPending(path)

	if current, err := fileSHA256(path); err == nil {
		mVersion, mSum, ok := readMarker(marker)
		switch {
		case !ok:
			// Installed by the MSI or the loader, which keep it in step
			// with the agent themselves.
			return path, false, nil
		case mSum != current:
			// Replaced since this package installed it, most likely by a
			// loader run. The new owner manages it from here.
			_ = os.Remove(marker)
			return path, false, nil
		case mVersion == version:
			return path, false, nil
		}
		// Our copy, from another agent version: replace it below.
		if err := f.install(ctx, path, version, arch); err != nil {
			return path, false, err
		}
		return path, true, nil
	}

	if err := f.install(ctx, path, version, arch); err != nil {
		return "", false, err
	}
	return path, true, nil
}

func (f *Fetcher) install(ctx context.Context, path, version, arch string) error {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	asset := AssetName(version, arch)
	base := strings.TrimSuffix(f.ReleaseBase, "/") + "/v" + version + "/" + asset

	sig, err := f.get(ctx, base+".sha256.sig", maxSigBytes)
	if err != nil {
		return fmt.Errorf("download signature: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+BinaryName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	sum, err := f.download(ctx, base, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download %s: %w", asset, err)
	}
	if err := f.Verify(sum, sig); err != nil {
		return fmt.Errorf("verify %s: %w", asset, err)
	}
	// #nosec G302 -- an executable: wsl.exe runs it as the distro's user.
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	// Claim first, publish second. The claim survives an interruption at any
	// later step, and recoverPending settles it on the next run.
	pending := path + pendingSuffix
	if err := writeFileAtomic(pending, []byte(version+" "+sum+"\n"), 0o600); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// The old copy and its marker are untouched; drop the claim.
		_ = os.Remove(pending)
		return fmt.Errorf("install %s: %w", path, err)
	}
	if err := os.Rename(pending, path+markerSuffix); err != nil {
		return fmt.Errorf("write marker: %w", err)
	}
	return nil
}

// recoverPending settles an install that stopped after writing its claim.
// A claim whose checksum matches the binary on disk was published, so it
// becomes the marker. Any other claim (binary never moved, or a truncated
// claim) is dropped, which leaves the previous state as it was.
func recoverPending(path string) {
	pending := path + pendingSuffix
	_, sum, ok := readMarker(pending)
	if ok {
		if current, err := fileSHA256(path); err == nil && current == sum {
			_ = os.Rename(pending, path+markerSuffix)
			return
		}
	}
	_ = os.Remove(pending)
}

// writeFileAtomic writes data to a temp file beside path and renames it into
// place, so a reader sees the old content or the new, never a partial file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// download streams url into w and returns the hex SHA-256 of what it wrote.
func (f *Fetcher) download(ctx context.Context, url string, w io.Writer) (string, error) {
	body, err := f.open(ctx, url)
	if err != nil {
		return "", err
	}
	defer body.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(body, maxBinaryBytes+1))
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", errors.New("empty response")
	}
	if n > maxBinaryBytes {
		return "", fmt.Errorf("larger than %d bytes", maxBinaryBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (f *Fetcher) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	body, err := f.open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}

func (f *Fetcher) open(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return resp.Body, nil
}

func fileSHA256(path string) (string, error) {
	// #nosec G304 -- path is dmg-linux beside the agent's own executable.
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readMarker(path string) (version, sum string, ok bool) {
	// #nosec G304 -- path is the marker beside the agent's own executable.
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	fields := strings.Fields(string(b))
	if len(fields) != 2 {
		return "", "", false
	}
	return fields[0], strings.ToLower(fields[1]), true
}
