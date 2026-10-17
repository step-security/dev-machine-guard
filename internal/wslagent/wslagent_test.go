package wslagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

var errBadSig = errors.New("bad signature")

// release serves one version's Linux agent and signature, and counts binary
// downloads. Signatures are "sig:<sha256>"; the fake verifier accepts exactly
// that, so a body/checksum mismatch fails verification like the real thing.
type release struct {
	version string
	arch    string
	body    []byte
	sigOK   bool
	hits    atomic.Int32
}

func (r *release) handler(t *testing.T) http.Handler {
	t.Helper()
	asset := "/v" + r.version + "/" + AssetName(r.version, r.arch)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case asset:
			r.hits.Add(1)
			_, _ = w.Write(r.body)
		case asset + ".sha256.sig":
			sum := sha256.Sum256(r.body)
			sig := "sig:" + hex.EncodeToString(sum[:])
			if !r.sigOK {
				sig = "sig:forged"
			}
			_, _ = w.Write([]byte(sig))
		default:
			http.NotFound(w, req)
		}
	})
}

func fakeVerify(checksum string, sig []byte) error {
	if string(sig) != "sig:"+checksum {
		return errBadSig
	}
	return nil
}

func newFetcher(t *testing.T, r *release) *Fetcher {
	t.Helper()
	srv := httptest.NewServer(r.handler(t))
	t.Cleanup(srv.Close)
	return &Fetcher{HTTP: srv.Client(), ReleaseBase: srv.URL + "/", Verify: fakeVerify}
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestEnsure_DownloadsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	r := &release{version: "1.18.0", arch: "amd64", body: []byte("ELF v1.18.0"), sigOK: true}
	f := newFetcher(t, r)

	path, downloaded, err := f.Ensure(context.Background(), dir, "1.18.0", "amd64")
	if err != nil || !downloaded {
		t.Fatalf("Ensure = (%q, %v, %v), want a download", path, downloaded, err)
	}
	if path != filepath.Join(dir, BinaryName) {
		t.Errorf("path = %q", path)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "ELF v1.18.0" {
		t.Errorf("installed %q", got)
	}
	marker, _ := os.ReadFile(path + markerSuffix)
	if strings.TrimSpace(string(marker)) != "1.18.0 "+sha(r.body) {
		t.Errorf("marker = %q", marker)
	}

	// Second run: same version, nothing to do.
	if _, downloaded, err := f.Ensure(context.Background(), dir, "1.18.0", "amd64"); err != nil || downloaded {
		t.Fatalf("second Ensure downloaded=%v err=%v, want no-op", downloaded, err)
	}
	if r.hits.Load() != 1 {
		t.Errorf("binary fetched %d times, want 1", r.hits.Load())
	}
}

// A copy with no marker came from the MSI or the loader. Their installer
// keeps it current, so it is used as is and never overwritten.
func TestEnsure_LeavesInstallerCopyAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, BinaryName)
	if err := os.WriteFile(path, []byte("from msi"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &release{version: "1.18.0", arch: "amd64", body: []byte("ELF"), sigOK: true}
	f := newFetcher(t, r)

	got, downloaded, err := f.Ensure(context.Background(), dir, "1.18.0", "amd64")
	if err != nil || downloaded || got != path {
		t.Fatalf("Ensure = (%q, %v, %v), want existing copy untouched", got, downloaded, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "from msi" {
		t.Errorf("installer copy overwritten: %q", b)
	}
	if r.hits.Load() != 0 {
		t.Error("must not download when an installer copy exists")
	}
}

// Our copy from an older agent version is replaced; a copy someone replaced
// after us (a loader run) is handed over to them.
func TestEnsure_VersionChangeAndHandover(t *testing.T) {
	t.Run("own copy from older version is replaced", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, BinaryName)
		old := []byte("ELF v1.17.0")
		_ = os.WriteFile(path, old, 0o755)
		_ = os.WriteFile(path+markerSuffix, []byte("1.17.0 "+sha(old)+"\n"), 0o644)

		r := &release{version: "1.18.0", arch: "arm64", body: []byte("ELF v1.18.0"), sigOK: true}
		_, downloaded, err := newFetcher(t, r).Ensure(context.Background(), dir, "1.18.0", "arm64")
		if err != nil || !downloaded {
			t.Fatalf("downloaded=%v err=%v, want replacement", downloaded, err)
		}
		if b, _ := os.ReadFile(path); string(b) != "ELF v1.18.0" {
			t.Errorf("binary = %q", b)
		}
	})

	t.Run("copy replaced by someone else is handed over", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, BinaryName)
		_ = os.WriteFile(path, []byte("loader wrote this"), 0o755)
		_ = os.WriteFile(path+markerSuffix, []byte("1.17.0 "+sha([]byte("ours"))+"\n"), 0o644)

		r := &release{version: "1.18.0", arch: "amd64", body: []byte("ELF"), sigOK: true}
		_, downloaded, err := newFetcher(t, r).Ensure(context.Background(), dir, "1.18.0", "amd64")
		if err != nil || downloaded {
			t.Fatalf("downloaded=%v err=%v, want handover", downloaded, err)
		}
		if _, err := os.Stat(path + markerSuffix); !os.IsNotExist(err) {
			t.Error("marker should be removed on handover")
		}
	})

	t.Run("failed update keeps the older own copy", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, BinaryName)
		old := []byte("ELF v1.17.0")
		_ = os.WriteFile(path, old, 0o755)
		_ = os.WriteFile(path+markerSuffix, []byte("1.17.0 "+sha(old)+"\n"), 0o644)

		r := &release{version: "1.18.0", arch: "amd64", body: []byte("ELF v1.18.0"), sigOK: false}
		got, downloaded, err := newFetcher(t, r).Ensure(context.Background(), dir, "1.18.0", "amd64")
		if err == nil || downloaded || got != path {
			t.Fatalf("Ensure = (%q, %v, %v), want old copy plus error", got, downloaded, err)
		}
		if b, _ := os.ReadFile(path); string(b) != "ELF v1.17.0" {
			t.Errorf("old copy damaged: %q", b)
		}
	})
}

// Nothing lands on disk unless the release signature checks out.
func TestEnsure_RejectsUnverified(t *testing.T) {
	cases := map[string]*release{
		"forged signature":  {version: "1.18.0", arch: "amd64", body: []byte("ELF"), sigOK: false},
		"missing release":   {version: "9.9.9", arch: "amd64", body: []byte("ELF"), sigOK: true},
		"empty binary body": {version: "1.18.0", arch: "amd64", body: nil, sigOK: true},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path, downloaded, err := newFetcher(t, r).Ensure(context.Background(), dir, "1.18.0", "amd64")
			if err == nil || downloaded || path != "" {
				t.Fatalf("Ensure = (%q, %v, %v), want failure", path, downloaded, err)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Errorf("left files behind: %v", entries)
			}
		})
	}
}

func TestEnsure_InputGuards(t *testing.T) {
	f := &Fetcher{HTTP: http.DefaultClient, ReleaseBase: "http://127.0.0.1:0", Verify: fakeVerify}
	if _, _, err := f.Ensure(context.Background(), t.TempDir(), "1.18.0", "386"); err == nil {
		t.Error("unsupported arch accepted")
	}
	if _, _, err := f.Ensure(context.Background(), t.TempDir(), "", "amd64"); err == nil {
		t.Error("empty version accepted")
	}
}

func TestAssetName(t *testing.T) {
	if got := AssetName("1.17.0", "arm64"); got != "stepsecurity-dev-machine-guard-1.17.0-linux_arm64" {
		t.Errorf("AssetName = %q", got)
	}
}

// A run that stopped after moving the new binary into place, before its
// marker, leaves only the claim. The next run must keep ownership: finish the
// marker, not download again, and still manage the next version change.
func TestEnsure_RecoversClaimAfterInterruptedPublish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, BinaryName)
	newBody := []byte("ELF v1.18.0")
	_ = os.WriteFile(path, newBody, 0o755)
	_ = os.WriteFile(path+pendingSuffix, []byte("1.18.0 "+sha(newBody)+"\n"), 0o600)

	r := &release{version: "1.18.0", arch: "amd64", body: newBody, sigOK: true}
	_, downloaded, err := newFetcher(t, r).Ensure(context.Background(), dir, "1.18.0", "amd64")
	if err != nil || downloaded {
		t.Fatalf("downloaded=%v err=%v, want the claim finished without a download", downloaded, err)
	}
	if m, _ := os.ReadFile(path + markerSuffix); strings.TrimSpace(string(m)) != "1.18.0 "+sha(newBody) {
		t.Errorf("marker = %q", m)
	}
	if _, err := os.Stat(path + pendingSuffix); !os.IsNotExist(err) {
		t.Error("claim should be gone")
	}

	next := &release{version: "1.19.0", arch: "amd64", body: []byte("ELF v1.19.0"), sigOK: true}
	if _, downloaded, err := newFetcher(t, next).Ensure(context.Background(), dir, "1.19.0", "amd64"); err != nil || !downloaded {
		t.Fatalf("version change: downloaded=%v err=%v, want our copy replaced", downloaded, err)
	}
}

// A run that stopped before moving the binary leaves a claim that does not
// match the file on disk. The claim is dropped and the previous state stands.
func TestEnsure_DropsClaimWhenBinaryNeverMoved(t *testing.T) {
	t.Run("own older copy is still updated", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, BinaryName)
		old := []byte("ELF v1.17.0")
		_ = os.WriteFile(path, old, 0o755)
		_ = os.WriteFile(path+markerSuffix, []byte("1.17.0 "+sha(old)+"\n"), 0o600)
		_ = os.WriteFile(path+pendingSuffix, []byte("1.18.0 "+sha([]byte("ELF v1.18.0"))+"\n"), 0o600)

		r := &release{version: "1.18.0", arch: "amd64", body: []byte("ELF v1.18.0"), sigOK: true}
		if _, downloaded, err := newFetcher(t, r).Ensure(context.Background(), dir, "1.18.0", "amd64"); err != nil || !downloaded {
			t.Fatalf("downloaded=%v err=%v, want our copy updated", downloaded, err)
		}
		if b, _ := os.ReadFile(path); string(b) != "ELF v1.18.0" {
			t.Errorf("binary = %q", b)
		}
	})

	t.Run("truncated claim beside an installer copy", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, BinaryName)
		_ = os.WriteFile(path, []byte("from msi"), 0o755)
		_ = os.WriteFile(path+pendingSuffix, []byte("1.18"), 0o600)

		r := &release{version: "1.18.0", arch: "amd64", body: []byte("ELF"), sigOK: true}
		if _, downloaded, err := newFetcher(t, r).Ensure(context.Background(), dir, "1.18.0", "amd64"); err != nil || downloaded {
			t.Fatalf("downloaded=%v err=%v, want installer copy left alone", downloaded, err)
		}
		if _, err := os.Stat(path + pendingSuffix); !os.IsNotExist(err) {
			t.Error("truncated claim should be removed")
		}
	})
}

// If the marker cannot be written after the binary moved, the run reports the
// error and the next run finishes the marker from the claim.
func TestEnsure_MarkerFailureRetriesNextRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, BinaryName)
	// A directory where the marker goes makes the claim-to-marker rename fail.
	if err := os.MkdirAll(filepath.Join(path+markerSuffix, "block"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &release{version: "1.18.0", arch: "amd64", body: []byte("ELF v1.18.0"), sigOK: true}
	f := newFetcher(t, r)
	if _, _, err := f.Ensure(context.Background(), dir, "1.18.0", "amd64"); err == nil {
		t.Fatal("want a marker error")
	}
	if _, err := os.Stat(path + pendingSuffix); err != nil {
		t.Fatalf("claim must survive the failure: %v", err)
	}

	_ = os.RemoveAll(path + markerSuffix)
	if _, downloaded, err := f.Ensure(context.Background(), dir, "1.18.0", "amd64"); err != nil || downloaded {
		t.Fatalf("retry: downloaded=%v err=%v, want the marker finished", downloaded, err)
	}
	if m, _ := os.ReadFile(path + markerSuffix); !strings.HasPrefix(string(m), "1.18.0 ") {
		t.Errorf("marker = %q", m)
	}
	if r.hits.Load() != 1 {
		t.Errorf("binary fetched %d times, want 1", r.hits.Load())
	}
}

// A successful install leaves the marker and no claim behind.
func TestEnsure_NoClaimLeftAfterInstall(t *testing.T) {
	dir := t.TempDir()
	r := &release{version: "1.18.0", arch: "amd64", body: []byte("ELF"), sigOK: true}
	if _, _, err := newFetcher(t, r).Ensure(context.Background(), dir, "1.18.0", "amd64"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != BinaryName+","+BinaryName+markerSuffix {
		t.Errorf("dir = %v", names)
	}
}
