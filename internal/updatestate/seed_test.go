package updatestate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSeedFiles(t *testing.T, l Layout, v Version) {
	t.Helper()
	dir := l.SeedDir(v)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range VersionFiles {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("seed:"+f), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(l.VersionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
}

// FR1-8: the seed's executables must pass the publisher check before
// anything is copied.
func TestCopySeedVersionChecksPublisherFirst(t *testing.T) {
	l := Layout{InstallRoot: t.TempDir(), DataRoot: t.TempDir()}
	v, _ := ParseVersion("1.21.0")
	writeSeedFiles(t, l, v)
	var checked []string
	bad := func(p string) error {
		checked = append(checked, filepath.Base(p))
		return errors.New("publisher differs")
	}
	if _, err := l.CopySeedVersion(v, time.Now(), bad); err == nil {
		t.Fatal("seed with a wrong publisher copied")
	}
	if _, err := os.Stat(l.VersionDir(v)); !os.IsNotExist(err) {
		t.Fatal("versions dir created despite the publisher failure")
	}
	if len(checked) == 0 || checked[0] != AgentFile {
		t.Fatalf("checked %v", checked)
	}
	ok := func(string) error { return nil }
	if _, err := l.CopySeedVersion(v, time.Now(), ok); err != nil {
		t.Fatal(err)
	}
}

// FR1-8: the copy must match hashes of the SOURCE taken before copying, so
// a seed changed mid-copy is not adopted.
func TestCopySeedVersionComparesSourceHashes(t *testing.T) {
	l := Layout{InstallRoot: t.TempDir(), DataRoot: t.TempDir()}
	v, _ := ParseVersion("1.21.0")
	writeSeedFiles(t, l, v)
	old := afterSeedHashed
	afterSeedHashed = func() {
		_ = os.WriteFile(filepath.Join(l.SeedDir(v), LinuxFile), []byte("swapped after hashing"), 0o755)
	}
	defer func() { afterSeedHashed = old }()
	if _, err := l.CopySeedVersion(v, time.Now(), nil); err == nil {
		t.Fatal("a seed changed during the copy was adopted")
	}
	if _, err := os.Stat(l.VersionDir(v)); !os.IsNotExist(err) {
		t.Fatal("versions dir created from a changed seed")
	}
}

// An open handle (an AV scanning the copied exe) blocks the final rename for
// a while; the copy waits it out instead of failing.
func TestCopySeedVersionRetriesBlockedRename(t *testing.T) {
	l := Layout{InstallRoot: t.TempDir(), DataRoot: t.TempDir()}
	v, _ := ParseVersion("1.21.0")
	writeSeedFiles(t, l, v)
	calls := stubRename(t, 0, nil)
	osRename = func(src, dst string) error {
		if *calls++; *calls <= 2 {
			return errBlocked
		}
		return os.Rename(src, dst)
	}
	if _, err := l.CopySeedVersion(v, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVersionDir(l.VersionDir(v), v); err != nil || *calls != 3 {
		t.Fatalf("verify=%v renames=%d, want nil and 3", err, *calls)
	}
}
