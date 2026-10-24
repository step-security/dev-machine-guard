package updatestate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/faultinject"
)

// CopySeedVersion copies seed\<v> into versions\<v> through a staging dir
// after the seed's agent and launcher pass verifyPublisher, checks every
// copied file against the source's sha256 and size taken before the copy,
// writes its manifest (so the updater treats it as a verified version) and
// renames it into place. A dir that already verifies is kept (immutable);
// anything else at that path is moved to trash first. Used by the MSI's
// adopt-seed and by the updater; the caller holds the update lock. It
// returns a note for the log ("" when nothing was copied).
func (l Layout) CopySeedVersion(v Version, now time.Time, verifyPublisher func(path string) error) (string, error) {
	// The seed's executables must come from our publisher (nil: skip).
	if verifyPublisher != nil {
		for _, name := range []string{AgentFile, LauncherFile} {
			if err := verifyPublisher(filepath.Join(l.SeedDir(v), name)); err != nil {
				return "", fmt.Errorf("seed %s %s: %w", v, name, err)
			}
		}
	}
	// Hash the source first: the copy must match it, not just itself.
	type fileSum struct {
		sum  string
		size int64
	}
	src := map[string]fileSum{}
	for _, name := range VersionFiles {
		p := filepath.Join(l.SeedDir(v), name)
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return "", fmt.Errorf("seed %s: %s missing or not a file", v, name)
		}
		sum, err := FileSHA256(p)
		if err != nil {
			return "", err
		}
		src[name] = fileSum{sum, fi.Size()}
	}
	afterSeedHashed()
	dst := l.VersionDir(v)
	note := ""
	if _, err := os.Lstat(dst); err == nil {
		if VerifyVersionDir(dst, v) == nil {
			return "", nil
		}
		trash := filepath.Join(l.VersionsDir(), fmt.Sprintf("%s%s-%x", TrashPrefix, v, now.UnixNano()))
		if err := os.Rename(dst, trash); err != nil {
			return "", fmt.Errorf("moving unverifiable %s aside: %w", dst, err)
		}
		_ = os.RemoveAll(trash)
		note = fmt.Sprintf("moved unverifiable %s aside; ", dst)
	}
	staging, err := l.StagingDir(v)
	if err != nil {
		return "", err
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(staging)
		}
	}()
	m := Manifest{Version: v.String(), Files: map[string]string{}}
	for _, name := range VersionFiles {
		dstFile := filepath.Join(staging, name)
		if err := copySeedFile(filepath.Join(l.SeedDir(v), name), dstFile); err != nil {
			return "", err
		}
		sum, err := FileSHA256(dstFile)
		if err != nil {
			return "", err
		}
		fi, err := os.Stat(dstFile)
		if err != nil {
			return "", err
		}
		if want := src[name]; sum != want.sum || fi.Size() != want.size {
			return "", fmt.Errorf("seed %s: copy of %s doesn't match the source hashed before copying", v, name)
		}
		m.Files[name] = sum
	}
	if err := WriteManifest(staging, m); err != nil {
		return "", err
	}
	if err := faultinject.Point("adopt.copied"); err != nil {
		return "", err
	}
	if err := os.Rename(staging, dst); err != nil {
		return "", err
	}
	done = true
	return note + fmt.Sprintf("copied seed %s into %s", v, dst), nil
}

// afterSeedHashed runs between hashing the seed and copying it (tests).
var afterSeedHashed = func() {}

func copySeedFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- MSI-owned seed payload
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) // #nosec G304 G302 -- fresh staging dir
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// AdoptSeedRule applies seed adoption to an existing state in memory:
// current = seed when current's dir is unusable, or when the seed is newer
// than current and not under an unexpired quarantine (previous = the old
// current, and the old current's probation ends). An MSI never downgrades a
// self-updated device. It reports whether st changed and why.
func (l Layout) AdoptSeedRule(st *State, seed Version, now time.Time) (changed bool, why string) {
	s, old := seed.String(), st.Current
	cur, _ := ParseVersion(old)
	switch {
	case !VersionDirUsable(l.VersionDir(cur)):
		st.Current = s
		if st.Probation != nil && st.Probation.Version == old {
			st.Probation = nil
		}
		if st.Previous == s {
			st.Previous = ""
		}
		return true, fmt.Sprintf("current %s unusable; current = seed %s", old, s)
	case Compare(seed, cur) <= 0:
		return false, ""
	}
	if q, ok := st.Quarantine[s]; ok && (q.Until.IsZero() || now.Before(q.Until)) {
		return false, fmt.Sprintf("seed %s is quarantined; current %s kept", s, old)
	}
	st.Previous, st.Current, st.Probation = old, s, nil
	return true, fmt.Sprintf("seed %s newer than current %s; current = seed", s, old)
}
