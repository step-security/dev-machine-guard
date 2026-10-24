package updatestate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Files of a version directory. They keep their release names so the
// launcher finds the agent beside itself (internal/launcher.AgentBinary) and
// the WSL scan finds dmg-linux beside the agent, unchanged.
const (
	AgentFile    = "stepsecurity-dev-machine-guard.exe"
	LauncherFile = "stepsecurity-dev-machine-guard-task.exe"
	LinuxFile    = "dmg-linux"
)

// VersionFiles lists every file a complete version directory holds besides
// its manifest.
var VersionFiles = []string{AgentFile, LauncherFile, LinuxFile}

// maxManifestSize bounds what ReadManifest reads.
const maxManifestSize = 64 << 10

// Manifest is versions\<v>\manifest.json: the sha256 of every file, written
// (and fsynced) before the directory is renamed into place.
type Manifest struct {
	Schema  int               `json:"schema"`
	Version string            `json:"version"`
	Files   map[string]string `json:"files"` // file name -> lowercase hex sha256
}

// WriteManifest atomically writes dir\manifest.json.
func WriteManifest(dir string, m Manifest) error {
	if !validVersion(m.Version) {
		return fmt.Errorf("updatestate: manifest version %q is not x.y.z", m.Version)
	}
	m.Schema = SchemaVersion
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, ManifestName), append(data, '\n'), nil, nil)
}

// ReadManifest reads dir\manifest.json.
func ReadManifest(dir string) (*Manifest, error) {
	data, err := readBounded(filepath.Join(dir, ManifestName), maxManifestSize)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("updatestate: manifest: %w", err)
	}
	return &m, nil
}

// ErrIncomplete means a version directory lacks a file or its manifest.
var ErrIncomplete = errors.New("updatestate: version directory incomplete")

// VersionDirComplete is the updater's cheap integrity check: every
// VersionFiles entry and the manifest exist as regular files. It does not
// hash. (VersionDirUsable is the bootstrap's narrower launchability check:
// agent and launcher only, no manifest.)
func VersionDirComplete(dir string) error {
	for _, name := range append([]string{ManifestName}, VersionFiles...) {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s", ErrIncomplete, name)
		}
	}
	return nil
}

// VerifyVersionDir checks that dir is a complete version v whose files match
// the manifest hashes.
func VerifyVersionDir(dir string, v Version) error {
	if err := VersionDirComplete(dir); err != nil {
		return err
	}
	m, err := ReadManifest(dir)
	if err != nil {
		return err
	}
	if m.Version != v.String() {
		return fmt.Errorf("updatestate: manifest version %q in %s, want %s", m.Version, dir, v)
	}
	for _, name := range VersionFiles {
		want := m.Files[name]
		if want == "" {
			return fmt.Errorf("%w: manifest lacks %s", ErrIncomplete, name)
		}
		got, err := FileSHA256(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("updatestate: %s in %s does not match its manifest hash", name, dir)
		}
	}
	return nil
}

// FileSHA256 returns the lowercase hex sha256 of a file.
func FileSHA256(path string) (string, error) {
	f, err := openShared(path)
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
