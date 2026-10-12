// Package updateinstall serializes executable replacement and recovers an
// interrupted Windows update before the stable bootstrap launches the agent.
package updateinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	Agent         = "stepsecurity-dev-machine-guard.exe"
	Launcher      = "stepsecurity-dev-machine-guard-task.exe"
	Bootstrap     = "stepsecurity-dev-machine-guard-bootstrap.exe"
	BootstrapFlag = "--recover-update"
	journalName   = ".update-transaction.json"
	backupPrefix  = ".update-backup-"
)

// Lock is an OS-owned lock, released by the kernel even after process death.
// The lock file must never be removed: all contenders must lock the same inode.
type Lock struct{ file *os.File }

func Acquire(dir string) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, ".selfupdate.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Lock{file: f}, nil
}

func (l *Lock) Release() {
	if l != nil && l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}

type backup struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Existed bool   `json:"existed"`
}
type journal struct {
	Schema    int      `json:"schema"`
	Directory string   `json:"directory"`
	Files     []backup `json:"files"`
}

// ReplacePair requires the installation lock and two fully verified downloads.
// Neither the bootstrap nor its path is ever replaced. A durable rollback
// journal precedes the first mutation; removing it commits the complete pair.
func ReplacePair(dir, launcher, agent string) error {
	return replacePair(dir, launcher, agent, nil)
}

// checkpoint lets process-level tests terminate at actual filesystem boundaries.
func replacePair(dir, launcher, agent string, checkpoint func(string)) error {
	if err := Recover(dir); err != nil {
		return err
	}
	backupDir, err := os.MkdirTemp(dir, backupPrefix)
	if err != nil {
		return err
	}
	pending := false
	defer func() {
		if !pending {
			_ = os.RemoveAll(backupDir)
		}
	}()
	j := journal{Schema: 1, Directory: filepath.Base(backupDir)}
	for _, name := range []string{Launcher, Agent} {
		b := backup{Name: name}
		src := filepath.Join(dir, name)
		fi, err := os.Lstat(src)
		if err == nil {
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("update target %s is not a regular file", name)
			}
			b.Existed = true
			if b.SHA256, err = copySynced(src, filepath.Join(backupDir, name)); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		j.Files = append(j.Files, b)
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".update-journal-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, filepath.Join(dir, journalName)); err != nil {
		return err
	}
	pending = true
	if checkpoint != nil {
		checkpoint("journal")
	}
	for _, name := range []string{Launcher, Agent} {
		src := launcher
		if name == Agent {
			src = agent
		}
		if err = replaceFile(src, filepath.Join(dir, name), backupDir, func() {
			if checkpoint != nil {
				checkpoint("aside:" + name)
			}
		}); err != nil {
			return errors.Join(err, Recover(dir))
		}
		if checkpoint != nil {
			checkpoint("installed:" + name)
		}
	}
	if err = os.Remove(filepath.Join(dir, journalName)); err != nil {
		return err
	}
	pending = false
	return nil
}

// Recover rolls an uncommitted pair back using untouched backup copies. It is
// repeatable even if a previous recovery died between renames. Caller holds
// the installation lock. Invalid/missing backup data fails closed.
func Recover(dir string) error {
	f, err := os.Open(filepath.Join(dir, journalName))
	if errors.Is(err, os.ErrNotExist) {
		cleanup(dir)
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return err
	}
	// Close before journal deletion: Windows does not permit deleting an open
	// file unless every handle shares delete access.
	if err = f.Close(); err != nil {
		return err
	}
	var j journal
	if len(raw) > 4096 || json.Unmarshal(raw, &j) != nil || j.Schema != 1 ||
		!strings.HasPrefix(j.Directory, backupPrefix) || filepath.Base(j.Directory) != j.Directory ||
		strings.ContainsAny(j.Directory, `/\:`) || len(j.Files) != 2 {
		return fmt.Errorf("invalid update recovery journal")
	}
	backupDir := filepath.Join(dir, j.Directory)
	fi, err := os.Lstat(backupDir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("invalid recovery directory")
	}
	// Validate BOTH backups before changing either canonical path.
	for i, name := range []string{Launcher, Agent} {
		b := j.Files[i]
		if b.Name != name {
			return fmt.Errorf("invalid update recovery target")
		}
		if b.Existed {
			sum, err := hashRegular(filepath.Join(backupDir, name))
			if err != nil || sum != b.SHA256 {
				return fmt.Errorf("invalid recovery backup for %s", name)
			}
		}
	}
	for _, b := range j.Files {
		dst := filepath.Join(dir, b.Name)
		if !b.Existed {
			if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err := moveAside(dst, backupDir); err != nil {
				return err
			}
			continue
		}
		tmp, err := os.CreateTemp(dir, ".update-restore-*")
		if err != nil {
			return err
		}
		path := tmp.Name()
		_ = tmp.Close()
		if _, err = copySynced(filepath.Join(backupDir, b.Name), path); err == nil {
			err = replaceFile(path, dst, backupDir, nil)
		}
		_ = os.Remove(path)
		if err != nil {
			return fmt.Errorf("restore %s: %w", b.Name, err)
		}
	}
	if err = os.Remove(filepath.Join(dir, journalName)); err != nil {
		return err
	}
	_ = os.RemoveAll(backupDir)
	return nil
}

func replaceFile(src, dst, backupDir string, afterAside func()) error {
	if _, err := os.Stat(dst); err == nil {
		if err = moveAside(dst, backupDir); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if afterAside != nil {
		afterAside()
	}
	return os.Rename(src, dst)
}
func moveAside(path, dir string) error {
	f, err := os.CreateTemp(dir, "retired-*")
	if err != nil {
		return err
	}
	aside := f.Name()
	_ = f.Close()
	if err = os.Remove(aside); err != nil {
		return err
	}
	return os.Rename(path, aside)
}
func hashRegular(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func copySynced(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	// Executable backup/restore copies need execute permission on Unix hosts.
	// #nosec G302 -- private transaction directory; these are executable images.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), in)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Retired mapped images cannot be removed until their owning processes exit.
// Only private transaction directories are swept, while holding the lock and
// with no active journal. Symlinks are not followed.
func cleanup(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), backupPrefix) {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}
