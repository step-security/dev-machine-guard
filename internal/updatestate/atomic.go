package updatestate

import (
	"os"
	"path/filepath"
	"strings"
)

// writeAtomic writes data to a temp file beside path, fsyncs it, then
// replaces path (MoveFileEx REPLACE_EXISTING|WRITE_THROUGH on Windows,
// rename + directory fsync elsewhere). afterTemp runs once the temp file is
// durable and afterRename once path holds data; a non-nil error from
// afterTemp abandons the write and leaves path untouched.
func writeAtomic(path string, data []byte, afterTemp, afterRename func() error) error {
	dir, base := filepath.Split(path)
	f, err := os.CreateTemp(dir, tempPrefix(base)+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if afterTemp != nil {
		if err := afterTemp(); err != nil {
			return err
		}
	}
	if err := replaceFile(tmp, path); err != nil {
		return err
	}
	committed = true
	if afterRename != nil {
		return afterRename()
	}
	return nil
}

func tempPrefix(base string) string { return "." + base + ".tmp-" }

// SweepTemps removes temp files that a killed writer left beside path. Call
// it only while holding the update lock, so no live writer is affected.
func SweepTemps(path string) {
	dir, base := filepath.Split(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), tempPrefix(base)) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
