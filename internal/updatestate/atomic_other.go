//go:build !windows

package updatestate

import (
	"os"
	"path/filepath"
)

func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
