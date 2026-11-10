package schtasks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func prepareLogDirectory(ctx context.Context, exec executor.Executor, dir string) error {
	if exec.IsRoot() {
		// Reject redirected machine-data paths before granting access.
		for path := filepath.Clean(dir); ; path = filepath.Dir(path) {
			info, err := os.Lstat(path)
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("inspect log directory: %w", err)
			}
			if err == nil && (!info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0) {
				return fmt.Errorf("log directory ancestor %q is not a plain directory", path)
			}
			if filepath.Dir(path) == path {
				break
			}
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}
	if !exec.IsRoot() {
		return nil
	}

	// Users create logs and shared identity state here, but must not rename
	// the directory containing protected config.json. Replace the legacy
	// effective Modify grants first: /grant:r alone can retain an ACE with
	// different inheritance flags. Modify applies only to inheriting children.
	for _, grant := range []struct{ mode, rights string }{
		{"/remove:g", "*S-1-5-32-545"},
		{"/grant:r", "*S-1-5-32-545:(RD,WD,AD,REA,X,RA,RC,S)"},
		{"/grant", "*S-1-5-32-545:(OI)(CI)(IO)M"},
	} {
		_, _, code, err := exec.RunWithTimeout(ctx, 30*time.Second, "icacls", dir, grant.mode, grant.rights, "/L", "/Q")
		if err != nil {
			return fmt.Errorf("protect machine-data directory: %w", err)
		}
		if code != 0 {
			return fmt.Errorf("protect machine-data directory: icacls exited %d", code)
		}
	}
	return nil
}
