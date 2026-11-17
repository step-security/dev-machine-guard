//go:build windows

package detector

import (
	"context"
	"errors"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// nixDirectRefs is never reached on Windows (Nix is not scanned there); the
// stub keeps the SQLite driver out of the Windows binary.
func nixDirectRefs(context.Context, executor.Executor, []string) (map[string][]string, error) {
	return nil, errors.New("nix: unsupported platform")
}
