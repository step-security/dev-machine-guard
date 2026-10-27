package updatestate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrUnsafeRoot means a binary's install root can't be trusted as an MSI
// install root: no bootstrap in it, or users can write it.
var ErrUnsafeRoot = errors.New("untrusted install root")

// checkRoot is checkRootProtected; tests replace it.
var checkRoot = checkRootProtected

// BootstrapRoot returns the install root of the MSI bootstrap install that
// the binary at exePath belongs to: its own directory (the bootstrap, or a
// legacy top-level agent) or, for a binary under seed\<v>\ or
// versions\<v>\, two levels up. ok is false when no bootstrap sits in that
// root. This is the one rule for finding the root; exists reports whether
// a file exists.
func BootstrapRoot(exePath string, exists func(string) bool) (string, bool) {
	dir := filepath.Dir(exePath)
	candidates := []string{dir}
	parent := filepath.Dir(dir)
	if b := strings.ToLower(filepath.Base(parent)); b == "seed" || b == "versions" {
		candidates = append(candidates, filepath.Dir(parent))
	}
	for _, root := range candidates {
		if exists(filepath.Join(root, BootstrapFile)) {
			return root, true
		}
	}
	return "", false
}

// ResolveInstallRoot returns the install root of the binary at exePath
// (BootstrapRoot) after checking users can't write it. A SYSTEM process
// must never trust a root it can't vouch for, so there is no fallback.
func ResolveInstallRoot(exePath string) (string, error) {
	root, ok := BootstrapRoot(exePath, func(p string) bool {
		fi, err := os.Lstat(p)
		return err == nil && fi.Mode().IsRegular()
	})
	if !ok {
		return "", fmt.Errorf("%w: no %s for %s", ErrUnsafeRoot, BootstrapFile, exePath)
	}
	if err := checkRoot(root); err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrUnsafeRoot, root, err)
	}
	return root, nil
}

// ResolveLayout is the MSI layout of the binary at exePath: the install
// root from ResolveInstallRoot and the data root from DataRoot.
func ResolveLayout(exePath string) (Layout, error) {
	root, err := ResolveInstallRoot(exePath)
	if err != nil {
		return Layout{}, err
	}
	return Layout{InstallRoot: root, DataRoot: DataRoot()}, nil
}
