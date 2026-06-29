//go:build darwin

package devicepolicy

import "path/filepath"

// darwinManagedPrefsDir holds MDM-delivered managed preferences. VS Code's
// policy watcher resolves AllowedExtensions through CFPreferences on the
// com.microsoft.VSCode domain, which an MDM materializes as a plist either
// machine-wide (directly in this dir) or per-user (in a <user> subdir).
const (
	darwinManagedPrefsDir = "/Library/Managed Preferences"
	darwinVSCodePlistName = "com.microsoft.VSCode.plist"
)

// ProbeManagedPolicy reports whether an MDM-installed VS Code managed
// preference mentions AllowedExtensions, machine-wide or for any user. The
// plists are typically binary, but plist key names are stored as plain ASCII
// runs in both binary and XML encodings, so a byte scan is a reliable
// presence check without a plist parser dependency.
func ProbeManagedPolicy() (bool, string) {
	return probeDarwinManagedPrefs(darwinManagedPrefsDir)
}

// probeDarwinManagedPrefs is ProbeManagedPolicy parameterized over the
// managed-preferences root so tests can stage a fake tree.
func probeDarwinManagedPrefs(root string) (bool, string) {
	candidates := []string{filepath.Join(root, darwinVSCodePlistName)}
	perUser, _ := filepath.Glob(filepath.Join(root, "*", darwinVSCodePlistName))
	candidates = append(candidates, perUser...)
	for _, p := range candidates {
		if fileMentionsKey(p, allowedExtensionsName) {
			return true, p + " [" + allowedExtensionsName + "]"
		}
	}
	return false, ""
}
