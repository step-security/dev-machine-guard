//go:build darwin

package devicepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

// darwinManagedPrefsDir holds MDM-delivered managed preferences. VS Code's
// policy watcher resolves AllowedExtensions through CFPreferences on the
// com.microsoft.VSCode domain, which an MDM materializes as a plist either
// machine-wide (directly in this dir) or per-user (in a <user> subdir).
const (
	darwinManagedPrefsDir = "/Library/Managed Preferences"
	darwinVSCodePlistName = "com.microsoft.VSCode.plist"
)

// ProbeManagedPolicy reports whether an MDM-installed VS Code managed
// preference mentions AllowedExtensions or ExtensionGalleryServiceUrl,
// machine-wide or for any user. The plists are typically binary, but plist key
// names are stored as plain ASCII runs in both binary and XML encodings, so a
// byte scan is a reliable presence check without a plist parser dependency.
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
		for _, name := range managedPolicyNames() {
			if fileMentionsKey(p, name) {
				return true, p + " [" + name + "]"
			}
		}
	}
	return false, ""
}

// ProbeManagedContent reads the VS Code managed-preferences values the running
// user's VS Code would resolve on the com.microsoft.VSCode domain: the machine-
// wide managed-prefs plist overlaid by that user's per-user plist (per-user
// wins). It parses the plists (binary or XML) and never globs other users.
func ProbeManagedContent() (bool, map[string]json.RawMessage, error) {
	return probeDarwinManagedContent(darwinManagedPrefsDir, currentManagedPrefsUser())
}

// probeDarwinManagedContent is ProbeManagedContent parameterized over the
// managed-preferences root and the running user's short name so tests can stage
// a fake tree. An empty user reads machine-wide managed prefs only.
func probeDarwinManagedContent(root, user string) (bool, map[string]json.RawMessage, error) {
	// Merge in ascending precedence: machine-wide, then this user's per-user
	// prefs (which override machine-wide for the same key).
	merged := map[string]any{}
	for _, path := range darwinManagedPrefsFiles(root, user) {
		dict, err := readPlistDict(path)
		if err != nil {
			return false, nil, err
		}
		for k, v := range dict {
			merged[k] = v
		}
	}

	raw := map[string]string{}
	for _, name := range []string{allowedExtensionsName, galleryServiceURLName} {
		v, ok := merged[name]
		if !ok {
			continue
		}
		// These are stored as string values; a non-string managed pref is
		// malformed evidence.
		s, ok := v.(string)
		if !ok {
			return false, nil, fmt.Errorf("devicepolicy: %s in managed preferences is not a string", name)
		}
		raw[name] = s
	}
	return buildObserved(raw)
}

// darwinManagedPrefsFiles lists the managed-prefs plists to merge, in ascending
// precedence: machine-wide, then the running user's per-user file (skipped when
// user is empty).
func darwinManagedPrefsFiles(root, user string) []string {
	files := []string{filepath.Join(root, darwinVSCodePlistName)}
	if user != "" {
		files = append(files, filepath.Join(root, user, darwinVSCodePlistName))
	}
	return files
}

// readPlistDict parses the plist at path into its top-level dictionary. An
// absent file yields (nil, nil) — no managed prefs there. A present-but-
// unreadable or non-dictionary plist is an error (verification_failed).
func readPlistDict(path string) (map[string]any, error) {
	// #nosec G304 -- path is the package-constant managed-prefs location joined
	// with the running user's short name (or a test fixture), never external input.
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("devicepolicy: read %s: %w", path, err)
	}
	var dict map[string]any
	if _, err := plist.Unmarshal(b, &dict); err != nil {
		return nil, fmt.Errorf("devicepolicy: parse %s: %w", path, err)
	}
	return dict, nil
}

// currentManagedPrefsUser resolves the running user's short name for the per-
// user managed-prefs path from $HOME's base name, matching the settings writer
// (settingsPath uses os.UserHomeDir); $USER is only the fallback. Both must
// resolve the same user, else the agent could write one user's settings.json
// while probing another's managed prefs. A root LaunchDaemon runs with $HOME
// baked to the console user but no $USER (see internal/launchd), so $HOME leads.
// Empty when neither resolves → machine-wide prefs only.
func currentManagedPrefsUser() string {
	if home, err := os.UserHomeDir(); err == nil {
		if base := filepath.Base(home); base != "" && base != "." && base != string(filepath.Separator) {
			return base
		}
	}
	if u := strings.TrimSpace(os.Getenv("USER")); u != "" {
		return u
	}
	return ""
}
