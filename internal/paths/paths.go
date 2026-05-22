// Package paths owns the single source of truth for "where does the
// agent put its files." It resolves a base directory (the install dir)
// from a layered set of sources so callers can stop deriving
// ~/.stepsecurity independently:
//
//  1. --install-dir CLI flag (set by main via SetOverride)
//  2. $STEPSECURITY_HOME environment variable (set by service unit / loader)
//  3. install_dir config field (loaded by internal/config)
//  4. ~/.stepsecurity (legacy default)
//
// config.json itself stays at the legacy location regardless — see
// internal/config.LegacyDir — so the agent can always bootstrap. All
// other files (logs, hook errors, the binary placed by the loader) live
// under Home().
package paths

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/config"
)

// HomeEnvVar is the environment variable consulted in resolution
// step 2. Service installers bake this into their unit files so
// scheduler-invoked runs see the same install dir as interactive ones.
const HomeEnvVar = "STEPSECURITY_HOME"

// cliOverride captures the --install-dir CLI flag value (step 1).
// Set once at startup by main; never mutated thereafter.
var cliOverride string

// SetOverride installs the CLI-flag value. Called by main after
// cli.Parse and before any code that calls Home() — see
// cmd/stepsecurity-dev-machine-guard/main.go.
func SetOverride(s string) {
	cliOverride = s
}

// Home returns the resolved install dir. Falls back to LegacyHome when
// nothing else is set. Empty string is possible only when the home
// directory itself cannot be resolved. A leading $HOME or ~ token in
// any source is expanded via expandHome so the returned path is
// canonical for the current OS, keeping the migration warning in main
// from misfiring on hand-edited values like "$HOME/.stepsecurity" that
// resolve to the legacy default.
//
// Note: this is a superset of resolveSearchDirs in internal/scan/scanner.go,
// which only expands the exact literal "$HOME" — the install dir comes
// from operator-edited config so it has to tolerate the "$HOME/foo" /
// "~/foo" forms our docs use; search_dirs come from --search-dirs flag
// values that operators don't combine with subpaths.
func Home() string {
	if cliOverride != "" {
		return expandHome(cliOverride)
	}
	if v := os.Getenv(HomeEnvVar); v != "" {
		return expandHome(v)
	}
	if config.InstallDir != "" {
		return expandHome(config.InstallDir)
	}
	return LegacyHome()
}

// expandHome replaces a leading $HOME or ~ token with the resolved
// user home directory. Returns the input unchanged when the home
// directory cannot be resolved or no token is present. Callers that
// hand-edit config.json with "$HOME/.stepsecurity" — the literal value
// our docs use — get the same canonical form as LegacyHome(), which
// keeps the migration warning in main from misfiring on identical
// paths.
func expandHome(s string) string {
	if s == "" {
		return s
	}
	if !strings.HasPrefix(s, "$HOME") && !strings.HasPrefix(s, "~") {
		return s
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return s
	}
	switch {
	case s == "$HOME" || s == "~":
		return home
	case strings.HasPrefix(s, "$HOME/") || strings.HasPrefix(s, `$HOME\`):
		// filepath.Join + Clean canonicalises separators so Windows
		// gets C:\Users\me\.stepsecurity (not C:\Users\me/.stepsecurity)
		// and the equality check against LegacyHome() can succeed.
		return filepath.Join(home, s[len("$HOME"):])
	case strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`):
		return filepath.Join(home, s[len("~"):])
	}
	return s
}

// LegacyHome returns ~/.stepsecurity. Exposed for the migration check
// in main and for ShowConfigure displays. Mirrors config.LegacyDir but
// kept here so callers can grab the legacy path without taking a
// package dependency on config.
func LegacyHome() string {
	return config.LegacyDir()
}
