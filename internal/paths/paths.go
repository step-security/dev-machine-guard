// Package paths owns the single source of truth for "where does the
// agent put its files." It resolves a base directory (the install dir)
// from a layered set of sources so callers can stop deriving
// ~/.stepsecurity independently:
//
//  1. --install-dir CLI flag (set by main via SetOverride / SetDisabled)
//  2. install_dir config field (loaded by internal/config)
//  3. $STEPSECURITY_HOME environment variable (fallback only)
//  4. ~/.stepsecurity (legacy default)
//
// Why config beats env: the install_dir field in config.json is the
// canonical source of truth — the loader scripts (agent-api) write to
// it on every run, and operators can hand-edit it. Service installers
// (launchd / systemd / schtasks) bake STEPSECURITY_HOME into their unit
// files at install time, but that snapshot becomes stale the moment the
// operator edits config.json. Letting config win means scheduler-
// invoked runs immediately reflect a config change without requiring
// the operator to re-run `install`. The env var stays as a defensive
// fallback for the rare case where config.json is unreadable.
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

// HomeEnvVar is the environment variable consulted as a defensive
// fallback when both the CLI override and config.InstallDir are unset.
// Service installers bake this into their unit files but its precedence
// is intentionally below config so that an edited install_dir wins.
const HomeEnvVar = "STEPSECURITY_HOME"

// cliOverride captures the --install-dir CLI flag value (step 1).
// Set once at startup by main; never mutated thereafter.
var cliOverride string

// cliDisabled records that --install-dir= (explicit empty) was passed.
// It is distinct from "cliOverride is empty" because the empty string
// is also the "unset" sentinel for cliOverride itself. When set, Home()
// returns "" so every on-disk consumer — filelog, ai-agent hook errors,
// any future file derived from Home() — uniformly skips file output.
var cliDisabled bool

// SetOverride installs the CLI-flag value. Called by main after
// cli.Parse and before any code that calls Home() — see
// cmd/stepsecurity-dev-machine-guard/main.go.
func SetOverride(s string) {
	cliOverride = s
	cliDisabled = false
}

// SetDisabled marks the install dir as explicitly disabled for this
// run. After this call Home() returns "" regardless of env/config/
// legacy values, so no on-disk artifact is written under the resolved
// install dir. Used by main when the operator passes --install-dir=
// (empty) to silence per-run file logging.
func SetDisabled() {
	cliDisabled = true
	cliOverride = ""
}

// Home returns the resolved install dir. Falls back to LegacyHome when
// nothing else is set. Returns "" when SetDisabled() was called or
// when the home directory itself cannot be resolved. A leading $HOME
// or ~ token in any source is expanded via expandHome so the returned
// path is canonical for the current OS; the result is run through
// filepath.Clean so trailing slashes and "." / ".." components don't
// cause spurious mismatches in the migration-warning equality check.
func Home() string {
	if cliDisabled {
		return ""
	}
	// Read the env var once so a concurrent mutation (test helpers,
	// future goroutine setup) can't flip the value between the switch
	// guard and the assignment below — and so we don't pay for a second
	// syscall on every lookup.
	envHome := os.Getenv(HomeEnvVar)
	var raw string
	switch {
	case cliOverride != "":
		raw = cliOverride
	case config.InstallDir != "":
		raw = config.InstallDir
	case envHome != "":
		raw = envHome
	default:
		return LegacyHome()
	}
	resolved := expandHome(raw)
	if resolved == "" {
		return ""
	}
	return filepath.Clean(resolved)
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
