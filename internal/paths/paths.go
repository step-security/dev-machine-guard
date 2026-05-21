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
// directory itself cannot be resolved.
func Home() string {
	if cliOverride != "" {
		return cliOverride
	}
	if v := os.Getenv(HomeEnvVar); v != "" {
		return v
	}
	if config.InstallDir != "" {
		return config.InstallDir
	}
	return LegacyHome()
}

// LegacyHome returns ~/.stepsecurity. Exposed for the migration check
// in main and for ShowConfigure displays. Mirrors config.LegacyDir but
// kept here so callers can grab the legacy path without taking a
// package dependency on config.
func LegacyHome() string {
	return config.LegacyDir()
}
