package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
)

// withOverride temporarily replaces the CLI override and restores it on
// cleanup. The override is package-level mutable state, so tests serialise
// through this helper. Also clears cliDisabled so a previous-test value
// can't leak through.
func withOverride(t *testing.T, v string) {
	t.Helper()
	prevOverride := cliOverride
	prevDisabled := cliDisabled
	cliOverride = v
	cliDisabled = false
	t.Cleanup(func() {
		cliOverride = prevOverride
		cliDisabled = prevDisabled
	})
}

// withDisabled sets the package-level disable flag for the test and
// restores it (plus cliOverride) on cleanup.
func withDisabled(t *testing.T) {
	t.Helper()
	prevOverride := cliOverride
	prevDisabled := cliDisabled
	cliOverride = ""
	cliDisabled = true
	t.Cleanup(func() {
		cliOverride = prevOverride
		cliDisabled = prevDisabled
	})
}

func withEnv(t *testing.T, key, value string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	t.Setenv(key, value)
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})
}

func withConfigInstallDir(t *testing.T, v string) {
	t.Helper()
	prev := config.InstallDir
	config.InstallDir = v
	t.Cleanup(func() { config.InstallDir = prev })
}

func TestHome_DefaultsToLegacy(t *testing.T) {
	withOverride(t, "")
	withEnv(t, HomeEnvVar, "")
	withConfigInstallDir(t, "")

	got := Home()
	legacy := LegacyHome()
	if legacy == "" {
		t.Skip("home dir unresolved in this environment")
	}
	if got != legacy {
		t.Errorf("Home() = %q, want LegacyHome() %q", got, legacy)
	}
	if !strings.HasSuffix(got, ".stepsecurity") {
		t.Errorf("Home() = %q, expected suffix .stepsecurity", got)
	}
}

func TestHome_ConfigOverridesLegacy(t *testing.T) {
	withOverride(t, "")
	withEnv(t, HomeEnvVar, "")
	withConfigInstallDir(t, "/from/config")

	if got := Home(); got != "/from/config" {
		t.Errorf("Home() = %q, want /from/config", got)
	}
}

// TestHome_ConfigOverridesEnv encodes the precedence flip that makes
// config.InstallDir authoritative: the loader scripts write to config,
// so editing config must immediately take effect even when a stale
// $STEPSECURITY_HOME was baked into a unit file at install time.
func TestHome_ConfigOverridesEnv(t *testing.T) {
	withOverride(t, "")
	withEnv(t, HomeEnvVar, "/from/env")
	withConfigInstallDir(t, "/from/config")

	if got := Home(); got != "/from/config" {
		t.Errorf("Home() = %q, want /from/config (config > env)", got)
	}
}

// TestHome_EnvFallsThroughWhenConfigUnset confirms env is still
// consulted when config is empty — it remains a defensive fallback,
// just at lower precedence than config.
func TestHome_EnvFallsThroughWhenConfigUnset(t *testing.T) {
	withOverride(t, "")
	withConfigInstallDir(t, "")
	withEnv(t, HomeEnvVar, "/from/env")

	if got := Home(); got != "/from/env" {
		t.Errorf("Home() = %q, want /from/env (env fallback when config unset)", got)
	}
}

func TestHome_CLIOverridesEverything(t *testing.T) {
	withConfigInstallDir(t, "/from/config")
	withEnv(t, HomeEnvVar, "/from/env")
	withOverride(t, "/from/cli")

	if got := Home(); got != "/from/cli" {
		t.Errorf("Home() = %q, want /from/cli (cli > config > env)", got)
	}
}

func TestHome_ExpandsHomeTokenFromConfig(t *testing.T) {
	withOverride(t, "")
	withEnv(t, HomeEnvVar, "")
	withConfigInstallDir(t, "$HOME/.stepsecurity")

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("home dir unresolved in this environment")
	}
	want := filepath.Join(home, ".stepsecurity")
	if got := Home(); got != want {
		t.Errorf("Home() = %q, want %q (config $HOME should expand)", got, want)
	}
	// And the migration warning's equality check must now succeed.
	if Home() != LegacyHome() {
		t.Errorf("Home()=%q vs LegacyHome()=%q — expected equal after $HOME expansion", Home(), LegacyHome())
	}
}

func TestHome_ExpandsTildeFromEnvVar(t *testing.T) {
	withOverride(t, "")
	withConfigInstallDir(t, "")
	withEnv(t, HomeEnvVar, "~/agent")

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("home dir unresolved in this environment")
	}
	want := filepath.Join(home, "agent")
	if got := Home(); got != want {
		t.Errorf("Home() = %q, want %q (env ~ should expand)", got, want)
	}
}

func TestHome_ExpandsHomeFromCLIFlag(t *testing.T) {
	withConfigInstallDir(t, "")
	withEnv(t, HomeEnvVar, "")
	withOverride(t, "$HOME/custom")

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("home dir unresolved in this environment")
	}
	want := filepath.Join(home, "custom")
	if got := Home(); got != want {
		t.Errorf("Home() = %q, want %q (CLI $HOME should expand)", got, want)
	}
}

func TestHome_AbsolutePathUnchanged(t *testing.T) {
	withOverride(t, "")
	withEnv(t, HomeEnvVar, "")
	withConfigInstallDir(t, "/opt/stepsecurity")

	if got := Home(); got != "/opt/stepsecurity" {
		t.Errorf("Home() = %q, want /opt/stepsecurity (absolute path must not be modified)", got)
	}
}

func TestSetOverride_Sticks(t *testing.T) {
	withOverride(t, "")
	SetOverride("/sticky")
	t.Cleanup(func() { SetOverride("") })

	if got := Home(); got != "/sticky" {
		t.Errorf("Home() = %q, want /sticky", got)
	}
}

// TestSetDisabled_ReturnsEmpty proves that --install-dir= (empty)
// makes Home() return "" globally — every downstream consumer
// (filelog, ai-agent hook errors, future files) uniformly skips,
// not just file logging.
func TestSetDisabled_ReturnsEmpty(t *testing.T) {
	withDisabled(t)
	withEnv(t, HomeEnvVar, "/from/env")
	withConfigInstallDir(t, "/from/config")

	if got := Home(); got != "" {
		t.Errorf("Home() = %q, want \"\" (SetDisabled must override every source)", got)
	}
}

// TestSetOverride_ClearsDisabled covers the case where a later
// SetOverride call must un-stick a prior SetDisabled — otherwise tests
// that exercise both flows in sequence would carry the disable through.
func TestSetOverride_ClearsDisabled(t *testing.T) {
	withDisabled(t)
	SetOverride("/back/on")
	t.Cleanup(func() { SetOverride("") })

	if got := Home(); got != "/back/on" {
		t.Errorf("Home() = %q, want /back/on (SetOverride should clear cliDisabled)", got)
	}
}

// TestHome_TrailingSlashCanonicalised ensures filepath.Clean normalises
// the resolved path so the migration warning's equality check (Home()
// vs LegacyHome()) does not misfire on "/foo/.stepsecurity/" vs
// "/foo/.stepsecurity".
func TestHome_TrailingSlashCanonicalised(t *testing.T) {
	withOverride(t, "")
	withEnv(t, HomeEnvVar, "")
	withConfigInstallDir(t, "/opt/stepsecurity/")

	if got := Home(); got != "/opt/stepsecurity" {
		t.Errorf("Home() = %q, want /opt/stepsecurity (trailing slash must be stripped)", got)
	}
}

// TestHome_DotComponentsCanonicalised covers filepath.Clean of internal
// "./" and "../" tokens — same goal as the trailing-slash case, just a
// different form of non-canonical input.
func TestHome_DotComponentsCanonicalised(t *testing.T) {
	withOverride(t, "")
	withEnv(t, HomeEnvVar, "")
	withConfigInstallDir(t, "/opt/./stepsecurity/../sec")

	if got := Home(); got != "/opt/sec" {
		t.Errorf("Home() = %q, want /opt/sec (Clean must collapse . and ..)", got)
	}
}
