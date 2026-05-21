package paths

import (
	"os"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
)

// withOverride temporarily replaces the CLI override and restores it on
// cleanup. The override is package-level mutable state, so tests serialise
// through this helper.
func withOverride(t *testing.T, v string) {
	t.Helper()
	prev := cliOverride
	cliOverride = v
	t.Cleanup(func() { cliOverride = prev })
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

func TestHome_EnvVarOverridesConfig(t *testing.T) {
	withOverride(t, "")
	withConfigInstallDir(t, "/from/config")
	withEnv(t, HomeEnvVar, "/from/env")

	if got := Home(); got != "/from/env" {
		t.Errorf("Home() = %q, want /from/env (env > config)", got)
	}
}

func TestHome_CLIOverridesEnv(t *testing.T) {
	withConfigInstallDir(t, "/from/config")
	withEnv(t, HomeEnvVar, "/from/env")
	withOverride(t, "/from/cli")

	if got := Home(); got != "/from/cli" {
		t.Errorf("Home() = %q, want /from/cli (cli > env > config)", got)
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
