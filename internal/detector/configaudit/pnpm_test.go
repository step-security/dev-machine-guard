package configaudit

import (
	"context"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestPnpmDetector_Discovery_AllScopes(t *testing.T) {
	tmp := t.TempDir()

	userPath := filepath.Join(tmp, "home", ".npmrc")
	mustWriteFile(t, userPath, "registry=https://registry.npmjs.org/\n"+
		"//registry.npmjs.org/:_authToken=npm_AbCdEfGhIjKlMnOpQrStUv\n"+
		"auto-install-peers=true\n"+
		"min-release-age=14\n")

	globalPath := filepath.Join(tmp, "etc", "pnpm", "npmrc")
	mustWriteFile(t, globalPath, "node-linker=hoisted\n")

	projectDir := filepath.Join(tmp, "code", "myapp")
	projectPath := filepath.Join(projectDir, ".npmrc")
	mustWriteFile(t, projectPath, "@mycompany:registry=https://npm.mycompany.com/\n"+
		"//npm.mycompany.com/:_authToken=${COMPANY_TOKEN}\n")

	mock := executor.NewMock()
	mock.SetPath("pnpm", filepath.Join(tmp, "bin", "pnpm"))
	mock.SetCommand("10.11.0\n", "", 0, "pnpm", "--version")
	mock.SetCommand(globalPath+"\n", "", 0, "pnpm", "config", "get", "globalconfig")
	mock.SetCommand(`{"registry":"https://registry.npmjs.org/","node-linker":"hoisted","auto-install-peers":true,"min-release-age":14}`,
		"", 0, "pnpm", "config", "list", "--json")
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewPnpmDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), []string{filepath.Join(tmp, "code")}, loggedIn)

	if !audit.Available {
		t.Fatalf("expected pnpm available")
	}
	if audit.PnpmVersion != "10.11.0" {
		t.Errorf("pnpm version = %q, want 10.11.0", audit.PnpmVersion)
	}

	gotScopes := map[string]string{}
	for _, f := range audit.Files {
		gotScopes[f.Scope] = f.Path
	}
	// pnpm has no builtin scope; only global/user/project are expected.
	for _, want := range []string{"global", "user", "project"} {
		if _, ok := gotScopes[want]; !ok {
			t.Errorf("missing scope %q in output (got: %v)", want, gotScopes)
		}
	}
	if _, ok := gotScopes["builtin"]; ok {
		t.Errorf("unexpected builtin scope from pnpm detector")
	}

	// User file: should redact auth and surface pnpm-specific keys.
	for _, f := range audit.Files {
		if f.Scope != "user" {
			continue
		}
		var sawAuth, sawAutoInstallPeers, sawMinReleaseAge bool
		for _, e := range f.Entries {
			if e.IsAuth {
				sawAuth = true
				if strings.Contains(e.DisplayValue, "AbCdEf") {
					t.Errorf("auth value leaked: %q", e.DisplayValue)
				}
			}
			if e.Key == "auto-install-peers" {
				sawAutoInstallPeers = true
			}
			if e.Key == "min-release-age" {
				sawMinReleaseAge = true
			}
		}
		if !sawAuth {
			t.Errorf("expected auth entry in user file")
		}
		if !sawAutoInstallPeers || !sawMinReleaseAge {
			t.Errorf("expected pnpm-specific keys to round-trip through parser")
		}
	}

	// Project file should preserve env-ref auth form.
	for _, f := range audit.Files {
		if f.Scope != "project" {
			continue
		}
		var sawEnvRef bool
		for _, e := range f.Entries {
			if e.IsEnvRef {
				sawEnvRef = true
				if !strings.Contains(e.DisplayValue, "${") {
					t.Errorf("env-ref form should be preserved: %q", e.DisplayValue)
				}
			}
		}
		if !sawEnvRef {
			t.Errorf("expected env-ref entry in project file")
		}
	}

	if audit.Effective == nil {
		t.Fatalf("expected effective view")
	}
	if _, ok := audit.Effective.Config["node-linker"]; !ok {
		t.Errorf("effective config missing pnpm-specific node-linker key")
	}
	if got := audit.Effective.Config["auto-install-peers"]; got != true {
		t.Errorf("effective auto-install-peers = %v, want true", got)
	}
}

func TestPnpmDetector_PnpmNotInstalled(t *testing.T) {
	tmp := t.TempDir()
	userPath := filepath.Join(tmp, "home", ".npmrc")
	mustWriteFile(t, userPath, "registry=https://npm.example.com/\n")

	mock := executor.NewMock()
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewPnpmDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), nil, loggedIn)

	if audit.Available {
		t.Errorf("pnpm should not be marked available")
	}
	if audit.Effective != nil {
		t.Errorf("effective view should be nil when pnpm missing, got %+v", audit.Effective)
	}
	if len(audit.Files) != 1 || audit.Files[0].Scope != "user" {
		t.Fatalf("expected exactly the user file, got %+v", audit.Files)
	}
	if !audit.Files[0].Readable {
		t.Errorf("user file should still be readable")
	}
}

func TestPnpmDetector_EnvVars_Snapshot(t *testing.T) {
	mock := executor.NewMock()
	mock.SetEnv("PNPM_HOME", "/home/tester/.local/share/pnpm")
	mock.SetEnv("NPM_TOKEN", "npm_secrettoken123456789")
	mock.SetEnv("COREPACK_ENABLE_STRICT", "1")

	d := NewPnpmDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	audit := d.Detect(context.Background(), nil, nil)

	byName := map[string]bool{}
	var npmTokenDisplay string
	var pnpmHomeDisplay string
	for _, e := range audit.Env {
		byName[e.Name] = e.Set
		if e.Name == "NPM_TOKEN" {
			npmTokenDisplay = e.DisplayValue
		}
		if e.Name == "PNPM_HOME" {
			pnpmHomeDisplay = e.DisplayValue
		}
	}
	if !byName["PNPM_HOME"] {
		t.Errorf("expected PNPM_HOME set in env snapshot")
	}
	if !byName["NPM_TOKEN"] {
		t.Errorf("expected NPM_TOKEN set in env snapshot")
	}
	if !byName["COREPACK_ENABLE_STRICT"] {
		t.Errorf("expected COREPACK_ENABLE_STRICT set in env snapshot")
	}
	if !byName["NPM_CONFIG_REGISTRY"] {
		// unset value but still recorded
		if _, present := byName["NPM_CONFIG_REGISTRY"]; !present {
			t.Errorf("expected NPM_CONFIG_REGISTRY recorded even when unset")
		}
	}
	if strings.Contains(npmTokenDisplay, "secrettoken") {
		t.Errorf("NPM_TOKEN display leaked: %q", npmTokenDisplay)
	}
	if pnpmHomeDisplay == "" || strings.Contains(pnpmHomeDisplay, "***") {
		t.Errorf("PNPM_HOME should be shown in clear (not a secret), got %q", pnpmHomeDisplay)
	}
}
