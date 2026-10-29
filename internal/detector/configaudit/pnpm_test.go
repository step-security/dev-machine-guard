package configaudit

import (
	"context"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
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
	if got := audit.Effective.Config["registry"]; got != "https://registry.npmjs.org/" {
		t.Errorf("effective registry = %v", got)
	}
	// Only security-relevant keys survive the effective allowlist.
	for _, k := range []string{"node-linker", "auto-install-peers", "min-release-age"} {
		if _, ok := audit.Effective.Config[k]; ok {
			t.Errorf("effective config kept non-allowlisted key %q", k)
		}
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
	var userFiles []model.NPMRCFile
	for _, f := range audit.Files {
		if f.Scope == "user" {
			userFiles = append(userFiles, f)
		} else if f.Exists || f.RuntimeApplicability != "unknown" {
			t.Errorf("native file without a pnpm version should be absent and unknown: %+v", f)
		}
	}
	if len(userFiles) != 1 || !userFiles[0].Readable {
		t.Fatalf("expected one readable user file, got %+v", userFiles)
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

func TestPnpmDetector_SourceApplicability(t *testing.T) {
	tests := []struct {
		name, goos, version, configYAML string
		env                             map[string]string
		want                            map[string]string // path ("~" = home) → applicability
		absent                          []string
	}{
		{name: "pnpm 10 reads native rc", goos: "linux", version: "10.11.0",
			want: map[string]string{"~/.config/pnpm/rc": "applicable", "~/.config/pnpm/config.yaml": "ignored", "~/.config/pnpm/auth.ini": "ignored", "~/.npmrc": "applicable"}},
		{name: "pnpm 11 reads yaml and auth.ini", goos: "linux", version: "11.6.0",
			want: map[string]string{"~/.config/pnpm/rc": "ignored", "~/.config/pnpm/config.yaml": "applicable", "~/.config/pnpm/auth.ini": "applicable"}},
		{name: "darwin native dir", goos: "darwin", version: "11.6.0",
			want: map[string]string{"~/Library/Preferences/pnpm/config.yaml": "applicable"}},
		{name: "xdg wins", goos: "darwin", version: "10.11.0", env: map[string]string{"XDG_CONFIG_HOME": "/xdg"},
			want: map[string]string{"/xdg/pnpm/rc": "applicable"}, absent: []string{"~/Library/Preferences/pnpm/rc"}},
		{name: "windows localappdata", goos: "windows", version: "11.6.0", env: map[string]string{"LOCALAPPDATA": "/local"},
			want: map[string]string{"/local/pnpm/config/config.yaml": "applicable"}},
		{name: "unknown version", goos: "linux",
			want: map[string]string{"~/.config/pnpm/rc": "unknown", "~/.config/pnpm/config.yaml": "unknown", "~/.npmrc": "unknown"}},
		{name: "pnpm 11 auth file override", goos: "linux", version: "11.6.0",
			env:  map[string]string{"pnpm_config_npmrc_auth_file": "/auth/npmrc", "npm_config_userconfig": "/npm/npmrc"},
			want: map[string]string{"/auth/npmrc": "applicable"}, absent: []string{"/npm/npmrc", "~/.npmrc"}},
		{name: "auth file resolves in home", goos: "linux", version: "11.6.0",
			env:  map[string]string{"pnpm_config_npmrc_auth_file": "~/auth/npmrc"},
			want: map[string]string{"~/auth/npmrc": "applicable"}},
		{name: "relative auth file resolves in home", goos: "linux", version: "11.6.0",
			env:  map[string]string{"pnpm_config_npmrc_auth_file": "auth/npmrc"},
			want: map[string]string{"~/auth/npmrc": "applicable"}},
		{name: "pnpm 11 yaml auth file", goos: "linux", version: "11.6.0", configYAML: "npmrcAuthFile: /yaml/npmrc\n",
			env:  map[string]string{"npm_config_userconfig": "/npm/npmrc"},
			want: map[string]string{"/yaml/npmrc": "applicable"}, absent: []string{"/npm/npmrc"}},
		{name: "pnpm 10 follows npm userconfig", goos: "linux", version: "10.11.0",
			env:  map[string]string{"pnpm_config_npmrc_auth_file": "/auth/npmrc", "npm_config_userconfig": "/npm/npmrc"},
			want: map[string]string{"/npm/npmrc": "applicable"}, absent: []string{"/auth/npmrc"}},
		{name: "unreliable globalconfig query skipped", goos: "linux", version: "10.17.0",
			absent: []string{"/query/rc"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			mock := executor.NewMock()
			mock.SetGOOS(tc.goos)
			mock.SetHomeDir(home)
			for k, v := range tc.env {
				mock.SetEnv(k, v)
			}
			if tc.version != "" {
				mock.SetPath("pnpm", "/bin/pnpm")
				mock.SetCommand(tc.version+"\n", "", 0, "pnpm", "--version")
				mock.SetCommand("/query/rc\n", "", 0, "pnpm", "config", "get", "globalconfig")
			}
			if tc.configYAML != "" {
				mustWriteFile(t, filepath.Join(home, ".config", "pnpm", "config.yaml"), tc.configYAML)
			}
			d := NewPnpmDetector(mock)
			d.ownerLookup = fixedOwner()
			audit := d.Detect(context.Background(), nil, &user.User{HomeDir: home})

			got := map[string]string{}
			for _, f := range audit.Files {
				got[strings.Replace(f.Path, home, "~", 1)] = f.RuntimeApplicability
			}
			for p, want := range tc.want {
				if got[p] != want {
					t.Errorf("%s applicability = %q, want %q (all: %v)", p, got[p], want, got)
				}
			}
			for _, p := range tc.absent {
				if _, ok := got[p]; ok {
					t.Errorf("%s should not be listed (all: %v)", p, got)
				}
			}
		})
	}
}
