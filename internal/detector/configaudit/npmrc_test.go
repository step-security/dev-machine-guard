package configaudit

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// fixedOwner returns an ownerLookup hook with fixed values, used to keep
// tests deterministic across platforms (no real syscall.Stat involved).
func fixedOwner() func(string) ownerInfo {
	return func(_ string) ownerInfo {
		return ownerInfo{UID: 1000, GID: 1000, OwnerName: "tester", GroupName: "staff", OK: true}
	}
}

func TestNPMRCDetector_Discovery_AllScopes(t *testing.T) {
	tmp := t.TempDir()

	// User config
	userPath := filepath.Join(tmp, "home", ".npmrc")
	mustWriteFile(t, userPath, "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_AbCdEfGhIjKlMnOpQrStUv\n")

	// Global config (e.g. /etc/npmrc)
	globalPath := filepath.Join(tmp, "etc", "npmrc")
	mustWriteFile(t, globalPath, "strict-ssl=true\n")

	// Builtin config (npm install dir)
	builtinPath := filepath.Join(tmp, "lib", "node_modules", "npm", "npmrc")
	mustWriteFile(t, builtinPath, "; default builtin config\n")

	// Project-level config inside a search dir
	projectDir := filepath.Join(tmp, "code", "myapp")
	projectPath := filepath.Join(projectDir, ".npmrc")
	mustWriteFile(t, projectPath, "@mycompany:registry=https://npm.mycompany.com/\n//npm.mycompany.com/:_authToken=${COMPANY_TOKEN}\n")

	// Mock npm command outputs
	mock := executor.NewMock()
	mock.SetPath("npm", filepath.Join(tmp, "bin", "npm"))
	mock.SetCommand("11.0.0\n", "", 0, "npm", "--version")
	mock.SetCommand(builtinPath+"\n", "", 0, "npm", "config", "get", "builtinconfig")
	mock.SetCommand(globalPath+"\n", "", 0, "npm", "config", "get", "globalconfig")
	mock.SetCommand(`{"registry":"https://registry.npmjs.org/","strict-ssl":true,"_authToken":"(protected)"}`, "", 0, "npm", "config", "ls", "-l", "--json")
	mock.SetCommand(`; "user" config from "`+userPath+`"
registry = "https://registry.npmjs.org/"
; "default" values
strict-ssl = true
`, "", 0, "npm", "config", "ls", "-l")
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewNPMRCDetector(mock)
	d.ownerLookup = fixedOwner()
	// Disable git checks so tests don't depend on git being installed.
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), []string{filepath.Join(tmp, "code")}, loggedIn)

	if !audit.Available {
		t.Fatalf("expected npm to be available")
	}
	if audit.NPMVersion != "11.0.0" {
		t.Errorf("npm version = %q, want 11.0.0", audit.NPMVersion)
	}

	// We should have discovered all four scopes.
	gotScopes := map[string]string{}
	for _, f := range audit.Files {
		gotScopes[f.Scope] = f.Path
	}
	for _, want := range []string{"builtin", "global", "user", "project"} {
		if _, ok := gotScopes[want]; !ok {
			t.Errorf("missing scope %q in output (got: %v)", want, gotScopes)
		}
	}

	// User file: should have parsed entries with redacted auth.
	for _, f := range audit.Files {
		if f.Scope != "user" {
			continue
		}
		if !f.Exists || !f.Readable {
			t.Errorf("user file should be readable: %+v", f)
		}
		if f.SHA256 == "" {
			t.Errorf("user file should have sha256")
		}
		if f.OwnerName != "tester" {
			t.Errorf("owner name = %q, want tester", f.OwnerName)
		}
		var sawAuth bool
		for _, e := range f.Entries {
			if e.IsAuth {
				sawAuth = true
				if strings.Contains(e.DisplayValue, "AbCdEf") {
					t.Errorf("auth value leaked: %q", e.DisplayValue)
				}
			}
		}
		if !sawAuth {
			t.Errorf("expected to see an auth entry in user file")
		}
	}

	// Project file: env-ref auth should be preserved.
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

	// Effective view should populate config + sources.
	if audit.Effective == nil {
		t.Fatalf("expected effective view")
	}
	if _, ok := audit.Effective.Config["registry"]; !ok {
		t.Errorf("effective config missing registry")
	}
	if src := audit.Effective.SourceByKey["registry"]; src != userPath {
		t.Errorf("expected registry source %q, got %q", userPath, src)
	}
}

func TestNPMRCDetector_NPMNotInstalled(t *testing.T) {
	tmp := t.TempDir()
	userPath := filepath.Join(tmp, "home", ".npmrc")
	mustWriteFile(t, userPath, "registry=https://npm.example.com/\n")

	mock := executor.NewMock()
	// No SetPath("npm", ...) -> LookPath fails.
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewNPMRCDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), nil, loggedIn)

	if audit.Available {
		t.Errorf("npm should not be marked available")
	}
	if audit.Effective != nil {
		t.Errorf("effective view should be nil when npm missing, got %+v", audit.Effective)
	}
	// User file should still be discovered and parsed.
	if len(audit.Files) != 1 || audit.Files[0].Scope != "user" {
		t.Fatalf("expected exactly the user file, got %+v", audit.Files)
	}
	if !audit.Files[0].Readable {
		t.Errorf("user file should be readable even with no npm")
	}
}

func TestNPMRCDetector_MissingFiles(t *testing.T) {
	tmp := t.TempDir()
	mock := executor.NewMock()
	mock.SetPath("npm", "/usr/bin/npm")
	mock.SetCommand("9.0.0\n", "", 0, "npm", "--version")
	mock.SetCommand("/nonexistent/builtin\n", "", 0, "npm", "config", "get", "builtinconfig")
	mock.SetCommand("/nonexistent/global\n", "", 0, "npm", "config", "get", "globalconfig")
	mock.SetCommand("{}", "", 0, "npm", "config", "ls", "-l", "--json")
	mock.SetCommand("", "", 0, "npm", "config", "ls", "-l")

	d := NewNPMRCDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "nohome")}
	audit := d.Detect(context.Background(), nil, loggedIn)

	// Even though no real files exist, the discovery records the absence.
	for _, f := range audit.Files {
		if f.Exists {
			t.Errorf("scope %q at %q should not exist", f.Scope, f.Path)
		}
		if len(f.Entries) != 0 {
			t.Errorf("missing file should have no entries, got %+v", f.Entries)
		}
	}
}

func TestNPMRCDetector_EnvVarRedaction(t *testing.T) {
	mock := executor.NewMock()
	mock.SetEnv("NPM_TOKEN", "npm_LongTokenValueZ1234")
	mock.SetEnv("npm_config__authToken", "npm_AnotherSecretValue999")
	mock.SetEnv("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org/")

	d := NewNPMRCDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	envs := d.collectEnv()

	for _, e := range envs {
		switch e.Name {
		case "NPM_TOKEN":
			if !e.Set {
				t.Error("NPM_TOKEN should be Set=true")
			}
			if !strings.HasPrefix(e.DisplayValue, "***") {
				t.Errorf("NPM_TOKEN should be redacted, got %q", e.DisplayValue)
			}
			if strings.Contains(e.DisplayValue, "Long") {
				t.Errorf("NPM_TOKEN raw value leaked: %q", e.DisplayValue)
			}
			if e.ValueSHA256 == "" {
				t.Error("NPM_TOKEN should have SHA-256 set")
			}
		case "npm_config__authToken":
			if !strings.HasPrefix(e.DisplayValue, "***") {
				t.Errorf("npm_config__authToken should be redacted, got %q", e.DisplayValue)
			}
		case "NPM_CONFIG_REGISTRY":
			// Not a secret; should pass through.
			if e.DisplayValue != "https://registry.npmjs.org/" {
				t.Errorf("registry env var should not be redacted, got %q", e.DisplayValue)
			}
		}
	}
}

func TestParseSourceAttribution(t *testing.T) {
	in := `; "default" values
access = null
audit = true

; "user" config from "/Users/me/.npmrc"
registry = "https://registry.npmjs.org/"
//registry.npmjs.org/:_authToken = "(protected)"

; "project" config from "/Users/me/code/myapp/.npmrc"
@mycompany:registry = "https://npm.mycompany.com/"
strict-ssl = false
`
	got := parseSourceAttribution(in)

	cases := map[string]string{
		"access":                           "default",
		"audit":                            "default",
		"registry":                         "/Users/me/.npmrc",
		"//registry.npmjs.org/:_authToken": "/Users/me/.npmrc",
		"@mycompany:registry":              "/Users/me/code/myapp/.npmrc",
		"strict-ssl":                       "/Users/me/code/myapp/.npmrc",
	}
	for k, want := range cases {
		if got[k] != want {
			t.Errorf("source[%q] = %q, want %q", k, got[k], want)
		}
	}
}

func TestNPMRCDetector_ProjectWalkSkipsExcludedDirs(t *testing.T) {
	tmp := t.TempDir()

	// Should be picked up.
	keep := filepath.Join(tmp, "real", ".npmrc")
	mustWriteFile(t, keep, "registry=https://kept/\n")

	// Should be skipped (inside node_modules).
	mustWriteFile(t, filepath.Join(tmp, "real", "node_modules", "lib", ".npmrc"), "registry=https://skipped/\n")

	// Should be skipped (inside .git).
	mustWriteFile(t, filepath.Join(tmp, "real", ".git", ".npmrc"), "registry=https://skipped/\n")

	// Should be skipped (hidden dir).
	mustWriteFile(t, filepath.Join(tmp, "real", ".cache", ".npmrc"), "registry=https://skipped/\n")

	mock := executor.NewMock()
	d := NewNPMRCDetector(mock)
	results := d.findProjectNPMRCs(tmp)

	if len(results) != 1 {
		t.Fatalf("expected exactly 1 .npmrc, got %d: %v", len(results), results)
	}
	if !strings.HasSuffix(results[0], filepath.Join("real", ".npmrc")) {
		t.Errorf("wrong file kept: %q", results[0])
	}
}

func TestNPMRCDetector_RespectsEnvOverridesForUserAndGlobal(t *testing.T) {
	tmp := t.TempDir()

	// User config redirected via NPM_CONFIG_USERCONFIG.
	overriddenUser := filepath.Join(tmp, "elsewhere", "myrc")
	mustWriteFile(t, overriddenUser, "registry=https://overridden/\n")

	// Global config redirected via NPM_CONFIG_GLOBALCONFIG.
	overriddenGlobal := filepath.Join(tmp, "elsewhere", "globalrc")
	mustWriteFile(t, overriddenGlobal, "audit=false\n")

	mock := executor.NewMock()
	mock.SetPath("npm", "/usr/bin/npm")
	mock.SetCommand("11.0.0\n", "", 0, "npm", "--version")
	mock.SetCommand("/should/not/be/used\n", "", 0, "npm", "config", "get", "builtinconfig")
	// NB: globalconfig command should NOT be called when env var is set.
	// We still register it so test fails loud if it is.
	mock.SetCommand("/should/not/be/used/global\n", "", 0, "npm", "config", "get", "globalconfig")
	mock.SetCommand("{}", "", 0, "npm", "config", "ls", "-l", "--json")
	mock.SetCommand("", "", 0, "npm", "config", "ls", "-l")

	mock.SetEnv("NPM_CONFIG_USERCONFIG", overriddenUser)
	mock.SetEnv("NPM_CONFIG_GLOBALCONFIG", overriddenGlobal)
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewNPMRCDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), nil, loggedIn)

	pathsByScope := map[string]string{}
	for _, f := range audit.Files {
		pathsByScope[f.Scope] = f.Path
	}
	if got := pathsByScope["user"]; got != overriddenUser {
		t.Errorf("user scope path = %q, want %q (NPM_CONFIG_USERCONFIG should win over $HOME/.npmrc)", got, overriddenUser)
	}
	if got := pathsByScope["global"]; got != overriddenGlobal {
		t.Errorf("global scope path = %q, want %q (NPM_CONFIG_GLOBALCONFIG should win)", got, overriddenGlobal)
	}
}

// mustWriteFile creates parent dirs as needed and writes the content.
func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
