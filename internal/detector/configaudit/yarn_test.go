package configaudit

import (
	"context"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const sampleYarnClassic = `# v1 yarnrc
registry "https://registry.yarnpkg.com"
yarn-offline-mirror "./.yarn-offline-mirror"
//npm.example.com/:_authToken eyJhbGciOiJIUzI1NiJ9HARDCODED
//npm.envref.com/:_authToken ${COMPANY_TOKEN}
network-timeout 60000
strict-ssl true
`

const sampleYarnBerry = `# berry yarnrc
npmRegistryServer: "https://registry.yarnpkg.com"
enableStrictSsl: true
enableImmutableInstalls: true
unsafeHttpWhitelist:
  - "npm.internal"

npmScopes:
  "@step-security":
    npmRegistryServer: "https://npm.stepsecurity.io"
    npmAuthToken: "${COMPANY_TOKEN}"
  "@private":
    npmRegistryServer: "https://npm.private.example.com"
    npmAuthToken: "yarnberrysecretvalue123456"

npmRegistries:
  "https://npm.alt.example.com":
    npmAuthToken: "registryscopedsecretvalue"
`

func TestYarnDetector_BothFlavors(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home")

	userClassic := filepath.Join(homeDir, ".yarnrc")
	mustWriteFile(t, userClassic, sampleYarnClassic)

	userBerry := filepath.Join(homeDir, ".yarnrc.yml")
	mustWriteFile(t, userBerry, sampleYarnBerry)

	projectDir := filepath.Join(tmp, "code", "myapp")
	projectBerry := filepath.Join(projectDir, ".yarnrc.yml")
	mustWriteFile(t, projectBerry, "enableScripts: false\n")

	mock := executor.NewMock()
	mock.SetPath("yarn", filepath.Join(tmp, "bin", "yarn"))
	mock.SetCommand("4.5.0\n", "", 0, "yarn", "--version")
	mock.SetHomeDir(homeDir)

	d := NewYarnDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: homeDir}
	audit := d.Detect(context.Background(), []string{filepath.Join(tmp, "code")}, loggedIn)

	if !audit.Available {
		t.Fatalf("expected yarn available")
	}
	if audit.YarnVersion != "4.5.0" {
		t.Errorf("yarn version = %q, want 4.5.0", audit.YarnVersion)
	}
	if audit.Flavor != "berry" {
		t.Errorf("yarn flavor = %q, want berry", audit.Flavor)
	}

	flavors := map[string]int{}
	for _, f := range audit.Files {
		if !f.Exists {
			continue
		}
		flavors[f.Flavor]++
	}
	if flavors["classic"] < 1 || flavors["berry"] < 1 {
		t.Errorf("expected at least one classic and one berry file, got: %+v", flavors)
	}

	// Classic file: hardcoded token redacted, env-ref preserved.
	for _, f := range audit.Files {
		if f.Path != userClassic {
			continue
		}
		var sawHardcoded, sawEnvRef bool
		for _, e := range f.Entries {
			if e.IsAuth && !e.IsEnvRef && strings.Contains(e.Key, "npm.example.com") {
				sawHardcoded = true
				if strings.Contains(e.DisplayValue, "eyJhbGc") {
					t.Errorf("classic hardcoded auth leaked: %q", e.DisplayValue)
				}
			}
			if e.IsEnvRef && strings.Contains(e.Key, "npm.envref.com") {
				sawEnvRef = true
				if !strings.Contains(e.DisplayValue, "${") {
					t.Errorf("classic env-ref auth lost ${} form: %q", e.DisplayValue)
				}
			}
		}
		if !sawHardcoded || !sawEnvRef {
			t.Errorf("classic file: expected hardcoded + env-ref auth entries; entries=%+v", f.Entries)
		}
	}

	// Berry file: nested keys flatten and hardcoded npmAuthToken is redacted.
	for _, f := range audit.Files {
		if f.Path != userBerry {
			continue
		}
		if f.Flavor != "berry" {
			t.Errorf("user .yarnrc.yml flavor = %q, want berry", f.Flavor)
		}
		var sawFlatten, sawHardcoded, sawEnvRef, sawRegistries bool
		for _, e := range f.Entries {
			if strings.HasPrefix(e.Key, "npmScopes.@step-security.npmAuthToken") {
				sawFlatten = true
				sawEnvRef = sawEnvRef || e.IsEnvRef
				if e.IsEnvRef && !strings.Contains(e.DisplayValue, "${") {
					t.Errorf("berry env-ref lost ${} form: %q", e.DisplayValue)
				}
			}
			if strings.HasPrefix(e.Key, "npmScopes.@private.npmAuthToken") {
				sawHardcoded = true
				if !e.IsAuth {
					t.Errorf("npmScopes.@private.npmAuthToken should be IsAuth=true")
				}
				if strings.Contains(e.DisplayValue, "yarnberrysecret") {
					t.Errorf("berry hardcoded npmAuthToken leaked: %q", e.DisplayValue)
				}
			}
			if strings.HasPrefix(e.Key, "npmRegistries.") {
				sawRegistries = true
			}
		}
		if !sawFlatten || !sawHardcoded || !sawEnvRef || !sawRegistries {
			t.Errorf("berry file expectations not met: flatten=%v hardcoded=%v envRef=%v registries=%v entries=%+v",
				sawFlatten, sawHardcoded, sawEnvRef, sawRegistries, f.Entries)
		}
	}
}

func TestYarnDetector_FlavorMismatch(t *testing.T) {
	// v1 binary with a project .yarnrc.yml — surfaces as a mismatch in
	// the verbose view; the audit captures both for the renderer to flag.
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home")

	projectDir := filepath.Join(tmp, "code", "myapp")
	projectBerry := filepath.Join(projectDir, ".yarnrc.yml")
	mustWriteFile(t, projectBerry, "enableScripts: false\n")

	mock := executor.NewMock()
	mock.SetPath("yarn", "/usr/local/bin/yarn")
	mock.SetCommand("1.22.22\n", "", 0, "yarn", "--version")
	mock.SetHomeDir(homeDir)

	d := NewYarnDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: homeDir}
	audit := d.Detect(context.Background(), []string{filepath.Join(tmp, "code")}, loggedIn)

	if audit.Flavor != "classic" {
		t.Errorf("flavor = %q, want classic", audit.Flavor)
	}
	var sawBerryFile bool
	for _, f := range audit.Files {
		if f.Exists && f.Flavor == "berry" {
			sawBerryFile = true
		}
	}
	if !sawBerryFile {
		t.Errorf("expected to discover the berry project file alongside the v1 binary")
	}
}

func TestYarnDetector_MalformedBerryYAML(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home")

	userBerry := filepath.Join(homeDir, ".yarnrc.yml")
	mustWriteFile(t, userBerry, "npmScopes:\n  : malformed\n\tnot yaml\n")

	mock := executor.NewMock()
	mock.SetHomeDir(homeDir)

	d := NewYarnDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: homeDir}
	audit := d.Detect(context.Background(), nil, loggedIn)

	var sawParseError bool
	for _, f := range audit.Files {
		if f.Path == userBerry && f.Exists {
			if f.ParseError == "" {
				t.Errorf("expected ParseError on malformed yarnrc.yml")
			}
			sawParseError = true
		}
	}
	if !sawParseError {
		t.Errorf("user yarnrc.yml should still be recorded even with parse error")
	}
}

func TestYarnFlavorFromVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.22.22", "classic"},
		{"1.0.0", "classic"},
		{"2.4.3", "berry"},
		{"3.6.4", "berry"},
		{"4.5.0", "berry"},
		{"", "unknown"},
		{"unknown", "unknown"},
	}
	for _, tc := range cases {
		if got := yarnFlavorFromVersion(tc.in); got != tc.want {
			t.Errorf("yarnFlavorFromVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
