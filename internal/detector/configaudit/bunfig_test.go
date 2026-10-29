package configaudit

import (
	"context"
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const sampleBunfig = `# bunfig
[install]
registry = "https://registry.npmjs.org/"
optional = true
production = false

[install.scopes]
"@step-security" = "https://npm.stepsecurity.io/"

[install.scopes."@private"]
url = "https://npm.private.example.com/"
username = "ci"
password = "supersecretpasswordvalue"
token = "${PRIVATE_REGISTRY_TOKEN}"

[install.cache]
dir = "/home/tester/.bun/install/cache"

[run]
shell = "bash"
`

func TestBunDetector_Discovery_AllScopes(t *testing.T) {
	tmp := t.TempDir()

	userPath := filepath.Join(tmp, "home", ".bunfig.toml")
	mustWriteFile(t, userPath, sampleBunfig)

	xdgPath := filepath.Join(tmp, "home", ".config", ".bunfig.toml")
	mustWriteFile(t, xdgPath, "[install]\nregistry = \"https://registry.npmjs.org/\"\n")

	projectDir := filepath.Join(tmp, "code", "myapp")
	projectPath := filepath.Join(projectDir, "bunfig.toml")
	mustWriteFile(t, projectPath, `[install]
frozenLockfile = true
`)

	mock := executor.NewMock()
	mock.SetPath("bun", filepath.Join(tmp, "bin", "bun"))
	mock.SetCommand("1.1.42\n", "", 0, filepath.Join(tmp, "bin", "bun"), "--version")
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewBunDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), []string{filepath.Join(tmp, "code")}, loggedIn)

	if !audit.Available {
		t.Fatalf("expected bun available")
	}
	if audit.BunVersion != "1.1.42" {
		t.Errorf("bun version = %q, want 1.1.42", audit.BunVersion)
	}

	gotScopes := map[string]string{}
	for _, f := range audit.Files {
		gotScopes[f.Scope] = f.Path
	}
	for _, want := range []string{"user", "project"} {
		if _, ok := gotScopes[want]; !ok {
			t.Errorf("missing bunfig scope %q (got: %v)", want, gotScopes)
		}
	}
	// Bun has no implicit ~/.config default when XDG_CONFIG_HOME is unset.
	if p, ok := gotScopes["user-xdg"]; ok {
		t.Errorf("unexpected user-xdg scope %q", p)
	}

	// User file should parse multiple sections including install.scopes.* and
	// redact the hardcoded password.
	for _, f := range audit.Files {
		if f.Scope != "user" {
			continue
		}
		if !f.Exists || !f.Readable {
			t.Fatalf("user file should be readable: %+v", f)
		}
		if f.ParseError != "" {
			t.Errorf("user file parse error: %s", f.ParseError)
		}

		secs := map[string]bool{}
		for _, s := range f.Sections {
			secs[s.Name] = true
		}
		for _, want := range []string{"install", "install.scopes", `install.scopes.@private`, "install.cache", "run"} {
			if !secs[want] {
				t.Errorf("missing section %q in user file; got sections %+v", want, secs)
			}
		}

		// password should be redacted; token (env-ref form) preserved.
		var sawPassword, sawToken, sawHardcoded bool
		for _, s := range f.Sections {
			if !strings.HasPrefix(s.Name, "install.scopes.@private") {
				continue
			}
			for _, e := range s.Entries {
				if e.Key == "password" {
					sawPassword = true
					if strings.Contains(e.DisplayValue, "supersecret") {
						t.Errorf("password value leaked: %q", e.DisplayValue)
					}
					if !e.IsAuth {
						t.Errorf("expected IsAuth=true for password")
					}
					if e.IsEnvRef {
						t.Errorf("expected IsEnvRef=false for hardcoded password")
					}
					sawHardcoded = true
				}
				if e.Key == "token" {
					sawToken = true
					if !strings.Contains(e.DisplayValue, "${") {
						t.Errorf("env-ref token should preserve ${} form: %q", e.DisplayValue)
					}
					if !e.IsEnvRef {
						t.Errorf("expected IsEnvRef=true for ${...} token")
					}
				}
			}
		}
		if !sawPassword || !sawToken || !sawHardcoded {
			t.Errorf("expected to see redacted password + env-ref token under install.scopes.@private")
		}
	}

	// Project file should parse cleanly with the install section.
	for _, f := range audit.Files {
		if f.Scope != "project" {
			continue
		}
		if f.ParseError != "" {
			t.Errorf("project file parse error: %s", f.ParseError)
		}
		if len(f.Sections) == 0 {
			t.Errorf("expected at least one section in project file")
		}
	}
}

func TestBunDetector_MalformedTOML(t *testing.T) {
	tmp := t.TempDir()
	userPath := filepath.Join(tmp, "home", ".bunfig.toml")
	mustWriteFile(t, userPath, "[install\nregistry = oops\n")

	mock := executor.NewMock()
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewBunDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), nil, loggedIn)

	var sawParseError bool
	for _, f := range audit.Files {
		if f.Scope == "user" && f.Exists {
			if f.ParseError == "" {
				t.Errorf("expected ParseError on malformed TOML")
			}
			sawParseError = true
		}
	}
	if !sawParseError {
		t.Errorf("user file should still be recorded even with parse error")
	}
}

func TestBunDetector_BunNotInstalled(t *testing.T) {
	tmp := t.TempDir()
	userPath := filepath.Join(tmp, "home", ".bunfig.toml")
	mustWriteFile(t, userPath, "[install]\nregistry = \"https://npm.example.com/\"\n")

	mock := executor.NewMock()
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewBunDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), nil, loggedIn)

	if audit.Available {
		t.Errorf("bun should not be marked available")
	}
	var foundUserFile bool
	for _, f := range audit.Files {
		if f.Scope == "user" && f.Readable {
			foundUserFile = true
		}
	}
	if !foundUserFile {
		t.Errorf("user bunfig should still be discovered + readable even without bun binary")
	}
}

func TestBunDetector_NpmrcSideChannel(t *testing.T) {
	tmp := t.TempDir()

	// Seed a user .npmrc that bun would read for auth.
	npmrcPath := filepath.Join(tmp, "home", ".npmrc")
	mustWriteFile(t, npmrcPath, "//registry.npmjs.org/:_authToken=npm_AbCdEfGhIjKlMnOpQr\n")

	// Seed a user bunfig.toml so bun discovery itself has something too.
	userBunfig := filepath.Join(tmp, "home", ".bunfig.toml")
	mustWriteFile(t, userBunfig, `[install]
registry = "https://registry.npmjs.org/"
`)

	mock := executor.NewMock()
	// bun present so the side-channel runs through the npmrc detector with
	// the same skipper / hooks; npm intentionally absent (LookPath fails)
	// so the npmrc effective view is skipped — we only need the discovered
	// files.
	mock.SetPath("bun", "/usr/local/bin/bun")
	mock.SetCommand("1.1.42\n", "", 0, "/usr/local/bin/bun", "--version")
	mock.SetHomeDir(filepath.Join(tmp, "home"))

	d := NewBunDetector(mock)
	d.ownerLookup = fixedOwner()
	d.gitTracked = func(_ context.Context, _ string) bool { return false }
	d.inGitRepo = func(_ string) bool { return false }

	loggedIn := &user.User{Username: "tester", HomeDir: filepath.Join(tmp, "home")}
	audit := d.Detect(context.Background(), nil, loggedIn)

	if len(audit.NPMRCFiles) == 0 {
		t.Fatalf("expected at least the user .npmrc in side-channel slot")
	}
	for _, f := range audit.NPMRCFiles {
		if f.Scope == "builtin" || f.Scope == "global" {
			t.Errorf("builtin/global scopes should be excluded from bun side-channel; got %+v", f)
		}
	}
}

func TestBunDetector_SourceApplicability(t *testing.T) {
	tests := []struct {
		name, version, xdg, userconfig string
		xdgNPMRC                       bool
		want                           map[string]string // bunfig scope → applicability
		wantNPMRC                      string            // user .npmrc path ("~" = home, "$XDG" = xdg)
	}{
		{name: "xdg unset", version: "1.4.4",
			want: map[string]string{"user": "applicable"}, wantNPMRC: "~/.npmrc"},
		{name: "absolute xdg wins", version: "1.4.4", xdg: "abs",
			want: map[string]string{"user-xdg": "applicable", "user": "ignored"}, wantNPMRC: "~/.npmrc"},
		{name: "existing xdg npmrc", version: "1.4.4", xdg: "abs", xdgNPMRC: true,
			want: map[string]string{"user-xdg": "applicable", "user": "ignored"}, wantNPMRC: "$XDG/.npmrc"},
		{name: "relative xdg skipped from 1.4.4", version: "1.4.4", xdg: "rel",
			want: map[string]string{"user-xdg": "ignored", "user": "applicable"}, wantNPMRC: "~/.npmrc"},
		{name: "relative xdg used before 1.4.4", version: "1.3.0", xdg: "rel",
			want: map[string]string{"user-xdg": "applicable", "user": "ignored"}, wantNPMRC: "~/.npmrc"},
		{name: "relative xdg unknown version", xdg: "rel",
			want: map[string]string{"user-xdg": "unknown", "user": "unknown"}, wantNPMRC: "~/.npmrc"},
		{name: "npm userconfig wins", version: "1.4.4", xdg: "abs", xdgNPMRC: true, userconfig: "/u/npmrc",
			want: map[string]string{"user-xdg": "applicable", "user": "ignored"}, wantNPMRC: "/u/npmrc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			home, xdg := filepath.Join(tmp, "home"), ""
			mock := executor.NewMock()
			mock.SetHomeDir(home)
			switch tc.xdg {
			case "abs":
				xdg = filepath.Join(tmp, "xdg")
			case "rel":
				xdg = "xdg"
			}
			mock.SetEnv("XDG_CONFIG_HOME", xdg)
			mock.SetEnv("NPM_CONFIG_USERCONFIG", tc.userconfig)
			if tc.xdgNPMRC {
				mock.SetFile(filepath.Join(xdg, ".npmrc"), nil)
			}
			if tc.version != "" {
				mock.SetPath("bun", "/opt/bun/bin/bun")
				mock.SetCommand(tc.version+"\n", "", 0, "/opt/bun/bin/bun", "--version")
			}
			d := NewBunDetector(mock)
			d.ownerLookup = fixedOwner()
			audit := d.Detect(context.Background(), nil, &user.User{HomeDir: home})

			got := map[string]string{}
			for _, f := range audit.Files {
				got[f.Scope] = f.RuntimeApplicability
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("bunfig applicability = %v, want %v", got, tc.want)
			}
			wantNPMRC := strings.NewReplacer("~", home, "$XDG", xdg).Replace(tc.wantNPMRC)
			if len(audit.NPMRCFiles) != 1 || audit.NPMRCFiles[0].Path != wantNPMRC || audit.NPMRCFiles[0].RuntimeApplicability != "applicable" {
				t.Errorf("npmrc files = %+v, want only %s", audit.NPMRCFiles, wantNPMRC)
			}
		})
	}
}
