package configaudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type condaConfigMock struct{ *composerConfigMock }

func (m *condaConfigMock) GuardedFiles([]string, func(string) string, int64) executor.Executor {
	return m
}
func (m *condaConfigMock) ReadDirLimit(path string, max int) ([]os.DirEntry, bool, error) {
	if !m.DirExists(path) {
		return nil, false, os.ErrNotExist
	}
	return m.Mock.ReadDirLimit(path, max)
}
func condaConfigTest(t *testing.T) (*condaConfigMock, CondaConfigScope) {
	t.Helper()
	inner, scope := composerConfigTest(t)
	return &condaConfigMock{inner}, CondaConfigScope{Username: scope.Username, Home: scope.Home, ProcessVerified: true}
}
func condaFile(t *testing.T, audit model.CondaConfigAudit, scope, path string) model.CondaConfigFile {
	t.Helper()
	for _, f := range audit.Files {
		if f.Scope == scope && f.Path == path {
			return f
		}
	}
	t.Fatalf("no %s file %q in %+v", scope, path, audit.Files)
	return model.CondaConfigFile{}
}
func condaSettings(f model.CondaConfigFile) map[string]string {
	out := map[string]string{}
	for _, s := range f.Settings {
		out[s.Key] = s.Display
	}
	return out
}
func condaFindingKeys(audit model.CondaConfigAudit) map[string]bool {
	got := map[string]bool{}
	for _, f := range audit.Findings {
		for _, file := range audit.Files {
			if file.SourceID == f.SourceID {
				got[f.Code+" "+file.Scope+" "+f.Key] = true
			}
		}
	}
	return got
}

func TestCondaConfigAllowlistRedactionAndFindings(t *testing.T) {
	m, scope := condaConfigTest(t)
	home := scope.Home
	m.SetEnv("HTTPS_PROXY", "https://alice:CANARY_PROXY@proxy.example.invalid:8443/?CANARY_QUERY")
	m.SetEnv("http_proxy", "proxy.example.invalid:3128")
	m.SetEnv("CONDA_CHANNEL_ALIAS", "https://conda.example.invalid/t/CANARY_TOKEN")
	m.SetEnv("CONDA_CHANNELS", "conda-forge, http://user:CANARY_PASS@mirror.example.invalid/ch ,")
	m.SetEnv("CONDA_ENVS_DIRS", filepath.Join(home, "envs-a")+":relative/envs:"+filepath.Join(home, "envs-a"))
	m.SetEnv("CONDA_PKGS_DIRS", "~/pkgs-a,$HOME/pkgs-b")
	m.SetEnv("CONDA_SSL_VERIFY", "truststore")
	m.SetEnv("CONDA_SAFETY_CHECKS", "Warn")
	m.SetEnv("CONDA_CANARY_UNKNOWN", "CANARY_UNKNOWN")
	m.SetEnv("NO_PROXY", "CANARY_NOPROXY")
	m.SetFile(filepath.Join(home, ".condarc"), []byte(`channels:
  - http://mirror.example.invalid/ch
  - https://user:CANARY_PASS@private.example.invalid/ch
  - conda-forge
  - bad channel
default_channels:
  - https://repo.anaconda.com/pkgs/main
channel_alias: https://conda.anaconda.org/t/CANARY_TOKEN
custom_channels:
  internal: https://internal.example.invalid/t/CANARY_TOKEN/conda
  "weird@name": http://weird.example.invalid
custom_multichannels:
  mine:
    - https://a.example.invalid/x
    - file:///srv/conda/mine
envs_dirs:
  - ~/my-envs
  - /opt/shared/envs
  - relative/envs
  - $CONDA_ROOT/envs
pkgs_dirs: ~/my-pkgs
ssl_verify: false
proxy_servers:
  http: http://CANARY_USER:CANARY_PASS@proxy.example.invalid:8080/t/CANARY_PROXY_TOKEN
  https://secure.example.invalid: proxy.example.invalid:8080
offline: yes
extra_safety_checks: "off"
channel_priority: true
safety_checks: disabled
allowlist_channels:
  - conda-forge
  - https://user:CANARY_PASS@allowed.example.invalid
denylist_channels: [bad-channel]
cooldown: "2024-01-01"
auto_activate_base: false
CANARY_KEY: CANARY_VALUE
`))
	a := NewCondaConfigDetector(m).Detect(context.Background(), scope)
	manifest := filepath.Join(home, "proj", "environment.yml")
	partial := a.Manifest(manifest, []string{"conda-forge", "http://insecure.example.invalid/ch", "https://user:CANARY_PASS@private.example.invalid/ch"}, "present", nil)
	audit := a.Finish()
	data, _ := json.Marshal(audit)
	if strings.Contains(string(data), "CANARY") {
		t.Fatalf("canary survived: %s", data)
	}
	if !partial {
		t.Error("manifest context ignored the partial ambient configuration")
	}
	if !slices.Equal(a.EnvsDirs, []string{filepath.Join(home, "envs-a"), filepath.Join(home, "my-envs"), "/opt/shared/envs"}) || !slices.Equal(a.PkgsDirs, []string{filepath.Join(home, "pkgs-a"), filepath.Join(home, "my-pkgs")}) {
		t.Errorf("leads envs %v pkgs %v", a.EnvsDirs, a.PkgsDirs)
	}
	process := condaSettings(condaFile(t, audit, "process", ""))
	for key, want := range map[string]string{
		"channel_alias": "https://conda.example.invalid", "channels.0.url": "conda-forge", "channels.1.url": "http://mirror.example.invalid/ch",
		"envs_dirs": `["` + filepath.Join(home, "envs-a") + `","relative/envs","` + filepath.Join(home, "envs-a") + `"]`, "pkgs_dirs": `["~/pkgs-a","$HOME/pkgs-b"]`,
		"ssl_verify": "truststore", "safety_checks": "warn", "auth_configured": "true",
		"proxy_servers.0.scheme": "http", "proxy_servers.0.url": "http://proxy.example.invalid:3128", "proxy_servers.1.scheme": "https", "proxy_servers.1.url": "https://proxy.example.invalid:8443/",
	} {
		if process[key] != want {
			t.Errorf("process %s=%q want %q", key, process[key], want)
		}
	}
	if len(process) != 12 {
		t.Errorf("process settings %+v", process)
	}
	user := condaFile(t, audit, "user", filepath.Join(home, ".condarc"))
	settings := condaSettings(user)
	for key, want := range map[string]string{
		"channels.0.url": "http://mirror.example.invalid/ch", "channels.1.url": "https://private.example.invalid/ch", "channels.2.url": "conda-forge", "channels.3.url": goRedacted,
		"default_channels.0.url": "https://repo.anaconda.com/pkgs/main", "channel_alias": "https://conda.anaconda.org",
		"custom_channels.0.name": "internal", "custom_channels.0.url": "https://internal.example.invalid/conda", "custom_channels.1.name": goRedacted, "custom_channels.1.url": "http://weird.example.invalid",
		"custom_multichannels.0.name": "mine", "custom_multichannels.0.urls": `["https://a.example.invalid/x","file:///srv/conda/mine"]`,
		"envs_dirs": `["~/my-envs","/opt/shared/envs","relative/envs","$CONDA_ROOT/envs"]`, "pkgs_dirs": `["~/my-pkgs"]`,
		"ssl_verify": "false", "proxy_servers.0.scheme": "http", "proxy_servers.0.url": "http://proxy.example.invalid:8080", "proxy_servers.1.scheme": "https://secure.example.invalid", "proxy_servers.1.url": "http://proxy.example.invalid:8080",
		"offline": "true", "extra_safety_checks": "false", "channel_priority": "flexible", "safety_checks": "disabled",
		"allowlist_channels": `["conda-forge","https://allowed.example.invalid"]`, "denylist_channels": `["bad-channel"]`, "exclude_newer": "2024-01-01", "auth_configured": "true",
	} {
		if settings[key] != want {
			t.Errorf("user %s=%q want %q", key, settings[key], want)
		}
	}
	if len(settings) != 27 || user.Status != "present" || len(user.Reasons) != 0 {
		t.Errorf("user file %+v", user)
	}
	if _, ok := settings["auto_activate_base"]; ok {
		t.Error("non-allowlisted key was serialized")
	}
	project := condaSettings(condaFile(t, audit, "project", manifest))
	if project["channels.0.url"] != "conda-forge" || project["channels.1.url"] != "http://insecure.example.invalid/ch" || project["channels.2.url"] != "https://private.example.invalid/ch" || project["auth_configured"] != "true" || len(project) != 4 {
		t.Errorf("project %+v", project)
	}
	got := condaFindingKeys(audit)
	for _, want := range []string{
		"conda-001 user channels.0.url", "conda-001 user custom_channels.1.url", "conda-002 user ssl_verify", "conda-003 user auth_configured", "conda-004 user safety_checks",
		"conda-001 project channels.1.url", "conda-003 project auth_configured", "conda-001 process channels.1.url",
	} {
		if !got[want] {
			t.Errorf("missing finding %s in %v", want, got)
		}
	}
	if len(got) != 8 {
		t.Errorf("findings %v; process credentials and proxies must not raise findings", got)
	}
	for _, f := range audit.Findings {
		if f.Severity != "MEDIUM" || strings.Contains(f.Detail, "CANARY") {
			t.Errorf("finding %+v", f)
		}
	}
	if len(audit.CredentialFiles) != 3 {
		t.Errorf("credential files %+v", audit.CredentialFiles)
	}
	for _, c := range audit.CredentialFiles {
		if c.Presence != "absent" || c.Status != "absent" {
			t.Errorf("credential file %+v", c)
		}
	}
	if len(audit.Contexts) != 2 {
		t.Fatalf("contexts %+v", audit.Contexts)
	}
	ambient, proj := audit.Contexts[0], audit.Contexts[1]
	if ambient.EnvironmentPath != "" || ambient.ProjectPath != "" || ambient.SelectionStatus != "partial" || ambient.ConfigSourceIDs[0] != condaFile(t, audit, "process", "").SourceID || !slices.Contains(ambient.ConfigSourceIDs, user.SourceID) {
		t.Errorf("ambient context %+v", ambient)
	}
	if proj.ProjectPath != filepath.Dir(manifest) || proj.SelectionStatus != "partial" || len(proj.ConfigSourceIDs) != 1 {
		t.Errorf("project context %+v", proj)
	}
	if audit.Status != "partial" || !slices.Equal(audit.Reasons, []string{"path_unresolved"}) {
		t.Errorf("audit %s %v", audit.Status, audit.Reasons)
	}
}

func TestCondaConfigYAMLShapes(t *testing.T) {
	for _, tc := range []struct {
		name, in, status string
		reasons          []string
		settings         int
	}{
		{"empty file", "", "present", nil, 0},
		{"comment flags ignored", "channels: #!final\n  - conda-forge #!top\n", "present", nil, 1},
		{"alias conflict drops both", "channel:\n  - a\nchannels:\n  - b\n", "present", []string{"unsupported_format"}, 0},
		{"anchor on relevant key", "channels: &c\n  - conda-forge\ndefault_channels: *c\n", "present", []string{"unsupported_format"}, 0},
		{"anchor on irrelevant key kept", "other: &o 1\nchannels:\n  - conda-forge\n", "present", nil, 1},
		{"merge key", "<<: {channels: [x]}\nchannels:\n  - conda-forge\n", "unsupported", []string{"unsupported_format"}, 0},
		{"channels mapping", "channels:\n  a: b\n", "invalid", []string{"parse_error"}, 0},
		{"custom_channels list", "custom_channels:\n  - x\n", "invalid", []string{"parse_error"}, 0},
		{"custom_channels multi-url", "custom_channels:\n  x:\n    - a\n    - b\n", "invalid", []string{"parse_error"}, 0},
		{"empty ssl_verify", "ssl_verify:\n", "present", []string{"unsupported_format"}, 0},
		{"ca bundle path", "ssl_verify: /etc/ssl/CANARY@bundle.pem\n", "present", nil, 1},
		{"bad boolean", "offline: maybe\n", "invalid", []string{"parse_error"}, 0},
		{"bad enum", "safety_checks: sometimes\n", "invalid", []string{"parse_error"}, 0},
		{"channel_priority enum", "channel_priority: disabled\n", "present", nil, 1},
		{"token reference is not a literal credential", "channels:\n  - https://example.invalid/t/${TOKEN}/private\n  - https://$USER:%PASS%@example.invalid/ch\n", "present", nil, 2},
		{"alias without scheme", "channel_alias: conda.example.invalid\n", "invalid", []string{"parse_error"}, 0},
		{"exclude_newer unsupported", "exclude_newer: 'CANARY;rm -rf'\n", "present", []string{"unsupported_format"}, 0},
		{"exclude_newer unquoted timestamp", "exclude_newer: 2024-01-01\n", "present", []string{"unsupported_format"}, 0},
		{"scalar channel", "channels: conda-forge\n", "present", nil, 1},
		{"null channels", "channels:\n", "present", nil, 0},
		{"sequence root", "- a\n", "invalid", []string{"parse_error"}, 0},
		{"invalid utf8", "\xff", "invalid", []string{"parse_error"}, 0},
		{"block scalar", "channel_alias: |\n  https://x\n", "present", []string{"unsupported_format"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := condaConfigTest(t)
			path := filepath.Join(scope.Home, ".condarc")
			m.SetFile(path, []byte(tc.in))
			audit := NewCondaConfigDetector(m).Detect(context.Background(), scope).Finish()
			f := condaFile(t, audit, "user", path)
			if f.Status != tc.status || !slices.Equal(f.Reasons, append([]string{}, tc.reasons...)) || len(f.Settings) != tc.settings {
				t.Errorf("%+v", f)
			}
			if data, _ := json.Marshal(audit); strings.Contains(string(data), "CANARY") {
				t.Errorf("canary survived: %s", data)
			}
		})
	}
}

func TestCondaConfigSearchPathRootsAndEnvironments(t *testing.T) {
	m, scope := condaConfigTest(t)
	home := scope.Home
	xdg := filepath.Join(home, "xdg")
	m.SetEnv("XDG_CONFIG_HOME", xdg)
	m.SetEnv("CONDARC", filepath.Join(home, "custom", "ci.yaml"))
	m.SetFile("/etc/conda/.condarc", []byte("channels:\n  - system\n"))
	m.SetFile("/etc/conda/condarc", []byte("channels:\n  - system-plain\n"))
	m.SetDirEntries("/etc/conda/condarc.d", []os.DirEntry{executor.MockDirEntry("zz.yml", false), executor.MockDirEntry("aa.yaml", false), executor.MockDirEntry("notes.txt", false), executor.MockDirEntry("sub.yml", true)})
	m.SetFile("/etc/conda/condarc.d/aa.yaml", []byte("channels:\n  - frag-a\n"))
	m.SetFile("/etc/conda/condarc.d/zz.yml", []byte("channels:\n  - frag-z\n"))
	m.SetFile(filepath.Join(xdg, "conda", ".condarc"), []byte("channels:\n  - xdg\n"))
	m.SetFile(filepath.Join(home, ".conda", "condarc"), []byte("channels:\n  - dotconda\n"))
	m.SetFile(filepath.Join(home, ".condarc"), []byte("channels:\n  - user\n"))
	m.SetFile(filepath.Join(home, "custom", "ci.yaml"), []byte("channels:\n  - ci\n"))
	root := filepath.Join(home, "miniforge3")
	m.SetFile(filepath.Join(root, ".condarc"), []byte("channels:\n  - root\n"))
	other := filepath.Join(home, "anaconda3")
	m.SetFile(filepath.Join(other, "condarc"), []byte("channels:\n  - other-root\n"))
	env := filepath.Join(root, "envs", "app")
	m.SetFile(filepath.Join(env, ".condarc"), []byte("channels:\n  - env\n"))
	m.SetFile(filepath.Join(env, "conda-meta", "state"), []byte(`{"env_vars":{"CONDA_SSL_VERIFY":"false","CONDA_CHANNELS":"***unset***","CONDA_VERIFY_SSL":"***unset***","HTTPS_PROXY":"https://user:CANARY@proxy.example.invalid:8443","CANARY_OTHER":"CANARY"}}`))
	a := NewCondaConfigDetector(m).Detect(context.Background(), scope)
	a.Root(root, false)
	a.Environment(env, false)
	a.Environment(root, false)
	a.Environment(env, false)
	audit := a.Finish()
	if data, _ := json.Marshal(audit); strings.Contains(string(data), "CANARY") {
		t.Fatalf("canary survived: %s", data)
	}
	ids := map[string]string{}
	for _, f := range audit.Files {
		ids[f.SourceID] = f.Scope + ":" + strings.TrimPrefix(f.Path, home)
	}
	want := map[string][]string{
		"": {"process:", "user:/custom/ci.yaml", "user:/.condarc", "user:/.conda/condarc", "user:/.conda/.condarc", "user:/.config/conda/condarc", "user:/.config/conda/.condarc", "user:/xdg/conda/condarc", "user:/xdg/conda/.condarc",
			"system:" + root[len(home):] + "/condarc", "system:" + root[len(home):] + "/.condarc", "system:/var/lib/conda/condarc", "system:/var/lib/conda/.condarc",
			"system:/etc/conda/condarc.d/zz.yml", "system:/etc/conda/condarc.d/aa.yaml", "system:/etc/conda/condarc", "system:/etc/conda/.condarc"},
	}
	want[env] = append([]string{"process:", "environment:" + env[len(home):] + "/conda-meta/state", "user:/custom/ci.yaml", "environment:" + env[len(home):] + "/condarc", "environment:" + env[len(home):] + "/.condarc"}, want[""][2:]...)
	want[root] = append([]string{"process:", "environment:" + root[len(home):] + "/conda-meta/state", "user:/custom/ci.yaml"}, want[""][2:]...)
	if len(audit.Contexts) != 3 {
		t.Fatalf("contexts %+v", audit.Contexts)
	}
	for _, c := range audit.Contexts {
		chain := []string{}
		for _, id := range c.ConfigSourceIDs {
			chain = append(chain, ids[id])
		}
		if !slices.Equal(chain, want[c.EnvironmentPath]) || c.SelectionStatus != "observed" {
			t.Errorf("context %q %s: %v", c.EnvironmentPath, c.SelectionStatus, chain)
		}
	}
	state := condaFile(t, audit, "environment", filepath.Join(env, "conda-meta", "state"))
	if s := condaSettings(state); s["ssl_verify"] != "false" || s["proxy_servers.0.url"] != "https://proxy.example.invalid:8443" || s["auth_configured"] != "true" || len(s) != 4 || state.Status != "present" {
		t.Errorf("state %+v", state)
	}
	got := condaFindingKeys(audit)
	if !got["conda-002 environment ssl_verify"] || !got["conda-003 environment auth_configured"] || len(got) != 2 {
		t.Errorf("findings %v", got)
	}
	if f := condaFile(t, audit, "system", "/etc/conda/condarc.d/aa.yaml"); condaSettings(f)["channels.0.url"] != "frag-a" {
		t.Errorf("fragment %+v", f)
	}
	for _, f := range audit.Files {
		if strings.HasSuffix(f.Path, "notes.txt") || strings.HasSuffix(f.Path, "sub.yml") {
			t.Errorf("non-fragment listed: %+v", f)
		}
	}

	// A second installation root with its own file makes the ambient chain
	// ambiguous unless CONDA_ROOT names the active one.
	a = NewCondaConfigDetector(m).Detect(context.Background(), scope)
	a.Root(root, false)
	a.Environment(env, false)
	a.Root(other, false)
	audit = a.Finish()
	if audit.Contexts[0].SelectionStatus != "partial" {
		t.Errorf("two roots left ambient %+v", audit.Contexts[0])
	}
	// A root found after the environment still applies to it.
	if c := audit.Contexts[1]; c.EnvironmentPath != env || c.SelectionStatus != "partial" || !slices.Contains(c.ConfigSourceIDs, condaFile(t, audit, "system", filepath.Join(other, "condarc")).SourceID) {
		t.Errorf("environment context finalized early: %+v", c)
	}
	m.SetEnv("CONDA_ROOT", other)
	a = NewCondaConfigDetector(m).Detect(context.Background(), scope)
	a.Root(root, false)
	a.Root(other, false)
	audit = a.Finish()
	if audit.Contexts[0].SelectionStatus != "observed" {
		t.Errorf("CONDA_ROOT did not settle ambient %+v", audit.Contexts[0])
	}
	if id := condaFile(t, audit, "system", filepath.Join(root, ".condarc")).SourceID; slices.Contains(audit.Contexts[0].ConfigSourceIDs, id) {
		t.Error("selected root context includes an unrelated installation")
	}
	if !slices.Contains(a.Prefixes, other) {
		t.Errorf("prefix leads %v", a.Prefixes)
	}

	// CONDARC that the loader would ignore is unresolved and never read.
	m.SetEnv("CONDARC", filepath.Join(home, "custom", "ci.txt"))
	m.SetFile(filepath.Join(home, "custom", "ci.txt"), []byte("channels:\n  - CANARY_TXT\n"))
	audit = NewCondaConfigDetector(m).Detect(context.Background(), scope).Finish()
	if data, _ := json.Marshal(audit); strings.Contains(string(data), "CANARY") || !slices.Contains(audit.Reasons, "path_unresolved") {
		t.Errorf("non-admitted CONDARC: %s %v", data, audit.Reasons)
	}
	// A partial root or environment leaves its context partial.
	a = NewCondaConfigDetector(m).Detect(context.Background(), scope)
	a.Root(root, true)
	a.Environment(env, false)
	for _, c := range a.Finish().Contexts {
		if c.SelectionStatus != "partial" {
			t.Errorf("partial root left context %+v", c)
		}
	}
}

func TestCondaConfigProcessVariants(t *testing.T) {
	t.Run("windows", func(t *testing.T) {
		// Path joining follows the host; only the Windows-specific rules are
		// exercised here.
		m, scope := condaConfigTest(t)
		m.SetGOOS(model.PlatformWindows)
		home := scope.Home
		envA, envB := filepath.Join(home, "envs-a"), filepath.Join(home, "envs-b")
		local := filepath.Join(home, "AppData", "Local")
		m.SetEnv("CONDA_ENVS_PATH", envA+";"+envB+";"+envA)
		m.SetEnv("HTTP_PROXY", "http://proxy.example.invalid:3128")
		m.SetEnv("http_proxy", "http://CANARY_LOWER:x@proxy.example.invalid:3128")
		m.SetEnv("CONDA_CHANNEL_PRIORITY", "false")
		m.SetEnv("PROGRAMDATA", filepath.Join(home, "CANARY_PROGRAMDATA"))
		m.SetEnv("LOCALAPPDATA", local)
		system := filepath.Join(`C:\ProgramData`, "conda", ".condarc")
		m.SetFile(system, []byte("channels:\n  - system\n"))
		a := NewCondaConfigDetector(m).Detect(context.Background(), scope)
		audit := a.Finish()
		if data, _ := json.Marshal(audit); strings.Contains(string(data), "CANARY") {
			t.Fatalf("canary survived: %s", data)
		}
		process := condaSettings(condaFile(t, audit, "process", ""))
		dirs, _ := json.Marshal([]string{envA, envB, envA})
		if process["envs_dirs"] != string(dirs) || process["proxy_servers.0.url"] != "http://proxy.example.invalid:3128" || process["channel_priority"] != "disabled" || len(process) != 4 {
			t.Errorf("process %+v", process)
		}
		if !slices.Equal(a.EnvsDirs, []string{envA, envB}) || a.Env("LOCALAPPDATA") != local {
			t.Errorf("leads %v env %q", a.EnvsDirs, a.Env("LOCALAPPDATA"))
		}
		condaFile(t, audit, "system", system)
		paths := []string{}
		for _, c := range audit.CredentialFiles {
			paths = append(paths, c.Path)
		}
		if !slices.Equal(paths, []string{filepath.Join(home, ".netrc"), filepath.Join(local, "ContinuumIO", "binstar", "data"), filepath.Join(home, "_netrc")}) {
			t.Errorf("credential files %v", paths)
		}
	})
	t.Run("alias conflict", func(t *testing.T) {
		m, scope := condaConfigTest(t)
		m.SetEnv("CONDA_SSL_VERIFY", "false")
		m.SetEnv("CONDA_VERIFY_SSL", "true")
		m.SetEnv("CONDA_WHITELIST_CHANNELS", "conda-forge")
		m.SetEnv("CONDA_OFFLINE", "sometimes")
		m.SetEnv("CONDA_PREFIX", "relative/prefix")
		audit := NewCondaConfigDetector(m).Detect(context.Background(), scope).Finish()
		process := condaFile(t, audit, "process", "")
		if len(process.Settings) != 0 || process.Status != "invalid" || !slices.Equal(slices.Sorted(slices.Values(process.Reasons)), []string{"parse_error", "unsupported_format"}) {
			t.Errorf("process %+v", process)
		}
		if !slices.Contains(audit.Reasons, "path_unresolved") {
			t.Errorf("relative prefix accepted: %v", audit.Reasons)
		}
	})
	t.Run("unverified process", func(t *testing.T) {
		m, scope := condaConfigTest(t)
		scope.ProcessVerified = false
		m.SetEnv("CONDA_CHANNELS", "CANARY")
		m.SetEnv("HTTPS_PROXY", "https://CANARY@x")
		audit := NewCondaConfigDetector(m).Detect(context.Background(), scope).Finish()
		process := condaFile(t, audit, "process", "")
		if process.Status != "unsupported" || !slices.Equal(process.Reasons, []string{"user_unresolved"}) || len(process.Settings) != 0 {
			t.Errorf("process %+v", process)
		}
		if data, _ := json.Marshal(audit); strings.Contains(string(data), "CANARY") || audit.Contexts[0].SelectionStatus != "partial" {
			t.Errorf("unverified process: %s", data)
		}
	})
	t.Run("credential files present and guarded", func(t *testing.T) {
		m, scope := condaConfigTest(t)
		netrc := filepath.Join(scope.Home, ".netrc")
		binstar := filepath.Join(scope.Home, ".config", "binstar", "data")
		m.SetFile(netrc, []byte("machine x login CANARY password CANARY\n"))
		m.SetDir(binstar)
		a := NewCondaConfigDetector(m).Detect(context.Background(), scope)
		if a.ContentGuard(netrc) != "skipped_protected" || a.ContentGuard(filepath.Join(binstar, "token")) != "skipped_protected" || a.ContentGuard(filepath.Join(scope.Home, ".condarc")) != "" {
			t.Error("credential paths not guarded")
		}
		audit := a.Finish()
		present := 0
		for _, c := range audit.CredentialFiles {
			if c.Presence == "present" {
				present++
			}
		}
		if present != 2 || audit.Status != "complete" {
			t.Errorf("credential files %+v", audit.CredentialFiles)
		}
	})
}

func TestCondaSanitizeURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		redacted bool
	}{
		{"https://conda.anaconda.org/conda-forge", "https://conda.anaconda.org/conda-forge", false},
		{"https://conda.anaconda.org/t/CANARY-token/conda-forge", "https://conda.anaconda.org/conda-forge", true},
		{"https://conda.anaconda.org/t/CANARY/t/CANARY2/x", "https://conda.anaconda.org/x", true},
		{"https://conda.anaconda.org/t/", "https://conda.anaconda.org", true},
		{"https://conda.anaconda.org/t/CANARY_under.score/x", "https://conda.anaconda.org/x", true},
		{"https://conda.anaconda.org%2Ft%2FCANARY/x", goRedacted, true},
		{"https://user:CANARY@repo.example.invalid/ch?x=CANARY#CANARY", "https://repo.example.invalid/ch", true},
		{"git@github.com:CANARY/repo.git", goRedacted, true},
		{"not a url\x00", goRedacted, true},
		{"conda-forge", "conda-forge", false},
	} {
		got, redacted := CondaSanitizeURL(tc.in)
		if got != tc.want || redacted != tc.redacted {
			t.Errorf("CondaSanitizeURL(%q) = %q %v", tc.in, got, redacted)
		}
	}
	for _, tc := range []struct {
		in, want string
		redacted bool
	}{
		{"conda-forge", "conda-forge", false},
		{"pkgs/main", "pkgs/main", false},
		{"https://user:CANARY@x.example.invalid/ch", "https://x.example.invalid/ch", true},
		{"/srv/conda/local", "/srv/conda/local", false},
		{`C:\conda\local`, `C:\conda\local`, false},
		{"file:///srv/conda/local", "file:///srv/conda/local", false},
		{"bad channel", goRedacted, true},
		{"-leading", goRedacted, true},
		{strings.Repeat("a", 257), goRedacted, true},
	} {
		got, redacted := CondaChannelDisplay(tc.in)
		if got != tc.want || redacted != tc.redacted {
			t.Errorf("CondaChannelDisplay(%q) = %q %v", tc.in, got, redacted)
		}
	}
	for _, tc := range []struct {
		in, want string
		bad      bool
	}{
		{"http", "http", false},
		{"https://secure.example.invalid:8443", "https://secure.example.invalid:8443", false},
		{"https://user:CANARY@secure.example.invalid", goRedacted, true},
		{"https://secure.example.invalid/path", goRedacted, true},
		{"HTTP", goRedacted, true},
	} {
		got, bad := condaProxySelector(tc.in)
		if got != tc.want || bad != tc.bad {
			t.Errorf("condaProxySelector(%q) = %q %v", tc.in, got, bad)
		}
	}
}

func TestCondaConfigBudget(t *testing.T) {
	old := maxCondaAuditBytes
	t.Cleanup(func() { maxCondaAuditBytes = old })
	m, scope := condaConfigTest(t)
	m.SetFile(filepath.Join(scope.Home, ".condarc"), []byte("channels:\n  - conda-forge\n"))
	maxCondaAuditBytes = 100
	audit := NewCondaConfigDetector(m).Detect(context.Background(), scope).Finish()
	if audit.Status != "partial" || !slices.Contains(audit.Reasons, "output_size_limit") || len(audit.Files) != 0 {
		t.Errorf("bounded audit %s %v %d files", audit.Status, audit.Reasons, len(audit.Files))
	}
	maxCondaAuditBytes = 600
	audit = NewCondaConfigDetector(m).Detect(context.Background(), scope).Finish()
	if audit.Status != "partial" || !slices.Contains(audit.Reasons, "output_size_limit") || len(audit.Files) == 0 {
		t.Errorf("bounded audit kept nothing: %s %v", audit.Status, audit.Reasons)
	}
	maxCondaAuditBytes = old
	entries := make([]os.DirEntry, condaSettingLimit+1)
	for i := range entries {
		entries[i] = executor.MockDirEntry("frag.yml", false)
	}
	m.SetDirEntries(filepath.Join(scope.Home, ".conda", "condarc.d"), entries)
	audit = NewCondaConfigDetector(m).Detect(context.Background(), scope).Finish()
	if !slices.Contains(audit.Reasons, "entry_limit") || audit.Contexts[0].SelectionStatus != "partial" {
		t.Errorf("truncated fragment listing %v %+v", audit.Reasons, audit.Contexts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	audit = NewCondaConfigDetector(m).Detect(ctx, scope).Finish()
	if audit.Status != "partial" || !slices.Equal(audit.Reasons, []string{"deadline_exceeded"}) || len(audit.Files) != 0 {
		t.Errorf("cancelled audit %s %v", audit.Status, audit.Reasons)
	}
	t.Run("context budget preserves audit", func(t *testing.T) {
		m, scope := condaConfigTest(t)
		m.SetFile(filepath.Join(scope.Home, ".condarc"), []byte("ssl_verify: false\n"))
		a := NewCondaConfigDetector(m).Detect(t.Context(), scope)
		for i := range 180 {
			a.Environment(filepath.Join(scope.Home, "envs", strings.Repeat("x", 40)+strconv.Itoa(i)), false)
		}
		audit := a.Finish()
		data, _ := json.Marshal(audit)
		if len(audit.Files) == 0 || len(audit.Findings) == 0 {
			t.Fatalf("context overflow erased audit: files=%d findings=%d bytes=%d reasons=%v", len(audit.Files), len(audit.Findings), len(data), audit.Reasons)
		}
		if len(data) > maxCondaAuditBytes {
			t.Fatalf("audit exceeds cap: %d", len(data))
		}
	})
}
