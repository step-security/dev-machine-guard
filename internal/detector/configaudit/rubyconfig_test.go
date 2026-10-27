package configaudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func rubyConfigTest(t *testing.T) (*composerConfigMock, RubyConfigScope) {
	t.Helper()
	m, scope := composerConfigTest(t)
	return m, RubyConfigScope{Username: scope.Username, Home: scope.Home, ProcessVerified: true}
}

func rubyFile(t *testing.T, audit model.RubyConfigAudit, manager, scope, path string) model.RubyConfigFile {
	t.Helper()
	for _, f := range audit.Files {
		if f.Manager == manager && f.Scope == scope && f.Path == path {
			return f
		}
	}
	t.Fatalf("no %s %s file %q in %+v", manager, scope, path, audit.Files)
	return model.RubyConfigFile{}
}

func rubySettings(f model.RubyConfigFile) map[string]string {
	out := map[string]string{}
	for _, s := range f.Settings {
		out[s.Key] = s.Display
	}
	return out
}

func TestRubyConfigAllowlistRedactionAndFindings(t *testing.T) {
	m, scope := rubyConfigTest(t)
	home := scope.Home
	m.SetEnv("GEM_HOST_API_KEY", "CANARY_HOST_KEY")
	m.SetEnv("HTTPS_PROXY", "https://alice:CANARY_PROXY@proxy.example.invalid:8443/?CANARY_QUERY")
	m.SetEnv("BUNDLE_GEMS__EXAMPLE__COM", "CANARY_USER:CANARY_PASS")
	m.SetEnv("BUNDLE_CANARY_UNKNOWN", "CANARY_UNKNOWN_VALUE")
	m.SetEnv("BUNDLE_WITHOUT", "development:test")
	m.SetFile(filepath.Join(home, ".gemrc"), []byte(`---
:sources:
- http://CANARY_USER:CANARY_PASS@gems.example.invalid/
- https://rubygems.org/
:ssl_verify_mode: 0
:rubygems_api_key: CANARY_API_KEY
gem: --source CANARY_OPTION
install: --CANARY_INSTALL
:s3_source:
  bucket:
    id: CANARY_ID
    secret: CANARY_SECRET
`))
	m.SetFile(filepath.Join(home, ".bundle", "config"), []byte(`---
BUNDLE_DISABLE_CHECKSUM_VALIDATION: "true"
BUNDLE_GEMS__EXAMPLE__COM: "CANARY_USER:CANARY_PASS"
BUNDLE_HTTPS://CANARY__EXAMPLE__COM/: "CANARY_URI_TOKEN"
BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: "http://mirror.example.invalid/"
BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/__FALLBACK_TIMEOUT/: "true"
BUNDLE_LOCAL__RACK: "~/src/rack"
BUNDLE_JOBS: "4"
`))
	a := NewRubyConfigDetector(m).Detect(context.Background(), scope)
	dir := filepath.Join(home, "app")
	leads := a.Project(RubyProject{Dir: dir, Manifests: []RubyManifest{{Path: filepath.Join(dir, "Gemfile"), Status: "present",
		Sources: []RubyManifestSource{{Type: "registry", URL: "http://CANARY_USER:CANARY_PASS@insecure.example.invalid/"}, {Type: "git", URL: "git@github.com:CANARY/repo.git"}}}}})
	audit := a.Finish()
	data, _ := json.Marshal(audit)
	if strings.Contains(string(data), "CANARY_") {
		t.Fatalf("canary survived: %s", data)
	}
	if leads.Path != "" || leads.CachePath != filepath.Join(dir, "vendor", "cache") || leads.AppConfig != filepath.Join(dir, ".bundle") {
		t.Fatalf("leads %+v", leads)
	}
	gemrc := rubySettings(rubyFile(t, audit, "rubygems", "user", filepath.Join(home, ".gemrc")))
	for key, want := range map[string]string{"sources.0.type": "registry", "sources.0.url": "http://gems.example.invalid/", "sources.1.url": "https://rubygems.org/", "ssl_verify_mode": "0", "auth_configured": "true"} {
		if gemrc[key] != want {
			t.Errorf("gemrc %s=%q want %q", key, gemrc[key], want)
		}
	}
	bundle := rubySettings(rubyFile(t, audit, "bundler", "user", filepath.Join(home, ".bundle", "config")))
	for key, want := range map[string]string{"disable_checksum_validation": "true", "mirrors.0.source": "https://rubygems.org/", "mirrors.0.url": "http://mirror.example.invalid/", "mirrors.0.fallback_timeout": "0.1", "local.0.name": "rack", "local.0.path": "~/src/rack", "auth_configured": "true"} {
		if bundle[key] != want {
			t.Errorf("bundler %s=%q want %q", key, bundle[key], want)
		}
	}
	if _, ok := bundle["jobs"]; ok {
		t.Error("non-allowlisted Bundler key was serialized")
	}
	process := rubySettings(rubyFile(t, audit, "bundler", "process", ""))
	if process["auth_configured"] != "true" || process["without"] != `["development","test"]` || len(process) != 2 {
		t.Errorf("bundler process %+v", process)
	}
	if gem := rubySettings(rubyFile(t, audit, "rubygems", "process", "")); gem["auth_configured"] != "true" || gem["https_proxy"] != "https://proxy.example.invalid:8443/" {
		t.Errorf("rubygems process %+v", gem)
	}
	manifest := rubySettings(rubyFile(t, audit, "bundler", "project", filepath.Join(dir, "Gemfile")))
	if manifest["sources.1.url"] != goRedacted || manifest["sources.1.type"] != "git" {
		t.Errorf("SCP-like remote was not redacted: %+v", manifest)
	}
	got := map[string]bool{}
	for _, f := range audit.Findings {
		if f.Severity != "MEDIUM" || strings.Contains(f.Detail, "CANARY") {
			t.Errorf("finding %+v", f)
		}
		for _, file := range audit.Files {
			if file.SourceID == f.SourceID {
				got[f.Code+" "+file.Manager+" "+file.Scope+" "+f.Key] = true
			}
		}
	}
	for _, want := range []string{
		"ruby-001 rubygems user sources.0.url", "ruby-002 rubygems user ssl_verify_mode", "ruby-003 rubygems user auth_configured",
		"ruby-001 bundler user mirrors.0.url", "ruby-003 bundler user auth_configured", "ruby-004 bundler user disable_checksum_validation",
		"ruby-001 bundler project sources.0.url", "ruby-003 bundler project auth_configured",
	} {
		if !got[want] {
			t.Errorf("missing finding %s in %v", want, got)
		}
	}
	if len(got) != 8 {
		t.Errorf("findings %v; process credentials must not raise ruby-003", got)
	}
	if len(audit.CredentialFiles) != 2 || audit.CredentialFiles[0].Presence != "absent" {
		t.Errorf("credential files %+v", audit.CredentialFiles)
	}
	for _, c := range audit.Contexts {
		if c.SelectionStatus != "observed" {
			t.Errorf("context %+v", c)
		}
	}
}

// Bundler's Settings#path: the first level holding path, path.system or
// disable_shared_gems decides; deployment applies only when none does.
func TestRubyConfigPathSelection(t *testing.T) {
	for _, tc := range []struct {
		name                string
		local, global       string
		env                 map[string]string
		path, cache, lock   string
		excludeLocalContext bool
	}{
		{name: "shared default"},
		{name: "deployment fallback", global: "BUNDLE_DEPLOYMENT: \"true\"\n", path: "vendor/bundle"},
		{name: "local relative path", local: "BUNDLE_PATH: \"gems\"\n", path: "gems"},
		{name: "local system wins over global path", local: "BUNDLE_PATH__SYSTEM: \"true\"\n", global: "BUNDLE_PATH: \"/opt/global\"\n"},
		{name: "global path wins over local deployment", local: "BUNDLE_DEPLOYMENT: \"true\"\n", global: "BUNDLE_PATH: \"/opt/global\"\n", path: "/opt/global"},
		{name: "env path wins over global", global: "BUNDLE_PATH: \"/opt/global\"\n", env: map[string]string{"BUNDLE_PATH": "/opt/env"}, path: "/opt/env"},
		{name: "cache and lockfile", local: "BUNDLE_CACHE_PATH: \"pkg/cache\"\nBUNDLE_LOCKFILE: \"Other.lock\"\n", cache: "pkg/cache", lock: "Other.lock"},
		{name: "ignore config", local: "BUNDLE_PATH: \"gems\"\n", global: "BUNDLE_DEPLOYMENT: \"true\"\n", env: map[string]string{"BUNDLE_IGNORE_CONFIG": "1"}, excludeLocalContext: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := rubyConfigTest(t)
			dir := filepath.Join(scope.Home, "app")
			for k, v := range tc.env {
				m.SetEnv(k, v)
			}
			if tc.local != "" {
				m.SetFile(filepath.Join(dir, ".bundle", "config"), []byte(tc.local))
			}
			if tc.global != "" {
				m.SetFile(filepath.Join(scope.Home, ".bundle", "config"), []byte(tc.global))
			}
			a := NewRubyConfigDetector(m).Detect(context.Background(), scope)
			leads := a.Project(RubyProject{Dir: dir, Manifests: []RubyManifest{{Path: filepath.Join(dir, "Gemfile"), Status: "present"}}})
			abs := func(p string) string {
				if p == "" || filepath.IsAbs(p) {
					return p
				}
				return filepath.Join(dir, p)
			}
			want := RubyProjectLeads{Path: abs(tc.path), CachePath: abs(cmpOr(tc.cache, "vendor/cache")), AppConfig: filepath.Join(dir, ".bundle"), Lockfile: abs(tc.lock)}
			if leads != want {
				t.Fatalf("leads %+v want %+v", leads, want)
			}
			audit := a.Finish()
			local := rubyFile(t, audit, "bundler", "project", filepath.Join(dir, ".bundle", "config")).SourceID
			for _, c := range audit.Contexts {
				if c.Manager == "bundler" && c.ProjectPath == dir && slices.Contains(c.ConfigSourceIDs, local) == tc.excludeLocalContext {
					t.Fatalf("ignored config context %+v", c)
				}
			}
		})
	}
}

func TestRubyConfigRejectsUnsafeYAMLAndUnverifiedProcess(t *testing.T) {
	for _, tc := range []struct{ name, body, status string }{
		{"plain", ":sources:\n- https://rubygems.org/\n", "present"},
		{"anchor", ":sources: &s\n- https://rubygems.org/\n", "unsupported"},
		{"alias", "base: &b [https://rubygems.org/]\n:sources: *b\n", "unsupported"},
		{"merge key", "<<: {sources: [https://rubygems.org/]}\n", "unsupported"},
		{"ruby tag", ":sources: !ruby/object:Gem::Source\n  uri: https://rubygems.org/\n", "unsupported"},
		{"block scalar", ":http_proxy: |\n  http://proxy.example.invalid\n", "unsupported"},
		{"duplicate key", ":sources: []\nsources: []\n", "unsupported"},
		{"not yaml", ":sources: [\n", "invalid"},
		{"irrelevant tag ignored", "gem: !ruby/object:CANARY {}\n", "present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := rubyConfigTest(t)
			m.SetFile(filepath.Join(scope.Home, ".gemrc"), []byte(tc.body))
			audit := NewRubyConfigDetector(m).Detect(context.Background(), scope).Finish()
			f := rubyFile(t, audit, "rubygems", "user", filepath.Join(scope.Home, ".gemrc"))
			if f.Status != tc.status || tc.status != "present" && len(f.Settings) != 0 {
				t.Fatalf("status %s settings %+v, want %s", f.Status, f.Settings, tc.status)
			}
		})
	}

	// Bundler's line reader, not YAML, decides what these files mean.
	for _, tc := range []struct{ name, body, status, display string }{
		{"quoted value", "BUNDLE_DISABLE_CHECKSUM_VALIDATION: \"false\"\n", "present", "false"},
		{"plain comment agrees", "BUNDLE_DISABLE_CHECKSUM_VALIDATION: false # keep validation\n", "present", "false"},
		{"quoted comment reads as true", "BUNDLE_DISABLE_CHECKSUM_VALIDATION: \"false\" # keep validation\n", "unsupported", ""},
		{"trailing space after quote", "BUNDLE_DISABLE_CHECKSUM_VALIDATION: \"false\"  \n", "unsupported", ""},
		{"escape", "BUNDLE_PATH: \"a\\\"b\"\n", "unsupported", ""},
		{"doubled single quote", "BUNDLE_PATH: 'it''s'\n", "unsupported", ""},
		{"hash inside quotes", "BUNDLE_PATH: \"a#b\"\n", "unsupported", ""},
		{"second space", "BUNDLE_PATH:  \"gems\"\n", "unsupported", ""},
		{"value on next line", "BUNDLE_PATH:\n  gems\n", "unsupported", ""},
		{"irrelevant key ignored", "BUNDLE_JOBS: \"4\" # comment\n", "present", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := rubyConfigTest(t)
			path := filepath.Join(scope.Home, ".bundle", "config")
			m.SetFile(path, []byte("---\n"+tc.body))
			audit := NewRubyConfigDetector(m).Detect(context.Background(), scope).Finish()
			f := rubyFile(t, audit, "bundler", "user", path)
			if f.Status != tc.status || tc.status != "present" && len(f.Settings) != 0 {
				t.Fatalf("status %s settings %+v, want %s", f.Status, f.Settings, tc.status)
			}
			if tc.display != "" && rubySettings(f)["disable_checksum_validation"] != tc.display {
				t.Errorf("settings %+v, want %s", f.Settings, tc.display)
			}
			for _, c := range audit.Contexts {
				if c.Manager == "bundler" && (c.SelectionStatus == "partial") != (tc.status != "present") {
					t.Errorf("context %+v for %s file", c, tc.status)
				}
			}
		})
	}

	m, scope := rubyConfigTest(t)
	scope.ProcessVerified = false
	m.SetEnv("GEM_HOST_API_KEY", "CANARY_HOST_KEY")
	m.SetEnv("GEMRC", "/CANARY/gemrc")
	audit := NewRubyConfigDetector(m).Detect(context.Background(), scope).Finish()
	for _, manager := range []string{"rubygems", "bundler"} {
		if f := rubyFile(t, audit, manager, "process", ""); f.Status != "unsupported" || !slices.Equal(f.Reasons, []string{"user_unresolved"}) || len(f.Settings) != 0 {
			t.Errorf("unverified %s process %+v", manager, f)
		}
	}
	for _, c := range audit.Contexts {
		if c.SelectionStatus != "partial" {
			t.Errorf("unverified process left context complete: %+v", c)
		}
	}
	if data, _ := json.Marshal(audit); strings.Contains(string(data), "CANARY") {
		t.Fatalf("unverified environment was read: %s", data)
	}
}

func TestRubyConfigGemrcSelection(t *testing.T) {
	t.Run("missing file under directory alias", func(t *testing.T) {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		physical, alias := filepath.Join(root, "physical"), filepath.Join(root, "alias")
		if err := os.Mkdir(physical, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(physical, alias); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		a := NewRubyConfigDetector(executor.NewReal()).Detect(t.Context(), RubyConfigScope{Username: "dev", Home: root})
		p := filepath.Join(alias, "gemrc")
		f := a.readFile("rubygems", "system", p, a.parseGemrc)
		if f.Status != "absent" || len(f.Reasons) != 0 {
			t.Fatalf("missing config = %+v", f)
		}
	})
	m, scope := rubyConfigTest(t)
	home := scope.Home
	first, second := filepath.Join(home, "one.gemrc"), filepath.Join(home, "two.gemrc")
	m.SetEnv("GEMRC", first+":"+second)
	m.SetFile(second, []byte(":ssl_verify_mode: 1\n"))
	xdg := filepath.Join(home, ".config", "gem", "gemrc")
	m.SetFile(xdg, []byte(":gemhome: ~/xdg-gems\n"))
	a := NewRubyConfigDetector(m).Detect(context.Background(), scope)
	prefix := filepath.Join(home, "rubies", "3.3.0")
	m.SetFile(filepath.Join(prefix, "etc", "gemrc"), []byte(":sources:\n- https://rubygems.org/\n"))
	a.Prefixes([]string{prefix}, nil)
	audit := a.Finish()
	// ~/.gemrc is absent, so the XDG file is a candidate.
	if f := rubyFile(t, audit, "rubygems", "user", xdg); f.Status != "present" || rubySettings(f)["gem_home"] != filepath.Join(home, "xdg-gems") {
		t.Fatalf("xdg gemrc %+v", f)
	}
	if !slices.Contains(a.GemHomes, filepath.Join(home, "xdg-gems")) {
		t.Fatalf("gemhome lead %v", a.GemHomes)
	}
	if f := rubyFile(t, audit, "rubygems", "system", filepath.Join(prefix, "etc", "gemrc")); f.Status != "present" {
		t.Fatalf("prefix gemrc %+v", f)
	}
	var ctx model.RubyConfigContext
	for _, c := range audit.Contexts {
		if c.Manager == "rubygems" {
			ctx = c
		}
	}
	// Process, both GEMRC files (last first), ~/.gemrc, XDG, then system files.
	if len(ctx.ConfigSourceIDs) != 7 || ctx.SelectionStatus != "partial" {
		t.Fatalf("rubygems context %+v", ctx)
	}
	if ctx.ConfigSourceIDs[1] != rubyFile(t, audit, "rubygems", "user", second).SourceID {
		t.Fatal("GEMRC precedence order lost")
	}

	// A present ~/.gemrc hides the XDG file.
	m, scope = rubyConfigTest(t)
	m.SetFile(filepath.Join(scope.Home, ".gemrc"), []byte("{}\n"))
	audit = NewRubyConfigDetector(m).Detect(context.Background(), scope).Finish()
	for _, f := range audit.Files {
		if strings.HasSuffix(f.Path, filepath.Join("gem", "gemrc")) {
			t.Fatalf("XDG gemrc observed beside ~/.gemrc: %+v", f)
		}
	}
	if audit.Status != "complete" {
		t.Fatalf("audit %s %v", audit.Status, audit.Reasons)
	}
}

func TestRubyURLSanitizer(t *testing.T) {
	for _, tc := range []struct {
		raw, display string
		credential   bool
	}{
		{"https://rubygems.org/", "https://rubygems.org/", false},
		{"https://CANARY_TOKEN@gems.example.invalid/", "https://gems.example.invalid/", true},
		{"https://user:CANARY_PASS@gems.example.invalid/", "https://gems.example.invalid/", true},
		{"ssh://git@github.com/org/repo.git", "ssh://github.com/org/repo.git", false},
		{"ssh://git:CANARY_PASS@github.com/org/repo.git", "ssh://github.com/org/repo.git", true},
		{"git@github.com:org/repo.git", goRedacted, false},
		{"git://github.com/org/repo.git", "git://github.com/org/repo.git", false},
	} {
		display, _ := SanitizeRubyURL(tc.raw)
		if display != tc.display || rubyURLCredential(tc.raw) != tc.credential {
			t.Errorf("%s: display %q credential %v, want %q %v", tc.raw, display, rubyURLCredential(tc.raw), tc.display, tc.credential)
		}
	}
}
