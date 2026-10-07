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

type composerConfigMock struct {
	*executor.Mock
	dirInfo os.FileInfo
}

func (m *composerConfigMock) GuardedFiles([]string, func(string) string, int64) executor.Executor {
	return m
}
func (m *composerConfigMock) Stat(path string) (os.FileInfo, error) {
	if m.DirExists(path) {
		return m.dirInfo, nil
	}
	info, err := m.Mock.Stat(path)
	if err != nil {
		return nil, os.ErrNotExist
	}
	return info, nil
}
func composerConfigTest(t *testing.T) (*composerConfigMock, ComposerConfigScope) {
	t.Helper()
	home := t.TempDir()
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	m := &composerConfigMock{Mock: executor.NewMock(), dirInfo: info}
	m.SetGOOS(model.PlatformLinux)
	return m, ComposerConfigScope{Username: "dev", Home: home, ProcessVerified: true}
}
func composerSettings(a model.ComposerConfigAudit, scope string) map[string]string {
	result := map[string]string{}
	for _, f := range a.Files {
		if f.Scope == scope {
			for _, s := range f.Settings {
				result[s.Key] = s.Display
			}
		}
	}
	return result
}
func TestComposerConfigAllowlistRedactionAndFindings(t *testing.T) {
	m, scope := composerConfigTest(t)
	m.SetEnv("COMPOSER_AUTH", `{"secret":"CANARY_AUTH"}`)
	m.SetEnv("HTTPS_PROXY", "https://alice:CANARY_PROXY@proxy.example.invalid:8443/?token=CANARY_QUERY#CANARY_FRAGMENT")
	m.SetEnv("NO_PROXY", "localhost,.example.invalid,127.0.0.1,::1")
	a := NewComposerConfigDetector(m).Detect(context.Background(), scope)
	manifest := filepath.Join(scope.Home, "app", "composer.json")
	body := `{
 "minimum-stability":"RC","prefer-stable":true,
 "config":{"disable-tls":true,"secure-http":false,"lock":false,"source-fallback":false,"store-auths":"prompt","platform-check":"php-only","vendor-dir":"deps/php","bin-dir":"{$vendor-dir}/bin","cafile":"/cert/path","allow-plugins":true,"preferred-install":{"example/*":"dist","*":"source"},"http-basic":{"CANARY_HOST":{"username":"CANARY_USER","password":"CANARY_PASS"}},"audit":{"abandoned":"report","block-insecure":true,"block-abandoned":false,"ignore-unreachable":true,"ignore":{"CANARY_IGNORE":"CANARY_REASON"}},"policy":{"advisories":{"block":true,"audit":"fail","ignore-id":["CANARY_ID"]},"malware":{"block":false,"audit":"report","block-scope":"update"},"abandoned":false,"ignore-unreachable":["audit","install"],"custom-CANARY_POLICY":{"key":"CANARY_VALUE"}}},
 "repositories":{"CANARY_REPO_NAME":{"type":"composer","url":"http://alice:CANARY_URL@repo.example.invalid/index?token=CANARY_TOKEN#CANARY_FRAGMENT","canonical":false,"only":["example/*"],"exclude":["example/dev"],"options":{"http":{"header":["Authorization: CANARY_HEADER"]}}},"packagist.org":false,"another":{"type":"path","url":"../local/*"},"CANARY_DISABLED_REPO":false},"scripts":{"post-install-cmd":"CANARY_SCRIPT"}}
 `
	paths := a.Project(manifest, []byte(body), "present", nil, "")
	audit := a.Finish()
	if audit.Status != "complete" {
		t.Fatalf("valid repository settings made audit %s: %v", audit.Status, audit.Reasons)
	}
	data, _ := json.Marshal(audit)
	if strings.Contains(string(data), "CANARY_") {
		t.Fatalf("canary survived: %s", data)
	}
	if paths.Vendor != filepath.Join(scope.Home, "app", "deps", "php") {
		t.Fatalf("vendor %s", paths.Vendor)
	}
	got := composerSettings(audit, "project")
	for key, want := range map[string]string{"disable-tls": "true", "secure-http": "false", "lock": "false", "source-fallback": "false", "minimum-stability": "RC", "preferred-install.example/*": "dist", "repositories.0.url": "http://repo.example.invalid/index", "repositories.0.only": "[\"example/*\"]", "repositories.packagist.org": "false", "repositories.2.url": "../local/*", "policy.ignore-unreachable": "[\"audit\",\"install\"]", "auth_configured": "true"} {
		if got[key] != want {
			t.Errorf("%s=%q want %q", key, got[key], want)
		}
	}
	if len(audit.Findings) != 4 {
		t.Fatalf("findings %+v", audit.Findings)
	}
	process := composerSettings(audit, "process")
	if process["auth_configured"] != "true" || process["HTTPS_PROXY"] != "https://proxy.example.invalid:8443/" {
		t.Fatalf("process %+v", process)
	}
}
func TestComposerConfigSafeControlsNoFindings(t *testing.T) {
	m, scope := composerConfigTest(t)
	a := NewComposerConfigDetector(m).Detect(context.Background(), scope)
	a.Project(filepath.Join(scope.Home, "app", "composer.json"), []byte(`{"config":{"allow-plugins":{"*":true},"secure-http":true,"disable-tls":false,"policy":false},"repositories":[{"type":"composer","url":"https://private.example.invalid","canonical":false}]}`), "present", nil, "")
	audit := a.Finish()
	if len(audit.Findings) != 0 || audit.Status != "complete" {
		t.Fatalf("safe controls %+v", audit)
	}
}
func TestComposerConfigHomeAndVendorSelection(t *testing.T) {
	for _, tc := range []struct {
		name, goos          string
		xdg, legacy, custom bool
		want                string
	}{
		{"legacy default", model.PlatformDarwin, false, true, false, ".composer"},
		{"XDG both", model.PlatformLinux, true, true, false, ".config/composer"},
		{"Mac XDG both", model.PlatformDarwin, true, true, false, ".config/composer"},
		{"Mac system XDG", model.PlatformDarwin, false, false, false, ".config/composer"},
		{"explicit home", model.PlatformLinux, true, true, true, "custom"},
		{"Windows developer", model.PlatformWindows, false, false, false, "AppData/Roaming/Composer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := composerConfigTest(t)
			m.SetGOOS(tc.goos)
			if tc.name == "Mac system XDG" {
				m.SetDir("/private/etc/xdg")
				m.SetDir(filepath.Join(scope.Home, ".config", "composer"))
			}
			if tc.xdg {
				m.SetEnv("XDG_SESSION_TYPE", "")
				m.SetDir(filepath.Join(scope.Home, ".config", "composer"))
			}
			if tc.legacy {
				m.SetDir(filepath.Join(scope.Home, ".composer"))
			}
			if tc.custom {
				m.SetEnv("COMPOSER_HOME", filepath.Join(scope.Home, "custom"))
			}
			a := NewComposerConfigDetector(m).Detect(context.Background(), scope)
			if a.Home != filepath.Join(scope.Home, filepath.FromSlash(tc.want)) {
				t.Fatalf("home %s", a.Home)
			}
		})
	}
	m, scope := composerConfigTest(t)
	global := filepath.Join(scope.Home, ".composer")
	m.SetDir(global)
	m.SetFile(filepath.Join(global, "config.json"), []byte(`{"config":{"vendor-dir":"global-deps"}}`))
	project := filepath.Join(scope.Home, "app")
	a := NewComposerConfigDetector(m).Detect(context.Background(), scope)
	paths := a.Project(filepath.Join(project, "composer.json"), []byte(`{}`), "present", nil, "")
	if paths.Vendor != filepath.Join(project, "global-deps") {
		t.Fatal("relative global setting anchored outside project")
	}
	a = NewComposerConfigDetector(m).Detect(context.Background(), scope)
	paths = a.Project(filepath.Join(project, "composer.json"), []byte(`{"config":{"vendor-dir":"project-deps"}}`), "present", nil, "")
	if paths.Vendor != filepath.Join(project, "project-deps") {
		t.Fatal("project override")
	}
	m.SetEnv("COMPOSER_VENDOR_DIR", filepath.Join(scope.Home, "process-deps"))
	a = NewComposerConfigDetector(m).Detect(context.Background(), scope)
	paths = a.Project(filepath.Join(project, "composer.json"), []byte(`{"config":{"vendor-dir":"project-deps"}}`), "present", nil, "")
	if paths.Vendor != filepath.Join(scope.Home, "process-deps") {
		t.Fatal("process override")
	}
	audit := a.Finish()
	ctx := audit.Contexts[0]
	scopes := map[string]string{}
	for _, f := range audit.Files {
		scopes[f.SourceID] = f.Scope
	}
	if len(ctx.ConfigSourceIDs) != 3 || scopes[ctx.ConfigSourceIDs[0]] != "process" || scopes[ctx.ConfigSourceIDs[1]] != "project" || scopes[ctx.ConfigSourceIDs[2]] != "user" {
		t.Fatal("context precedence")
	}
}
func TestComposerConfigUnresolvedAndFailedSources(t *testing.T) {
	for _, key := range []string{"COMPOSER_HOME", "COMPOSER", "COMPOSER_VENDOR_DIR"} {
		t.Run(key, func(t *testing.T) {
			m, scope := composerConfigTest(t)
			m.SetEnv(key, "relative/unknown")
			a := NewComposerConfigDetector(m).Detect(context.Background(), scope)
			paths := a.Project(filepath.Join(scope.Home, "app", "composer.json"), []byte(`{}`), "present", nil, "")
			audit := a.Finish()
			if !paths.Partial || audit.Status != "partial" || a.AlternateManifest != "" {
				t.Fatal("relative override treated as resolved")
			}
			for _, f := range audit.Files {
				if f.Scope == "user" && f.Path == "" && (f.Status != "unsupported" || !slices.Equal(f.Reasons, []string{"path_unresolved"})) {
					t.Fatal("unresolved user wire shape")
				}
			}
		})
	}
	m, scope := composerConfigTest(t)
	global := filepath.Join(scope.Home, ".composer")
	m.SetDir(global)
	m.SetFile(filepath.Join(global, "config.json"), []byte(`{"config":`))
	a := NewComposerConfigDetector(m).Detect(context.Background(), scope)
	paths := a.Project(filepath.Join(scope.Home, "app", "composer.json"), []byte(`{"config":{"vendor-dir":"deps"}}`), "present", nil, "")
	if !paths.Partial || paths.Vendor != filepath.Join(scope.Home, "app", "deps") {
		t.Fatal("failed global source hidden by readable fallback")
	}
	for _, v := range []string{"{$vendor-dir}/loop", "{$unknown}/dir"} {
		if _, ok := composerResolvePath(v, scope.Home, scope.Home, map[string]string{"vendor-dir": v}); ok {
			t.Fatal("expression falsely resolved")
		}
	}
}
func TestComposerConfigBoundedAudit(t *testing.T) {
	m, scope := composerConfigTest(t)
	old := maxComposerAuditBytes
	maxComposerAuditBytes = 256
	t.Cleanup(func() { maxComposerAuditBytes = old })
	a := NewComposerConfigDetector(m).Detect(context.Background(), scope)
	a.Project(filepath.Join(scope.Home, "app", "composer.json"), []byte(`{}`), "present", nil, "")
	audit := a.Finish()
	if audit.Status != "partial" || !slices.Contains(audit.Reasons, "output_size_limit") {
		t.Fatal("audit overflow complete")
	}
}
func TestComposerURLSanitizer(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://u:CANARY@host.invalid/path?q=CANARY#CANARY", "https://host.invalid/path"},
		{"alice:CANARY@host.invalid", "[redacted]"},
		{"https://u:CANARY@bad host/path", "[redacted]"},
		{"https://host.invalid/%40CANARY", "[redacted]"},
		{"https://host.invalid/\nCANARY", "[redacted]"},
		{"git@github.com:example/lib.git", "ssh://github.com/example/lib.git"},
		{`C:\Users\dev\repo`, `C:\Users\dev\repo`},
		{`\\server\share\repo`, `\\server\share\repo`},
	} {
		got, _ := SanitizeComposerURL(tc.in)
		if got != tc.want {
			t.Errorf("sanitized value %q want %q", got, tc.want)
		}
	}
}

func TestComposerConfigFailedSourcesDoNotPublishCurrentSettings(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"invalid types", `{"config":{"secure-http":"false","allow-plugins":[],"policy":{"ignore-unreachable":["CANARY_BAD"]}}}`},
		{"invalid pattern", `{"config":{"secure-http":false,"allow-plugins":{"CANARY_BAD@key":true}}}`},
		{"invalid lock", `{"config":{"secure-http":false,"lock":"false"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := composerConfigTest(t)
			a := NewComposerConfigDetector(m).Detect(context.Background(), scope)
			a.Project(filepath.Join(scope.Home, "app", "composer.json"), []byte(tc.body), "present", nil, "")
			audit := a.Finish()
			if audit.Status != "partial" || len(composerSettings(audit, "project")) != 0 || len(audit.Findings) != 0 {
				t.Fatal("invalid source published current settings or findings")
			}
		})
	}
	m, scope := composerConfigTest(t)
	m.SetEnv("COMPOSER", "relative.json")
	m.SetEnv("HTTPS_PROXY", "https://proxy.example.invalid")
	a := NewComposerConfigDetector(m).Detect(context.Background(), scope).Finish()
	if len(composerSettings(a, "process")) != 0 || a.Status != "partial" {
		t.Fatal("unsupported process context published current settings")
	}
}

func TestComposerConfigDocumentedProxyForms(t *testing.T) {
	for _, tc := range []struct{ key, raw, want string }{
		{"HTTPS_PROXY", "proxy.example.invalid:8080", "http://proxy.example.invalid:8080"},
		{"http_proxy", "proxy.example.invalid", "http://proxy.example.invalid"},
		{"HTTPS_PROXY", "[2001:db8::1]:8080", "http://[2001:db8::1]:8080"},
		{"HTTPS_PROXY", "user:CANARY_PASSWORD@proxy.example.invalid:8080?CANARY_QUERY#CANARY_FRAGMENT", "http://proxy.example.invalid:8080"},
		{"HTTPS_PROXY", "https://user:CANARY_PASSWORD@proxy.example.invalid:8443/", "https://proxy.example.invalid:8443/"},
		{"HTTPS_PROXY", "bad host:8080", "[redacted]"},
		{"HTTPS_PROXY", "proxy.example.invalid:not-a-port", "[redacted]"},
		{"HTTPS_PROXY", "proxy.example.invalid:65536", "[redacted]"},
		{"HTTPS_PROXY", "file:///CANARY_SECRET", "[redacted]"},
		{"HTTPS_PROXY", "https://proxy.example.invalid/%40CANARY_SECRET", "[redacted]"},
		{"NO_PROXY", "localhost,10.0.0.0/8,192.168.0.0/16", "localhost,10.0.0.0/8,192.168.0.0/16"},
		{"no_proxy", ".example.invalid:8080,::1,2001:db8::/32,*", ".example.invalid:8080,::1,2001:db8::/32,*"},
		{"NO_PROXY", "localhost,[2001:db8::]/32", "localhost,[2001:db8::]/32"},
		{"NO_PROXY", "localhost,example.invalid/CANARY_SECRET", "[redacted]"},
		{"NO_PROXY", "localhost,10.0.0.0/99", "[redacted]"},
		{"NO_PROXY", "user:CANARY_PASSWORD@host.invalid", "[redacted]"},
		{"NO_PROXY", "localhost,host.invalid?CANARY_QUERY", "[redacted]"},
	} {
		t.Run(tc.key+"/"+tc.raw, func(t *testing.T) {
			m, scope := composerConfigTest(t)
			m.SetEnv(tc.key, tc.raw)
			a := NewComposerConfigDetector(m).Detect(context.Background(), scope).Finish()
			if got := composerSettings(a, "process")[tc.key]; got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got, _ := SanitizeComposerURL("proxy.example.invalid:8080"); got != "[redacted]" {
		t.Fatal("proxy rules leaked into package-origin URLs")
	}
}
