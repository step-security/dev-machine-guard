package configaudit

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// swiftConfigExec reads the real temporary tree, reports a chosen platform
// and environment, and fails on any read of a credential or signing file.
type swiftConfigExec struct {
	executor.Executor
	t     *testing.T
	goos  string
	env   map[string]string
	reads map[string]int
}

func (x *swiftConfigExec) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	return &swiftConfigExec{x.Executor.GuardedFiles(roots, guard, max), x.t, x.goos, x.env, x.reads}
}
func (x *swiftConfigExec) GOOS() string             { return x.goos }
func (x *swiftConfigExec) Getenv(key string) string { return x.env[key] }
func (x *swiftConfigExec) ReadFile(path string) ([]byte, error) {
	if filepath.Base(path) == ".netrc" || strings.Contains(filepath.ToSlash(path), "/security/") {
		x.t.Fatalf("read forbidden file %s", path)
	}
	x.reads[filepath.Clean(path)]++
	return x.Executor.ReadFile(path)
}

func swiftConfigTest(t *testing.T, goos string) (*swiftConfigExec, SwiftConfigScope) {
	t.Helper()
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("fixture paths are POSIX")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	x := &swiftConfigExec{Executor: executor.NewReal(), t: t, goos: goos, env: map[string]string{}, reads: map[string]int{}}
	return x, SwiftConfigScope{Username: "dev", Home: home, ProcessVerified: true}
}

func swiftConfigWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func swiftConfigFile(t *testing.T, audit model.SwiftConfigAudit, path string) model.RubyConfigFile {
	t.Helper()
	for _, f := range audit.Files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("no audit file %s in %+v", path, audit.Files)
	return model.RubyConfigFile{}
}

func swiftConfigSettings(f model.RubyConfigFile) map[string]string {
	out := map[string]string{}
	for _, s := range f.Settings {
		out[s.Key] = s.Display
	}
	return out
}

func swiftFindingKeys(audit model.SwiftConfigAudit) []string {
	keys := []string{}
	for _, f := range audit.Findings {
		keys = append(keys, f.Code+" "+f.Key)
	}
	return keys
}

func TestSwiftURL(t *testing.T) {
	for _, tc := range []struct {
		in, display string
		literal, ok bool
	}{
		{"https://GitHub.com/Apple/swift-algorithms.git", "https://github.com/Apple/swift-algorithms.git", false, true},
		{"https://registry.example.invalid/", "https://registry.example.invalid", false, true},
		{"HTTP://Example.invalid:8080/x/", "http://example.invalid:8080/x", false, true},
		{"https://user:CANARY@example.invalid/x.git", "https://example.invalid/x.git", true, true},
		{"https://CANARY_TOKEN@example.invalid/x.git", "https://example.invalid/x.git", true, true},
		{"ssh://git@Example.invalid/o/r.git", "ssh://git@example.invalid/o/r.git", false, true},
		// The SSH username selects whose home a relative path names.
		{"alice@Example.invalid:widgets.git", "alice@example.invalid:widgets.git", false, true},
		{"bob@Example.invalid:widgets.git", "bob@example.invalid:widgets.git", false, true},
		{"ssh://alice@example.invalid/~/widgets.git", "ssh://alice@example.invalid/~/widgets.git", false, true},
		{"git+ssh://alice@example.invalid/o/r.git", "git+ssh://alice@example.invalid/o/r.git", false, true},
		{"ssh://alice:CANARY@example.invalid/o/r.git", "ssh://example.invalid/o/r.git", true, true},
		{"git+ssh://alice:CANARY@example.invalid/o/r.git", "git+ssh://example.invalid/o/r.git", true, true},
		{"ssh://a%40CANARY@example.invalid/o/r.git", "", false, false},
		{"https://alice@example.invalid/o/r.git", "https://example.invalid/o/r.git", true, true},
		{"git+ssh://example.invalid/o/r.git/", "git+ssh://example.invalid/o/r.git/", false, true},
		{"git@GitHub.com:apple/x.git", "git@github.com:apple/x.git", false, true},
		{"/src/Local Library", "/src/Local Library", false, true},
		{`C:\src\lib`, `C:\src\lib`, false, true},
		{`\\server\share\lib`, `\\server\share\lib`, false, true},
		{"file:///src/Renamed.git", "file:///src/Renamed.git", false, true},
		{"acme.lib", "acme.lib", false, true},
		// Rejected forms are never displayed or used.
		{"https://example.invalid/x.git?token=CANARY", "", false, false},
		{"https://example.invalid/x.git#CANARY", "", false, false},
		{"https://example.invalid/a%40CANARY/x.git", "", false, false},
		{"https://a@b@example.invalid/x.git", "", true, false},
		{"file://user@host/x", "", false, false},
		{"file://server/share", "", false, false},
		{"ftp://example.invalid/x", "", false, false},
		{"mailto:CANARY@example.invalid", "", false, false},
		{"user@host", "", false, false},
		{"@host:path", "", false, false},
		{"host:pa@th", "", false, false},
		{"https:///x", "", false, false},
		{"https://example.invalid/\x00", "", false, false},
		{"", "", false, false},
	} {
		display, literal, ok := SwiftURL(tc.in)
		if display != tc.display || literal != tc.literal || ok != tc.ok {
			t.Errorf("SwiftURL(%q) = %q, %v, %v", tc.in, display, literal, ok)
		}
	}
}

func TestSwiftLibraryGuard(t *testing.T) {
	roots := []string{"/Users/dev/Library/Caches/org.swift.swiftpm", "/Users/dev/Library/Developer/Xcode/DerivedData"}
	protected := func(p string) string {
		if strings.HasPrefix(strings.ToLower(p), "/users/dev/library") {
			return "skipped_protected"
		}
		return ""
	}
	volume := func(p string) bool { return strings.HasPrefix(p, "/Users/dev/Library/Developer") }
	guard := SwiftLibraryGuard(protected, volume, roots)
	for _, tc := range []struct{ path, want string }{
		{"/Users/dev/Library/Caches/org.swift.swiftpm", ""},
		{"/Users/dev/Library/Caches/org.swift.swiftpm/repositories/x/config", ""},
		{"/Users/dev/library/caches/ORG.SWIFT.SWIFTPM/x", ""},
		// Ancestors are admitted only so a reader rooted below can reach its root.
		{"/Users/dev/Library", ""},
		{"/Users/dev/Library/Caches", ""},
		{"/Users/dev/Library/Caches/com.apple.Safari", "skipped_protected"},
		{"/Users/dev/Library/Mail", "skipped_protected"},
		{"/Users/dev/Library/Caches/org.swift.swiftpm.evil", "skipped_protected"},
		{"/Users/dev/Library/Developer/Xcode/DerivedData", "skipped_protected"},
		{"/Users/dev/src", ""},
	} {
		if got := guard(tc.path); got != tc.want {
			t.Errorf("guard(%s) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestSwiftConfigMirrors(t *testing.T) {
	x, scope := swiftConfigTest(t, model.PlatformLinux)
	dot := filepath.Join(scope.Home, ".swiftpm")
	swiftConfigWrite(t, filepath.Join(dot, "configuration", "mirrors.json"), `{"version":1,"object":[
		{"original":"https://example.invalid/b.git","mirror":"http://mirror.example.invalid/b.git"},
		{"original":"https://user:CANARY@example.invalid/a.git","mirror":"git@Mirror.example.invalid:a.git"},
		{"original":"https://example.invalid/b.git","mirror":"https://ignored.example.invalid/b.git"},
		{"original":"http://example.invalid/plain.git","mirror":"https://example.invalid/q?t=CANARY"}]}`)
	// The legacy file has the same shape.
	swiftConfigWrite(t, filepath.Join(dot, "config", "mirrors.json"), string(mustSwiftFixture(t, "mirrors-legacy.json")))
	audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
	if strings.Contains(swiftJSONString(t, audit), "CANARY") {
		t.Fatalf("canary leaked: %s", swiftJSONString(t, audit))
	}
	modern := swiftConfigFile(t, audit, filepath.Join(dot, "configuration", "mirrors.json"))
	want := map[string]string{
		"mirrors.0.original": "http://example.invalid/plain.git", "mirrors.0.mirror": "[redacted]",
		"mirrors.1.original": "https://example.invalid/a.git", "mirrors.1.mirror": "git@mirror.example.invalid:a.git", "mirrors.1.original.literal_auth": "true",
		"mirrors.2.original": "https://example.invalid/b.git", "mirrors.2.mirror": "http://mirror.example.invalid/b.git",
	}
	if got := swiftConfigSettings(modern); modern.Status != "present" || !maps.Equal(got, want) {
		t.Errorf("modern mirrors = %v", got)
	}
	legacy := swiftConfigFile(t, audit, filepath.Join(dot, "config", "mirrors.json"))
	if got := swiftConfigSettings(legacy); got["mirrors.0.mirror"] != "https://example.invalid/legacy.git" {
		t.Errorf("legacy mirrors = %v", got)
	}
	// The plain-HTTP original is not a destination and is never flagged.
	if got := swiftFindingKeys(audit); !slices.Equal(got, []string{"swift-001 mirrors.2.mirror", "swift-002 mirrors.1.original.literal_auth"}) {
		t.Errorf("findings = %v", got)
	}

	t.Run("order independent", func(t *testing.T) {
		x, scope := swiftConfigTest(t, model.PlatformLinux)
		path := filepath.Join(scope.Home, ".swiftpm", "configuration", "mirrors.json")
		rows := []string{`{"original":"https://u:CANARY1@a.invalid/x","mirror":"https://m.invalid/1"}`, `{"original":"https://u:CANARY2@a.invalid/x?q","mirror":"https://m.invalid/2"}`, `{"original":"https://b.invalid/y","mirror":"https://m.invalid/3"}`}
		outputs := []string{}
		for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}} {
			doc := []string{}
			for _, i := range order {
				doc = append(doc, rows[i])
			}
			swiftConfigWrite(t, path, `{"version":1,"object":[`+strings.Join(doc, ",")+`]}`)
			audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
			outputs = append(outputs, swiftJSONString(t, swiftConfigFile(t, audit, path).Settings))
		}
		if outputs[0] != outputs[1] || outputs[1] != outputs[2] {
			t.Errorf("settings depend on file order:\n%s", strings.Join(outputs, "\n"))
		}
	})

	for _, tc := range []struct{ name, data, status string }{
		{"missing object", `{"version":1}`, "invalid"},
		{"missing mirror", `{"object":[{"original":"a"}]}`, "invalid"},
		{"trailing data", `{"object":[]} {}`, "invalid"},
		{"no version", `{"object":[]}`, "present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, scope := swiftConfigTest(t, model.PlatformLinux)
			path := filepath.Join(scope.Home, ".swiftpm", "configuration", "mirrors.json")
			swiftConfigWrite(t, path, tc.data)
			audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
			if f := swiftConfigFile(t, audit, path); f.Status != tc.status || len(f.Settings) != 0 {
				t.Errorf("file = %+v", f)
			}
		})
	}
}

func TestSwiftConfigRegistries(t *testing.T) {
	x, scope := swiftConfigTest(t, model.PlatformLinux)
	path := filepath.Join(scope.Home, ".swiftpm", "configuration", "registries.json")
	swiftConfigWrite(t, path, `{"version":1,
		"registries":{"[default]":{"url":"https://registry.example.invalid/"},"acme":{"url":"http://u:CANARY@insecure.example.invalid","supportsAvailability":true}},
		"authentication":{"Registry.example.invalid":{"type":"token","loginAPIPath":"/login"},"other.invalid":{"type":"kerberos"}},
		"security":{
			"default":{"signing":{"onUnsigned":"silentAllow","onUntrustedCertificate":"warn","trustedRootCertificatesPath":"/certs","includeDefaultTrustedRootCertificates":false,
				"validationChecks":{"certificateExpiration":"disabled","certificateRevocation":"bogus"}}},
			"registryOverrides":{"registry.example.invalid":{"signing":{"onUntrustedCertificate":"silentAllow"}}},
			"scopeOverrides":{"acme":{"signing":{"onUnsigned":"silentAllow","includeDefaultTrustedRootCertificates":true}}},
			"packageOverrides":{"acme.Lib":{"signing":{"trustedRootCertificatesPath":"/pkg-certs"}}}}}`)
	audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
	if strings.Contains(swiftJSONString(t, audit), "CANARY") || strings.Contains(swiftJSONString(t, audit), "/login") {
		t.Fatalf("credential or login path leaked: %s", swiftJSONString(t, audit))
	}
	f := swiftConfigFile(t, audit, path)
	want := map[string]string{
		"registries.0.scope": "[default]", "registries.0.url": "https://registry.example.invalid",
		"registries.1.scope": "acme", "registries.1.url": "http://insecure.example.invalid", "registries.1.url.literal_auth": "true",
		"authentication.0.host": "registry.example.invalid", "authentication.0.type": "token", "authentication.0.configured": "true",
		"authentication.1.host": "other.invalid", "authentication.1.configured": "true",
		"security.default.signing.onUnsigned": "silentAllow", "security.default.signing.onUntrustedCertificate": "warn",
		"security.default.signing.trustedRootCertificatesPath": "/certs", "security.default.signing.includeDefaultTrustedRootCertificates": "false",
		"security.default.signing.validationChecks.certificateExpiration": "disabled",
		"security.registry_overrides.0.host":                              "registry.example.invalid", "security.registry_overrides.0.signing.onUntrustedCertificate": "silentAllow",
		"security.scope_overrides.0.scope": "acme", "security.scope_overrides.0.signing.includeDefaultTrustedRootCertificates": "true",
		"security.package_overrides.0.package": "acme.Lib", "security.package_overrides.0.signing.trustedRootCertificatesPath": "/pkg-certs",
	}
	if got := swiftConfigSettings(f); !maps.Equal(got, want) {
		t.Errorf("settings = %v", got)
	}
	// An unknown auth type and an invalid enum degrade the file without inventing values.
	if f.Status != "present" || !slices.Equal(f.Reasons, []string{"unsupported_format"}) || audit.Status != "partial" {
		t.Errorf("file = %s %v audit = %s", f.Status, f.Reasons, audit.Status)
	}
	// A scope override's signing action is ignored by SwiftPM and never flagged.
	if got := swiftFindingKeys(audit); !slices.Equal(got, []string{"swift-001 registries.1.url", "swift-002 registries.1.url.literal_auth",
		"swift-003 security.default.signing.onUnsigned", "swift-003 security.registry_overrides.0.signing.onUntrustedCertificate"}) {
		t.Errorf("findings = %v", got)
	}

	for _, tc := range []struct{ name, data, status string }{
		{"version 2", `{"version":2,"registries":{}}`, "unsupported"},
		{"missing registries", `{"version":1}`, "invalid"},
		{"missing version", `{"registries":{}}`, "invalid"},
		{"invalid scope", `{"version":1,"registries":{"-bad":{"url":"https://r.invalid"}}}`, "invalid"},
		{"missing url", `{"version":1,"registries":{"acme":{}}}`, "invalid"},
		{"invalid package override", `{"version":1,"registries":{},"security":{"packageOverrides":{"nodot":{}}}}`, "invalid"},
		{"empty", `{"version":1,"registries":{}}`, "present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, scope := swiftConfigTest(t, model.PlatformLinux)
			path := filepath.Join(scope.Home, ".swiftpm", "configuration", "registries.json")
			swiftConfigWrite(t, path, tc.data)
			audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
			if f := swiftConfigFile(t, audit, path); f.Status != tc.status || len(f.Settings) != 0 {
				t.Errorf("file = %+v", f)
			}
		})
	}
	t.Run("native fixtures", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			findings []string
		}{
			{"registries.json", []string{"swift-001 registries.1.url"}},
			{"registries-security.json", []string{"swift-003 security.default.signing.onUnsigned", "swift-003 security.default.signing.onUntrustedCertificate"}},
		} {
			x, scope := swiftConfigTest(t, model.PlatformLinux)
			path := filepath.Join(scope.Home, ".swiftpm", "configuration", "registries.json")
			swiftConfigWrite(t, path, string(mustSwiftFixture(t, tc.name)))
			audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
			if f := swiftConfigFile(t, audit, path); f.Status != "present" || len(f.Reasons) != 0 || !slices.Equal(swiftFindingKeys(audit), tc.findings) {
				t.Errorf("%s: file = %+v findings = %v", tc.name, f, swiftFindingKeys(audit))
			}
		}
	})
}

// Project, process and user files form one context per project, highest
// precedence first; netrc is observed by existence only.
func TestSwiftConfigContexts(t *testing.T) {
	x, scope := swiftConfigTest(t, model.PlatformLinux)
	home := scope.Home
	process := filepath.Join(home, "ci", "mirrors.json")
	swiftConfigWrite(t, process, `{"object":[]}`)
	swiftConfigWrite(t, filepath.Join(home, ".netrc"), "machine r.invalid password CANARY_NETRC\n")
	app := filepath.Join(home, "src", "app")
	local := filepath.Join(app, ".swiftpm", "configuration", "mirrors.json")
	swiftConfigWrite(t, local, `{"object":[]}`)
	legacy := filepath.Join(app, ".swiftpm", "config")
	swiftConfigWrite(t, legacy, `{"object":[]}`)
	// A project file redirected at netrc is refused, never read.
	stolen := filepath.Join(app, ".swiftpm", "configuration", "registries.json")
	if err := os.Symlink(filepath.Join(home, ".netrc"), stolen); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	x.env["SWIFTPM_MIRROR_CONFIG"] = process
	snapshot := NewSwiftConfigDetector(x).Detect(context.Background(), scope)
	snapshot.Project(app, SwiftProjectFiles{Mirrors: local, Registries: stolen, Legacy: legacy})
	other := filepath.Join(home, "src", "other")
	snapshot.Project(other, SwiftProjectFiles{})
	snapshot.Unlisted(other, "permission_denied")
	audit := snapshot.Finish()
	if x.reads[filepath.Join(home, ".netrc")] != 0 || strings.Contains(swiftJSONString(t, audit), "CANARY") {
		t.Fatal("netrc content read")
	}
	if f := swiftConfigFile(t, audit, stolen); f.Status != "skipped_protected" {
		t.Errorf("redirected file = %+v", f)
	}
	if len(audit.CredentialFiles) != 1 || audit.CredentialFiles[0] != (model.SwiftCredentialFile{Path: filepath.Join(home, ".netrc"), Status: "present", Presence: "present"}) {
		t.Errorf("credential files = %+v", audit.CredentialFiles)
	}
	id := func(scope, path string) string { return GoSourceID("dev", "swift_config_"+scope, path) }
	user := []string{id("user", filepath.Join(home, ".swiftpm", "configuration", "mirrors.json")), id("user", filepath.Join(home, ".swiftpm", "configuration", "registries.json"))}
	contexts := map[string]model.RubyConfigContext{}
	for _, c := range audit.Contexts {
		contexts[c.ProjectPath] = c
	}
	if c := contexts[""]; !slices.Equal(c.ConfigSourceIDs, append([]string{id("process", process)}, user...)) || c.SelectionStatus != "observed" {
		t.Errorf("user context = %+v", c)
	}
	appIDs := append([]string{id("process", process), id("project", local), id("project", stolen), id("project", legacy)}, user...)
	if c := contexts[app]; !slices.Equal(c.ConfigSourceIDs, appIDs) || c.SelectionStatus != "partial" {
		t.Errorf("app context = %+v", c)
	}
	if c := contexts[other]; c.SelectionStatus != "partial" {
		t.Errorf("unlisted context = %+v", c)
	}
}

func TestSwiftConfigEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name      string
		env       map[string]string
		verified  bool
		audit     []string
		inventory []string
	}{
		{"relative build dir", map[string]string{"SWIFTPM_BUILD_DIR": "out"}, true, []string{}, []string{"path_unresolved"}},
		{"relative mirror config", map[string]string{"SWIFTPM_MIRROR_CONFIG": "m.json"}, true, []string{"path_unresolved"}, nil},
		{"relative config home", map[string]string{"XDG_CONFIG_HOME": "cfg"}, true, []string{"path_unresolved"}, []string{"path_unresolved"}},
		{"relative cache home", map[string]string{"XDG_CACHE_HOME": "cache"}, true, []string{}, []string{"path_unresolved"}},
		{"unverified", map[string]string{"SWIFTPM_BUILD_DIR": "/out"}, false, []string{"user_unresolved"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, scope := swiftConfigTest(t, model.PlatformLinux)
			x.env, scope.ProcessVerified = tc.env, tc.verified
			snapshot := NewSwiftConfigDetector(x).Detect(context.Background(), scope)
			audit := snapshot.Finish()
			if !slices.Equal(audit.Reasons, tc.audit) || !slices.Equal(snapshot.InventoryReasons, tc.inventory) || len(snapshot.ScratchLeads) != 0 {
				t.Errorf("audit = %v inventory = %v leads = %v", audit.Reasons, snapshot.InventoryReasons, snapshot.ScratchLeads)
			}
		})
	}
	t.Run("leads", func(t *testing.T) {
		x, scope := swiftConfigTest(t, model.PlatformLinux)
		cfg := filepath.Join(scope.Home, "cfg")
		x.env = map[string]string{"SWIFTPM_BUILD_DIR": "/out/", "XDG_CACHE_HOME": "/cache", "XDG_CONFIG_HOME": cfg}
		// The default base's legacy files are still read when present.
		swiftConfigWrite(t, filepath.Join(scope.Home, ".swiftpm", "configuration", "mirrors.json"), `{"object":[]}`)
		snapshot := NewSwiftConfigDetector(x).Detect(context.Background(), scope)
		audit := snapshot.Finish()
		if !slices.Equal(snapshot.ScratchLeads, []string{"/out"}) || !slices.Equal(snapshot.CacheLeads, []string{"/cache/org.swift.swiftpm"}) ||
			!slices.Equal(snapshot.DotSwiftPM, []string{filepath.Join(cfg, "swiftpm")}) {
			t.Errorf("snapshot = %+v", snapshot)
		}
		swiftConfigFile(t, audit, filepath.Join(cfg, "swiftpm", "configuration", "mirrors.json"))
		swiftConfigFile(t, audit, filepath.Join(scope.Home, ".swiftpm", "configuration", "mirrors.json"))
	})
	t.Run("cache home is Linux only", func(t *testing.T) {
		x, scope := swiftConfigTest(t, model.PlatformDarwin)
		x.env = map[string]string{"XDG_CACHE_HOME": "/cache"}
		if snapshot := NewSwiftConfigDetector(x).Detect(context.Background(), scope); len(snapshot.CacheLeads) != 0 {
			t.Errorf("cache leads = %v", snapshot.CacheLeads)
		}
	})
}

// macOS user configuration lives under ~/Library; it is read only through
// the Library reader, and legacy files only when listed.
func TestSwiftConfigDarwinLibrary(t *testing.T) {
	x, scope := swiftConfigTest(t, model.PlatformDarwin)
	lib := filepath.Join(scope.Home, "Library")
	base := filepath.Join(lib, "org.swift.swiftpm")
	scope.Protected = func(p string) string {
		if strings.HasPrefix(p, lib) {
			return "skipped_protected"
		}
		return ""
	}
	scope.LibraryRoots = []string{base}
	scope.Library = SwiftLibraryGuard(scope.Protected, nil, scope.LibraryRoots)
	swiftConfigWrite(t, filepath.Join(base, "configuration", "registries.json"), string(mustSwiftFixture(t, "registries.json")))
	swiftConfigWrite(t, filepath.Join(base, "registries.json"), `{"version":1,"registries":{}}`)
	swiftConfigWrite(t, filepath.Join(base, "security", "fingerprints", "x.json"), "CANARY")
	audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
	if audit.Status != "complete" {
		t.Fatalf("audit = %s %v", audit.Status, audit.Reasons)
	}
	for path, status := range map[string]string{
		filepath.Join(base, "configuration", "registries.json"): "present",
		filepath.Join(base, "configuration", "mirrors.json"):    "absent",
		filepath.Join(base, "registries.json"):                  "present",
	} {
		if f := swiftConfigFile(t, audit, path); f.Status != status {
			t.Errorf("%s = %+v", path, f)
		}
	}
	if len(audit.Files) != 3 {
		t.Errorf("files = %+v", audit.Files)
	}
	t.Run("without the Library reader", func(t *testing.T) {
		scope := scope
		scope.Library = nil
		audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
		if f := swiftConfigFile(t, audit, filepath.Join(base, "configuration", "registries.json")); f.Status != "skipped_protected" {
			t.Errorf("file = %+v", f)
		}
	})
}

// SwiftPM security state stays unread when a configuration link, a project
// file or a process lead points into it, while ordinary files still parse.
func TestSwiftConfigSecurityState(t *testing.T) {
	link := func(t *testing.T, target, path string) {
		t.Helper()
		swiftConfigWrite(t, target, string(mustSwiftFixture(t, "registries.json")))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("darwin Library link", func(t *testing.T) {
		x, scope := swiftConfigTest(t, model.PlatformDarwin)
		lib := filepath.Join(scope.Home, "Library")
		base := filepath.Join(lib, "org.swift.swiftpm")
		scope.Protected = func(p string) string {
			if strings.HasPrefix(p, lib) {
				return "skipped_protected"
			}
			return ""
		}
		scope.LibraryRoots = []string{base}
		scope.Library = SwiftLibraryGuard(scope.Protected, nil, scope.LibraryRoots)
		path := filepath.Join(base, "configuration", "registries.json")
		link(t, filepath.Join(base, "security", "fingerprints", "private.json"), path)
		swiftConfigWrite(t, filepath.Join(base, "configuration", "mirrors.json"), string(mustSwiftFixture(t, "mirrors-modern.json")))
		audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
		if f := swiftConfigFile(t, audit, path); f.Status != "skipped_protected" || len(f.Settings) != 0 || x.reads[path] != 0 {
			t.Errorf("redirected file = %+v reads = %d", f, x.reads[path])
		}
		if f := swiftConfigFile(t, audit, filepath.Join(base, "configuration", "mirrors.json")); f.Status != "present" || len(f.Settings) == 0 {
			t.Errorf("ordinary file = %+v", f)
		}
	})
	// A relocated security folder is excluded at its target too.
	for _, target := range []string{"Library/org.swift.swiftpm/relocated-history", "relocated-history"} {
		t.Run("darwin security relocated to "+target, func(t *testing.T) {
			x, scope := swiftConfigTest(t, model.PlatformDarwin)
			lib := filepath.Join(scope.Home, "Library")
			base := filepath.Join(lib, "org.swift.swiftpm")
			scope.Protected = func(p string) string {
				if strings.HasPrefix(p, lib) {
					return "skipped_protected"
				}
				return ""
			}
			scope.LibraryRoots = []string{base}
			scope.Library = SwiftLibraryGuard(scope.Protected, nil, scope.LibraryRoots)
			history := filepath.Join(scope.Home, target)
			swiftConfigWrite(t, filepath.Join(history, "mirrors.json"), string(mustSwiftFixture(t, "mirrors-modern.json")))
			if err := os.MkdirAll(base, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(history, filepath.Join(base, "security")); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, "configuration", "registries.json")
			link(t, filepath.Join(history, "registries.json"), path)
			process := filepath.Join(history, "mirrors.json")
			x.env["SWIFTPM_MIRROR_CONFIG"] = process
			audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
			for _, p := range []string{process, path} {
				if f := swiftConfigFile(t, audit, p); f.Status != "skipped_protected" || len(f.Settings) != 0 || x.reads[p] != 0 {
					t.Errorf("%s = %+v reads = %d", p, f, x.reads[p])
				}
			}
		})
	}
	t.Run("linux relocated security", func(t *testing.T) {
		x, scope := swiftConfigTest(t, model.PlatformLinux)
		dot := filepath.Join(scope.Home, ".swiftpm")
		history := filepath.Join(dot, "relocated-history")
		swiftConfigWrite(t, filepath.Join(history, "mirrors.json"), string(mustSwiftFixture(t, "mirrors-modern.json")))
		if err := os.Symlink(history, filepath.Join(dot, "security")); err != nil {
			t.Fatal(err)
		}
		process := filepath.Join(history, "mirrors.json")
		x.env["SWIFTPM_MIRROR_CONFIG"] = process
		audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
		if f := swiftConfigFile(t, audit, process); f.Status != "skipped_protected" || x.reads[process] != 0 {
			t.Errorf("process file = %+v reads = %d", f, x.reads[process])
		}
	})
	t.Run("user, project and process", func(t *testing.T) {
		x, scope := swiftConfigTest(t, model.PlatformLinux)
		dot := filepath.Join(scope.Home, ".swiftpm")
		user := filepath.Join(dot, "configuration", "registries.json")
		link(t, filepath.Join(dot, "security", "fingerprints", "user.json"), user)
		app := filepath.Join(scope.Home, "src", "app")
		project := filepath.Join(app, ".swiftpm", "configuration", "registries.json")
		link(t, filepath.Join(dot, "security", "fingerprints", "project.json"), project)
		process := filepath.Join(dot, "security", "mirrors.json")
		swiftConfigWrite(t, process, string(mustSwiftFixture(t, "mirrors-modern.json")))
		ordinary := filepath.Join(app, ".swiftpm", "configuration", "mirrors.json")
		swiftConfigWrite(t, ordinary, string(mustSwiftFixture(t, "mirrors-modern.json")))
		swiftConfigWrite(t, filepath.Join(scope.Home, ".netrc"), "machine example.invalid password CANARY\n")
		x.env["SWIFTPM_MIRROR_CONFIG"] = process
		snapshot := NewSwiftConfigDetector(x).Detect(context.Background(), scope)
		snapshot.Project(app, SwiftProjectFiles{Mirrors: ordinary, Registries: project})
		audit := snapshot.Finish()
		for _, path := range []string{user, project, process} {
			if f := swiftConfigFile(t, audit, path); f.Status != "skipped_protected" || len(f.Settings) != 0 || x.reads[path] != 0 {
				t.Errorf("%s = %+v reads = %d", path, f, x.reads[path])
			}
		}
		if f := swiftConfigFile(t, audit, ordinary); f.Status != "present" || len(f.Settings) == 0 {
			t.Errorf("ordinary file = %+v", f)
		}
		if len(audit.CredentialFiles) != 1 || audit.CredentialFiles[0].Presence != "present" {
			t.Errorf("credential files = %+v", audit.CredentialFiles)
		}
	})
}

func TestSwiftConfigUnresolved(t *testing.T) {
	x, _ := swiftConfigTest(t, model.PlatformLinux)
	snapshot := NewSwiftConfigDetector(x).Detect(context.Background(), SwiftConfigScope{})
	snapshot.Project("/src/app", SwiftProjectFiles{Mirrors: "/src/app/.swiftpm/configuration/mirrors.json"})
	audit := snapshot.Finish()
	if audit.Status != "partial" || !slices.Equal(audit.Reasons, []string{"user_unresolved"}) || len(audit.Files) != 0 || len(audit.Contexts) != 0 || len(x.reads) != 0 {
		t.Errorf("audit = %+v", audit)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	x, scope := swiftConfigTest(t, model.PlatformLinux)
	audit = NewSwiftConfigDetector(x).Detect(ctx, scope).Finish()
	if audit.Status != "partial" || !slices.Contains(audit.Reasons, "deadline_exceeded") || len(x.reads) != 0 {
		t.Errorf("canceled audit = %+v", audit)
	}
}

func TestSwiftConfigBudget(t *testing.T) {
	old := maxSwiftAuditBytes
	t.Cleanup(func() { maxSwiftAuditBytes = old })
	x, scope := swiftConfigTest(t, model.PlatformLinux)
	path := filepath.Join(scope.Home, ".swiftpm", "configuration", "mirrors.json")
	rows := []string{}
	for i := range 300 {
		rows = append(rows, `{"original":"https://example.invalid/`+strings.Repeat("o", i+1)+`","mirror":"http://m.invalid/x"}`)
	}
	swiftConfigWrite(t, path, `{"object":[`+strings.Join(rows, ",")+`]}`)
	audit := NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
	f := swiftConfigFile(t, audit, path)
	if len(f.Settings) != swiftSettingLimit || !slices.Contains(f.Reasons, "record_limit") || len(audit.Findings) != swiftSettingLimit/2 {
		t.Errorf("settings = %d reasons = %v findings = %d", len(f.Settings), f.Reasons, len(audit.Findings))
	}
	maxSwiftAuditBytes = 8 << 10
	audit = NewSwiftConfigDetector(x).Detect(context.Background(), scope).Finish()
	if size := swiftAuditSize(audit); size > maxSwiftAuditBytes || !slices.Contains(audit.Reasons, "output_size_limit") {
		t.Errorf("audit size = %d reasons = %v", size, audit.Reasons)
	}
}

func mustSwiftFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "swift", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func swiftJSONString(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSwiftConfigCredentialAliasIntoLibrary(t *testing.T) {
	for _, kind := range []string{"netrc", "security"} {
		t.Run(kind, func(t *testing.T) {
			x, scope := swiftConfigTest(t, model.PlatformDarwin)
			lib := filepath.Join(scope.Home, "Library")
			base := filepath.Join(lib, "org.swift.swiftpm")
			scope.Protected = func(p string) string {
				if strings.HasPrefix(p, lib) {
					return "skipped_protected"
				}
				return ""
			}
			scope.LibraryRoots = []string{base}
			scope.Library = SwiftLibraryGuard(scope.Protected, nil, scope.LibraryRoots)
			target := filepath.Join(base, "relocated", "mirrors.json")
			swiftConfigWrite(t, target, string(mustSwiftFixture(t, "mirrors-modern.json")))
			source := filepath.Join(scope.Home, ".netrc")
			dest := target
			if kind == "security" {
				source = filepath.Join(scope.Home, ".swiftpm", "security")
				dest = filepath.Dir(target)
			}
			if err := os.MkdirAll(filepath.Dir(source), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(dest, source); err != nil {
				t.Fatal(err)
			}
			x.env["SWIFTPM_MIRROR_CONFIG"] = target
			a := NewSwiftConfigDetector(x).Detect(t.Context(), scope).Finish()
			f := swiftConfigFile(t, a, target)
			if x.reads[target] != 0 || f.Status != "skipped_protected" {
				t.Fatalf("alias kind %s read %d status %s", kind, x.reads[target], f.Status)
			}
		})
	}
}
func TestSwiftConfigRejectedLeadContext(t *testing.T) {
	for _, key := range []string{"SWIFTPM_MIRROR_CONFIG", "XDG_CONFIG_HOME"} {
		t.Run(key, func(t *testing.T) {
			x, s := swiftConfigTest(t, model.PlatformLinux)
			x.env[key] = "relative/path"
			a := NewSwiftConfigDetector(x).Detect(t.Context(), s).Finish()
			if a.Status != "partial" {
				t.Fatal(a.Status)
			}
			for _, c := range a.Contexts {
				if c.SelectionStatus != "partial" {
					t.Fatalf("audit partial but context %s", c.SelectionStatus)
				}
			}
		})
	}
}
func TestSwiftConfigBudgetDeterminism(t *testing.T) {
	old := maxSwiftAuditBytes
	t.Cleanup(func() { maxSwiftAuditBytes = old })
	maxSwiftAuditBytes = 350
	seen := map[string]bool{}
	for range 100 {
		a := &SwiftConfigSnapshot{scope: SwiftConfigScope{Username: "dev"}, audit: emptySwiftAudit(), projects: map[string]*swiftProjectConfig{}, files: map[string]*model.RubyConfigFile{}}
		for _, key := range strings.Split("a b c d e f g h i j k l m n o p q r s t", " ") {
			a.projects[key] = &swiftProjectConfig{dir: "/home/dev/src/" + key}
		}
		out := a.Finish()
		if len(out.Contexts) < 2 || len(out.Contexts) > 20 {
			t.Fatalf("probe budget invalid %d", len(out.Contexts))
		}
		paths := []string{}
		for _, c := range out.Contexts {
			paths = append(paths, c.ProjectPath)
		}
		seen[strings.Join(paths, ",")] = true
	}
	if len(seen) > 1 {
		t.Fatalf("unchanged projects yield %d different retained context subsets", len(seen))
	}
}

func TestSwiftConfigPhysicalAliases(t *testing.T) {
	for _, tc := range []struct {
		name, goos, scope string
		linked            bool
	}{
		{"shared alias", model.PlatformDarwin, "user", true},
		{"project alias", model.PlatformDarwin, "project", true},
		{"Linux project alias", model.PlatformLinux, "project", true},
		{"shared copy", model.PlatformDarwin, "user", false},
		{"project copy", model.PlatformLinux, "project", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, scope := swiftConfigTest(t, tc.goos)
			project := filepath.Join(scope.Home, "src", "app")
			base := filepath.Join(project, ".swiftpm")
			legacy := filepath.Join(base, "config")
			if tc.scope == "user" {
				base = filepath.Join(scope.Home, "Library", "org.swift.swiftpm")
				legacy = filepath.Join(base, "mirrors.json")
				lib := filepath.Join(scope.Home, "Library")
				scope.Protected = func(p string) string {
					if p == lib || strings.HasPrefix(p, lib+string(filepath.Separator)) {
						return "skipped_protected"
					}
					return ""
				}
				scope.LibraryRoots = []string{base}
				scope.Library = SwiftLibraryGuard(scope.Protected, nil, scope.LibraryRoots)
			}
			modern := filepath.Join(base, "configuration", "mirrors.json")
			data := `{"version":1,"object":[{"original":"https://example.invalid/widgets.git","mirror":"http://mirror.example.invalid/widgets.git"}]}`
			swiftConfigWrite(t, modern, data)
			if tc.linked {
				if err := os.Symlink(modern, legacy); err != nil {
					t.Fatal(err)
				}
			} else {
				swiftConfigWrite(t, legacy, data)
			}
			snapshot := NewSwiftConfigDetector(x).Detect(t.Context(), scope)
			if tc.scope == "project" {
				snapshot.Project(project, SwiftProjectFiles{Mirrors: modern, Legacy: legacy})
			}
			audit := snapshot.Finish()
			want := 2
			if tc.linked {
				want = 1
			}
			ids := []string{}
			for _, f := range audit.Files {
				if f.Scope == tc.scope && len(f.Settings) > 0 {
					ids = append(ids, f.SourceID)
				}
			}
			if len(ids) != want || len(audit.Findings) != want || x.reads[modern]+x.reads[legacy] != want {
				t.Fatalf("files=%d findings=%d reads=%d, want %d", len(ids), len(audit.Findings), x.reads[modern]+x.reads[legacy], want)
			}
			for _, c := range audit.Contexts {
				if tc.scope == "project" && c.ProjectPath != project {
					continue
				}
				for _, id := range ids {
					if !slices.Contains(c.ConfigSourceIDs, id) {
						t.Fatalf("context lost source %s: %+v", id, c)
					}
				}
			}
		})
	}
}
