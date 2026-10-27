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

// nugetConfigMock adds the directory listings the NuGet audit probes; an
// unregistered directory is absent rather than an error.
type nugetConfigMock struct{ *composerConfigMock }

func (m *nugetConfigMock) GuardedFiles([]string, func(string) string, int64) executor.Executor {
	return m
}
func (m *nugetConfigMock) ReadDirLimit(path string, max int) ([]os.DirEntry, bool, error) {
	if !m.DirExists(path) {
		return nil, false, os.ErrNotExist
	}
	return m.Mock.ReadDirLimit(path, max)
}
func nugetConfigTest(t *testing.T) (*nugetConfigMock, NuGetConfigScope) {
	t.Helper()
	inner, scope := composerConfigTest(t)
	return &nugetConfigMock{inner}, NuGetConfigScope{Username: scope.Username, Home: scope.Home, Roots: []string{scope.Home}, ProcessVerified: true}
}
func nugetSettings(a model.NuGetConfigAudit, path string) map[string]string {
	result := map[string]string{}
	for _, f := range a.Files {
		if f.Path == path {
			for _, s := range f.Settings {
				result[s.Key] = s.Display
			}
		}
	}
	return result
}
func nugetFile(t *testing.T, a model.NuGetConfigAudit, path string) model.NuGetConfigFile {
	t.Helper()
	for _, f := range a.Files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("no file record for %q", path)
	return model.NuGetConfigFile{}
}

func TestNuGetConfigAllowlistRedactionAndFindings(t *testing.T) {
	m, scope := nugetConfigTest(t)
	packages := filepath.Join(scope.Home, "CANARY_DIR", "packages")
	fallback := filepath.Join(scope.Home, "fallback")
	legacy := filepath.Join(scope.Home, "legacy")
	m.SetEnv("NUGET_PACKAGES", packages)
	m.SetEnv("NUGET_FALLBACK_PACKAGES", "/opt/fallback;relative/ignored")
	m.SetEnv("HTTPS_PROXY", "https://alice:CANARY_PROXY@proxy.example.invalid:8443/?token=CANARY_QUERY")
	m.SetEnv("NO_PROXY", "localhost,.example.invalid")
	m.SetEnv("NuGetPackageSourceCredentials_internal", "Username=alice;Password=CANARY_ENV_PASSWORD")
	m.SetEnv("NUGET_CREDENTIALPROVIDERS_PATH", "/opt/CANARY_PROVIDER")
	user := filepath.Join(scope.Home, ".nuget", "NuGet", "NuGet.Config")
	m.SetFile(user, []byte(`<?xml version="1.0"?><configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
    <add key="plain" value="http://alice:CANARY_URL_PASSWORD@plain.example.invalid/v3/index.json?CANARY_QUERY" allowInsecureConnections="true" />
    <add key="lab" value="https://lab.example.invalid/v3/index.json" disableTLSCertificateValidation="true" />
    <add key="off" value="http://off.example.invalid/v3/index.json" />
    <add key="CANARY_KEY@host" value="C:\feeds\local" />
    <add key="rel" value="../shared/feed" />
  </packageSources>
  <disabledPackageSources><add key="off" value="true" /><add key="elsewhere" value="true" /></disabledPackageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org"><package pattern="*" /></packageSource>
    <packageSource key="lab"><package pattern="Contoso.*" /><package pattern="Fabrikam" /></packageSource>
  </packageSourceMapping>
  <fallbackPackageFolders><add key="shared" value="`+fallback+`" /><add key="expr" value="%USERPROFILE%\fallback" /></fallbackPackageFolders>
  <config>
    <add key="globalPackagesFolder" value="pkgs" />
    <add key="repositoryPath" value="`+legacy+`" />
    <add key="http_proxy" value="http://bob:CANARY_CONFIG_PROXY@proxy.example.invalid:8080" />
    <add key="http_proxy.user" value="bob" />
    <add key="http_proxy.password" value="CANARY_CONFIG_PROXY" />
    <add key="no_proxy" value="localhost" />
    <add key="signatureValidationMode" value="Require" />
    <add key="maxHttpRequestsPerSource" value="16" />
    <add key="defaultPushSource" value="https://push.example.invalid" />
  </config>
  <apikeys><add key="https://push.example.invalid" value="CANARY_API_KEY" /></apikeys>
  <trustedSigners>
    <author name="CANARY_AUTHOR"><certificate fingerprint="CANARY_FINGERPRINT" hashAlgorithm="SHA256" allowUntrustedRoot="true" /></author>
    <repository name="nuget.org" serviceIndex="https://api.nuget.org/v3/index.json"><certificate fingerprint="x" hashAlgorithm="SHA256" allowUntrustedRoot="false" /><owners>CANARY_OWNER</owners></repository>
  </trustedSigners>
</configuration>`))
	a := NewNuGetConfigDetector(m).Detect(context.Background(), scope)
	if a.GlobalPackages != packages || a.CLIHome != scope.Home {
		t.Errorf("GlobalPackages = %q CLIHome = %q", a.GlobalPackages, a.CLIHome)
	}
	if !slices.Equal(a.PackageRoots, []string{fallback, filepath.Join(filepath.Dir(user), "pkgs"), legacy}) {
		t.Errorf("PackageRoots = %v", a.PackageRoots)
	}
	audit := a.Finish()
	if audit.Status != "partial" || !slices.Contains(audit.Reasons, "path_unresolved") {
		t.Errorf("status = %s reasons = %v", audit.Status, audit.Reasons)
	}
	process := nugetSettings(audit, "")
	want := map[string]string{
		"environment.NUGET_PACKAGES": packages, "environment.HTTPS_PROXY": "https://proxy.example.invalid:8443/",
		"environment.NO_PROXY": "localhost,.example.invalid", "auth_configured": "true", "credential_provider_configured": "true",
	}
	for key, value := range want {
		if process[key] != value {
			t.Errorf("process %s = %q, want %q", key, process[key], value)
		}
	}
	if _, ok := process["environment.NUGET_FALLBACK_PACKAGES"]; ok {
		t.Error("list with a relative entry recorded")
	}
	got := nugetSettings(audit, user)
	want = map[string]string{
		"packageSources.0.name": "nuget.org", "packageSources.0.url": "https://api.nuget.org/v3/index.json", "packageSources.0.enabled": "true",
		"packageSources.1.name": "plain", "packageSources.1.url": "http://plain.example.invalid/v3/index.json", "packageSources.1.enabled": "true", "packageSources.1.allowInsecureConnections": "true",
		"packageSources.2.name": "lab", "packageSources.2.url": "https://lab.example.invalid/v3/index.json", "packageSources.2.enabled": "true", "packageSources.2.disableTLSCertificateValidation": "true",
		"packageSources.3.name": "off", "packageSources.3.url": "http://off.example.invalid/v3/index.json", "packageSources.3.enabled": "false",
		"packageSources.4.name": goRedacted, "packageSources.4.url": `C:\feeds\local`, "packageSources.4.enabled": "true",
		"packageSources.5.name": "rel", "packageSources.5.url": filepath.Join(filepath.Dir(user), "..", "shared", "feed"), "packageSources.5.enabled": "true",
		"packageSources.6.name": "elsewhere", "packageSources.6.enabled": "false",
		"packageSourceMapping.0.source": "nuget.org", "packageSourceMapping.0.pattern": "*",
		"packageSourceMapping.1.source": "lab", "packageSourceMapping.1.pattern": "Contoso.*", "packageSourceMapping.2.source": "lab", "packageSourceMapping.2.pattern": "Fabrikam",
		"fallbackPackageFolders.0.path": fallback,
		"config.globalPackagesFolder":   filepath.Join(filepath.Dir(user), "pkgs"), "config.repositoryPath": legacy,
		"config.http_proxy": "http://proxy.example.invalid:8080", "config.no_proxy": "localhost",
		"config.signatureValidationMode": "require", "config.maxHttpRequestsPerSource": "16",
		"trustedSigners.0.type": "author", "trustedSigners.0.allowUntrustedRoot": "true",
		"trustedSigners.1.type": "repository", "trustedSigners.1.allowUntrustedRoot": "false",
		"auth_configured": "true",
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected setting %s = %q", key, got[key])
		}
	}
	codes := []string{}
	for _, f := range audit.Findings {
		codes = append(codes, f.Code+":"+f.Key)
	}
	if !slices.Equal(codes, []string{"nuget-001:packageSources.1.url", "nuget-002:packageSources.2.disableTLSCertificateValidation"}) {
		t.Errorf("findings = %v", codes)
	}
	wantRegistries := []string{`C:\feeds\local`, filepath.Join(filepath.Dir(user), "..", "shared", "feed"), "http://off.example.invalid/v3/index.json", "http://plain.example.invalid/v3/index.json", "https://api.nuget.org/v3/index.json", "https://lab.example.invalid/v3/index.json"}
	slices.Sort(wantRegistries)
	if audit.SourceCount != 2 || !slices.Equal(audit.ObservedRegistries, wantRegistries) || !slices.Equal(audit.ObservedProxies, []string{"http://proxy.example.invalid:8080", "https://proxy.example.invalid:8443/"}) ||
		audit.FindingCount != 2 || audit.FindingCodeCounts["nuget-001"] != 1 || audit.FindingCounts["HIGH"] != 1 || audit.ObservedRegistryCount != 6 || audit.ObservedProxyCount != 2 {
		t.Errorf("summary = %+v", audit)
	}
	if data := string(mustJSON(t, audit)); strings.Contains(data, "CANARY_") && !strings.Contains(data, "CANARY_DIR") || strings.Count(data, "CANARY_") != 1 {
		t.Errorf("audit leaked a secret: %s", data)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Only a literal password in the file is a cleartext finding; a %VARIABLE%
// reference, an empty value and an encrypted password keep presence only.
func TestNuGetConfigCredentialFinding(t *testing.T) {
	tests := []struct {
		name, credentials string
		finding           bool
	}{
		{"literal password", `<add key="Username" value="alice" /><add key="ClearTextPassword" value="CANARY_LITERAL" />`, true},
		{"mixed literal and reference", `<add key="ClearTextPassword" value="CANARY_%NUGET_TOKEN%" />`, true},
		{"environment reference", `<add key="Username" value="alice" /><add key="ClearTextPassword" value="%NUGET_TOKEN%" />`, false},
		{"empty value", `<add key="ClearTextPassword" value="" />`, false},
		{"encrypted password", `<add key="Username" value="alice" /><add key="Password" value="CANARY_ENCRYPTED" />`, false},
		{"provider only", `<add key="ValidAuthenticationTypes" value="basic" />`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := nugetConfigTest(t)
			path := filepath.Join(scope.Home, ".nuget", "NuGet", "NuGet.Config")
			m.SetFile(path, []byte(`<configuration><packageSources><add key="internal" value="https://feed.example.invalid/v3/index.json" /></packageSources><packageSourceCredentials><internal>`+tc.credentials+`</internal></packageSourceCredentials></configuration>`))
			audit := NewNuGetConfigDetector(m).Detect(context.Background(), scope).Finish()
			got := nugetSettings(audit, path)
			if got["auth_configured"] != "true" || len(got) != 4 {
				t.Errorf("settings = %v", got)
			}
			found := slices.ContainsFunc(audit.Findings, func(f model.CargoConfigFinding) bool {
				return f.Code == "nuget-003" && f.Key == "auth_configured" && f.Severity == "MEDIUM"
			})
			if found != tc.finding || len(audit.Findings) != audit.FindingCount {
				t.Errorf("nuget-003 reported = %v, want %v (%+v)", found, tc.finding, audit.Findings)
			}
			if strings.Contains(string(mustJSON(t, audit)), "CANARY_") {
				t.Error("credential text leaked")
			}
		})
	}
}

func TestNuGetConfigPrecedenceAndContexts(t *testing.T) {
	m, scope := nugetConfigTest(t)
	fallback := filepath.Join(scope.Home, "fallback")
	userDir := filepath.Join(scope.Home, ".nuget", "NuGet")
	primary := filepath.Join(userDir, "NuGet.Config")
	alt := filepath.Join(scope.Home, ".config", "NuGet", "NuGet.Config")
	extra := filepath.Join(userDir, "config", "zextra.config")
	additional := filepath.Join(userDir, "config", "additional.config")
	machine := filepath.Join("/etc/opt/NuGet/Config", "machine.config")
	for _, p := range []string{primary, alt, extra, additional, machine} {
		m.SetFile(p, []byte(`<configuration><packageSources><add key="`+filepath.Base(filepath.Dir(p))+`" value="https://`+strings.TrimSuffix(filepath.Base(p), ".config")+`.example.invalid/v3/index.json" /></packageSources></configuration>`))
	}
	m.SetDirEntries(filepath.Join(userDir, "config"), []os.DirEntry{executor.MockDirEntry("zextra.config", false), executor.MockDirEntry("additional.config", false), executor.MockDirEntry("notes.txt", false), executor.MockDirEntry("sub", true)})
	m.SetDirEntries("/etc/opt/NuGet/Config", []os.DirEntry{executor.MockDirEntry("machine.config", false)})
	project := filepath.Join(scope.Home, "src", "app")
	m.SetFile(filepath.Join(scope.Home, "src", "nuget.config"), []byte(`<configuration><config><add key="repositoryPath" value="packages" /></config></configuration>`))
	m.SetFile(filepath.Join(project, "NuGet.Config"), []byte(`<configuration/>`))
	a := NewNuGetConfigDetector(m).Detect(context.Background(), scope)
	record := a.ProjectFile(filepath.Join(project, "App.csproj"), "read", nil, map[string]string{"NuGetAudit": "false", "NuGetAuditLevel": "High", "RestorePackagesPath": "$(MSBuildProjectDirectory)/pkgs", "NuGetLockFilePath": "locks/packages.lock.json", "RestoreFallbackFolders": fallback + ";../shared"}, project)
	// A shared file keeps only paths anchored to itself; consumer-relative ones wait for each consumer.
	shared := a.ProjectFile(filepath.Join(scope.Home, "src", "Directory.Build.props"), "read", nil, map[string]string{"RestorePackagesPath": "packages", "NuGetLockFilePath": "$(MSBuildThisFileDirectory)locks/shared.lock.json", "RestoreFallbackFolders": "/opt/fb2;fallback"}, "")
	if len(shared.Settings) != 1 || shared.Settings[0].Key != "project.NuGetLockFilePath" || shared.Settings[0].Display != filepath.Join(scope.Home, "src", "locks", "shared.lock.json") {
		t.Errorf("shared file settings = %+v", shared.Settings)
	}
	paths := a.Ambient(project, record)
	a.Restore(filepath.Join(project, "obj", "project.assets.json"), project, []string{filepath.Join(project, "NuGet.Config"), primary, "relative.config"})
	audit := a.Finish()
	if paths.Repository != filepath.Join(scope.Home, "src", "packages") {
		t.Errorf("Repository = %q", paths.Repository)
	}
	if !slices.Equal(a.PackageRoots, []string{fallback, filepath.Join(scope.Home, "src", "shared"), filepath.Join(project, "pkgs"), filepath.Join(scope.Home, "src", "packages")}) {
		t.Errorf("PackageRoots = %v", a.PackageRoots)
	}
	ids := func(paths ...string) []string {
		out := []string{}
		for _, p := range paths {
			out = append(out, GoSourceID(scope.Username, "nuget_config_"+nugetFile(t, audit, p).Scope, p))
		}
		return out
	}
	process := GoSourceID(scope.Username, "nuget_config_process", "")
	if len(audit.Contexts) != 2 {
		t.Fatalf("contexts = %+v", audit.Contexts)
	}
	ambient, restore := audit.Contexts[0], audit.Contexts[1]
	wantAmbient := append([]string{process}, ids(filepath.Join(project, "App.csproj"), filepath.Join(project, "NuGet.Config"), filepath.Join(scope.Home, "src", "nuget.config"), primary, additional, extra, machine)...)
	if ambient.ContextKind != "ambient" || ambient.Status != "complete" || len(ambient.Reasons) != 0 || !slices.Equal(ambient.ConfigSourceIDs, wantAmbient) {
		t.Errorf("ambient = %+v\nwant %v", ambient, wantAmbient)
	}
	if restore.ContextKind != "restore" || restore.RestoreMetadataPath != filepath.Join(project, "obj", "project.assets.json") || restore.Status != "partial" || !slices.Equal(restore.Reasons, []string{"path_unresolved"}) || !slices.Equal(restore.ConfigSourceIDs, ids(filepath.Join(project, "NuGet.Config"), primary)) {
		t.Errorf("restore = %+v", restore)
	}
	if f := nugetFile(t, audit, alt); f.Scope != "user" || f.Status != "read" || slices.Contains(wantAmbient, f.SourceID) {
		t.Errorf("alternate user file = %+v", f)
	}
	got := nugetSettings(audit, filepath.Join(project, "App.csproj"))
	want := map[string]string{"project.NuGetAudit": "false", "project.NuGetAuditLevel": "high", "project.RestorePackagesPath": filepath.Join(project, "pkgs"), "project.NuGetLockFilePath": filepath.Join(project, "locks", "packages.lock.json"), "project.RestoreFallbackFolders": fallback + ";" + filepath.Join(scope.Home, "src", "shared")}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
	if len(got) != len(want) {
		t.Errorf("project settings = %v", got)
	}
	codes := []string{}
	for _, f := range audit.Findings {
		codes = append(codes, f.Code)
	}
	if !slices.Equal(codes, []string{"nuget-004"}) {
		t.Errorf("findings = %v", codes)
	}
}

// A verified DOTNET_CLI_HOME moves the Unix user profile NuGet reads; Windows
// stays on APPDATA.
func TestNuGetConfigCLIHomeUserConfig(t *testing.T) {
	tests := []struct {
		name, goos string
		want       func(home, cli string) string
	}{
		{"unix follows cli home", "linux", func(_, cli string) string { return filepath.Join(cli, ".nuget", "NuGet", "NuGet.Config") }},
		{"windows keeps appdata", "windows", func(home, _ string) string { return filepath.Join(home, "AppData", "Roaming", "NuGet", "NuGet.Config") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := nugetConfigTest(t)
			m.SetGOOS(tc.goos)
			cli := filepath.Join(scope.Home, "profiles", "cli")
			m.SetEnv("DOTNET_CLI_HOME", cli)
			want := tc.want(scope.Home, cli)
			m.SetFile(want, []byte(`<configuration><packageSources><add key="cli" value="https://cli.example.invalid/v3/index.json" /></packageSources></configuration>`))
			a := NewNuGetConfigDetector(m).Detect(context.Background(), scope)
			a.Ambient(filepath.Join(scope.Home, "app"))
			audit := a.Finish()
			if a.CLIHome != cli {
				t.Fatalf("CLIHome = %q", a.CLIHome)
			}
			f := nugetFile(t, audit, want)
			if f.Scope != "user" || f.Status != "read" || !slices.Contains(audit.Contexts[0].ConfigSourceIDs, f.SourceID) {
				t.Errorf("user config = %+v", f)
			}
			for _, other := range audit.Files {
				if other.Scope == "user" && other.Status == "read" && other.Path != want {
					t.Errorf("unexpected user config read: %+v", other)
				}
			}
		})
	}
}

func TestNuGetConfigUnverifiedProcessAndFailedSources(t *testing.T) {
	m, scope := nugetConfigTest(t)
	scope.ProcessVerified = false
	m.SetEnv("NUGET_PACKAGES", "/srv/CANARY_DIR")
	m.SetEnv("NuGetPackageSourceCredentials_x", "CANARY")
	user := filepath.Join(scope.Home, ".nuget", "NuGet", "NuGet.Config")
	m.SetFile(user, []byte(`<!DOCTYPE configuration [<!ENTITY x SYSTEM "file:///etc/passwd">]><configuration>&x;</configuration>`))
	a := NewNuGetConfigDetector(m).Detect(context.Background(), scope)
	paths := a.Ambient(filepath.Join(scope.Home, "app"))
	audit := a.Finish()
	if a.GlobalPackages != filepath.Join(scope.Home, ".nuget", "packages") || !paths.Partial {
		t.Errorf("GlobalPackages = %q partial = %v", a.GlobalPackages, paths.Partial)
	}
	if f := nugetFile(t, audit, ""); f.Status != "unsupported" || !slices.Equal(f.Reasons, []string{"process_context_unverified"}) || len(f.Settings) != 0 {
		t.Errorf("process file = %+v", f)
	}
	if f := nugetFile(t, audit, user); f.Status != "unreadable" || !slices.Equal(f.Reasons, []string{"parse_error"}) || len(f.Settings) != 0 {
		t.Errorf("invalid file = %+v", f)
	}
	if c := audit.Contexts[0]; c.Status != "partial" || !slices.Equal(c.Reasons, []string{"parse_error", "process_context_unverified"}) || strings.Contains(string(mustJSON(t, audit)), "CANARY") {
		t.Errorf("audit = %s", mustJSON(t, audit))
	}
}

func TestNuGetConfigBoundedAudit(t *testing.T) {
	m, scope := nugetConfigTest(t)
	old := maxNuGetAuditBytes
	maxNuGetAuditBytes = 256
	t.Cleanup(func() { maxNuGetAuditBytes = old })
	a := NewNuGetConfigDetector(m).Detect(context.Background(), scope)
	a.Ambient(filepath.Join(scope.Home, "app"))
	audit := a.Finish()
	if audit.Status != "partial" || !slices.Contains(audit.Reasons, "output_size_limit") {
		t.Fatalf("audit overflow = %+v", audit)
	}
}

func TestNuGetConfigInvalidAndIncompleteInputs(t *testing.T) {
	for _, input := range []string{"", " ", `<Project/>`, `<configuration/><configuration/>`, `<configuration/>text`, `<configuration><config><add key="signatureValidationMode" value="invalid"/></config></configuration>`} {
		m, scope := nugetConfigTest(t)
		path := filepath.Join(scope.Home, ".nuget", "NuGet", "NuGet.Config")
		m.SetFile(path, []byte(input))
		a := NewNuGetConfigDetector(m).Detect(t.Context(), scope)
		a.Ambient(scope.Home)
		a.Restore(filepath.Join(scope.Home, "obj", "project.assets.json"), scope.Home, []string{path})
		audit := a.Finish()
		if f := nugetFile(t, audit, path); f.Status != "unreadable" || len(f.Settings) != 0 || !slices.Contains(f.Reasons, "parse_error") {
			t.Errorf("input %q: %+v", input, f)
		}
		for _, c := range audit.Contexts {
			if c.Status != "partial" || !slices.Contains(c.Reasons, "parse_error") {
				t.Errorf("input %q: %+v", input, c)
			}
		}
	}
	m, scope := nugetConfigTest(t)
	entries := make([]os.DirEntry, nugetSettingLimit+1)
	for i := range entries {
		entries[i] = executor.MockDirEntry("extra.config", false)
	}
	m.SetDirEntries(filepath.Join(scope.Home, ".nuget", "NuGet", "config"), entries)
	a := NewNuGetConfigDetector(m).Detect(t.Context(), scope)
	a.Ambient(scope.Home)
	a.Restore(filepath.Join(scope.Home, "obj", "project.assets.json"), scope.Home, nil)
	for _, c := range a.Finish().Contexts {
		if c.Status != "partial" || !slices.Contains(c.Reasons, "entry_limit") {
			t.Errorf("truncated config selection: %+v", c)
		}
	}
}
