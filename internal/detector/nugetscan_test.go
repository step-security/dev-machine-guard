package detector

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Valid base64 SHA-512 values: 64 zero or 0x41 bytes.
const (
	nugetHashA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	nugetHashB = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="
)

func nugetTestScanner(t *testing.T, home string) (*NuGetScanner, *composerTrap) {
	t.Helper()
	x := &composerTrap{goTrap: &goTrap{Executor: executor.NewReal(), t: t, current: goTestTarget(home)}, env: map[string]string{}, denied: map[string]error{}, reads: map[string]int{}, readErrors: map[string]error{}}
	s := NewNuGetScanner(x, progress.NewNoop())
	s.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(string) string { return "" }, func(string) bool { return false }
	}
	return s, x
}

// nugetJSONPath escapes native paths embedded in receipt fixtures.
func nugetJSONPath(path string) string {
	data, _ := json.Marshal(path)
	return string(data[1 : len(data)-1])
}

func nugetTestToolName(name string) string {
	if runtime.GOOS == model.PlatformWindows {
		return name + ".exe"
	}
	return name
}

func nugetNuspec(id, version string) string {
	return `<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>` + id + `</id><version>` + version + `</version></metadata></package>`
}

func nugetArchive(t *testing.T, nuspec string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("Archived.nuspec")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte(nuspec))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// nugetWriteFixture lays out every evidence kind under home: a central-managed
// project with restore graph and lock, a legacy project, caches with each
// marker shape, global and local tools, a template receipt, a runtime
// manifest and file-based scripts. Secrets are canaries that must never appear.
func nugetWriteFixture(t *testing.T, home, root string) {
	t.Helper()
	app := filepath.Join(root, "app")
	packages := filepath.Join(home, ".nuget", "packages")
	userConfigDir := filepath.Join(home, ".nuget", "NuGet")
	if runtime.GOOS == model.PlatformWindows {
		userConfigDir = filepath.Join(home, "AppData", "Roaming", "NuGet")
	}
	goWrite(t, filepath.Join(root, "Directory.Build.props"), `<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`, 0o600)
	goWrite(t, filepath.Join(root, "Directory.Packages.props"), `<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally><NuGetAuditMode>all</NuGetAuditMode></PropertyGroup><ItemGroup><PackageVersion Include="Central" Version="1.0.0" /><GlobalPackageReference Include="Analyzer" Version="2.0.0" /></ItemGroup></Project>`, 0o600)
	goWrite(t, filepath.Join(app, "App.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
    <NuGetAudit>false</NuGetAudit>
    <RestoreLockedMode>true</RestoreLockedMode>
    <RestorePackagesPath>$(UnknownProperty)/packages</RestorePackagesPath>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" PrivateAssets="all" />
    <PackageReference Include="Central" />
    <PackageReference Include="Missing" />
    <PackageReference Include="Expr" Version="$(JsonVersion)" />
    <PackageDownload Include="Downloaded" Version="[1.0.0]" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net8.0'">
    <PackageReference Include="Conditional" Version="1.0.0-Beta" />
  </ItemGroup>
</Project>`, 0o600)
	goWrite(t, filepath.Join(app, "Program.cs"), "#:package Ignored@1.0.0\nSystem.Console.WriteLine();\n", 0o600)
	goWrite(t, filepath.Join(app, "packages.lock.json"), `{"version":3,"net8.0":{"framework":".NETCoreApp,Version=v8.0","dependencies":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1","contentHash":"`+nugetHashA+`"},"Transitive.Dep":{"type":"Transitive","resolved":"2.0.0","contentHash":"not-base64"},"App":{"type":"Project"}}}}`, 0o600)
	goWrite(t, filepath.Join(app, "obj", "project.assets.json"), `{"version":3,"targets":{"net8.0":{"Newtonsoft.Json/13.0.1":{"type":"package"},"Transitive.Dep/2.0.0":{"type":"package"},"App/1.0.0":{"type":"project"}},"net8.0/linux-x64":{"Newtonsoft.Json/13.0.1":{"type":"package"}}},"libraries":{"Newtonsoft.Json/13.0.1":{"sha512":"`+nugetHashA+`","type":"package","path":"newtonsoft.json/13.0.1"},"Transitive.Dep/2.0.0":{"sha512":"`+nugetHashB+`","type":"package","path":"transitive.dep/2.0.0"},"App/1.0.0":{"type":"project"}},"packageFolders":{"`+nugetJSONPath(packages)+`":{}},"project":{"restore":{"projectPath":"`+nugetJSONPath(filepath.Join(app, "App.csproj"))+`","packagesPath":"`+nugetJSONPath(packages)+`","configFilePaths":["`+nugetJSONPath(filepath.Join(app, "NuGet.Config"))+`","`+nugetJSONPath(filepath.Join(root, "NuGet.Config"))+`"]},"frameworks":{"net8.0":{"targetAlias":"net8.0","framework":".NETCoreApp,Version=v8.0","dependencies":{"Newtonsoft.Json":{"version":"[13.0.1, )"}}}}}}`, 0o600)
	goWrite(t, filepath.Join(app, "bin", "Debug", "net8.0", "App.deps.json"), `{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"targets":{},"libraries":{"App/1.0.0":{"type":"project"},"Newtonsoft.Json/13.0.1":{"type":"package","sha512":"sha512-`+nugetHashA+`","path":"newtonsoft.json/13.0.1"}}}`, 0o600)
	goWrite(t, filepath.Join(app, "NuGet.Config"), `<?xml version="1.0"?><configuration>
  <packageSources>
    <clear />
    <add key="CANARY_SOURCE_KEY@internal" value="http://user:CANARY_PASSWORD@feed.example.invalid/v3/index.json?CANARY_QUERY" />
    <add key="local" value="../feed" />
    <add key="off" value="https://off.example.invalid/v3/index.json" />
  </packageSources>
  <disabledPackageSources><add key="off" value="true" /><add key="elsewhere" value="true" /></disabledPackageSources>
  <packageSourceMapping><packageSource key="local"><package pattern="Example.*" /></packageSource></packageSourceMapping>
  <packageSourceCredentials><internal><add key="Username" value="CANARY_USER" /><add key="ClearTextPassword" value="CANARY_PASSWORD" /></internal></packageSourceCredentials>
  <config><add key="http_proxy" value="http://user:CANARY_PASSWORD@proxy.example.invalid:8080" /><add key="signatureValidationMode" value="require" /><add key="maxHttpRequestsPerSource" value="8" /></config>
</configuration>`, 0o600)
	legacy := filepath.Join(root, "legacy")
	goWrite(t, filepath.Join(legacy, "packages.config"), `<?xml version="1.0"?><packages><package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" developmentDependency="true" /><package id="Absent.Legacy" version="1.0.0" /><package id="Empty.Legacy" version="1.0.0" /></packages>`, 0o600)
	goWrite(t, filepath.Join(legacy, "packages", "Newtonsoft.Json.13.0.1", "Newtonsoft.Json.13.0.1.nuspec"), nugetNuspec("Newtonsoft.Json", "13.0.1"), 0o600)
	goMkdir(t, filepath.Join(legacy, "packages", "Empty.Legacy.1.0.0"))
	goWrite(t, filepath.Join(root, "tools", ".config", "dotnet-tools.json"), `{"version":1,"isRoot":true,"tools":{"dotnet-format":{"version":"8.0.0","commands":["dotnet-format"]},"unresolved-tool":{"version":"1.0.0","commands":["unresolved"]}}}`, 0o600)
	goWrite(t, filepath.Join(root, "scripts", "app.cs"), "#:sdk Microsoft.NET.Sdk.Web\n#:sdk Aspire.AppHost.Sdk@9.0.0\n#:package Humanizer@2.14.1\nSystem.Console.WriteLine();\n", 0o600)
	goWrite(t, filepath.Join(root, "scripts", "script.fsx"), "#r \"nuget: FSharp.Data, 6.3.0\"\nlet x = 1\n", 0o600)
	goWrite(t, filepath.Join(root, "scripts", "plain.cs"), "System.Console.WriteLine();\n", 0o600)
	goWrite(t, filepath.Join(root, "scripts", "NuGet.Config"), `<configuration><packageSources><add key="scripts" value="http://scripts.example.invalid/v3/index.json" /></packageSources><config><add key="globalPackagesFolder" value="`+filepath.Join(home, "scriptcache")+`" /></config></configuration>`, 0o600)
	goWrite(t, filepath.Join(home, "scriptcache", "example.cached", "1.0.0", "example.cached.nuspec"), nugetNuspec("Example.Cached", "1.0.0"), 0o600)
	goWrite(t, filepath.Join(home, "scriptcache", "example.cached", "1.0.0", ".nupkg.metadata"), `{"version":2,"contentHash":"`+nugetHashB+`","source":"https://api.nuget.org/v3/index.json"}`, 0o600)
	goWrite(t, filepath.Join(root, "orphan", "obj", "project.assets.json"), `{"version":3,"targets":{"net8.0":{"Orphaned/1.0.0":{"type":"package"}}},"libraries":{"Orphaned/1.0.0":{"sha512":"`+nugetHashB+`","type":"package","path":"orphaned/1.0.0"}},"packageFolders":{"`+nugetJSONPath(packages)+`":{}},"project":{"restore":{"projectPath":"`+nugetJSONPath(filepath.Join(root, "gone", "Gone.csproj"))+`"}}}`, 0o600)
	// Pack output beside a project is still a project; an extracted package is not.
	goWrite(t, filepath.Join(root, "packed", "Packed.1.0.0.nupkg"), "", 0o600)
	goWrite(t, filepath.Join(root, "packed", "Packed.csproj"), `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><RestorePackagesPath>pkgs</RestorePackagesPath></PropertyGroup></Project>`, 0o600)
	goWrite(t, filepath.Join(root, "packed", "Directory.Build.targets"), `<Project><PropertyGroup><NuGetAudit>false</NuGetAudit></PropertyGroup></Project>`, 0o600)
	goWrite(t, filepath.Join(root, "packed", "pkgs", "custom.pkg", "1.0.0", "custom.pkg.nuspec"), nugetNuspec("Custom.Pkg", "1.0.0"), 0o600)
	goWrite(t, filepath.Join(root, "packed", "pkgs", "custom.pkg", "1.0.0", ".nupkg.metadata"), `{"version":1,"contentHash":"`+nugetHashA+`"}`, 0o600)
	// A shared build file: its reference stays unparsed (coverage partial), and
	// its relative cache path belongs to the consuming project, not the file.
	goWrite(t, filepath.Join(root, "shared", "Directory.Build.props"), `<Project><PropertyGroup><RestorePackagesPath>packages</RestorePackagesPath><NuGetLockFilePath>$(MSBuildThisFileDirectory)locks/shared.lock.json</NuGetLockFilePath></PropertyGroup><ItemGroup><PackageReference Include="Shared.Analyzer" Version="1.0.0" /></ItemGroup></Project>`, 0o600)
	goWrite(t, filepath.Join(root, "shared", "lib", "Lib.csproj"), `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`, 0o600)
	goWrite(t, filepath.Join(root, "shared", "lib", "packages", "shared.cached", "1.0.0", "shared.cached.nuspec"), nugetNuspec("Shared.Cached", "1.0.0"), 0o600)
	goWrite(t, filepath.Join(root, "shared", "lib", "packages", "shared.cached", "1.0.0", ".nupkg.metadata"), `{"version":1,"contentHash":"`+nugetHashA+`"}`, 0o600)
	// An unreadable consumer of the central file leaves its shared declarations unproven.
	goWrite(t, filepath.Join(root, "corrupt", "Corrupt.csproj"), `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>`, 0o600)
	goWrite(t, filepath.Join(root, "extracted", "Extracted.1.0.0.nupkg"), "", 0o600)
	goWrite(t, filepath.Join(root, "extracted", "content", "Sample.csproj"), `<Project Sdk="Microsoft.NET.Sdk"/>`, 0o600)
	goWrite(t, filepath.Join(packages, "newtonsoft.json", "13.0.1", "newtonsoft.json.nuspec"), nugetNuspec("Newtonsoft.Json", "13.0.1"), 0o600)
	goWrite(t, filepath.Join(packages, "newtonsoft.json", "13.0.1", ".nupkg.metadata"), `{"version":2,"contentHash":"`+nugetHashA+`","source":"https://user:CANARY_PASSWORD@api.nuget.org/v3/index.json?CANARY_QUERY"}`, 0o600)
	goWrite(t, filepath.Join(packages, "newtonsoft.json", "13.0.1", "newtonsoft.json.13.0.1.nupkg.sha512"), nugetHashB+"\n", 0o600)
	goWrite(t, filepath.Join(packages, "transitive.dep", "2.0.0", "transitive.dep.nuspec"), nugetNuspec("Transitive.Dep", "2.0.0"), 0o600)
	goWrite(t, filepath.Join(packages, "transitive.dep", "2.0.0", ".nupkg.metadata"), `{"version":2,"contentHash":"`+nugetHashB+`","source":"`+nugetJSONPath(filepath.Join(home, "feed"))+`"}`, 0o600)
	goWrite(t, filepath.Join(packages, "archived", "2.0.0", "archived.2.0.0.nupkg"), nugetArchive(t, nugetNuspec("Archived", "2.0.0")), 0o600)
	goWrite(t, filepath.Join(packages, "archived", "2.0.0", ".nupkg.metadata"), `{"version":1,"contentHash":"`+nugetHashB+`"}`, 0o600)
	goWrite(t, filepath.Join(packages, "mismatch", "1.0.0", "mismatch.nuspec"), nugetNuspec("Other", "1.0.0"), 0o600)
	goWrite(t, filepath.Join(packages, "bare", "1.0.0", "bare.nuspec"), nugetNuspec("Bare", "1.0.0"), 0o600)
	goWrite(t, filepath.Join(userConfigDir, "NuGet.Config"), `<configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" /><add key="lab" value="https://lab.example.invalid/v3/index.json" disableTLSCertificateValidation="true" allowInsecureConnections="false" /></packageSources><config><add key="http_proxy.password" value="CANARY_PASSWORD" /></config></configuration>`, 0o600)
	goWrite(t, filepath.Join(userConfigDir, "config", "signers.config"), `<configuration><trustedSigners><author name="CANARY_AUTHOR"><certificate fingerprint="CANARY_FINGERPRINT" hashAlgorithm="SHA256" allowUntrustedRoot="true" /></author><repository name="nuget.org" serviceIndex="https://api.nuget.org/v3/index.json"><certificate fingerprint="x" hashAlgorithm="SHA256" allowUntrustedRoot="false" /></repository></trustedSigners></configuration>`, 0o600)
	store := filepath.Join(home, ".dotnet", "tools", ".store")
	goWrite(t, filepath.Join(store, "dotnet-format", "8.0.0", "project.assets.json"), `{"version":3,"targets":{".NETCoreApp,Version=v8.0/any":{"dotnet-format/8.0.0":{"type":"package"},"Humanizer/2.14.1":{"type":"package"}}},"libraries":{"dotnet-format/8.0.0":{"sha512":"`+nugetHashA+`","type":"package","path":"dotnet-format/8.0.0"},"Humanizer/2.14.1":{"sha512":"`+nugetHashB+`","type":"package","path":"humanizer/2.14.1"}},"packageFolders":{"`+nugetJSONPath(store)+`":{}}}`, 0o600)
	goWrite(t, filepath.Join(store, "dotnet-format", "8.0.0", "dotnet-format", "8.0.0", "tools", "net8.0", "any", "DotnetToolSettings.xml"), `<DotNetCliTool Version="1"><Commands><Command Name="dotnet-format" EntryPoint="dotnet-format.dll" Runner="dotnet" /></Commands></DotNetCliTool>`, 0o600)
	goWrite(t, filepath.Join(store, ".stage", "ignored"), "", 0o600)
	goWrite(t, filepath.Join(home, ".dotnet", "tools", nugetTestToolName("dotnet-format")), "#!/bin/sh\n", 0o700)
	// A RID-specific tool: the SDK 10 pointer receipt plus the payload receipt
	// that names the platform package holding the commands.
	goWrite(t, filepath.Join(store, "example.ridcli", "1.0.0", "project.assets.json"), `{"version":3,"targets":{"net10.0/osx-arm64":{"Example.RidCli/1.0.0":{"type":"package"}}},"libraries":{},"packageFolders":{"`+nugetJSONPath(store)+`":{}}}`, 0o600)
	goWrite(t, filepath.Join(store, "example.ridcli", "1.0.0", "project.assets.ridpackage.json"), `{"version":3,"targets":{"net10.0/osx-arm64":{"Example.RidCli.osx-arm64/1.0.0":{"type":"package"}}},"libraries":{},"packageFolders":{"`+nugetJSONPath(store)+`":{}}}`, 0o600)
	goWrite(t, filepath.Join(store, "example.ridcli", "1.0.0", "Example.RidCli.osx-arm64", "1.0.0", "tools", "net10.0", "osx-arm64", "DotnetToolSettings.xml"), `<DotNetCliTool Version="1"><Commands><Command Name="ridcli" EntryPoint="ridcli" Runner="executable" /></Commands></DotNetCliTool>`, 0o600)
	goWrite(t, filepath.Join(home, ".dotnet", "tools", nugetTestToolName("ridcli")), "#!/bin/sh\n", 0o700)
	goWrite(t, filepath.Join(home, ".dotnet", "toolResolverCache", "1", "dotnet-format"), `[{"Version":"8.0.0","TargetFramework":"net8.0","RuntimeIdentifier":"any","Name":"dotnet-format","PathToExecutable":"`+nugetJSONPath(filepath.Join(packages, "dotnet-format", "8.0.0", "tools", "net8.0", "any", "dotnet-format.dll"))+`"}]`, 0o600)
	goWrite(t, filepath.Join(home, ".templateengine", "packages", "Example.Templates.1.0.0.nupkg"), nugetArchive(t, nugetNuspec("Example.Templates", "1.0.0")), 0o600)
	goWrite(t, filepath.Join(home, ".templateengine", "packages", "Broken.Templates.1.0.0.nupkg"), "", 0o600)
	goWrite(t, filepath.Join(home, ".templateengine", "packages", "Mismatch.Templates.1.0.0.nupkg"), nugetArchive(t, nugetNuspec("Other.Templates", "1.0.0")), 0o600)
	goWrite(t, filepath.Join(home, ".templateengine", "packages.json"), `{"Packages":[{"MountPointUri":"`+nugetJSONPath(filepath.Join(home, ".templateengine", "packages", "Example.Templates.1.0.0.nupkg"))+`","Details":{"PackageId":"Example.Templates","Version":"1.0.0","NuGetSource":"https://api.nuget.org/v3/index.json"}},{"MountPointUri":"`+nugetJSONPath(filepath.Join(home, ".templateengine", "packages", "Broken.Templates.1.0.0.nupkg"))+`","Details":{"PackageId":"Broken.Templates","Version":"1.0.0","NuGetSource":""}},{"MountPointUri":"`+nugetJSONPath(filepath.Join(home, ".templateengine", "packages", "Mismatch.Templates.1.0.0.nupkg"))+`","Details":{"PackageId":"Mismatch.Templates","Version":"1.0.0","NuGetSource":""}}]}`, 0o600)
}

func nugetFixtureEnv(x *composerTrap) {
	x.env["HTTPS_PROXY"] = "https://user:CANARY_PASSWORD@proxy.example.invalid:8443/?CANARY_QUERY"
	x.env["NO_PROXY"] = "localhost,.example.invalid"
	x.env["NuGetPackageSourceCredentials_internal"] = "Username=CANARY_USER;Password=CANARY_PASSWORD"
	x.env["NUGET_PLUGIN_PATHS"] = "/opt/CANARY_PLUGIN"
}

func nugetAssertRefs(t *testing.T, inv *model.NuGetInventory, audit *model.NuGetConfigAudit) {
	t.Helper()
	ids := map[string]bool{}
	for _, s := range inv.Sources {
		if ids[s.SourceID] {
			t.Error("duplicate source")
		}
		ids[s.SourceID] = true
	}
	ref := func(id string) {
		if !ids[id] {
			t.Errorf("dangling inventory source %s", id)
		}
	}
	for _, s := range inv.Sources {
		if s.ParentSourceID != "" {
			ref(s.ParentSourceID)
		}
		for _, id := range s.DiscoveredSources {
			ref(id)
		}
	}
	for _, p := range inv.Packages {
		ref(p.SourceID)
		for _, hash := range p.RecordedChecksums {
			ref(hash.SourceID)
		}
	}
	for _, p := range inv.Projects {
		ref(p.ManifestSourceID)
	}
	files := map[string]bool{}
	for _, f := range audit.Files {
		files[f.SourceID] = true
	}
	for _, c := range audit.Contexts {
		for _, id := range c.ConfigSourceIDs {
			if !files[id] {
				t.Error("dangling config context")
			}
		}
	}
	for _, f := range audit.Findings {
		if !files[f.SourceID] {
			t.Error("dangling finding")
		}
	}
	for _, v := range []any{inv, audit} {
		data, _ := json.Marshal(v)
		if bytes.Contains(data, []byte(":null")) {
			t.Fatal("null array")
		}
		if bytes.Contains(data, []byte("CANARY_")) {
			t.Fatal("output contains a credential canary")
		}
	}
}

func nugetSource(t *testing.T, inv *model.NuGetInventory, kind, path string) model.NuGetSource {
	t.Helper()
	for _, src := range inv.Sources {
		if src.Kind == kind && src.Path == path {
			return src
		}
	}
	t.Fatalf("no %s source for %s", kind, path)
	return model.NuGetSource{}
}

func nugetPackages(inv *model.NuGetInventory, evidence, name string) []model.NuGetPackage {
	var out []model.NuGetPackage
	for _, p := range inv.Packages {
		if p.Evidence == evidence && (name == "" || p.PackageName == name) {
			out = append(out, p)
		}
	}
	return out
}

func nugetProject(t *testing.T, inv *model.NuGetInventory, manifest string) model.NuGetProject {
	t.Helper()
	for _, p := range inv.Projects {
		if p.ManifestPath == manifest {
			return p
		}
	}
	t.Fatalf("no project for %s", manifest)
	return model.NuGetProject{}
}

func TestNuGetScanFixtureEvidence(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	nugetWriteFixture(t, home, root)
	scanner, x := nugetTestScanner(t, home)
	nugetFixtureEnv(x)
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	nugetAssertRefs(t, inv, audit)
	app := filepath.Join(root, "app")
	packages := filepath.Join(home, ".nuget", "packages")

	project := nugetProject(t, inv, filepath.Join(app, "App.csproj"))
	if !slices.Equal(project.TargetFrameworks, []string{"net8.0", "net9.0"}) || project.AssetsPath != filepath.Join(app, "obj", "project.assets.json") || project.LockfilePath != filepath.Join(app, "packages.lock.json") || project.SelectionStatus != "resolved" {
		t.Errorf("project = %+v", project)
	}
	declared := map[string]model.NuGetPackage{}
	for _, p := range nugetPackages(inv, "declared_requirement", "") {
		if p.ProjectPath == app {
			declared[p.PackageName] = p
		}
	}
	if p := declared["newtonsoft.json"]; p.RequestedVersion != "13.0.1" || p.DeclarationKind != "package_reference" || p.PrivateAssets != "all" || p.VersionStatus != "unknown" || p.DependencyRelation != "direct" {
		t.Errorf("package reference = %+v", p)
	}
	if p := declared["central"]; p.RequestedVersion != "1.0.0" {
		t.Errorf("central version not applied: %+v", p)
	}
	if p := declared["missing"]; p.RequestedVersion != "" || !slices.Contains(p.Reasons, "context_unresolved") {
		t.Errorf("missing version = %+v", p)
	}
	if p := declared["expr"]; p.RequestedVersion != "" || !slices.Contains(p.Reasons, "context_unresolved") {
		t.Errorf("property expression leaked: %+v", p)
	}
	if p := declared["downloaded"]; p.Version != "" || p.VersionStatus != "unknown" || p.RequestedVersion != "[1.0.0]" || p.DeclarationKind != "package_download" {
		t.Errorf("package download = %+v", p)
	}
	if p := declared["conditional"]; !p.Conditional || p.RequestedVersion != "1.0.0-Beta" {
		t.Errorf("conditional = %+v", p)
	}
	if _, ok := declared["microsoft.net.sdk"]; ok {
		t.Error("SDK without an explicit version recorded as a declaration")
	}
	if p := declared["analyzer"]; p.DeclarationKind != "global_package_reference" || p.SourcePath != filepath.Join(root, "Directory.Packages.props") || p.RequestedVersion != "2.0.0" {
		t.Errorf("global package reference = %+v", p)
	}
	if _, ok := declared["ignored"]; ok {
		t.Error("source file beside a project treated as a file-based app")
	}
	packed := nugetProject(t, inv, filepath.Join(root, "packed", "Packed.csproj"))
	if !slices.Equal(packed.TargetFrameworks, []string{"net8.0"}) || packed.SelectionStatus != "resolved" {
		t.Errorf("Directory.Build.props not layered under packed project: %+v", packed)
	}
	source := func(path string) model.NuGetSource {
		for _, s := range inv.Sources {
			if s.Path == path {
				return s
			}
		}
		t.Fatalf("no source for %s", path)
		return model.NuGetSource{}
	}
	// An unparsed shared reference is partial coverage for the file and its consumer, never absence.
	if lib := nugetProject(t, inv, filepath.Join(root, "shared", "lib", "Lib.csproj")); lib.SelectionStatus != "partial" || lib.LockfilePath != "" {
		t.Errorf("consumer of a deferred shared reference = %+v", lib)
	}
	if s := source(filepath.Join(root, "shared", "lib", "Lib.csproj")); s.Status != "partial" || !slices.Equal(s.Reasons, []string{"unsupported_format"}) {
		t.Errorf("consumer manifest still proves absence of a moved reference: %+v", s)
	}
	if s := source(filepath.Join(root, "shared", "Directory.Build.props")); s.Status != "partial" || !slices.Equal(s.Reasons, []string{"unsupported_format"}) {
		t.Errorf("shared build file = %+v", s)
	}
	if _, ok := declared["shared.analyzer"]; ok {
		t.Error("imported PackageReference emitted without an evaluator")
	}
	// A consumer that cannot be read may still consume the central file's declarations.
	if s := source(filepath.Join(root, "Directory.Packages.props")); s.Status != "partial" || !slices.Equal(s.Reasons, []string{"parse_error"}) {
		t.Errorf("central file with an unreadable consumer = %+v", s)
	}

	locked := nugetPackages(inv, "locked_package", "")
	if len(locked) != 2 {
		t.Fatalf("locked = %+v", locked)
	}
	if p := locked[0]; p.PackageName != "newtonsoft.json" || p.Version != "13.0.1" || p.LockDependencyType != "Direct" || p.DependencyRelation != "direct" || p.FrameworkAlias != "net8.0" || p.ChecksumStatus != "recorded" || p.RecordedChecksums[0].Kind != "content" || p.RecordedChecksums[0].SourceKind != "lockfile" {
		t.Errorf("locked direct = %+v", p)
	}
	if p := locked[1]; p.ChecksumStatus != "partial" || !slices.Contains(p.Reasons, "checksum_invalid") || p.DependencyRelation != "transitive" {
		t.Errorf("locked transitive = %+v", p)
	}

	restored := nugetPackages(inv, "restored_package", "newtonsoft.json")
	var fromAssets []model.NuGetPackage
	for _, p := range restored {
		if p.SourcePath == project.AssetsPath {
			fromAssets = append(fromAssets, p)
		}
	}
	if len(fromAssets) != 2 {
		t.Fatalf("restored newtonsoft rows = %+v", restored)
	}
	for _, p := range fromAssets {
		if p.Scope != "project" || p.ProjectPath != app || p.DependencyRelation != "direct" || p.Origin.Kind != "feed" || p.Origin.URL != "https://api.nuget.org/v3/index.json" || p.Installation == nil || p.Installation.Presence != "present" || p.TargetFramework != ".NETCoreApp,Version=v8.0" {
			t.Errorf("restored = %+v origin = %+v installation = %+v", p, p.Origin, p.Installation)
		}
	}
	if fromAssets[0].RuntimeIdentifier != "" || fromAssets[1].RuntimeIdentifier != "linux-x64" {
		t.Errorf("runtime identifiers = %q %q", fromAssets[0].RuntimeIdentifier, fromAssets[1].RuntimeIdentifier)
	}
	if p := nugetPackages(inv, "restored_package", "transitive.dep"); len(p) != 1 || p[0].DependencyRelation != "transitive" || p[0].Origin.Kind != "local" || p[0].Origin.Path != filepath.Join(home, "feed") {
		t.Errorf("transitive restored = %+v", p)
	}
	if p := nugetPackages(inv, "restored_package", "orphaned"); len(p) != 1 || p[0].Scope != "unknown" || p[0].ProjectPath != filepath.Join(root, "gone") || p[0].DependencyRelation != "unknown" || p[0].Installation == nil || p[0].Installation.Presence != "unknown" {
		t.Errorf("orphan restored = %+v", p)
	}
	for _, name := range []string{"absent.legacy", "empty.legacy"} {
		if p := nugetPackages(inv, "restored_package", name); len(p) != 0 {
			t.Errorf("%s reported as restored without a readable package", name)
		}
	}
	legacy := nugetProject(t, inv, filepath.Join(root, "legacy", "packages.config"))
	if legacy.ProjectKind != "legacy" || legacy.PackagesPath != filepath.Join(root, "legacy", "packages") {
		t.Errorf("legacy project = %+v", legacy)
	}
	if src := nugetSource(t, inv, "legacy_manifest", legacy.ManifestPath); !slices.Equal(src.Reasons, []string{"extraction_incomplete"}) {
		t.Errorf("empty legacy folder not reported: %+v", src)
	}
	var legacyRestored []model.NuGetPackage
	for _, p := range nugetPackages(inv, "restored_package", "newtonsoft.json") {
		if p.SourcePath == legacy.ManifestPath {
			legacyRestored = append(legacyRestored, p)
		}
	}
	if len(legacyRestored) != 1 || legacyRestored[0].Installation.Path != filepath.Join(legacy.PackagesPath, "Newtonsoft.Json.13.0.1") || legacyRestored[0].DevelopmentDependency == nil {
		t.Errorf("legacy restored = %+v", legacyRestored)
	}

	cache := nugetSource(t, inv, "package_cache", packages)
	if cache.Status != "partial" || !slices.Equal(cache.Reasons, []string{"identity_mismatch"}) {
		t.Errorf("cache source = %+v", cache)
	}
	cached := map[string]model.NuGetPackage{}
	for _, p := range nugetPackages(inv, "cached_package", "") {
		cached[p.PackageName] = p
	}
	if len(cached) != 7 {
		t.Errorf("cached = %+v", cached)
	}
	// A shared relative RestorePackagesPath resolves beside the consuming project.
	if p := cached["shared.cached"]; p.Scope != "custom" || p.SourcePath != filepath.Join(root, "shared", "lib", "packages") {
		t.Errorf("cached shared = %+v", p)
	}
	// A cache named only by a script's adjacent NuGet.Config is still read.
	if p := cached["example.cached"]; p.Scope != "custom" || p.SourcePath != filepath.Join(home, "scriptcache") || p.Origin.Kind != "feed" {
		t.Errorf("cached script = %+v", p)
	}
	if p := cached["custom.pkg"]; p.Scope != "custom" || p.SourcePath != filepath.Join(root, "packed", "pkgs") || p.ChecksumStatus != "recorded" {
		t.Errorf("project RestorePackagesPath cache = %+v", p)
	}
	if p := cached["newtonsoft.json"]; p.Scope != "user" || len(p.RecordedChecksums) != 2 || p.RecordedChecksums[0].Kind != "content" || p.RecordedChecksums[1].Kind != "archive" || p.Origin.Kind != "feed" {
		t.Errorf("cached newtonsoft = %+v", p)
	}
	if p := cached["archived"]; p.Version != "2.0.0" || p.Origin.Kind != "unknown" || p.ChecksumStatus != "recorded" {
		t.Errorf("cached archived = %+v", p)
	}
	if p := cached["bare"]; !slices.Contains(p.Reasons, "extraction_incomplete") || p.ChecksumStatus != "not_recorded" {
		t.Errorf("cached bare = %+v", p)
	}

	tools := nugetPackages(inv, "installed_tool", "")
	if len(tools) != 5 {
		t.Fatalf("installed tools = %+v", tools)
	}
	for _, p := range tools {
		switch {
		case p.PackageName == "dotnet-format" && p.Scope == "user":
			if !slices.Equal(p.ToolCommands, []string{"dotnet-format"}) || p.Installation == nil || p.Installation.Presence != "present" || p.Installation.Path != filepath.Join(home, ".dotnet", "tools", nugetTestToolName("dotnet-format")) || p.RuntimeIdentifier != "any" {
				t.Errorf("global tool = %+v", p)
			}
		case p.PackageName == "example.ridcli", p.PackageName == "example.ridcli.osx-arm64":
			if p.DependencyRelation != "direct" || !slices.Equal(p.ToolCommands, []string{"ridcli"}) || p.Installation == nil || p.Installation.Presence != "present" || p.RuntimeIdentifier != "osx-arm64" || p.FrameworkAlias != "net10.0" {
				t.Errorf("rid tool = %+v", p)
			}
		case p.PackageName == "humanizer":
			if p.DependencyRelation != "transitive" || p.ToolCommands != nil {
				t.Errorf("tool dependency = %+v", p)
			}
		case p.PackageName == "dotnet-format" && p.Scope == "project":
			if p.Installation == nil || p.Installation.Presence != "absent" || p.SourcePath != filepath.Join(root, "tools", ".config", "dotnet-tools.json") {
				t.Errorf("local tool = %+v", p)
			}
		default:
			t.Errorf("unexpected tool = %+v", p)
		}
	}
	if p := nugetPackages(inv, "declared_requirement", "unresolved-tool"); len(p) != 1 || p[0].Version != "1.0.0" || p[0].ProjectPath != filepath.Join(root, "tools") {
		t.Errorf("unresolved tool = %+v", p)
	}
	if p := nugetPackages(inv, "installed_template", "example.templates"); len(p) != 1 || p[0].Origin.Kind != "feed" || p[0].Installation == nil || p[0].Installation.Presence != "present" || len(p[0].Reasons) != 0 {
		t.Errorf("template = %+v", p)
	}
	// A receipt without a readable matching archive proves nothing installed.
	if p := nugetPackages(inv, "installed_template", ""); len(p) != 1 {
		t.Errorf("unverified template archives accepted: %+v", p)
	}
	if s := source(filepath.Join(home, ".templateengine", "packages.json")); s.Status != "partial" || !slices.Equal(s.Reasons, []string{"identity_mismatch", "parse_error"}) {
		t.Errorf("template receipt = %+v", s)
	}
	if p := nugetPackages(inv, "binary_dependency", ""); len(p) != 1 || p[0].Scope != "project" || p[0].ProjectPath != app || p[0].ChecksumStatus != "recorded" {
		t.Errorf("binary dependency = %+v", p)
	}
	if p := nugetProject(t, inv, filepath.Join(root, "scripts", "app.cs")); p.ProjectKind != "file_based" {
		t.Errorf("file-based app = %+v", p)
	}
	if p := nugetProject(t, inv, filepath.Join(root, "scripts", "script.fsx")); p.ProjectKind != "fsharp_script" {
		t.Errorf("fsharp script = %+v", p)
	}
	if p := nugetPackages(inv, "declared_requirement", "humanizer"); len(p) != 1 || p[0].RequestedVersion != "2.14.1" {
		t.Errorf("script package = %+v", p)
	}
	if p := nugetPackages(inv, "declared_requirement", "aspire.apphost.sdk"); len(p) != 1 || p[0].DeclarationKind != "msbuild_sdk" || p[0].RequestedVersion != "9.0.0" {
		t.Errorf("versioned script sdk = %+v", p)
	}
	if p := nugetPackages(inv, "declared_requirement", "microsoft.net.sdk.web"); len(p) != 0 {
		t.Error("unversioned #:sdk recorded as a package")
	}
	for _, src := range inv.Sources {
		if strings.HasSuffix(src.Path, "plain.cs") || strings.Contains(src.Path, "extracted") {
			t.Errorf("unexpected source %s", src.Path)
		}
	}

	codes := map[string]int{}
	for _, f := range audit.Findings {
		codes[f.Code]++
	}
	if codes["nuget-001"] != 2 || codes["nuget-002"] != 1 || codes["nuget-003"] != 1 || codes["nuget-004"] != 2 {
		t.Errorf("findings = %+v", audit.Findings)
	}
	settings := func(path string) map[string]string {
		out := map[string]string{}
		for _, f := range audit.Files {
			if f.Path == path {
				for _, s := range f.Settings {
					out[s.Key] = s.Display
				}
			}
		}
		return out
	}
	scriptsConfig := configaudit.GoSourceID(goTestTarget(home).Username, "nuget_config_project", filepath.Join(root, "scripts", "NuGet.Config"))
	kinds := map[string]int{}
	for _, c := range audit.Contexts {
		kinds[c.ContextKind]++
		if c.ContextKind == "restore" && (c.RestoreMetadataPath != project.AssetsPath || len(c.ConfigSourceIDs) != 2 || c.Status != "complete" || len(c.Reasons) != 0) {
			t.Errorf("restore context = %+v", c)
		}
		if c.ContextKind == "ambient" && c.ProjectPath == app && (c.ConfigSourceIDs[0] != audit.Files[0].SourceID && audit.Files[0].Scope != "process" || c.Status != "complete") {
			t.Errorf("ambient context = %+v", c)
		}
		if c.ContextKind == "ambient" && c.ProjectPath == filepath.Join(root, "scripts") && !slices.Contains(c.ConfigSourceIDs, scriptsConfig) {
			t.Errorf("script context misses its adjacent config: %+v", c)
		}
		if c.ContextKind == "ambient" && c.ProjectPath == filepath.Join(root, "shared", "lib") && (c.Status != "partial" || !slices.Equal(c.Reasons, []string{"unsupported_format"})) {
			t.Errorf("context over a deferred shared reference = %+v", c)
		}
	}
	// One ambient context per project directory: app, corrupt, legacy, packed, shared/lib, tools, scripts.
	if kinds["restore"] != 1 || kinds["ambient"] != 7 {
		t.Errorf("context kinds = %v", kinds)
	}
	if projectSettings := settings(filepath.Join(app, "App.csproj")); projectSettings["project.NuGetAudit"] != "false" || projectSettings["project.RestoreLockedMode"] != "true" || projectSettings["project.RestorePackagesPath"] != "" || !slices.Contains(audit.Reasons, "path_unresolved") {
		t.Errorf("project settings = %+v reasons = %v", projectSettings, audit.Reasons)
	}
	if got := settings(filepath.Join(root, "packed", "Directory.Build.targets")); got["project.NuGetAudit"] != "false" {
		t.Errorf("Directory.Build.targets settings = %+v", got)
	}
	// Shared paths: $(MSBuildThisFileDirectory) anchors to the file; anything else to each consumer.
	shared, lib := settings(filepath.Join(root, "shared", "Directory.Build.props")), settings(filepath.Join(root, "shared", "lib", "Lib.csproj"))
	if shared["project.RestorePackagesPath"] != "" || shared["project.NuGetLockFilePath"] != filepath.Join(root, "shared", "locks", "shared.lock.json") {
		t.Errorf("shared build file settings = %+v", shared)
	}
	if lib["project.RestorePackagesPath"] != filepath.Join(root, "shared", "lib", "packages") || lib["project.NuGetLockFilePath"] != filepath.Join(root, "shared", "locks", "shared.lock.json") {
		t.Errorf("consumer settings = %+v", lib)
	}
}

func TestNuGetScanUnknownProcessAndDeveloper(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	nugetWriteFixture(t, home, root)
	scanner, x := nugetTestScanner(t, home)
	x.current.Uid = "1001"
	x.env["NUGET_PACKAGES"] = filepath.Join(home, "elsewhere")
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	nugetAssertRefs(t, inv, audit)
	for _, f := range audit.Files {
		if f.Scope == "process" && (f.Status != "unsupported" || !slices.Contains(f.Reasons, "process_context_unverified")) {
			t.Errorf("process file = %+v", f)
		}
	}
	nugetSource(t, inv, "package_cache", filepath.Join(home, ".nuget", "packages"))
	for _, c := range audit.Contexts {
		if c.Status != "partial" || !slices.Contains(c.Reasons, "process_context_unverified") {
			t.Errorf("unverified process left %s context complete: %+v", c.ContextKind, c)
		}
	}
	scanner, x = nugetTestScanner(t, home)
	target := goTestTarget(home)
	target.Uid = "0"
	if x.GOOS() == model.PlatformWindows {
		target.Uid = "S-1-5-18"
	}
	x.current = target
	inv, audit = scanner.Scan(context.Background(), target, []string{root}, nil)
	if inv.Status != "partial" || !slices.Equal(inv.Reasons, []string{"user_unresolved"}) || len(inv.Sources) != 0 || audit.Status != "partial" {
		t.Fatalf("service identity scanned: %+v", inv)
	}
}

func TestNuGetScanLimitsDeadlineAndGuards(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	app := filepath.Join(root, "app")
	nugetWriteFixture(t, home, root)
	scanner, x := nugetTestScanner(t, home)
	nugetFixtureEnv(x)
	full, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	total := len(full.Sources) + len(full.Projects) + len(full.Packages)
	old := maxNuGetRecords
	t.Cleanup(func() { maxNuGetRecords = old })
	script := filepath.Join(root, "scripts", "app.cs")
	// Only script evidence and the cache a script's config names come after
	// the scripts, so everything else is charged before any script is probed.
	beforeScripts := total
	scriptCache := nugetSource(t, full, "package_cache", filepath.Join(home, "scriptcache")).SourceID
	for _, src := range full.Sources {
		if src.Kind == "script_manifest" || src.SourceID == scriptCache {
			beforeScripts--
		}
	}
	for _, p := range full.Projects {
		if p.ProjectKind == "file_based" || p.ProjectKind == "fsharp_script" {
			beforeScripts--
		}
	}
	for _, p := range full.Packages {
		if p.SourceID == scriptCache || p.SourceID == nugetSource(t, full, "script_manifest", script).SourceID || p.SourceID == nugetSource(t, full, "script_manifest", filepath.Join(root, "scripts", "script.fsx")).SourceID {
			beforeScripts--
		}
	}
	owned := nugetOwned(full)
	// Every budget boundary: an assets file queued without a record must not
	// be dereferenced, an exhausted budget must stop script probes, and a
	// source left complete must prove every observation it owns.
	for budget := 1; budget < total; budget++ {
		maxNuGetRecords = budget
		x.reads = map[string]int{}
		inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if inv.Status != "partial" || !slices.Contains(inv.Reasons, "record_limit") || len(inv.Sources)+len(inv.Projects)+len(inv.Packages) > budget {
			t.Fatalf("budget %d: status %s reasons %v", budget, inv.Status, inv.Reasons)
		}
		if budget <= beforeScripts && x.reads[script] > 0 {
			t.Fatalf("budget %d: script read after the record budget was exhausted", budget)
		}
		nugetAssertComplete(t, budget, owned, inv)
		nugetAssertRefs(t, inv, audit)
	}
	maxNuGetRecords = old

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv, audit := scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	nugetAssertRefs(t, inv, audit)
	if inv.Status != "partial" || !slices.Contains(inv.Reasons, "deadline_exceeded") || len(inv.Packages) != 0 {
		t.Fatalf("cancelled scan = %s %v %d packages", inv.Status, inv.Reasons, len(inv.Packages))
	}
	// Cancellation after discovery must not read the queued scripts.
	ctx, cancel = context.WithCancel(context.Background())
	x.reads, x.afterRead = map[string]int{}, func(path string) {
		if path == filepath.Join(app, "obj", "project.assets.json") {
			cancel()
		}
	}
	inv, audit = scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	x.afterRead = nil
	nugetAssertRefs(t, inv, audit)
	if !slices.Contains(inv.Reasons, "deadline_exceeded") || x.reads[script] != 0 || len(nugetPackages(inv, "declared_requirement", "humanizer")) != 0 {
		t.Fatalf("cancelled scan read a script: reasons %v reads %d", inv.Reasons, x.reads[script])
	}

	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if strings.HasPrefix(p, filepath.Join(root, "legacy")) {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	nugetAssertRefs(t, inv, audit)
	if src := nugetSource(t, inv, "project_search_root", root); !slices.Contains(src.Reasons, "skipped_protected") {
		t.Errorf("protected directory not reported: %+v", src)
	}
	for _, p := range inv.Projects {
		if p.ProjectKind == "legacy" {
			t.Error("protected legacy project scanned")
		}
	}

	// An archive that cannot be checked proves nothing installed.
	scanner, x = nugetTestScanner(t, home)
	nugetFixtureEnv(x)
	x.denied[filepath.Join(home, ".templateengine", "packages", "Example.Templates.1.0.0.nupkg")] = os.ErrPermission
	inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	nugetAssertRefs(t, inv, audit)
	if p := nugetPackages(inv, "installed_template", ""); len(p) != 0 {
		t.Errorf("unverified template emitted: %+v", p)
	}
	if src := nugetSource(t, inv, "template_receipt", filepath.Join(home, ".templateengine", "packages.json")); src.Status != "partial" || !slices.Contains(src.Reasons, "permission_denied") {
		t.Errorf("receipt with an unreadable archive = %+v", src)
	}

	// An unreadable script does not prove its previous package evidence gone.
	for _, reason := range []string{"permission_denied", "size_limit"} {
		t.Run("script_"+reason, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "code")
			script := filepath.Join(root, "app.cs")
			scanner, x := nugetTestScanner(t, home)
			content := "#:package Example.Script@1.0.0"
			if reason == "permission_denied" {
				x.readErrors[script] = os.ErrPermission
			} else {
				content += strings.Repeat(" ", int(maxNuGetMetadataBytes))
			}
			goWrite(t, script, content, 0o600)
			inv, audit := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
			nugetAssertRefs(t, inv, audit)
			if src := nugetSource(t, inv, "project_search_root", root); src.Status != "partial" || !slices.Contains(src.Reasons, reason) {
				t.Errorf("unreadable script proves absence: %+v", src)
			}
		})
	}

	// Every output budget keeps admitted records and leaves only fully
	// collected sources complete.
	oldOut := maxNuGetOutputBytes
	t.Cleanup(func() { maxNuGetOutputBytes = oldOut })
	empty := emptyNuGetInventory()
	base, step := goJSONSize(&empty)+(256<<10), goJSONSize(full)/40
	for limit := base; ; limit += step {
		if limit > base+4*goJSONSize(full) {
			t.Fatal("output budget never admitted the full inventory")
		}
		maxNuGetOutputBytes = limit
		inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if !slices.Contains(inv.Reasons, "output_size_limit") {
			break
		}
		if inv.Status != "partial" || goJSONSize(inv)+goJSONSize(audit) > limit {
			t.Fatalf("limit %d: status %s size %d", limit, inv.Status, goJSONSize(inv)+goJSONSize(audit))
		}
		nugetAssertComplete(t, limit, owned, inv)
		nugetAssertRefs(t, inv, audit)
	}
}

// A large tree stops reading once the output budget is spent, without
// discarding the records admitted before it.
func TestNuGetScanOutputBudgetStopsCollection(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	deps := map[string]any{}
	for i := range 120 {
		deps[fmt.Sprintf("Example.Library%03d", i)] = map[string]string{"type": "Direct", "requested": "[1.2.3, )", "resolved": "1.2.3", "contentHash": nugetHashA}
	}
	lock, _ := json.Marshal(map[string]any{"version": 1, "dependencies": map[string]any{"net8.0": deps}})
	for i := range 20 {
		dir := filepath.Join(root, fmt.Sprintf("project%02d", i))
		goWrite(t, filepath.Join(dir, "App.csproj"), `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`, 0o600)
		goWrite(t, filepath.Join(dir, "packages.lock.json"), string(lock), 0o600)
	}
	scanner, x := nugetTestScanner(t, home)
	full, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if len(nugetPackages(full, "locked_package", "")) != 20*120 {
		t.Fatalf("unbounded scan = %d packages", len(full.Packages))
	}
	old := maxNuGetOutputBytes
	maxNuGetOutputBytes = 512 << 10
	t.Cleanup(func() { maxNuGetOutputBytes = old })
	x.reads = map[string]int{}
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	nugetAssertRefs(t, inv, audit)
	if len(inv.Packages) == 0 || !slices.Contains(inv.Reasons, "output_size_limit") || goJSONSize(inv)+goJSONSize(audit) > maxNuGetOutputBytes {
		t.Fatalf("output budget discarded bounded facts or exceeded the limit: %d packages, reasons %v", len(inv.Packages), inv.Reasons)
	}
	if src := nugetSource(t, inv, "project_search_root", root); src.Status != "partial" || !slices.Contains(src.Reasons, "output_size_limit") {
		t.Fatalf("limited discovery root = %+v", src)
	}
	nugetAssertComplete(t, maxNuGetOutputBytes, nugetOwned(full), inv)
	reads := 0
	for path, n := range x.reads {
		if filepath.Base(path) == "packages.lock.json" {
			reads += n
		}
	}
	if reads >= 20 {
		t.Fatal("continued reading lockfiles after the output budget was exhausted")
	}

	// A legacy declaration that spends the budget must not lead to reading its
	// installed package.
	legacy := filepath.Join(home, "legacy")
	goWrite(t, filepath.Join(legacy, "packages.config"), `<?xml version="1.0"?><packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, 0o600)
	nuspec := filepath.Join(legacy, "packages", "Newtonsoft.Json.13.0.1", "Newtonsoft.Json.13.0.1.nuspec")
	goWrite(t, nuspec, nugetNuspec("Newtonsoft.Json", "13.0.1"), 0o600)
	maxNuGetOutputBytes = old
	x.reads = map[string]int{}
	full, _ = scanner.Scan(context.Background(), goTestTarget(home), []string{legacy}, nil)
	if x.reads[nuspec] == 0 || len(nugetPackages(full, "restored_package", "newtonsoft.json")) != 1 {
		t.Fatalf("unbounded legacy scan = %+v", full.Packages)
	}
	empty := emptyNuGetInventory()
	for limit := goJSONSize(&empty) + (256 << 10); ; limit += 16 {
		maxNuGetOutputBytes = limit
		x.reads = map[string]int{}
		inv, audit = scanner.Scan(context.Background(), goTestTarget(home), []string{legacy}, nil)
		nugetAssertRefs(t, inv, audit)
		if !slices.Contains(inv.Reasons, "output_size_limit") {
			break
		}
		if x.reads[nuspec] > 0 && len(nugetPackages(inv, "declared_requirement", "newtonsoft.json")) == 0 {
			t.Fatalf("limit %d: nuspec read after the declaration exhausted the budget", limit)
		}
	}
}

func nugetOwned(inv *model.NuGetInventory) map[string]int {
	owned := map[string]int{}
	for _, p := range inv.Packages {
		owned[p.SourceID]++
	}
	return owned
}

// nugetAssertComplete checks the retirement contract: a source a bounded scan
// leaves complete must still hold everything it holds unbounded.
func nugetAssertComplete(t *testing.T, budget int, owned map[string]int, inv *model.NuGetInventory) {
	t.Helper()
	got := nugetOwned(inv)
	for _, src := range inv.Sources {
		if src.Status == "complete" && got[src.SourceID] != owned[src.SourceID] {
			t.Fatalf("budget %d: complete %s %s holds %d of %d packages", budget, src.Kind, src.Path, got[src.SourceID], owned[src.SourceID])
		}
	}
}

// The last consumer of a central file can exhaust the budget mid-project, with
// no later consumer left to report the shared declarations unproven.
func TestNuGetScanLastConsumerBudget(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	goWrite(t, filepath.Join(root, "Directory.Packages.props"), `<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><GlobalPackageReference Include="Shared.Analyzer" Version="1.0.0" /></ItemGroup></Project>`, 0o600)
	goWrite(t, filepath.Join(root, "app", "App.csproj"), `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`, 0o600)
	goWrite(t, filepath.Join(root, "app", "packages.lock.json"), `{"version":1,"dependencies":{"net8.0":{"Example.Locked":{"type":"Direct","requested":"[1.0.0, )","resolved":"1.0.0","contentHash":"`+nugetHashA+`"}}}}`, 0o600)
	scanner, _ := nugetTestScanner(t, home)
	full, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if len(nugetPackages(full, "declared_requirement", "shared.analyzer")) != 1 {
		t.Fatalf("unbounded scan = %+v", full.Packages)
	}
	owned := nugetOwned(full)
	old := maxNuGetRecords
	t.Cleanup(func() { maxNuGetRecords = old })
	for budget := 1; budget < len(full.Sources)+len(full.Projects)+len(full.Packages); budget++ {
		maxNuGetRecords = budget
		inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		nugetAssertRefs(t, inv, audit)
		nugetAssertComplete(t, budget, owned, inv)
	}
}

func TestNuGetEffectiveAnchorsEachListEntry(t *testing.T) {
	shared := "src"
	file := &nugetProjectFile{properties: map[string]string{"RestoreFallbackFolders": "$(MSBuildThisFileDirectory)cache1;$(MSBuildThisFileDirectory)cache2;rel"}}
	got := nugetEffective(nugetLayer{shared, file}).properties["RestoreFallbackFolders"]
	want := filepath.Join(shared, "cache1") + ";" + filepath.Join(shared, "cache2") + ";rel"
	if got != want {
		t.Errorf("RestoreFallbackFolders = %q, want %q", got, want)
	}
}

func TestNuGetScanDeterministicAndRootDedupe(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	nugetWriteFixture(t, home, root)
	scanner, _ := nugetTestScanner(t, home)
	first, firstAudit := scanner.Scan(context.Background(), goTestTarget(home), []string{root, root, filepath.Join(root, "app")}, nil)
	second, secondAudit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	a, _ := json.Marshal([]any{first, firstAudit})
	b, _ := json.Marshal([]any{second, secondAudit})
	if !bytes.Equal(a, b) {
		t.Fatal("nested or repeated roots changed the inventory")
	}
	if _, err := os.Stat(filepath.Join(home, ".nuget", "packages")); err != nil {
		t.Fatal(err)
	}
}

func TestNuGetScanConfiguredAssets(t *testing.T) {
	for _, name := range []string{"extensions", "intermediate", "artifacts", "relative", "already discovered", "denied", "unreadable props", "missing", "unresolved"} {
		t.Run(name, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "code")
			dir := filepath.Join(root, "app")
			manifest := filepath.Join(dir, "App.csproj")
			output := filepath.Join(home, "external output")
			if name == "already discovered" {
				output = filepath.Join(dir, "obj")
			}
			props := "<MSBuildProjectExtensionsPath>" + output + "</MSBuildProjectExtensionsPath>"
			if name == "intermediate" {
				props = "<BaseIntermediateOutputPath>" + output + "</BaseIntermediateOutputPath>"
			}
			if name == "artifacts" {
				props = "<UseArtifactsOutput>true</UseArtifactsOutput><ArtifactsPath>" + output + "</ArtifactsPath>"
				output = filepath.Join(output, "obj", "App")
			}
			if name == "relative" {
				props = "<BaseIntermediateOutputPath>../../external output</BaseIntermediateOutputPath>"
			}
			if name == "unresolved" {
				props = "<MSBuildProjectExtensionsPath>$(Unknown)/obj</MSBuildProjectExtensionsPath>"
			}
			goWrite(t, filepath.Join(root, "Directory.Build.props"), "<Project><PropertyGroup>"+props+"</PropertyGroup></Project>", 0o600)
			goWrite(t, manifest, `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`, 0o600)
			assetPath := filepath.Join(output, "project.assets.json")
			if name != "missing" {
				data, err := json.Marshal(map[string]any{
					"version":   3,
					"targets":   map[string]any{"net8.0": map[string]any{"Example.Widget/1.0.0": map[string]any{"type": "package"}}},
					"libraries": map[string]any{"Example.Widget/1.0.0": map[string]any{"type": "package", "path": "example.widget/1.0.0"}},
					"project":   map[string]any{"restore": map[string]any{"projectPath": manifest}},
				})
				if err != nil {
					t.Fatal(err)
				}
				goWrite(t, assetPath, string(data), 0o600)
			}
			scanner, x := nugetTestScanner(t, home)
			if name == "denied" {
				x.denied[assetPath] = os.ErrPermission
			}
			if name == "unreadable props" {
				x.denied[filepath.Join(root, "Directory.Build.props")] = os.ErrPermission
			}
			inv, _ := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
			got := nugetPackages(inv, "restored_package", "example.widget")
			if name == "missing" || name == "unresolved" || name == "denied" || name == "unreadable props" {
				if len(got) != 0 {
					t.Fatalf("unexpected restored facts: %+v", got)
				}
				source := nugetSource(t, inv, "project_manifest", manifest)
				if (source.Status == "partial") != (name != "missing") {
					t.Fatalf("source = %+v", source)
				}
				return
			}
			if len(got) != 1 || got[0].ProjectPath != dir || got[0].SourcePath != assetPath {
				t.Fatalf("configured assets missing: %+v", got)
			}
			if p := nugetProject(t, inv, manifest); p.AssetsPath != assetPath {
				t.Fatalf("assets path = %q", p.AssetsPath)
			}
			if x.reads[assetPath] != 1 {
				t.Fatalf("assets read %d times", x.reads[assetPath])
			}
		})
	}
}

func TestNuGetScanIncompleteEvidence(t *testing.T) {
	for _, mode := range []string{"disabled", "imported", "conditional", "expression", "central import"} {
		t.Run(mode, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "code")
			central := filepath.Join(root, "Directory.Packages.props")
			goWrite(t, central, `<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><PackageVersion Include="Example.Lib" Version="1.0.0"/><GlobalPackageReference Include="Example.Analyzer" Version="2.0.0"/></ItemGroup></Project>`, 0o600)
			extra := `<PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup>`
			switch mode {
			case "imported":
				extra = `<Import Project="shared.props"/>`
			case "conditional":
				extra = `<PropertyGroup><ManagePackageVersionsCentrally Condition="'$(Configuration)' == 'Debug'">false</ManagePackageVersionsCentrally></PropertyGroup>`
			case "expression":
				extra = `<PropertyGroup><ManagePackageVersionsCentrally>$(EnableCPM)</ManagePackageVersionsCentrally></PropertyGroup>`
			case "central import":
				extra = `<PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>`
				goWrite(t, central, `<Project><Import Project="parent.props"/><ItemGroup><PackageVersion Include="Example.Lib" Version="1.0.0"/><GlobalPackageReference Include="Example.Analyzer" Version="2.0.0"/></ItemGroup></Project>`, 0o600)
			}
			manifest := filepath.Join(root, "app", "App.csproj")
			goWrite(t, manifest, `<Project>`+extra+`<ItemGroup><PackageReference Include="Example.Lib"/></ItemGroup></Project>`, 0o600)
			scanner, _ := nugetTestScanner(t, home)
			inv, _ := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
			p := nugetPackages(inv, "declared_requirement", "example.lib")
			if len(p) != 1 || p[0].RequestedVersion != "" || len(nugetPackages(inv, "declared_requirement", "example.analyzer")) != 0 {
				t.Fatalf("central values applied: %+v", inv.Packages)
			}
			if mode != "disabled" {
				for _, path := range []string{manifest, central} {
					kind := "project_manifest"
					if path == central {
						kind = "central_versions"
					}
					if src := nugetSource(t, inv, kind, path); src.Status != "partial" || !slices.Contains(src.Reasons, "unsupported_format") {
						t.Errorf("unevaluated source proves absence: %+v", src)
					}
				}
			}
		})
	}
	for _, fallbackComplete := range []bool{false, true} {
		c := &nugetScan{goos: "linux", cacheDone: map[string]bool{"/primary": true, "/fallback": fallbackComplete}}
		p := model.NuGetPackage{PackageName: "example.lib", VersionNormalized: "1.0.0"}
		c.locate(&p, []string{"/primary", "/fallback"}, "")
		want := "unknown"
		if fallbackComplete {
			want = "absent"
		}
		if p.Installation.Presence != want {
			t.Errorf("fallback complete %v: %+v", fallbackComplete, p.Installation)
		}
	}
	for _, blocked := range []string{".nuget/NuGet/config", "code/NuGet.Config"} {
		t.Run("config selection "+blocked, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "code")
			goWrite(t, filepath.Join(root, "App.csproj"), `<Project/>`, 0o600)
			scanner, _ := nugetTestScanner(t, home)
			scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
				return func(path string) string {
					if path == filepath.Join(home, filepath.FromSlash(blocked)) {
						return "skipped_protected"
					}
					return ""
				}, func(string) bool { return false }
			}
			_, audit := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
			if len(audit.Contexts) == 0 {
				t.Fatal("no ambient context")
			}
			for _, c := range audit.Contexts {
				if c.Status != "partial" || !slices.Contains(c.Reasons, "skipped_protected") {
					t.Errorf("incomplete selection: %+v", c)
				}
			}
		})
	}
	t.Run("orphan receipts", func(t *testing.T) {
		home := goTestHome(t)
		root := filepath.Join(home, "code")
		nugetWriteFixture(t, home, root)
		scanner, x := nugetTestScanner(t, home)
		nugetFixtureEnv(x)
		for _, path := range []string{
			filepath.Join(home, ".dotnet", "tools", ".store", "dotnet-format", "8.0.0", "dotnet-format", "8.0.0", "tools", "net8.0", "any", "DotnetToolSettings.xml"),
			filepath.Join(home, ".templateengine", "packages", "Example.Templates.1.0.0.nupkg"),
		} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		inv, _ := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
		for _, p := range nugetPackages(inv, "installed_tool", "dotnet-format") {
			if p.Scope == "user" {
				t.Errorf("orphan tool installed: %+v", p)
			}
		}
		if len(nugetPackages(inv, "installed_template", "example.templates")) != 0 {
			t.Error("missing template archive installed")
		}
	})
}
