package detector

import (
	"archive/zip"
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNuGetNormalizeVersion(t *testing.T) {
	tests := []struct {
		raw, want string
		ok        bool
	}{
		{"1.2.3", "1.2.3", true},
		{"01.02.03", "1.2.3", true},
		{"1.2", "1.2.0", true},
		{"1", "1.0.0", true},
		{"1.2.0.0", "1.2.0", true},
		{"1.2.0.4", "1.2.0.4", true},
		{"1.2.3+build.7", "1.2.3", true},
		{"1.2.3-BETA", "1.2.3-beta", true},
		{"1.2.3-alpha01", "1.2.3-alpha01", true},
		{"1.2.3-rc.1.x-y", "1.2.3-rc.1.x-y", true},
		{"1.2.3-01", "", false},
		{"1.2.3-", "", false},
		{"1.2.3.4.5", "", false},
		{"1.2.3-beta+", "1.2.3-beta", true},
		{"[1.2.3]", "", false},
		{"1.*", "", false},
		{"", "", false},
		{"1..2", "", false},
		{"1.2.3-be ta", "", false},
		{"1.2.3-be_ta", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := nugetNormalizeVersion(tc.raw)
			if got != tc.want || ok != tc.ok {
				t.Errorf("nugetNormalizeVersion(%q) = %q, %v, want %q, %v", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNuGetID(t *testing.T) {
	tests := []struct {
		raw, want string
		ok        bool
	}{
		{"Newtonsoft.Json", "newtonsoft.json", true},
		{"My-Lib_2", "my-lib_2", true},
		{"a", "a", true},
		{".hidden", "", false},
		{"bad..id", "", false},
		{"bad/id", "", false},
		{"", "", false},
		{strings.Repeat("a", 101), "", false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := nugetID(tc.raw)
			if got != tc.want || ok != tc.ok {
				t.Errorf("nugetID(%q) = %q, %v, want %q, %v", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNuGetProjectParser(t *testing.T) {
	data := []byte(`<Project Sdk="Microsoft.NET.Sdk;Example.Sdk/1.2.3">
  <Sdk Name="Other.Sdk" Version="2.0.0" />
  <Import Sdk="Imported.Sdk/3.0.0" Project="Sdk.props" />
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0</TargetFrameworks>
    <NuGetAudit>false</NuGetAudit>
    <RestorePackagesPath Condition="'$(OS)' == 'Windows_NT'">C:\packages</RestorePackagesPath>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" PrivateAssets="all" />
    <PackageReference Include="Serilog"><Version Condition="'$(TargetFramework)' == 'net8.0'">3.*</Version><IncludeAssets>runtime</IncludeAssets></PackageReference>
    <PackageReference Include="Central" VersionOverride="2.0.0" />
    <PackageVersion Include="Central" Version="1.0.0" />
    <PackageDownload Include="Downloaded" Version="[1.0.0]" />
    <PackageReference Update="Updated" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net8.0'">
    <PackageReference Include="Conditional" Version="1.0.0" />
  </ItemGroup>
  <Import Project="..\shared.targets" />
</Project>`)
	f, err := parseNuGetProject(data)
	if err != nil {
		t.Fatal(err)
	}
	if !f.imports || f.properties["TargetFrameworks"] != "net8.0;net9.0" || f.properties["NuGetAudit"] != "false" || !f.conditional["RestorePackagesPath"] || f.properties["RestorePackagesPath"] != "" {
		t.Errorf("properties = %+v conditional = %+v imports = %v", f.properties, f.conditional, f.imports)
	}
	wantSDKs := []nugetItem{{kind: "msbuild_sdk", id: "Example.Sdk", version: "1.2.3"}, {kind: "msbuild_sdk", id: "Other.Sdk", version: "2.0.0"}, {kind: "msbuild_sdk", id: "Imported.Sdk", version: "3.0.0"}}
	if !reflect.DeepEqual(f.sdks, wantSDKs) {
		t.Errorf("sdks = %+v", f.sdks)
	}
	wantItems := []nugetItem{
		{kind: "PackageReference", id: "Newtonsoft.Json", version: "13.0.1", privateAssets: "all"},
		{kind: "PackageReference", id: "Serilog", version: "3.*", includeAssets: "runtime", conditional: true},
		{kind: "PackageReference", id: "Central", versionOverride: "2.0.0"},
		{kind: "PackageVersion", id: "Central", version: "1.0.0"},
		{kind: "PackageDownload", id: "Downloaded", version: "[1.0.0]"},
		{kind: "PackageReference", id: "Updated"},
		{kind: "PackageReference", id: "Conditional", version: "1.0.0", conditional: true},
	}
	if !reflect.DeepEqual(f.items, wantItems) {
		t.Errorf("items = %+v", f.items)
	}
	for name, bad := range map[string]string{
		"doctype":        `<!DOCTYPE Project [<!ENTITY x SYSTEM "file:///etc/passwd">]><Project>&x;</Project>`,
		"unbalanced":     `<Project><ItemGroup></Project>`,
		"empty":          "",
		"wrong root":     `<configuration/>`,
		"multiple roots": `<Project/><Project/>`,
		"outside text":   `<Project/>text`,
		"binary":         "\xff\xfe<Project/>",
	} {
		if _, err := parseNuGetProject([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestNuGetLegacyAndNuspecParsers(t *testing.T) {
	entries, partial, err := parseNuGetPackagesConfig([]byte(`<?xml version="1.0"?><packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" allowedVersions="[13,14)" developmentDependency="true" />
  <package id="bad/id" version="1.0.0" />
  <package id="Plain" version="1.0" />
</packages>`))
	if err != nil || !partial || len(entries) != 2 {
		t.Fatalf("entries = %+v partial = %v err = %v", entries, partial, err)
	}
	if e := entries[0]; e.id != "Newtonsoft.Json" || e.version != "13.0.1" || e.targetFramework != "net472" || e.allowedVersions != "[13,14)" || e.developmentDependency == nil || !*e.developmentDependency {
		t.Errorf("entry = %+v", e)
	}
	if entries[1].developmentDependency != nil {
		t.Error("absent developmentDependency should stay nil")
	}
	nuspec := []byte(`<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>Newtonsoft.Json</id><version>13.0.1</version><dependencies><group><dependency id="Other" version="1.0.0"/></group></dependencies></metadata></package>`)
	id, version, err := parseNuGetNuspec(nuspec)
	if err != nil || id != "Newtonsoft.Json" || version != "13.0.1" {
		t.Fatalf("nuspec = %q %q %v", id, version, err)
	}
	if _, _, err := parseNuGetNuspec([]byte(`<package><metadata><id>Only</id></metadata></package>`)); err == nil {
		t.Error("nuspec without version accepted")
	}
	if _, _, err := parseNuGetNuspec([]byte(`<!DOCTYPE package><package><metadata><id>X</id><version>1</version></metadata></package>`)); err == nil {
		t.Error("DOCTYPE accepted")
	}
	archive := func(names ...string) []byte {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		for _, name := range names {
			f, err := w.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(name, ".nuspec") {
				_, _ = f.Write(nuspec)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	tests := []struct {
		name   string
		data   []byte
		reason string
	}{
		{"good", archive("Newtonsoft.Json.nuspec", "lib/net6.0/Newtonsoft.Json.dll", "[Content_Types].xml"), ""},
		{"nested nuspec only", archive("lib/Newtonsoft.Json.nuspec"), "unsupported_format"},
		{"two nuspecs", archive("A.nuspec", "B.nuspec"), "parse_error"},
		{"traversal", archive("Newtonsoft.Json.nuspec", "../evil"), "parse_error"},
		{"backslash", archive("Newtonsoft.Json.nuspec", `lib\x.dll`), "parse_error"},
		{"not a zip", []byte("PK garbage"), "parse_error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, reason := nugetArchiveNuspec(tc.data)
			if reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
			if reason == "" && !bytes.Equal(data, nuspec) {
				t.Error("nuspec member not returned")
			}
		})
	}
}

func TestNuGetAssetsParser(t *testing.T) {
	v3 := []byte(`{"version":3,"targets":{".NETCoreApp,Version=v8.0":{"Newtonsoft.Json/13.0.1":{"type":"package"},"App/1.0.0":{"type":"project"}},".NETCoreApp,Version=v8.0/win-x64":{"Newtonsoft.Json/13.0.1":{"type":"package"}}},"libraries":{"Newtonsoft.Json/13.0.1":{"sha512":"abc","type":"package","path":"newtonsoft.json/13.0.1"},"App/1.0.0":{"type":"project"}},"packageFolders":{"/home/dev/.nuget/packages/":{},"/usr/share/fallback/":{}},"project":{"restore":{"projectPath":"/home/dev/app/App.csproj","packagesPath":"/home/dev/.nuget/packages/","configFilePaths":["/home/dev/app/NuGet.Config","/home/dev/.nuget/NuGet/NuGet.Config"],"fallbackFolders":["/usr/share/fallback/"]},"frameworks":{"net8.0":{"dependencies":{"Newtonsoft.Json":{"target":"Package","version":"[13.0.1, )"}}}}}}`)
	a, err := parseNuGetAssets(v3)
	if err != nil {
		t.Fatal(err)
	}
	if a.version != 3 || !a.hasProject || a.partial || len(a.libraries) != 1 || a.libraries["newtonsoft.json/13.0.1"].sha512 != "abc" {
		t.Errorf("assets = %+v", a)
	}
	if !reflect.DeepEqual(a.folders, []string{"/home/dev/.nuget/packages/", "/usr/share/fallback/"}) || a.restore.projectPath != "/home/dev/app/App.csproj" || len(a.restore.configFilePaths) != 2 {
		t.Errorf("folders = %v restore = %+v", a.folders, a.restore)
	}
	// Without a recorded framework name the schema 3 target cannot be tied to
	// the alias, so its membership stays unresolved.
	if len(a.targets) != 2 || a.targets[0].alias != "" || a.targets[0].framework != ".NETCoreApp,Version=v8.0" || a.targets[0].rid != "" || a.targets[1].rid != "win-x64" || len(a.targets[0].packages) != 1 {
		t.Errorf("targets = %+v", a.targets)
	}
	if !a.direct["net8.0"]["newtonsoft.json"] {
		t.Error("direct dependency missing")
	}
	// Ordinary schema 3 output keys targets by framework name while the project
	// records the alias; the unique name maps back so direct lookups work.
	named := []byte(`{"version":3,"targets":{".NETCoreApp,Version=v8.0":{"Newtonsoft.Json/13.0.1":{"type":"package"}},".NETFramework,Version=v4.7.2":{}},"libraries":{"Newtonsoft.Json/13.0.1":{"sha512":"abc","type":"package","path":"newtonsoft.json/13.0.1"}},"project":{"frameworks":{"net8.0":{"targetAlias":"net8.0","framework":".NETCoreApp,Version=v8.0","dependencies":{"Newtonsoft.Json":{"version":"[13.0.1, )"}}},"net472":{"targetAlias":"net472","framework":".NETFramework,Version=v4.7.2"},"net472-dup":{"targetAlias":"net472-dup","framework":".NETFramework,Version=v4.7.2"}}}}`)
	if a, err = parseNuGetAssets(named); err != nil || len(a.targets) != 2 {
		t.Fatalf("named = %+v %v", a, err)
	}
	if a.targets[0].alias != "net8.0" || a.targets[0].framework != ".NETCoreApp,Version=v8.0" || !a.direct[a.targets[0].alias]["newtonsoft.json"] || a.targets[1].alias != "" {
		t.Errorf("named targets = %+v", a.targets)
	}
	v4 := []byte(`{"version":4,"targets":{"net8.0":{"Serilog/3.1.1":{"type":"package"}},"net8.0/linux-x64":{}},"libraries":{"Serilog/3.1.1":{"sha512":"def","type":"package","path":"serilog/3.1.1"}},"project":{"frameworks":{"net8.0":{"targetAlias":"net8.0","framework":".NETCoreApp,Version=v8.0","dependencies":{"Serilog":{"version":"[3.1.1, )"}}}}}}`)
	if a, err = parseNuGetAssets(v4); err != nil || a.version != 4 || a.partial {
		t.Fatalf("v4 = %+v %v", a, err)
	}
	if a.targets[0].alias != "net8.0" || a.targets[0].framework != ".NETCoreApp,Version=v8.0" || a.targets[1].rid != "linux-x64" || !a.direct["net8.0"]["serilog"] {
		t.Errorf("v4 targets = %+v", a.targets)
	}
	tool := []byte(`{"version":3,"targets":{".NETCoreApp,Version=v8.0/any":{"dotnet-format/8.0.0":{"type":"package"}}},"libraries":{"dotnet-format/8.0.0":{"sha512":"ghi","type":"package","path":"dotnet-format/8.0.0"}},"packageFolders":{"/home/dev/.dotnet/tools/.store":{}}}`)
	if a, err = parseNuGetAssets(tool); err != nil || a.hasProject || a.targets[0].rid != "any" || a.targets[0].framework != ".NETCoreApp,Version=v8.0" {
		t.Errorf("tool receipt = %+v %v", a, err)
	}
	for name, bad := range map[string]string{"version 2": `{"version":2,"targets":{},"libraries":{}}`, "no libraries": `{"version":3,"targets":{}}`, "not an object": `[]`} {
		if _, err := parseNuGetAssets([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestNuGetLockAndMarkerParsers(t *testing.T) {
	v1 := []byte(`{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1","contentHash":"abc=="},"System.Text.Json":{"type":"Transitive","resolved":"8.0.0","contentHash":"def=="},"App":{"type":"Project"},"Broken":{"type":"Direct","resolved":"","contentHash":""}}}}`)
	entries, partial, err := parseNuGetLock(v1)
	if err != nil || !partial || len(entries) != 2 {
		t.Fatalf("v1 = %+v %v %v", entries, partial, err)
	}
	if e := entries[0]; e.id != "Newtonsoft.Json" || e.typ != "Direct" || e.requested != "[13.0.1, )" || e.resolved != "13.0.1" || e.contentHash != "abc==" || e.framework != "net8.0" || e.alias != "" {
		t.Errorf("v1 entry = %+v", e)
	}
	v3 := []byte(`{"version":3,"net8.0":{"framework":".NETCoreApp,Version=v8.0","dependencies":{"Serilog":{"type":"CentralTransitive","requested":"[3.1.1, )","resolved":"3.1.1","contentHash":"ghi=="}}}}`)
	if entries, partial, err = parseNuGetLock(v3); err != nil || partial || len(entries) != 1 || entries[0].alias != "net8.0" || entries[0].framework != ".NETCoreApp,Version=v8.0" || entries[0].typ != "CentralTransitive" {
		t.Errorf("v3 = %+v %v %v", entries, partial, err)
	}
	if _, _, err := parseNuGetLock([]byte(`{"version":4}`)); !errors.Is(err, errNuGetUnsupportedFormat) {
		t.Errorf("v4 err = %v", err)
	}
	hash, source, err := parseNuGetMarker([]byte(`{"version":2,"contentHash":"abc==","source":"https://api.nuget.org/v3/index.json"}`))
	if err != nil || hash != "abc==" || source != "https://api.nuget.org/v3/index.json" {
		t.Errorf("marker v2 = %q %q %v", hash, source, err)
	}
	if hash, source, err = parseNuGetMarker([]byte(`{"version":1,"contentHash":"abc=="}`)); err != nil || hash != "abc==" || source != "" {
		t.Errorf("marker v1 = %q %q %v", hash, source, err)
	}
	if _, _, err := parseNuGetMarker([]byte(`{"version":3,"contentHash":"x"}`)); err == nil {
		t.Error("marker v3 accepted")
	}
}

func TestNuGetToolTemplateAndDepsParsers(t *testing.T) {
	tools, partial, err := parseNuGetToolManifest([]byte(`{"version":1,"isRoot":true,"tools":{"dotnet-format":{"version":"8.0.0","commands":["dotnet-format"]},"bad/id":{"version":"1.0.0","commands":[]},"noversion":{"commands":["x"]}}}`))
	if err != nil || !partial || len(tools) != 1 || tools[0].id != "dotnet-format" || tools[0].version != "8.0.0" || !reflect.DeepEqual(tools[0].commands, []string{"dotnet-format"}) {
		t.Errorf("tools = %+v %v %v", tools, partial, err)
	}
	if _, _, err := parseNuGetToolManifest([]byte(`{"version":2,"tools":{}}`)); !errors.Is(err, errNuGetUnsupportedFormat) {
		t.Errorf("manifest v2 err = %v", err)
	}
	cache, partial, err := parseNuGetResolverCache([]byte(`[{"Version":"8.0.0","TargetFramework":"net8.0","RuntimeIdentifier":"any","Name":"dotnet-format","PathToExecutable":"/home/dev/.nuget/packages/dotnet-format/8.0.0/tools/net8.0/any/dotnet-format.dll"},{"Name":"nover"}]`))
	if err != nil || !partial || len(cache) != 1 || cache[0].executable == "" || cache[0].rid != "any" {
		t.Errorf("resolver = %+v %v %v", cache, partial, err)
	}
	commands, err := parseNuGetToolSettings([]byte(`<?xml version="1.0"?><DotNetCliTool Version="1"><Commands><Command Name="dotnet-format" EntryPoint="dotnet-format.dll" Runner="dotnet" /><Command Name="bad name" /></Commands></DotNetCliTool>`))
	if err != nil || !reflect.DeepEqual(commands, []string{"dotnet-format"}) {
		t.Errorf("commands = %v %v", commands, err)
	}
	for _, prefix := range []string{"", "\xef\xbb\xbf"} {
		templates, partial, err := parseNuGetTemplates([]byte(prefix + `{"Packages":[{"MountPointUri":"/home/dev/.templateengine/packages/Example.Templates.1.0.0.nupkg","Details":{"PackageId":"Example.Templates","Version":"1.0.0","NuGetSource":"https://api.nuget.org/v3/index.json"}},{"MountPointUri":"/opt/templates","Details":{"Author":"dir"}},{"MountPointUri":"/x","Details":{"PackageId":"bad/id","Version":"1"}}]}`))
		if err != nil || !partial || len(templates) != 1 || templates[0].id != "Example.Templates" || templates[0].source == "" {
			t.Errorf("templates = %+v %v %v", templates, partial, err)
		}
	}
	deps, partial, err := parseNuGetDeps([]byte(`{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0/linux-x64"},"targets":{},"libraries":{"App/1.0.0":{"type":"project"},"Newtonsoft.Json/13.0.1":{"type":"package","sha512":"sha512-abc==","path":"newtonsoft.json/13.0.1"},"bad":{"type":"package"}}}`))
	if err != nil || !partial || len(deps) != 1 || deps[0].sha512 != "abc==" || deps[0].framework != ".NETCoreApp,Version=v8.0" || deps[0].rid != "linux-x64" {
		t.Errorf("deps = %+v %v %v", deps, partial, err)
	}
}

func TestNuGetScriptDirectives(t *testing.T) {
	// A built-in SDK name is not a package; only a versioned #:sdk is a declaration.
	cs := []byte("#!/usr/bin/env dotnet\n// comment\n/* block\n   comment */ #:sdk Microsoft.NET.Sdk.Web\n#:sdk Aspire.AppHost.Sdk@9.0.0\n#:package Humanizer@2.14.1\n#:package NoVersion\n#:property LangVersion=preview\nusing System;\n#:package Late@1.0.0\n")
	want := []nugetDirective{{kind: "sdk", id: "Aspire.AppHost.Sdk", version: "9.0.0"}, {kind: "package", id: "Humanizer", version: "2.14.1"}, {kind: "package", id: "NoVersion"}}
	for _, prefix := range []string{"", "\xef\xbb\xbf"} {
		if got := parseNuGetCSharpDirectives(append([]byte(prefix), cs...)); !reflect.DeepEqual(got, want) {
			t.Errorf("csharp prefix %q = %+v", prefix, got)
		}
	}
	fsx := []byte("#r \"nuget: FSharp.Data, 6.3.0\"\n#r \"nuget:Newtonsoft.Json\"\n#r \"nuget: bad/id\"\n#i \"nuget: https://private.example.invalid/v3/index.json\"\nlet x = 1\n")
	want = []nugetDirective{{kind: "package", id: "FSharp.Data", version: "6.3.0"}, {kind: "package", id: "Newtonsoft.Json"}}
	for _, prefix := range []string{"", "\xef\xbb\xbf"} {
		if got := parseNuGetFSharpDirectives(append([]byte(prefix), fsx...)); !reflect.DeepEqual(got, want) {
			t.Errorf("fsharp prefix %q = %+v", prefix, got)
		}
	}
}
