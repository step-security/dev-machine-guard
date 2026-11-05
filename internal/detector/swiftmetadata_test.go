package detector

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func swiftFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "swift", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Fixtures are the bytes SwiftPM 5.5 through 6.x and Xcode wrote in the
// macOS, Linux and Windows labs.
func TestParseSwiftResolvedFixtures(t *testing.T) {
	for _, tc := range []struct {
		file string
		want []swiftPin
	}{
		{"resolved-v1.json", []swiftPin{
			{identity: "swift-algorithms", kind: "remoteSourceControl", location: "https://github.com/apple/swift-algorithms.git", version: "1.2.1", revision: "87e50f483c54e6efd60e885f7f5aa946cee68023"},
			{identity: "swift-numerics", kind: "remoteSourceControl", location: "https://github.com/apple/swift-numerics.git", version: "1.1.1", revision: "0c0290ff6b24942dadb83a929ffaaa1481df04a2"},
		}},
		{"resolved-v2.json", []swiftPin{
			{identity: "swift-algorithms", kind: "remoteSourceControl", location: "https://github.com/apple/swift-algorithms.git", version: "1.2.1", revision: "87e50f483c54e6efd60e885f7f5aa946cee68023"},
			{identity: "swift-numerics", kind: "remoteSourceControl", location: "https://github.com/apple/swift-numerics.git", version: "1.1.1", revision: "0c0290ff6b24942dadb83a929ffaaa1481df04a2"},
		}},
		{"resolved-branch.json", []swiftPin{
			{identity: "swift-algorithms", kind: "remoteSourceControl", location: "https://github.com/apple/swift-algorithms.git", branch: "main", revision: "5b7143f8e291dee0e14c118fd0212487f0b37af5"},
			{identity: "swift-numerics", kind: "remoteSourceControl", location: "https://github.com/apple/swift-numerics.git", version: "1.1.1", revision: "0c0290ff6b24942dadb83a929ffaaa1481df04a2"},
		}},
		{"resolved-revision.json", []swiftPin{
			{identity: "swift-algorithms", kind: "remoteSourceControl", location: "https://github.com/apple/swift-algorithms.git", revision: "87e50f483c54e6efd60e885f7f5aa946cee68023"},
			{identity: "swift-numerics", kind: "remoteSourceControl", location: "https://github.com/apple/swift-numerics.git", version: "1.1.1", revision: "0c0290ff6b24942dadb83a929ffaaa1481df04a2"},
		}},
		// A registry pin records the package identity, never an endpoint.
		{"resolved-registry.json", []swiftPin{{identity: "exampleregistry.helloworld", kind: "registry", version: "1.0.0"}}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			pins, reasons, err := parseSwiftResolved(swiftFixture(t, tc.file))
			if err != nil || len(reasons) != 0 || !slices.Equal(pins, tc.want) {
				t.Fatalf("pins = %+v reasons = %v err = %v", pins, reasons, err)
			}
		})
	}
	for _, file := range []string{"resolved-v3.json", "resolved-v1-mirror.json", "resolved-xcode-app.json"} {
		pins, reasons, err := parseSwiftResolved(swiftFixture(t, file))
		if err != nil || len(reasons) != 0 || len(pins) < 2 {
			t.Errorf("%s: pins = %d reasons = %v err = %v", file, len(pins), reasons, err)
		}
	}
}

func TestParseSwiftResolvedInvalid(t *testing.T) {
	pin := func(state string) string {
		return `{"identity":"a","kind":"remoteSourceControl","location":"https://example.invalid/a.git","state":` + state + `}`
	}
	doc := func(pins ...string) string { return `{"version":3,"pins":[` + strings.Join(pins, ",") + `]}` }
	for _, tc := range []struct {
		name, data string
		pins       int
		reasons    []string
		err        error
	}{
		{"empty pins", `{"version":2,"pins":[]}`, 0, nil, nil},
		{"version only", doc(pin(`{"version":"1.0.0"}`)), 1, nil, nil},
		{"branch without revision", doc(pin(`{"branch":"main"}`)), 0, []string{"parse_error"}, nil},
		{"empty state", doc(pin(`{}`)), 0, []string{"parse_error"}, nil},
		{"wrong type", doc(pin(`{"revision":1}`)), 0, []string{"parse_error"}, nil},
		{"duplicate keeps first", doc(pin(`{"version":"1.0.0"}`), pin(`{"version":"2.0.0"}`)), 1, []string{"parse_error"}, nil},
		{"invalid neighbor kept", doc(pin(`{"version":"1.0.0"}`), `{"identity":"b","kind":"bogus","location":"x","state":{"version":"1"}}`), 1, []string{"parse_error"}, nil},
		{"relative local", doc(`{"identity":"b","kind":"localSourceControl","location":"repo","state":{"revision":"r"}}`), 0, []string{"parse_error"}, nil},
		{"control character", doc(pin(`{"revision":"a\u0000b"}`)), 0, []string{"parse_error"}, nil},
		{"version 4", `{"version":4,"pins":[]}`, 0, nil, errSwiftUnsupported},
		{"version 0", `{"version":0,"pins":[]}`, 0, nil, errSwiftUnsupported},
		{"missing pins", `{"version":2}`, 0, nil, errors.New("")},
		{"v1 without object", `{"version":1,"pins":[]}`, 0, nil, errors.New("")},
		{"trailing data", doc() + `{}`, 0, nil, errors.New("")},
		{"array", `[]`, 0, nil, errors.New("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pins, reasons, err := parseSwiftResolved([]byte(tc.data))
			switch {
			case tc.err == errSwiftUnsupported:
				if !errors.Is(err, errSwiftUnsupported) {
					t.Fatalf("err = %v, want unsupported", err)
				}
			case tc.err != nil:
				if err == nil || errors.Is(err, errSwiftUnsupported) {
					t.Fatalf("err = %v, want invalid", err)
				}
			default:
				if err != nil || len(pins) != tc.pins || !slices.Equal(reasons, append([]string{}, tc.reasons...)) {
					t.Fatalf("pins = %+v reasons = %v err = %v", pins, reasons, err)
				}
			}
		})
	}
	// The first of two pins sharing an identity stands.
	pins, _, _ := parseSwiftResolved([]byte(doc(pin(`{"version":"1.0.0"}`), pin(`{"version":"2.0.0"}`))))
	if pins[0].version != "1.0.0" {
		t.Errorf("duplicate kept %+v", pins[0])
	}
	// A version 1 pin derives its identity from the URL, never the display name.
	pins, _, _ = parseSwiftResolved([]byte(`{"version":1,"object":{"pins":[{"package":"Display","repositoryURL":"C:\\repos\\Local.git\\","state":{"revision":"r","branch":"dev","version":null}}]}}`))
	if len(pins) != 1 || pins[0].identity != "local" || pins[0].kind != "localSourceControl" || pins[0].branch != "dev" {
		t.Errorf("v1 pin = %+v", pins)
	}
	// A version 1 URL that cannot be shown safely names no package.
	pins, reasons, err := parseSwiftResolved([]byte(`{"version":1,"object":{"pins":[` +
		`{"package":"W","repositoryURL":"https://example.invalid/widgets.git?token=CANARY","state":{"revision":"r","version":"1.0.0"}},` +
		`{"package":"F","repositoryURL":"https://example.invalid/frag.git#CANARY","state":{"revision":"r","version":"1.0.0"}},` +
		`{"package":"N","repositoryURL":"https://example.invalid/numerics.git","state":{"revision":"r","version":"1.0.0"}}]}}`))
	if err != nil || len(pins) != 1 || pins[0].identity != "numerics" || !slices.Equal(reasons, []string{"parse_error"}) {
		t.Errorf("v1 unsafe pins = %+v reasons = %v err = %v", pins, reasons, err)
	}
}

func TestParseSwiftWorkspaceFixtures(t *testing.T) {
	type dep struct{ identity, kind, state, path, subpath, version, branch string }
	project := "/Users/supermac/swift-inventory-lab-20261104"
	for _, tc := range []struct {
		file      string
		deps      []dep
		artifacts []swiftManagedArtifact
	}{
		{"workspace-macos.json", []dep{
			{"swift-algorithms", "remoteSourceControl", "checkout", "", "swift-algorithms", "1.2.1", ""},
			{"swift-numerics", "remoteSourceControl", "checkout", "", "swift-numerics", "1.1.1", ""},
		}, nil},
		{"workspace-path-linux.json", []dep{{"local library", "fileSystem", "filesystem", "/home/superping/swift-inventory-lab-20261104/second-pass/Local Library", "local library", "", ""}}, nil},
		{"workspace-path-windows.json", []dep{{"local library", "fileSystem", "filesystem", `C:\Users\intune-01\swift-inventory-lab-20261104\second-pass\Local Library`, "local library", "", ""}}, nil},
		{"workspace-v1-mirror.json", []dep{
			{"renamedalgorithms", "remoteSourceControl", "checkout", "", "RenamedAlgorithms", "1.2.1", ""},
			{"swift-numerics", "remoteSourceControl", "checkout", "", "swift-numerics", "1.1.1", ""},
		}, nil},
		{"workspace-binary-plugin.json", []dep{{"swiftlintplugins", "remoteSourceControl", "checkout", "", "SwiftLintPlugins", "0.63.2", ""}},
			[]swiftManagedArtifact{{identity: "swiftlintplugins", refKind: "remoteSourceControl", location: "https://github.com/SimplyDanny/SwiftLintPlugins.git", target: "SwiftLintBinary", kind: "artifact_archive",
				url: "https://github.com/realm/SwiftLint/releases/download/0.63.2/SwiftLintBinary.artifactbundle.zip", checksum: "12befab676fc972ffde2ec295d016d53c3a85f64aabd9c7fee0032d681e307e9",
				path: project + "/projects/BinaryPlugin/.build/artifacts/swiftlintplugins/SwiftLintBinary/SwiftLintBinary.artifactbundle"}}},
		{"workspace-local-artifact.json", []dep{{"mybinarytoolplugin", "fileSystem", "filesystem", project + "/third-pass-20261105/reference/Fixtures/Miscellaneous/Plugins/MyBinaryToolPlugin", "mybinarytoolplugin", "", ""}},
			[]swiftManagedArtifact{{identity: "mybinarytoolplugin", refKind: "fileSystem", location: project + "/third-pass-20261105/reference/Fixtures/Miscellaneous/Plugins/MyBinaryToolPlugin", target: "MyVendedSourceGenBuildTool", kind: "artifact_archive",
				path: project + "/third-pass-20261105/reference/Fixtures/Miscellaneous/Plugins/MyBinaryToolPlugin/Binaries/MyVendedSourceGenBuildTool.artifactbundle"}}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			deps, artifacts, reasons, err := parseSwiftWorkspace(swiftFixture(t, tc.file))
			if err != nil || len(reasons) != 0 {
				t.Fatalf("reasons = %v err = %v", reasons, err)
			}
			got := []dep{}
			for _, d := range deps {
				got = append(got, dep{d.identity, d.refKind, d.state, d.path, d.subpath, d.version, d.branch})
			}
			if !slices.Equal(got, tc.deps) || !slices.Equal(artifacts, append([]swiftManagedArtifact{}, tc.artifacts...)) {
				t.Fatalf("deps = %+v\nartifacts = %+v", got, artifacts)
			}
		})
	}
	for _, file := range []string{"workspace-edited-macos.json", "workspace-edited-windows.json"} {
		deps, _, reasons, err := parseSwiftWorkspace(swiftFixture(t, file))
		if err != nil || len(reasons) != 0 {
			t.Fatalf("%s: reasons = %v err = %v", file, reasons, err)
		}
		d := deps[0]
		if d.state != "edited" || d.path != "" || d.basedOn == nil || d.basedOn.Revision == "" || d.version != "" {
			t.Errorf("%s: edited = %+v based on %+v", file, d, d.basedOn)
		}
	}
}

// Versions 4 to 6 are reconstructed from SwiftPM's own decoders; no lab
// produced them.
func TestParseSwiftWorkspaceSourceBackedVersions(t *testing.T) {
	ref := func(kind, location string) string {
		return `{"identity":"Lib","kind":"` + kind + `","location":"` + location + `","name":"Lib"}`
	}
	artifact := func(kind string) string {
		k := ""
		if kind != "" {
			k = `,"kind":` + kind
		}
		return `{"packageRef":` + ref("remoteSourceControl", "https://example.invalid/lib.git") + `,"targetName":"Bin","path":"/s/artifacts/lib/Bin.xcframework","source":{"type":"remote","url":"https://example.invalid/bin.zip","checksum":"abc"}` + k + `}`
	}
	ws := func(version, deps, artifacts string) []byte {
		return []byte(`{"version":` + version + `,"object":{"dependencies":[` + deps + `],"artifacts":[` + artifacts + `]}}`)
	}
	local := `{"basedOn":null,"packageRef":` + ref("fileSystem", "/src/lib") + `,"state":{"name":"fileSystem","path":"/src/lib"},"subpath":"lib"}`
	prebuilts := func(list string) []byte {
		return []byte(`{"version":7,"object":{"dependencies":[` + local + `],"artifacts":[` + artifact(`"xcframework"`) + `],"prebuilts":` + list + `}}`)
	}
	for _, tc := range []struct {
		name               string
		data               []byte
		kind, state, path  string
		artifactKind       string
		reasons            []string
		dependencies, arts int
	}{
		{"v4 remote checkout", ws("4", `{"basedOn":null,"packageRef":{"identity":"lib","kind":"remote","path":"https://example.invalid/lib.git","name":"lib"},"state":{"name":"checkout","checkoutState":{"revision":"r","version":"1.0.0"}},"subpath":"lib"}`,
			`{"packageRef":{"identity":"lib","kind":"remote","path":"https://example.invalid/lib.git","name":"lib"},"targetName":"Bin","path":"/s/a/Bin.artifactbundle","source":{"type":"local"}}`),
			"remoteSourceControl", "checkout", "", "artifact_archive", nil, 1, 1},
		{"v4 remote at a path", ws("4", `{"basedOn":null,"packageRef":{"identity":"lib","kind":"remote","location":"/repos/lib","name":"lib"},"state":{"name":"checkout","checkoutState":{"revision":"r"}},"subpath":"lib"}`, ""),
			"localSourceControl", "checkout", "", "", nil, 1, 0},
		{"v4 local", ws("4", `{"basedOn":null,"packageRef":{"identity":"lib","kind":"local","location":"/src/lib","name":"lib"},"state":{"name":"local"},"subpath":"lib"}`, ""),
			"fileSystem", "filesystem", "/src/lib", "", nil, 1, 0},
		{"v5 file system", ws("5", `{"basedOn":null,"packageRef":`+ref("fileSystem", "/src/lib")+`,"state":{"name":"fileSystem","path":"/src/lib"},"subpath":"lib"}`, artifact("")),
			"fileSystem", "filesystem", "/src/lib", "xcframework", nil, 1, 1},
		{"v5 registry", ws("5", `{"basedOn":null,"packageRef":{"identity":"acme.lib","kind":"registry","location":"acme.lib","name":"lib"},"state":{"name":"registryDownload","version":"1.0.0"},"subpath":"acme/lib/1.0.0"}`, ""),
			"registry", "registry", "", "", nil, 1, 0},
		{"v5 custom", ws("5", `{"basedOn":null,"packageRef":`+ref("remoteSourceControl", "https://example.invalid/lib.git")+`,"state":{"name":"custom","version":"1.0.0","path":"/custom/lib"},"subpath":"lib"}`, ""),
			"remoteSourceControl", "custom", "/custom/lib", "", nil, 1, 0},
		{"v6 string kind", ws("6", "", artifact(`"artifactsArchive"`)), "", "", "", "artifact_archive", nil, 0, 1},
		{"v6 enum object", ws("6", "", artifact(`{"xcframework":{}}`)), "", "", "", "unknown", []string{"unsupported_format"}, 0, 1},
		{"v7 enum object", ws("7", "", artifact(`{"xcframework":{}}`)), "", "", "", "xcframework", nil, 0, 1},
		{"v7 unknown kind", ws("7", "", artifact(`"library"`)), "", "", "", "unknown", []string{"unsupported_format"}, 0, 1},
		// Prebuilt binaries are not inventoried, so any recorded one leaves coverage partial.
		{"v7 empty prebuilts", prebuilts(`[]`), "fileSystem", "filesystem", "/src/lib", "xcframework", nil, 1, 1},
		{"v7 prebuilts", prebuilts(`[{"identity":"swift-syntax","version":"600.0.1","libraryName":"MacroSupport"}]`),
			"fileSystem", "filesystem", "/src/lib", "xcframework", []string{"unsupported_format"}, 1, 1},
		{"v7 registry scm url", ws("7", `{"basedOn":null,"packageRef":{"identity":"acme.lib","kind":"registry","location":"acme.lib","name":"lib"},"state":{"name":"registryDownload","version":"1.0.0","scmUrl":"https://example.invalid/lib.git"},"subpath":"acme/lib/1.0.0"}`, ""),
			"registry", "registry", "", "", nil, 1, 0},
		{"root dependency skipped", ws("7", `{"basedOn":null,"packageRef":`+ref("root", "/src/app")+`,"state":{"name":"fileSystem","path":"/src/app"},"subpath":"app"}`, ""),
			"", "", "", "", []string{"parse_error"}, 0, 0},
		{"missing basedOn", ws("7", `{"packageRef":`+ref("remoteSourceControl", "https://example.invalid/lib.git")+`,"state":{"name":"sourceControlCheckout","checkoutState":{"revision":"r"}},"subpath":"lib"}`, ""),
			"", "", "", "", []string{"parse_error"}, 0, 0},
		{"v4 state name in v7", ws("7", `{"basedOn":null,"packageRef":`+ref("fileSystem", "/src/lib")+`,"state":{"name":"local","path":"lib"},"subpath":"lib"}`, ""),
			"", "", "", "", []string{"parse_error"}, 0, 0},
		{"remote artifact without checksum", ws("7", "", `{"packageRef":`+ref("remoteSourceControl", "https://example.invalid/lib.git")+`,"targetName":"Bin","path":"/s/Bin.xcframework","source":{"type":"remote","url":"https://example.invalid/b.zip"},"kind":"xcframework"}`),
			"", "", "", "", []string{"parse_error"}, 0, 0},
		{"relative artifact path", ws("7", "", `{"packageRef":`+ref("remoteSourceControl", "https://example.invalid/lib.git")+`,"targetName":"Bin","path":"Bin.xcframework","source":{"type":"local"},"kind":"xcframework"}`),
			"", "", "", "", []string{"parse_error"}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, artifacts, reasons, err := parseSwiftWorkspace(tc.data)
			if err != nil || len(deps) != tc.dependencies || len(artifacts) != tc.arts || !slices.Equal(reasons, append([]string{}, tc.reasons...)) {
				t.Fatalf("deps = %+v artifacts = %+v reasons = %v err = %v", deps, artifacts, reasons, err)
			}
			if len(deps) == 1 && (deps[0].refKind != tc.kind || deps[0].state != tc.state || deps[0].path != tc.path) {
				t.Errorf("dep = %+v", deps[0])
			}
			if len(artifacts) == 1 && artifacts[0].kind != tc.artifactKind {
				t.Errorf("artifact kind = %q, want %q", artifacts[0].kind, tc.artifactKind)
			}
		})
	}
	for _, v := range []string{"1", "2", "3", "8"} {
		if _, _, _, err := parseSwiftWorkspace(ws(v, "", "")); !errors.Is(err, errSwiftUnsupported) {
			t.Errorf("version %s: err = %v", v, err)
		}
	}
	for _, data := range []string{`{"version":7}`, `{"version":7,"object":{"dependencies":[]}}`, `{"object":{}}`, `{"version":"7"}`, `{} {}`} {
		if _, _, _, err := parseSwiftWorkspace([]byte(data)); err == nil || errors.Is(err, errSwiftUnsupported) {
			t.Errorf("%s: err = %v", data, err)
		}
	}
	// A branch checkout carries no version, as SwiftPM restores the branch.
	deps, _, _, _ := parseSwiftWorkspace(ws("7", `{"basedOn":null,"packageRef":`+ref("remoteSourceControl", "https://example.invalid/lib.git")+`,"state":{"name":"sourceControlCheckout","checkoutState":{"revision":"r","branch":"main","version":"1.0.0"}},"subpath":"lib"}`, ""))
	if len(deps) != 1 || deps[0].version != "" || deps[0].branch != "main" {
		t.Errorf("branch checkout = %+v", deps)
	}
}

func TestSwiftSubpath(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"swift-algorithms", []string{"swift-algorithms"}},
		{"local library", []string{"local library"}},
		{"acme/Lib/1.0.0", []string{"acme", "Lib", "1.0.0"}},
		{`acme\Lib\1.0.0`, []string{"acme", "Lib", "1.0.0"}},
		{"", nil},
		{"..", nil},
		{"a/../b", nil},
		{"./a", nil},
		{"/etc", nil},
		{`\\server\share`, nil},
		{`C:\x`, nil},
		{"c:x", nil},
		{"a//b", nil},
		{"a/", nil},
		{"a\x00b", nil},
		{strings.Repeat("a/", maxSwiftSubpathParts) + "a", nil},
	} {
		got, ok := swiftSubpath(tc.in)
		if ok != (tc.want != nil) || !slices.Equal(got, tc.want) {
			t.Errorf("swiftSubpath(%q) = %v, %v", tc.in, got, ok)
		}
	}
}

func TestParseSwiftGitConfig(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		bare       bool
		origin     string
		ok         bool
	}{
		{"swiftpm clone", "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n\tignorecase = true\n[remote \"origin\"]\n\turl = https://github.com/apple/swift-algorithms.git\n\tfetch = +refs/*:refs/*\n\tmirror = true\n", true, "https://github.com/apple/swift-algorithms.git", true},
		{"quoted and commented", "# c\n[Core]\nbare\n; c\n[remote \"origin\"] url = \"git@github.com:o/r.git\" # tail\n", true, "git@github.com:o/r.git", true},
		{"escaped subsection", "[core]\nbare = yes\n[remote \"ori\\\"gin\"]\nurl = https://example.invalid/x.git\n", true, "", true},
		{"not bare", "[core]\nbare = false\n[remote \"origin\"]\nurl = /src/x\n", false, "/src/x", true},
		{"other remote", "[core]\nbare = true\n[remote \"upstream\"]\nurl = https://example.invalid/x.git\n", true, "", true},
		{"two origins", "[core]\nbare = true\n[remote \"origin\"]\nurl = a\nurl = b\n", false, "", false},
		{"include not followed", "[include]\npath = /etc/evil\n[core]\nbare = true\n", true, "", true},
		{"unterminated header", "[core\nbare = true\n", false, "", false},
		{"unquoted subsection", "[remote origin]\nurl = a\n", false, "", false},
		{"unterminated quote", "[core]\nbare = \"true\n", false, "", false},
		{"bad escape", "[remote \"origin\"]\nurl = a\\qb\n", false, "", false},
		{"oversized", "[core]\n" + strings.Repeat("#", maxSwiftGitConfigBytes), false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bare, origin, ok := parseSwiftGitConfig([]byte(tc.data))
			if bare != tc.bare || origin != tc.origin || ok != tc.ok {
				t.Fatalf("= %v %q %v", bare, origin, ok)
			}
		})
	}
}

func TestParseSwiftReceipt(t *testing.T) {
	if got, err := parseSwiftReceipt(swiftFixture(t, "registry-receipt.json")); err != nil || got != "http://127.0.0.1:8080" {
		t.Fatalf("receipt = %q, %v", got, err)
	}
	// Author and signature metadata are ignored, never surfaced.
	if got, err := parseSwiftReceipt([]byte(`{"registry":"https://r.example.invalid","metadata":{"author":{"name":"CANARY"}},"signature":{"signedBy":"x"}}`)); err != nil || got != "https://r.example.invalid" {
		t.Errorf("receipt = %q, %v", got, err)
	}
	for _, data := range []string{`{}`, `{"registry":""}`, `{"registry":1}`, `[]`, `{"registry":"x"} x`, ``} {
		if _, err := parseSwiftReceipt([]byte(data)); err == nil {
			t.Errorf("%q accepted", data)
		}
	}
}

func TestParseSwiftInfoPlist(t *testing.T) {
	data := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
		`<plist version="1.0"><dict><key>LastAccessedDate</key><date>2026-11-04T10:00:00Z</date><key>WorkspacePath</key><string>/Users/dev/App/App.xcodeproj</string></dict></plist>`
	if got, err := parseSwiftInfoPlist([]byte(data)); err != nil || got != "/Users/dev/App/App.xcodeproj" {
		t.Fatalf("WorkspacePath = %q, %v", got, err)
	}
	if _, err := parseSwiftInfoPlist([]byte("not a plist")); err == nil {
		t.Error("malformed plist accepted")
	}
}

func TestSwiftRegistryLayoutValidators(t *testing.T) {
	for _, tc := range []struct {
		value string
		check func(string) bool
		want  bool
	}{
		{"mona", configaudit.SwiftRegistryScope, true},
		{"Mona-Lisa1", configaudit.SwiftRegistryScope, true},
		{strings.Repeat("a", 39), configaudit.SwiftRegistryScope, true},
		{strings.Repeat("a", 40), configaudit.SwiftRegistryScope, false},
		{"-mona", configaudit.SwiftRegistryScope, false},
		{"mona-", configaudit.SwiftRegistryScope, false},
		{"mo--na", configaudit.SwiftRegistryScope, false},
		{"mo_na", configaudit.SwiftRegistryScope, false},
		{"", configaudit.SwiftRegistryScope, false},
		{"Hello_World-2", configaudit.SwiftRegistryName, true},
		{strings.Repeat("a", 100), configaudit.SwiftRegistryName, true},
		{strings.Repeat("a", 101), configaudit.SwiftRegistryName, false},
		{"_hello", configaudit.SwiftRegistryName, false},
		{"hello_", configaudit.SwiftRegistryName, false},
		{"he-_llo", configaudit.SwiftRegistryName, false},
		{"héllo", configaudit.SwiftRegistryName, false},
		{"1.0.0", swiftVersion, true},
		{"1.0.0-beta.1+build.5", swiftVersion, true},
		{"1.0", swiftVersion, false},
		{"v1.0.0", swiftVersion, false},
		{"1.0.0-", swiftVersion, false},
		// The development layout keys a version folder by storage key.
		{"1.0.0.abc", swiftVersion, false},
	} {
		if got := tc.check(tc.value); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestSwiftIdentityFromLocation(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://github.com/apple/swift-algorithms.git", "swift-algorithms"},
		{"https://github.com/apple/Swift-Algorithms/", "swift-algorithms"},
		{"file:///Users/dev/RenamedAlgorithms.git", "renamedalgorithms"},
		{`C:\Users\dev\Local Library`, "local library"},
		{"git@github.com:apple/swift-numerics.git", "swift-numerics"},
		{"host:repo.git", "repo"},
		{"https://Example.invalid/", "example.invalid"},
		{"ssh://alice@example.invalid", "alice@example.invalid"},
		{"https://user:pw@example.invalid/a/Lib.git", "lib"},
	} {
		if got, ok := swiftIdentityFromLocation(tc.in); !ok || got != tc.want {
			t.Errorf("identity(%q) = %q, %v", tc.in, got, ok)
		}
	}
	for _, in := range []string{"https://example.invalid/.git", "https://example.invalid/widgets.git?token=CANARY", "https://example.invalid/widgets.git#CANARY",
		"https://user:CANARY@example.invalid/", "https://CANARY@example.invalid", "ssh://alice:CANARY@example.invalid"} {
		if id, ok := swiftIdentityFromLocation(in); ok {
			t.Errorf("identity(%q) = %q accepted", in, id)
		}
	}
}

func TestSwiftOrigin(t *testing.T) {
	for _, tc := range []struct {
		kind, location string
		want           model.SwiftOrigin
		reason         string
	}{
		{"remoteSourceControl", "https://GitHub.com/apple/swift-algorithms.git", model.SwiftOrigin{Kind: "git", URL: "https://github.com/apple/swift-algorithms.git"}, ""},
		{"remoteSourceControl", "git@GitHub.com:apple/x.git", model.SwiftOrigin{Kind: "git", URL: "git@github.com:apple/x.git"}, ""},
		{"remoteSourceControl", "file:///src/Renamed.git", model.SwiftOrigin{Kind: "path", Path: "/src/Renamed.git"}, ""},
		{"localSourceControl", `C:\src\lib`, model.SwiftOrigin{Kind: "path", Path: `C:\src\lib`}, ""},
		{"fileSystem", "/src/Local Library", model.SwiftOrigin{Kind: "path", Path: "/src/Local Library"}, ""},
		{"registry", "acme.lib", model.SwiftOrigin{Kind: "unknown"}, ""},
		{"remoteSourceControl", "", model.SwiftOrigin{Kind: "unknown"}, "origin_unresolved"},
		{"remoteSourceControl", "relative/repo", model.SwiftOrigin{Kind: "unknown"}, "origin_unresolved"},
		{"remoteSourceControl", "https://example.invalid/x.git?token=CANARY", model.SwiftOrigin{Kind: "unknown"}, "origin_unresolved"},
		{"fileSystem", "https://example.invalid/x.git", model.SwiftOrigin{Kind: "unknown"}, "origin_unresolved"},
		// A file URL is validated before it becomes a path: a user, remote
		// host or query makes it unknown; an encoded "@" is a filename.
		{"remoteSourceControl", "file:///src/lib.git?token=CANARY", model.SwiftOrigin{Kind: "unknown"}, "origin_unresolved"},
		{"remoteSourceControl", "file://user@remote/lib.git", model.SwiftOrigin{Kind: "unknown"}, "origin_unresolved"},
		{"remoteSourceControl", "file://remote/lib.git", model.SwiftOrigin{Kind: "unknown"}, "origin_unresolved"},
		{"remoteSourceControl", "file://localhost/src/lib.git", model.SwiftOrigin{Kind: "path", Path: "/src/lib.git"}, ""},
		{"remoteSourceControl", "file:///tmp/pkg%40developer.git", model.SwiftOrigin{Kind: "path", Path: "/tmp/pkg@developer.git"}, ""},
		// Userinfo never survives into an origin.
		{"remoteSourceControl", "https://user:CANARY@example.invalid/x.git", model.SwiftOrigin{Kind: "git", URL: "https://example.invalid/x.git"}, ""},
	} {
		got, reason := swiftOrigin(tc.kind, tc.location)
		if got != tc.want || reason != tc.reason {
			t.Errorf("swiftOrigin(%s, %q) = %+v, %q", tc.kind, tc.location, got, reason)
		}
	}
}
