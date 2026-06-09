package detector

import (
	"context"
	"fmt"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestIDEDetector_FindsVSCode(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Visual Studio Code.app")
	mock.SetFile("/Applications/Visual Studio Code.app/Contents/Info.plist", []byte{})
	mock.SetCommand("1.96.0\n", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Visual Studio Code.app/Contents/Info.plist")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 IDE, got %d", len(results))
	}
	if results[0].IDEType != "vscode" {
		t.Errorf("expected vscode, got %s", results[0].IDEType)
	}
	if results[0].Version != "1.96.0" {
		t.Errorf("expected 1.96.0, got %s", results[0].Version)
	}
	if results[0].Vendor != "Microsoft" {
		t.Errorf("expected Microsoft, got %s", results[0].Vendor)
	}
	if !results[0].IsInstalled {
		t.Error("expected is_installed=true")
	}
}

func TestIDEDetector_NotInstalled(t *testing.T) {
	mock := executor.NewMock()
	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 IDEs, got %d", len(results))
	}
}

func TestIDEDetector_VersionFromBinary(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Cursor.app")
	mock.SetFile("/Applications/Cursor.app/Contents/Resources/app/bin/cursor", []byte{})
	mock.SetCommand("0.50.1\n1234abcd\nx64", "", 0, "/Applications/Cursor.app/Contents/Resources/app/bin/cursor", "--version")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 IDE, got %d", len(results))
	}
	if results[0].Version != "0.50.1" {
		t.Errorf("expected 0.50.1, got %s", results[0].Version)
	}
}

func TestIDEDetector_MultipleIDEs(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Visual Studio Code.app")
	mock.SetFile("/Applications/Visual Studio Code.app/Contents/Info.plist", []byte{})
	mock.SetCommand("1.96.0", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Visual Studio Code.app/Contents/Info.plist")

	mock.SetDir("/Applications/Claude.app")
	mock.SetFile("/Applications/Claude.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.7.1", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/Claude.app/Contents/Info.plist")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 2 {
		t.Fatalf("expected 2 IDEs, got %d", len(results))
	}
}

func TestIDEDetector_Windows_FindsVSCode(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)

	// resolveEnvPath("%PROGRAMFILES%\Microsoft VS Code") on macOS produces
	// the backslash-containing path since filepath.FromSlash is a no-op.
	vscodePath := `C:\Program Files\Microsoft VS Code`
	mock.SetDir(vscodePath)

	// filepath.Join on macOS uses "/" between parts, keeps existing backslashes.
	binaryPath := vscodePath + `/bin\code.cmd`
	mock.SetFile(binaryPath, []byte{})
	mock.SetCommand("1.96.0\n1234abcd\nx64", "", 0, binaryPath, "--version")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 IDE, got %d", len(results))
	}
	if results[0].IDEType != "vscode" {
		t.Errorf("expected vscode, got %s", results[0].IDEType)
	}
	if results[0].Version != "1.96.0" {
		t.Errorf("expected 1.96.0, got %s", results[0].Version)
	}
	if results[0].Vendor != "Microsoft" {
		t.Errorf("expected Microsoft, got %s", results[0].Vendor)
	}
	if !results[0].IsInstalled {
		t.Error("expected is_installed=true")
	}
	if results[0].InstallPath != vscodePath {
		t.Errorf("expected install path %s, got %s", vscodePath, results[0].InstallPath)
	}
}

func TestIDEDetector_Windows_FindsClaude(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)

	// resolveEnvPath("%LOCALAPPDATA%\Programs\Claude") on macOS:
	// result is "C:\Users\testuser\AppData\Local\Programs\Claude"
	// (all backslashes since the spec uses backslashes throughout)
	claudePath := `C:\Users\testuser\AppData\Local\Programs\Claude`
	mock.SetDir(claudePath)

	// Claude has no WinBinary, so version falls back to readRegistryVersion.
	// Registry query tries multiple roots; succeed on the first one.
	mock.SetCommand(
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Claude\n    DisplayVersion    REG_SZ    0.8.2\n",
		"", 0,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Claude", "/d",
	)

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 1 {
		t.Fatalf("expected 1 IDE, got %d", len(results))
	}
	if results[0].IDEType != "claude_desktop" {
		t.Errorf("expected claude_desktop, got %s", results[0].IDEType)
	}
	if results[0].Version != "0.8.2" {
		t.Errorf("expected 0.8.2, got %s", results[0].Version)
	}
	if results[0].Vendor != "Anthropic" {
		t.Errorf("expected Anthropic, got %s", results[0].Vendor)
	}
	if !results[0].IsInstalled {
		t.Error("expected is_installed=true")
	}
}

// --- JetBrains IDE tests (from upstream) ---

func TestIDEDetector_JetBrains(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/GoLand.app")
	mock.SetFile("/Applications/GoLand.app/Contents/Info.plist", []byte{})
	mock.SetCommand("2024.3.1", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/GoLand.app/Contents/Info.plist")

	mock.SetDir("/Applications/IntelliJ IDEA.app")
	mock.SetFile("/Applications/IntelliJ IDEA.app/Contents/Info.plist", []byte{})
	mock.SetCommand("2024.3.2", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/IntelliJ IDEA.app/Contents/Info.plist")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := map[string]string{}
	for _, r := range results {
		found[r.IDEType] = r.Version
	}

	if v, ok := found["goland"]; !ok {
		t.Error("expected GoLand to be detected")
	} else if v != "2024.3.1" {
		t.Errorf("expected GoLand version 2024.3.1, got %s", v)
	}

	if v, ok := found["intellij_idea"]; !ok {
		t.Error("expected IntelliJ IDEA to be detected")
	} else if v != "2024.3.2" {
		t.Errorf("expected IntelliJ IDEA version 2024.3.2, got %s", v)
	}

	for _, r := range results {
		if r.IDEType == "goland" && r.Vendor != "JetBrains" {
			t.Errorf("expected JetBrains vendor for GoLand, got %s", r.Vendor)
		}
	}
}

// --- Windows IDE detection tests ---

func TestIDEDetector_FindsGoLand_macOS_ProductInfo(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/GoLand.app")
	mock.SetFile("/Applications/GoLand.app/Contents/Resources/product-info.json",
		[]byte(`{"name":"GoLand","version":"2025.1.3","buildNumber":"251.26927.50","productCode":"GO"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "goland")
	if found == nil {
		t.Fatal("expected GoLand to be detected")
	}
	if found.Version != "2025.1.3" {
		t.Errorf("expected 2025.1.3, got %s", found.Version)
	}
	if found.Vendor != "JetBrains" {
		t.Errorf("expected JetBrains, got %s", found.Vendor)
	}
}

func TestIDEDetector_FindsIntelliJ_macOS_PlistFallback(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/IntelliJ IDEA.app")
	mock.SetFile("/Applications/IntelliJ IDEA.app/Contents/Info.plist", []byte{})
	mock.SetCommand("2024.3.2", "", 0, "/usr/libexec/PlistBuddy", "-c",
		"Print :CFBundleShortVersionString", "/Applications/IntelliJ IDEA.app/Contents/Info.plist")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "intellij_idea")
	if found == nil {
		t.Fatal("expected IntelliJ IDEA to be detected")
	}
	if found.Version != "2024.3.2" {
		t.Errorf("expected 2024.3.2, got %s", found.Version)
	}
}

// macOS Electron IDEs that previously had BinaryPath pointing at
// Contents/MacOS/<App> (a GUI binary) — Windsurf, Antigravity. Without
// the package.json fast-path in resolveDarwinVersion, runVersionCmd
// would shell out to the GUI binary and flash a window; before PR #122's
// process-group fix it also hung indefinitely. These tests register NO
// command for the binary path: if the detector falls through, the mock
// returns an unregistered-command error and version stays "unknown",
// failing the assertion.

func TestIDEDetector_Darwin_Windsurf_PackageJSONFastPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Windsurf.app")
	mock.SetFile("/Applications/Windsurf.app/Contents/Resources/app/package.json",
		[]byte(`{"name":"Windsurf","version":"1.42.0"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "windsurf")
	if found == nil {
		t.Fatal("expected Windsurf to be detected")
	}
	if found.Version != "1.42.0" {
		t.Errorf("version should come from package.json (1.42.0), got %s", found.Version)
	}
}

func TestIDEDetector_Darwin_Antigravity_PackageJSONFastPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Antigravity.app")
	mock.SetFile("/Applications/Antigravity.app/Contents/Resources/app/package.json",
		[]byte(`{"name":"Antigravity","version":"0.3.1"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "antigravity")
	if found == nil {
		t.Fatal("expected Antigravity to be detected")
	}
	if found.Version != "0.3.1" {
		t.Errorf("version should come from package.json (0.3.1), got %s", found.Version)
	}
}

// The current Antigravity ships as "Antigravity IDE.app" (verified on a real
// install: package.json version 1.107.0, bundle id com.google.antigravity-ide).
// The detector must find it at the renamed bundle path via AppPathAlts and
// resolve the version from package.json without touching any binary.
func TestIDEDetector_Darwin_Antigravity_RenamedBundle(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Antigravity IDE.app")
	mock.SetFile("/Applications/Antigravity IDE.app/Contents/Resources/app/package.json",
		[]byte(`{"name":"Antigravity IDE","version":"1.107.0"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "antigravity")
	if found == nil {
		t.Fatal("expected Antigravity to be detected at the renamed Antigravity IDE.app bundle")
	}
	if found.Version != "1.107.0" {
		t.Errorf("version should come from package.json (1.107.0), got %s", found.Version)
	}
	if found.InstallPath != "/Applications/Antigravity IDE.app" {
		t.Errorf("InstallPath should be the resolved bundle, got %s", found.InstallPath)
	}
}

// Defense in depth for the Coveo incident: even when every static version
// source is missing — forcing resolveDarwinVersion all the way to the exec
// fallback — the target must be the CLI shim (Contents/Resources/app/bin/
// antigravity-ide), NEVER the GUI binary (Contents/MacOS/Electron) which, on a
// real install, boots the app and hangs instead of printing a version. The GUI
// binary path is poisoned here with a sentinel; if the detector ever targets
// it, the test fails loudly. Uses the legacy Antigravity.app path to also
// exercise AppPathAlts resolution.
func TestIDEDetector_Darwin_Antigravity_FallbackUsesCLIShimNotGUIBinary(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Antigravity.app") // legacy bundle name → resolved via AppPathAlts
	// No package.json, no product-info.json, no Info.plist → all three static
	// reads return "unknown", forcing the binary-exec fallback.
	shim := "/Applications/Antigravity.app/Contents/Resources/app/bin/antigravity-ide"
	mock.SetFile(shim, []byte{})
	mock.SetCommand("2.0.3", "", 0, shim, "--version")
	// Poison the real GUI binary: reaching it would surface this sentinel.
	guiBinary := "/Applications/Antigravity.app/Contents/MacOS/Electron"
	mock.SetFile(guiBinary, []byte{})
	mock.SetCommand("9.9.9-GUI-LAUNCHED", "", 0, guiBinary, "--version")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "antigravity")
	if found == nil {
		t.Fatal("expected Antigravity to be detected")
	}
	if found.Version == "9.9.9-GUI-LAUNCHED" {
		t.Fatal("GUI binary Contents/MacOS/Electron was executed — it must never be the exec target")
	}
	if found.Version != "2.0.3" {
		t.Errorf("expected version from CLI shim (2.0.3), got %s", found.Version)
	}
}

// Linux must be GUI-safe too: resolveLinuxVersion now reads package.json
// before exec'ing any binary, mirroring macOS/Windows. The renamed Antigravity
// installs under /opt/antigravity-ide with the CLI named antigravity-ide. Here
// the in-dir binary is poisoned with a sentinel; if the detector execs it
// instead of reading package.json, the test fails loudly.
func TestIDEDetector_Linux_Antigravity_PackageJSONFastPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	installDir := "/opt/antigravity-ide/Antigravity-IDE"
	mock.SetDir(installDir)
	mock.SetFile(installDir+"/resources/app/package.json",
		[]byte(`{"name":"Antigravity IDE","version":"1.107.0"}`))
	// Poison both candidate binary paths: reaching either means we exec'd
	// instead of reading package.json.
	for _, b := range []string{installDir + "/bin/antigravity-ide", installDir + "/antigravity-ide"} {
		mock.SetFile(b, []byte{})
		mock.SetCommand("9.9.9-GUI-LAUNCHED", "", 0, b, "--version")
	}

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "antigravity")
	if found == nil {
		t.Fatal("expected Antigravity to be detected on Linux at /opt/antigravity-ide")
	}
	if found.Version == "9.9.9-GUI-LAUNCHED" {
		t.Fatal("Linux exec'd the binary before reading package.json — GUI-launch risk")
	}
	if found.Version != "1.107.0" {
		t.Errorf("version should come from package.json (1.107.0), got %s", found.Version)
	}
}

// Zed is Rust, not Electron — there is no Contents/Resources/app/package.json.
// It falls through to Info.plist instead. Same guarantee: no exec of the
// Contents/MacOS/zed GUI binary.
func TestIDEDetector_Darwin_Zed_PlistFastPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Zed.app")
	mock.SetFile("/Applications/Zed.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.180.4", "", 0, "/usr/libexec/PlistBuddy", "-c",
		"Print :CFBundleShortVersionString", "/Applications/Zed.app/Contents/Info.plist")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "zed")
	if found == nil {
		t.Fatal("expected Zed to be detected")
	}
	if found.Version != "0.180.4" {
		t.Errorf("version should come from Info.plist (0.180.4), got %s", found.Version)
	}
}

// VS Code's BinaryPath is the safe CLI shim, but the package.json fast-path
// still wins because we want zero subprocess overhead for every macOS IDE
// detection — not just the ones whose binary would hang. Asserts the
// package.json version is reported even when the binary would also work.
func TestIDEDetector_Darwin_VSCode_PackageJSONPreferred(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Visual Studio Code.app")
	mock.SetFile("/Applications/Visual Studio Code.app/Contents/Resources/app/package.json",
		[]byte(`{"name":"Code","version":"1.96.0"}`))
	binaryPath := "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
	mock.SetFile(binaryPath, []byte{})
	// Register a different version on the binary so we can prove the fast-path won.
	mock.SetCommand("1.95.0\n1234abcd\nx64", "", 0, binaryPath, "--version")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "vscode")
	if found == nil {
		t.Fatal("expected VS Code to be detected")
	}
	if found.Version != "1.96.0" {
		t.Errorf("expected 1.96.0 (package.json fast-path), got %s", found.Version)
	}
}

func TestIDEDetector_FindsEclipse_macOS(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/Eclipse.app")
	mock.SetFile("/Applications/Eclipse.app/Contents/Info.plist", []byte{})
	mock.SetCommand("4.33.0", "", 0, "/usr/libexec/PlistBuddy", "-c",
		"Print :CFBundleShortVersionString", "/Applications/Eclipse.app/Contents/Info.plist")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "eclipse")
	if found == nil {
		t.Fatal("expected Eclipse to be detected")
	}
	if found.Version != "4.33.0" {
		t.Errorf("expected 4.33.0, got %s", found.Version)
	}
	if found.Vendor != "Eclipse Foundation" {
		t.Errorf("expected Eclipse Foundation, got %s", found.Vendor)
	}
}

func TestIDEDetector_Windows_FindsGoLand_Glob(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)

	globPattern := `C:\Program Files\JetBrains\GoLand *`
	golandPath := `C:\Program Files\JetBrains\GoLand 2025.1.3`
	mock.SetGlob(globPattern, []string{golandPath})
	mock.SetDir(golandPath)

	productInfoPath := golandPath + "/product-info.json"
	mock.SetFile(productInfoPath,
		[]byte(`{"name":"GoLand","version":"2025.1.3","buildNumber":"251.26927.50"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "goland")
	if found == nil {
		t.Fatal("expected GoLand to be detected")
	}
	if found.Version != "2025.1.3" {
		t.Errorf("expected 2025.1.3, got %s", found.Version)
	}
	if found.InstallPath != golandPath {
		t.Errorf("expected install path %s, got %s", golandPath, found.InstallPath)
	}
}

func TestIDEDetector_Windows_FindsRider_Glob(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)

	globPattern := `C:\Program Files\JetBrains\JetBrains Rider *`
	riderPath := `C:\Program Files\JetBrains\JetBrains Rider 2024.3.2`
	mock.SetGlob(globPattern, []string{riderPath})
	mock.SetDir(riderPath)

	productInfoPath := riderPath + "/product-info.json"
	mock.SetFile(productInfoPath,
		[]byte(`{"name":"JetBrains Rider","version":"2024.3.2","productCode":"RD"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "rider")
	if found == nil {
		t.Fatal("expected Rider to be detected")
	}
	if found.Version != "2024.3.2" {
		t.Errorf("expected 2024.3.2, got %s", found.Version)
	}
}

func TestIDEDetector_Windows_GlobNoMatches(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	for _, r := range results {
		if r.Vendor == "JetBrains" {
			t.Errorf("unexpected JetBrains IDE detected: %s", r.IDEType)
		}
	}
}

func TestIDEDetector_Windows_FindsEclipse_EclipseProduct(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)

	eclipsePath := `C:\Program Files\eclipse`
	mock.SetDir(eclipsePath)

	eclipseProductPath := eclipsePath + "/.eclipseproduct"
	mock.SetFile(eclipseProductPath,
		[]byte("name=Eclipse Platform\nid=org.eclipse.platform\nversion=4.33.0\n"))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "eclipse")
	if found == nil {
		t.Fatal("expected Eclipse to be detected")
	}
	if found.Version != "4.33.0" {
		t.Errorf("expected 4.33.0, got %s", found.Version)
	}
}

func TestIDEDetector_Windows_FindsEclipse_UserProfile_Glob(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)
	mock.SetEnv("USERPROFILE", `C:\Users\dev`)

	globPattern := `C:\Users\dev\eclipse\*\eclipse`
	eclipsePath := `C:\Users\dev\eclipse\java-2024-09\eclipse`
	mock.SetGlob(globPattern, []string{eclipsePath})
	mock.SetDir(eclipsePath)

	eclipseProductPath := eclipsePath + "/.eclipseproduct"
	mock.SetFile(eclipseProductPath,
		[]byte("name=Eclipse Platform\nid=org.eclipse.platform\nversion=4.33.0\n"))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "eclipse")
	if found == nil {
		t.Fatal("expected Eclipse to be detected")
	}
	if found.InstallPath != eclipsePath {
		t.Errorf("expected install path %s, got %s", eclipsePath, found.InstallPath)
	}
}

// When resources\app\package.json is readable, version must come from
// it WITHOUT shelling out to the bin\code.cmd subprocess — that shim
// flashes a console under Task Scheduler. The mock has no command
// registered for the binary; if the detector falls through, the test
// fails.
func TestIDEDetector_Windows_VSCode_PackageJSONFastPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)

	vscodePath := `C:\Program Files\Microsoft VS Code`
	mock.SetDir(vscodePath)
	mock.SetFile(vscodePath+`/bin\code.cmd`, []byte{})
	mock.SetFile(vscodePath+`/resources/app/package.json`,
		[]byte(`{"name":"Code","version":"1.115.0"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "vscode")
	if found == nil {
		t.Fatal("expected VS Code to be detected")
	}
	if found.Version != "1.115.0" {
		t.Errorf("version should come from package.json (1.115.0), got %s", found.Version)
	}
}

func TestIDEDetector_Windows_VSCode_StillWorks(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)

	vscodePath := `C:\Program Files\Microsoft VS Code`
	mock.SetDir(vscodePath)

	binaryPath := vscodePath + `/bin\code.cmd`
	mock.SetFile(binaryPath, []byte{})
	mock.SetCommand("1.96.0\n1234abcd\nx64", "", 0, binaryPath, "--version")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "vscode")
	if found == nil {
		t.Fatal("expected VS Code to still be detected after glob changes")
	}
	if found.Version != "1.96.0" {
		t.Errorf("expected 1.96.0, got %s", found.Version)
	}
}

func TestIDEDetector_Windows_AndroidStudio(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)

	studioPath := `C:\Program Files\Android\Android Studio`
	mock.SetDir(studioPath)

	productInfoPath := studioPath + "/product-info.json"
	mock.SetFile(productInfoPath,
		[]byte(`{"name":"Android Studio","version":"2024.2.1","productCode":"AI"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "android_studio")
	if found == nil {
		t.Fatal("expected Android Studio to be detected")
	}
	if found.Version != "2024.2.1" {
		t.Errorf("expected 2024.2.1, got %s", found.Version)
	}
	if found.Vendor != "Google" {
		t.Errorf("expected Google, got %s", found.Vendor)
	}
}

// --- Helper function tests ---

func TestReadProductInfoVersion(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/test/product-info.json",
		[]byte(`{"name":"GoLand","version":"2025.1.3","buildNumber":"251.26927.50"}`))

	v := readJSONVersion(mock, "/test/product-info.json")
	if v != "2025.1.3" {
		t.Errorf("expected 2025.1.3, got %s", v)
	}
}

func TestReadProductInfoVersion_MissingFile(t *testing.T) {
	mock := executor.NewMock()
	v := readJSONVersion(mock, "/nonexistent/product-info.json")
	if v != "unknown" {
		t.Errorf("expected unknown, got %s", v)
	}
}

func TestReadProductInfoVersion_InvalidJSON(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/test/product-info.json", []byte(`not json`))

	v := readJSONVersion(mock, "/test/product-info.json")
	if v != "unknown" {
		t.Errorf("expected unknown, got %s", v)
	}
}

func TestReadEclipseProductVersion(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/test/.eclipseproduct",
		[]byte("name=Eclipse Platform\nid=org.eclipse.platform\nversion=4.33.0\n"))

	v := readEclipseProductVersion(mock, "/test/.eclipseproduct")
	if v != "4.33.0" {
		t.Errorf("expected 4.33.0, got %s", v)
	}
}

func TestReadEclipseProductVersion_MissingFile(t *testing.T) {
	mock := executor.NewMock()
	v := readEclipseProductVersion(mock, "/nonexistent/.eclipseproduct")
	if v != "unknown" {
		t.Errorf("expected unknown, got %s", v)
	}
}

func TestReadEclipseProductVersion_NoVersionKey(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/test/.eclipseproduct", []byte("name=Eclipse Platform\nid=org.eclipse.platform\n"))

	v := readEclipseProductVersion(mock, "/test/.eclipseproduct")
	if v != "unknown" {
		t.Errorf("expected unknown, got %s", v)
	}
}

// --- Registry fallback tests ---

func TestIDEDetector_Windows_VSCode_RegistryFallback(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)
	// Neither standard path exists — simulating custom install

	// Registry returns InstallLocation at a custom path
	regOutput := "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{VSCode}\n" +
		"    DisplayName    REG_SZ    Microsoft Visual Studio Code\n" +
		"    DisplayVersion    REG_SZ    1.96.0\n" +
		"    InstallLocation    REG_SZ    D:\\Tools\\VSCode\n"
	mock.SetCommand(regOutput, "", 0,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Visual Studio Code", "/d")

	mock.SetDir(`D:\Tools\VSCode`)
	binaryPath := `D:\Tools\VSCode` + `/bin\code.cmd`
	mock.SetFile(binaryPath, []byte{})
	mock.SetCommand("1.96.0\n1234abcd\nx64", "", 0, binaryPath, "--version")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "vscode")
	if found == nil {
		t.Fatal("expected VS Code to be found via registry fallback")
	}
	if found.Version != "1.96.0" {
		t.Errorf("expected 1.96.0, got %s", found.Version)
	}
	if found.InstallPath != `D:\Tools\VSCode` {
		t.Errorf("expected D:\\Tools\\VSCode, got %s", found.InstallPath)
	}
}

func TestIDEDetector_Windows_RegistryFallback_DirNotExists(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)

	regOutput := "HKLM\\SOFTWARE\\...\\Uninstall\\{VSCode}\n" +
		"    DisplayName    REG_SZ    Microsoft Visual Studio Code\n" +
		"    InstallLocation    REG_SZ    D:\\Deleted\\VSCode\n"
	mock.SetCommand(regOutput, "", 0,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Visual Studio Code", "/d")
	// Do NOT set dir — it doesn't exist

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if findIDE(results, "vscode") != nil {
		t.Error("expected VS Code NOT detected when registry InstallLocation doesn't exist")
	}
}

func TestIDEDetector_Windows_RegistryFallback_NoInstallLocation(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)

	regOutput := "HKLM\\SOFTWARE\\...\\Uninstall\\{VSCode}\n" +
		"    DisplayName    REG_SZ    Microsoft Visual Studio Code\n" +
		"    DisplayVersion    REG_SZ    1.96.0\n"
	// No InstallLocation line
	mock.SetCommand(regOutput, "", 0,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Visual Studio Code", "/d")

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	if findIDE(results, "vscode") != nil {
		t.Error("expected VS Code NOT detected when registry has no InstallLocation")
	}
}

func TestIDEDetector_Windows_GoLand_RegistryFallback_ProductInfo(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)
	// Standard glob path does NOT match

	regOutput := "HKLM\\SOFTWARE\\...\\Uninstall\\GoLand 2025.1.3\n" +
		"    DisplayName    REG_SZ    GoLand 2025.1.3\n" +
		"    DisplayVersion    REG_SZ    251.26927.50\n" +
		"    InstallLocation    REG_SZ    E:\\JetBrains\\GoLand\n"
	mock.SetCommand(regOutput, "", 0,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "GoLand", "/d")

	mock.SetDir(`E:\JetBrains\GoLand`)
	mock.SetFile(`E:\JetBrains\GoLand/product-info.json`,
		[]byte(`{"name":"GoLand","version":"2025.1.3","buildNumber":"251.26927.50"}`))

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "goland")
	if found == nil {
		t.Fatal("expected GoLand via registry fallback")
	}
	// product-info.json version preferred over registry DisplayVersion (build number)
	if found.Version != "2025.1.3" {
		t.Errorf("expected 2025.1.3, got %s", found.Version)
	}
	if found.InstallPath != `E:\JetBrains\GoLand` {
		t.Errorf("expected E:\\JetBrains\\GoLand, got %s", found.InstallPath)
	}
}

func TestIDEDetector_Windows_RegistryFallback_HKCU(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("PROGRAMFILES", `C:\Program Files`)
	mock.SetEnv("LOCALAPPDATA", `C:\Users\testuser\AppData\Local`)

	// HKLM queries fail
	mock.SetCommandError(errNotFound,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Cursor", "/d")
	mock.SetCommandError(errNotFound,
		"reg", "query", `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Cursor", "/d")

	// HKCU succeeds (per-user install)
	regOutput := "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Cursor\n" +
		"    DisplayName    REG_SZ    Cursor\n" +
		"    DisplayVersion    REG_SZ    0.50.1\n" +
		"    InstallLocation    REG_SZ    D:\\Apps\\Cursor\n"
	mock.SetCommand(regOutput, "", 0,
		"reg", "query", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Cursor", "/d")

	mock.SetDir(`D:\Apps\Cursor`)

	det := NewIDEDetector(mock)
	results := det.Detect(context.Background())

	found := findIDE(results, "cursor")
	if found == nil {
		t.Fatal("expected Cursor via HKCU registry fallback")
	}
	if found.InstallPath != `D:\Apps\Cursor` {
		t.Errorf("expected D:\\Apps\\Cursor, got %s", found.InstallPath)
	}
}

// --- readRegistryInstallInfo unit tests ---

func TestReadRegistryInstallInfo_ParsesBothFields(t *testing.T) {
	mock := executor.NewMock()
	regOutput := "HKLM\\SOFTWARE\\...\\Uninstall\\VSCode\n" +
		"    DisplayName    REG_SZ    Microsoft Visual Studio Code\n" +
		"    DisplayVersion    REG_SZ    1.96.0\n" +
		"    InstallLocation    REG_SZ    C:\\Program Files\\Microsoft VS Code\n"
	mock.SetCommand(regOutput, "", 0,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "Visual Studio Code", "/d")

	info := readRegistryInstallInfo(context.Background(), mock, "Visual Studio Code")
	if info.Version != "1.96.0" {
		t.Errorf("expected 1.96.0, got %s", info.Version)
	}
	if info.InstallLocation != `C:\Program Files\Microsoft VS Code` {
		t.Errorf("expected C:\\Program Files\\Microsoft VS Code, got %s", info.InstallLocation)
	}
}

func TestReadRegistryInstallInfo_InstallLocationWithSpaces(t *testing.T) {
	mock := executor.NewMock()
	regOutput := "HKLM\\SOFTWARE\\...\\Uninstall\\GoLand\n" +
		"    InstallLocation    REG_SZ    C:\\Program Files\\JetBrains\\GoLand 2025.1.3\n" +
		"    DisplayVersion    REG_SZ    251.26927\n"
	mock.SetCommand(regOutput, "", 0,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "GoLand", "/d")

	info := readRegistryInstallInfo(context.Background(), mock, "GoLand")
	if info.InstallLocation != `C:\Program Files\JetBrains\GoLand 2025.1.3` {
		t.Errorf("expected path with spaces, got %s", info.InstallLocation)
	}
}

func TestReadRegistryInstallInfo_NoMatch(t *testing.T) {
	mock := executor.NewMock()
	mock.SetCommandError(errNotFound,
		"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "NonExistent", "/d")
	mock.SetCommandError(errNotFound,
		"reg", "query", `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "NonExistent", "/d")
	mock.SetCommandError(errNotFound,
		"reg", "query", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/f", "NonExistent", "/d")

	info := readRegistryInstallInfo(context.Background(), mock, "NonExistent")
	if info.Version != "" || info.InstallLocation != "" {
		t.Errorf("expected empty info, got %+v", info)
	}
}

var errNotFound = fmt.Errorf("not found")

// findIDE is a test helper that locates an IDE by type in the results slice.
func findIDE(results []model.IDE, ideType string) *model.IDE {
	for i := range results {
		if results[i].IDEType == ideType {
			return &results[i]
		}
	}
	return nil
}
