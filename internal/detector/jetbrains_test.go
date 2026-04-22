package detector

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestJetBrainsPluginDetector_macOS(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHomeDir("/Users/testuser")

	// GoLand installed with product-info.json (productVendor determines config path)
	mock.SetFile("/Applications/GoLand.app/Contents/Resources/product-info.json",
		[]byte(`{"name":"GoLand","version":"2025.1.3","dataDirectoryName":"GoLand2025.1","productVendor":"JetBrains"}`))

	// User-installed plugins directory
	pluginsDir := "/Users/testuser/Library/Application Support/JetBrains/GoLand2025.1/plugins"
	mock.SetDir(pluginsDir)

	// IdeaVIM plugin
	ideaVimDir := pluginsDir + "/IdeaVIM"
	mock.SetDirEntries(pluginsDir, []os.DirEntry{
		&mockDirEntry{name: "IdeaVIM", isDir: true},
	})

	ideaVimLib := ideaVimDir + "/lib"
	mock.SetDirEntries(ideaVimLib, []os.DirEntry{
		&mockDirEntry{name: "IdeaVIM-2.27.2.jar"},
		&mockDirEntry{name: "IdeaVIM-2.27.2-searchableOptions.jar"},
		&mockDirEntry{name: "vim-engine-2.27.2.jar"},
		&mockDirEntry{name: "antlr4-runtime-4.13.2.jar"},
	})

	mock.SetFileInfo(ideaVimDir, &testFileInfo{
		name: "IdeaVIM", dir: true,
	})

	ides := []model.IDE{
		{IDEType: "goland", InstallPath: "/Applications/GoLand.app", Vendor: "JetBrains"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(results))
	}
	if results[0].ID != "IdeaVIM" {
		t.Errorf("expected ID IdeaVIM, got %s", results[0].ID)
	}
	if results[0].Version != "2.27.2" {
		t.Errorf("expected version 2.27.2, got %s", results[0].Version)
	}
	if results[0].IDEType != "goland" {
		t.Errorf("expected IDEType goland, got %s", results[0].IDEType)
	}
}

func TestJetBrainsPluginDetector_Windows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("APPDATA", `C:\Users\dev\AppData\Roaming`)

	// IntelliJ CE installed
	installPath := `C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2024.3.2`
	productInfoPath := installPath + "/product-info.json"
	mock.SetFile(productInfoPath,
		[]byte(`{"name":"IntelliJ IDEA","version":"2024.3.2","dataDirectoryName":"IdeaIC2024.3","productVendor":"JetBrains"}`))

	// User plugins directory
	pluginsDir := `C:\Users\dev\AppData\Roaming/JetBrains/IdeaIC2024.3/plugins`
	mock.SetDir(pluginsDir)
	mock.SetDirEntries(pluginsDir, []os.DirEntry{
		&mockDirEntry{name: "Kotlin", isDir: true},
		&mockDirEntry{name: "some-file.txt"}, // non-directory, should be skipped
	})

	kotlinLib := pluginsDir + "/Kotlin/lib"
	mock.SetDirEntries(kotlinLib, []os.DirEntry{
		&mockDirEntry{name: "Kotlin-251.123.45.jar"},
		&mockDirEntry{name: "kotlin-stdlib-1.9.0.jar"},
	})

	mock.SetFileInfo(pluginsDir+"/Kotlin", &testFileInfo{name: "Kotlin", dir: true})

	ides := []model.IDE{
		{IDEType: "intellij_idea_ce", InstallPath: installPath, Vendor: "JetBrains"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(results))
	}
	if results[0].ID != "Kotlin" {
		t.Errorf("expected ID Kotlin, got %s", results[0].ID)
	}
	if results[0].Version != "251.123.45" {
		t.Errorf("expected version 251.123.45, got %s", results[0].Version)
	}
	if results[0].IDEType != "intellij_idea_ce" {
		t.Errorf("expected IDEType intellij_idea_ce, got %s", results[0].IDEType)
	}
}

func TestJetBrainsPluginDetector_MultipleIDEs(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHomeDir("/Users/testuser")

	// GoLand
	mock.SetFile("/Applications/GoLand.app/Contents/Resources/product-info.json",
		[]byte(`{"dataDirectoryName":"GoLand2025.1"}`))
	golandPlugins := "/Users/testuser/Library/Application Support/JetBrains/GoLand2025.1/plugins"
	mock.SetDir(golandPlugins)
	mock.SetDirEntries(golandPlugins, []os.DirEntry{
		&mockDirEntry{name: "IdeaVIM", isDir: true},
	})
	mock.SetDirEntries(golandPlugins+"/IdeaVIM/lib", []os.DirEntry{
		&mockDirEntry{name: "IdeaVIM-2.27.2.jar"},
	})
	mock.SetFileInfo(golandPlugins+"/IdeaVIM", &testFileInfo{name: "IdeaVIM", dir: true})

	// PyCharm — no plugins installed (empty dir)
	mock.SetFile("/Applications/PyCharm CE.app/Contents/Resources/product-info.json",
		[]byte(`{"dataDirectoryName":"PyCharmCE2025.1"}`))
	pycharmPlugins := "/Users/testuser/Library/Application Support/JetBrains/PyCharmCE2025.1/plugins"
	mock.SetDir(pycharmPlugins)
	mock.SetDirEntries(pycharmPlugins, []os.DirEntry{})

	ides := []model.IDE{
		{IDEType: "goland", InstallPath: "/Applications/GoLand.app", Vendor: "JetBrains"},
		{IDEType: "pycharm_ce", InstallPath: "/Applications/PyCharm CE.app", Vendor: "JetBrains"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 1 {
		t.Fatalf("expected 1 plugin (from GoLand only), got %d", len(results))
	}
	if results[0].IDEType != "goland" {
		t.Errorf("expected goland, got %s", results[0].IDEType)
	}
}

func TestJetBrainsPluginDetector_NoProductInfo(t *testing.T) {
	mock := executor.NewMock()

	// VS Code — no product-info.json, should be silently skipped
	ides := []model.IDE{
		{IDEType: "vscode", InstallPath: "/Applications/Visual Studio Code.app", Vendor: "Microsoft"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 0 {
		t.Errorf("expected 0 plugins for VS Code, got %d", len(results))
	}
}

func TestJetBrainsPluginDetector_NoPluginsDir(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHomeDir("/Users/testuser")

	// IDE installed but never launched (no config dir created)
	mock.SetFile("/Applications/GoLand.app/Contents/Resources/product-info.json",
		[]byte(`{"dataDirectoryName":"GoLand2025.1"}`))
	// plugins dir does NOT exist

	ides := []model.IDE{
		{IDEType: "goland", InstallPath: "/Applications/GoLand.app", Vendor: "JetBrains"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 0 {
		t.Errorf("expected 0 plugins (IDE never launched), got %d", len(results))
	}
}

func TestJetBrainsPluginDetector_VersionFromCaseInsensitiveJAR(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHomeDir("/Users/testuser")

	mock.SetFile("/Applications/GoLand.app/Contents/Resources/product-info.json",
		[]byte(`{"dataDirectoryName":"GoLand2025.1"}`))

	pluginsDir := "/Users/testuser/Library/Application Support/JetBrains/GoLand2025.1/plugins"
	mock.SetDir(pluginsDir)
	mock.SetDirEntries(pluginsDir, []os.DirEntry{
		&mockDirEntry{name: "ej", isDir: true},
	})

	// JAR name starts with directory name (case-insensitive match)
	mock.SetDirEntries(pluginsDir+"/ej/lib", []os.DirEntry{
		&mockDirEntry{name: "ej-251.204.122.jar"},
		&mockDirEntry{name: "model-gec-jvm-0.4.32.jar"},
	})
	mock.SetFileInfo(pluginsDir+"/ej", &testFileInfo{name: "ej", dir: true})

	ides := []model.IDE{
		{IDEType: "goland", InstallPath: "/Applications/GoLand.app"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(results))
	}
	if results[0].Version != "251.204.122" {
		t.Errorf("expected 251.204.122, got %s", results[0].Version)
	}
}

func TestJetBrainsPluginDetector_NoMatchingJAR(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHomeDir("/Users/testuser")

	mock.SetFile("/Applications/GoLand.app/Contents/Resources/product-info.json",
		[]byte(`{"dataDirectoryName":"GoLand2025.1"}`))

	pluginsDir := "/Users/testuser/Library/Application Support/JetBrains/GoLand2025.1/plugins"
	mock.SetDir(pluginsDir)
	mock.SetDirEntries(pluginsDir, []os.DirEntry{
		&mockDirEntry{name: "mystery-plugin", isDir: true},
	})

	// No JAR matches the directory name
	mock.SetDirEntries(pluginsDir+"/mystery-plugin/lib", []os.DirEntry{
		&mockDirEntry{name: "completely-different-1.0.0.jar"},
	})
	mock.SetFileInfo(pluginsDir+"/mystery-plugin", &testFileInfo{name: "mystery-plugin", dir: true})

	ides := []model.IDE{
		{IDEType: "goland", InstallPath: "/Applications/GoLand.app"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(results))
	}
	if results[0].Version != "unknown" {
		t.Errorf("expected unknown version, got %s", results[0].Version)
	}
}

func TestJetBrainsPluginDetector_AndroidStudio_GoogleVendor(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHomeDir("/Users/testuser")

	// Android Studio uses "Google" as productVendor — different config path
	mock.SetFile("/Applications/Android Studio.app/Contents/Resources/product-info.json",
		[]byte(`{"name":"Android Studio","dataDirectoryName":"AndroidStudio2024.2","productVendor":"Google","productCode":"AI"}`))

	// Plugins are under ~/Library/Application Support/Google/ not JetBrains/
	pluginsDir := "/Users/testuser/Library/Application Support/Google/AndroidStudio2024.2/plugins"
	mock.SetDir(pluginsDir)
	mock.SetDirEntries(pluginsDir, []os.DirEntry{
		&mockDirEntry{name: "flutter-intellij", isDir: true},
	})
	mock.SetDirEntries(pluginsDir+"/flutter-intellij/lib", []os.DirEntry{
		&mockDirEntry{name: "flutter-intellij-82.0.3.jar"},
	})
	mock.SetFileInfo(pluginsDir+"/flutter-intellij", &testFileInfo{name: "flutter-intellij", dir: true})

	ides := []model.IDE{
		{IDEType: "android_studio", InstallPath: "/Applications/Android Studio.app", Vendor: "Google"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(results))
	}
	if results[0].ID != "flutter-intellij" {
		t.Errorf("expected flutter-intellij, got %s", results[0].ID)
	}
	if results[0].Version != "82.0.3" {
		t.Errorf("expected 82.0.3, got %s", results[0].Version)
	}
	if results[0].IDEType != "android_studio" {
		t.Errorf("expected android_studio, got %s", results[0].IDEType)
	}
}

func TestJetBrainsPluginDetector_Windows_AndroidStudio_LocalAppData(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetEnv("APPDATA", `C:\Users\dev\AppData\Roaming`)
	mock.SetEnv("LOCALAPPDATA", `C:\Users\dev\AppData\Local`)

	installPath := `C:\Program Files\Android\Android Studio`
	mock.SetFile(installPath+"/product-info.json",
		[]byte(`{"dataDirectoryName":"AndroidStudio2024.2","productVendor":"Google"}`))

	// Android Studio config is under LOCALAPPDATA\Google\ on Windows
	configDir := `C:\Users\dev\AppData\Local/Google/AndroidStudio2024.2`
	pluginsDir := configDir + "/plugins"
	mock.SetDir(configDir)
	mock.SetDir(pluginsDir)
	mock.SetDirEntries(pluginsDir, []os.DirEntry{
		&mockDirEntry{name: "Dart", isDir: true},
	})
	mock.SetDirEntries(pluginsDir+"/Dart/lib", []os.DirEntry{
		&mockDirEntry{name: "Dart-242.100.200.jar"},
	})
	mock.SetFileInfo(pluginsDir+"/Dart", &testFileInfo{name: "Dart", dir: true})

	ides := []model.IDE{
		{IDEType: "android_studio", InstallPath: installPath, Vendor: "Google"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(results))
	}
	if results[0].ID != "Dart" {
		t.Errorf("expected Dart, got %s", results[0].ID)
	}
}

func TestJetBrainsPluginDetector_CustomPluginsPath(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHomeDir("/Users/testuser")

	mock.SetFile("/Applications/GoLand.app/Contents/Resources/product-info.json",
		[]byte(`{"dataDirectoryName":"GoLand2025.1","productVendor":"JetBrains"}`))

	// idea.properties overrides the plugin directory
	configDir := "/Users/testuser/Library/Application Support/JetBrains/GoLand2025.1"
	mock.SetFile(configDir+"/idea.properties",
		[]byte("# Custom config\nidea.plugins.path=/custom/plugins/dir\n"))

	// Plugins are at the custom location, not the default
	customDir := "/custom/plugins/dir"
	mock.SetDir(customDir)
	mock.SetDirEntries(customDir, []os.DirEntry{
		&mockDirEntry{name: "MyPlugin", isDir: true},
	})
	mock.SetDirEntries(customDir+"/MyPlugin/lib", []os.DirEntry{
		&mockDirEntry{name: "MyPlugin-3.0.0.jar"},
	})
	mock.SetFileInfo(customDir+"/MyPlugin", &testFileInfo{name: "MyPlugin", dir: true})

	ides := []model.IDE{
		{IDEType: "goland", InstallPath: "/Applications/GoLand.app"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	if len(results) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(results))
	}
	if results[0].ID != "MyPlugin" {
		t.Errorf("expected MyPlugin, got %s", results[0].ID)
	}
	if results[0].Version != "3.0.0" {
		t.Errorf("expected 3.0.0, got %s", results[0].Version)
	}
}

func TestJetBrainsPluginDetector_IdeaProperties_CommentedOut(t *testing.T) {
	mock := executor.NewMock()
	mock.SetHomeDir("/Users/testuser")

	mock.SetFile("/Applications/GoLand.app/Contents/Resources/product-info.json",
		[]byte(`{"dataDirectoryName":"GoLand2025.1","productVendor":"JetBrains"}`))

	// idea.properties exists but plugin path is commented out — should use default
	configDir := "/Users/testuser/Library/Application Support/JetBrains/GoLand2025.1"
	mock.SetFile(configDir+"/idea.properties",
		[]byte("# idea.plugins.path=/old/path\n"))

	defaultPluginsDir := configDir + "/plugins"
	mock.SetDir(defaultPluginsDir)
	mock.SetDirEntries(defaultPluginsDir, []os.DirEntry{})

	ides := []model.IDE{
		{IDEType: "goland", InstallPath: "/Applications/GoLand.app"},
	}

	det := NewJetBrainsPluginDetector(mock)
	results := det.Detect(context.Background(), ides)

	// No plugins, but importantly no crash — default path was used
	if len(results) != 0 {
		t.Errorf("expected 0 plugins, got %d", len(results))
	}
}

// mockDirEntry implements os.DirEntry for testing.
type mockDirEntry struct {
	name  string
	isDir bool
}

func (e *mockDirEntry) Name() string      { return e.name }
func (e *mockDirEntry) IsDir() bool       { return e.isDir }
func (e *mockDirEntry) Type() os.FileMode { return 0 }
func (e *mockDirEntry) Info() (os.FileInfo, error) {
	return &testFileInfo{name: e.name, dir: e.isDir}, nil
}

// testFileInfo implements os.FileInfo for testing.
type testFileInfo struct {
	name string
	dir  bool
}

func (fi *testFileInfo) Name() string       { return fi.name }
func (fi *testFileInfo) Size() int64        { return 0 }
func (fi *testFileInfo) IsDir() bool        { return fi.dir }
func (fi *testFileInfo) ModTime() time.Time { return time.Time{} }
func (fi *testFileInfo) Mode() os.FileMode  { return 0o644 }
func (fi *testFileInfo) Sys() any           { return nil }
