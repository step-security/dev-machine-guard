package detector

import (
	"context"
	"os"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func mockDir(name string) os.DirEntry { return executor.MockDirEntry(name, true) }

func TestJetBrainsPluginDetection(t *testing.T) {
	mock := executor.NewMock()

	jbBase := "/Users/testuser/Library/Application Support/JetBrains"
	golandPlugins := jbBase + "/GoLand2024.3/plugins"

	mock.SetDirEntries(jbBase, []os.DirEntry{mockDir("GoLand2024.3")})
	mock.SetDirEntries(golandPlugins, []os.DirEntry{
		mockDir("org.jetbrains.kotlin"),
		mockDir("IdeaVIM"),
	})

	mock.SetFile(golandPlugins+"/org.jetbrains.kotlin/META-INF/plugin.xml", []byte(`<?xml version="1.0" encoding="UTF-8"?>
<idea-plugin>
  <id>org.jetbrains.kotlin</id>
  <name>Kotlin</name>
  <version>2.1.0</version>
  <vendor>JetBrains</vendor>
</idea-plugin>`))

	mock.SetFile(golandPlugins+"/IdeaVIM/META-INF/plugin.xml", []byte(`<?xml version="1.0" encoding="UTF-8"?>
<idea-plugin>
  <name>IdeaVim</name>
  <version>2.10.0</version>
  <vendor>JetBrains</vendor>
</idea-plugin>`))

	det := NewExtensionDetector(mock)
	plugins := det.DetectJetBrainsPlugins()

	if len(plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(plugins))
	}

	found := map[string]bool{}
	for _, p := range plugins {
		found[p.Name] = true
		if p.IDEType != "goland" {
			t.Errorf("expected ide_type goland, got %s for plugin %s", p.IDEType, p.Name)
		}
	}
	if !found["Kotlin"] {
		t.Error("expected Kotlin plugin to be detected")
	}
	if !found["IdeaVim"] {
		t.Error("expected IdeaVim plugin to be detected")
	}
}

func TestJetBrainsPluginXMLParsing(t *testing.T) {
	mock := executor.NewMock()

	pluginDir := "/test/plugins/my-plugin"
	mock.SetFile(pluginDir+"/META-INF/plugin.xml", []byte(`<?xml version="1.0" encoding="UTF-8"?>
<idea-plugin>
  <id>com.example.myplugin</id>
  <name>My Plugin</name>
  <version>3.5.1</version>
  <vendor>Example Corp</vendor>
</idea-plugin>`))

	det := NewExtensionDetector(mock)
	ext := det.parseJetBrainsPlugin(pluginDir, "intellij_idea")

	if ext == nil {
		t.Fatal("expected plugin to be parsed")
	}
	if ext.ID != "com.example.myplugin" {
		t.Errorf("expected ID com.example.myplugin, got %s", ext.ID)
	}
	if ext.Name != "My Plugin" {
		t.Errorf("expected name My Plugin, got %s", ext.Name)
	}
	if ext.Version != "3.5.1" {
		t.Errorf("expected version 3.5.1, got %s", ext.Version)
	}
	if ext.Publisher != "Example Corp" {
		t.Errorf("expected publisher Example Corp, got %s", ext.Publisher)
	}
}

func TestJetBrainsPluginNoXML(t *testing.T) {
	mock := executor.NewMock()
	det := NewExtensionDetector(mock)
	ext := det.parseJetBrainsPlugin("/test/plugins/jar-only-plugin", "goland")
	if ext != nil {
		t.Error("expected nil for plugin without plugin.xml")
	}
}

func TestAndroidStudioPluginDetection(t *testing.T) {
	mock := executor.NewMock()

	googleBase := "/Users/testuser/Library/Application Support/Google"
	asPlugins := googleBase + "/AndroidStudio2024.2/plugins"

	mock.SetDirEntries(googleBase, []os.DirEntry{mockDir("AndroidStudio2024.2")})
	mock.SetDirEntries(asPlugins, []os.DirEntry{mockDir("flutter-plugin")})
	mock.SetFile(asPlugins+"/flutter-plugin/META-INF/plugin.xml", []byte(`<?xml version="1.0" encoding="UTF-8"?>
<idea-plugin>
  <id>io.flutter</id>
  <name>Flutter</name>
  <version>80.0.1</version>
  <vendor>flutter.dev</vendor>
</idea-plugin>`))

	det := NewExtensionDetector(mock)
	plugins := det.DetectJetBrainsPlugins()

	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].IDEType != "android_studio" {
		t.Errorf("expected ide_type android_studio, got %s", plugins[0].IDEType)
	}
	if plugins[0].Name != "Flutter" {
		t.Errorf("expected Flutter plugin, got %s", plugins[0].Name)
	}
}

func TestMatchProductDir(t *testing.T) {
	tests := []struct {
		dirName  string
		expected string
	}{
		{"GoLand2024.3", "goland"},
		{"IntelliJIdea2024.3", "intellij_idea"},
		{"IdeaIC2024.3", "intellij_idea_ce"},
		{"PyCharm2024.3", "pycharm"},
		{"PyCharmCE2024.3", "pycharm_ce"},
		{"WebStorm2024.3", "webstorm"},
		{"UnknownProduct2024.3", ""},
	}

	for _, tt := range tests {
		t.Run(tt.dirName, func(t *testing.T) {
			got := matchProductDir(tt.dirName, jetbrainsProductDir)
			if got != tt.expected {
				t.Errorf("matchProductDir(%q) = %q, want %q", tt.dirName, got, tt.expected)
			}
		})
	}
}

func TestExtensionDetector_IncludesJetBrains(t *testing.T) {
	mock := executor.NewMock()

	// VS Code extension
	mock.SetDirEntries("/Users/testuser/.vscode/extensions", []os.DirEntry{
		mockDir("ms-python.python-2024.22.0"),
	})

	// JetBrains plugin
	jbBase := "/Users/testuser/Library/Application Support/JetBrains"
	mock.SetDirEntries(jbBase, []os.DirEntry{mockDir("GoLand2024.3")})
	pluginsDir := jbBase + "/GoLand2024.3/plugins"
	mock.SetDirEntries(pluginsDir, []os.DirEntry{mockDir("IdeaVIM")})
	mock.SetFile(pluginsDir+"/IdeaVIM/META-INF/plugin.xml", []byte(
		`<idea-plugin><name>IdeaVim</name><version>2.10.0</version><vendor>JetBrains</vendor></idea-plugin>`))

	det := NewExtensionDetector(mock)
	results := det.Detect(context.Background(), nil)

	vscodeCount := 0
	jetbrainsCount := 0
	for _, r := range results {
		switch r.IDEType {
		case "vscode":
			vscodeCount++
		case "goland":
			jetbrainsCount++
		}
	}

	if vscodeCount != 1 {
		t.Errorf("expected 1 vscode extension, got %d", vscodeCount)
	}
	if jetbrainsCount != 1 {
		t.Errorf("expected 1 goland plugin, got %d", jetbrainsCount)
	}
}
