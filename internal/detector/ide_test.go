package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
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
