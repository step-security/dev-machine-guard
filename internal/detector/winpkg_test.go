//go:build !windows

package detector

import (
	"context"
	"os"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

const regQueryHKLM64 = `
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{4F1E1A6B-0000-0000-0000-NODEJS000001}
    DisplayName    REG_SZ    Node.js
    DisplayVersion    REG_SZ    18.20.4
    Publisher    REG_SZ    Node.js Foundation
    InstallLocation    REG_SZ    C:\Program Files\nodejs\
    InstallDate    REG_SZ    20240315
    WindowsInstaller    REG_DWORD    0x1
    EstimatedSize    REG_DWORD    0x13c68

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{HIDDEN-RUNTIME}
    DisplayName    REG_SZ    Microsoft Visual C++ 2022 X64 Minimum Runtime
    DisplayVersion    REG_SZ    14.38.33130
    SystemComponent    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KB5034441
    DisplayName    REG_SZ    Security Update for Windows (KB5034441)
    ParentKeyName    REG_SZ    OperatingSystem

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NoName
    UninstallString    REG_SZ    C:\x\uninstall.exe

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\XAMPP
    DisplayName    REG_SZ    XAMPP
    DisplayVersion    REG_SZ    8.2.12-0
    Publisher    REG_SZ    Bitnami
`

const regQueryHKLM32 = `
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip
    DisplayName    REG_SZ    7-Zip 23.01
    DisplayVersion    REG_SZ    23.01
    Publisher    REG_SZ    Igor Pavlov
`

const regQueryHKCU = `
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft VS Code
    DisplayName    REG_SZ    Microsoft Visual Studio Code (User)
    DisplayVersion    REG_SZ    1.95.3
    Publisher    REG_SZ    Microsoft Corporation

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Schniz.fnm_Microsoft.Winget.Source_8wekyb3d8bbwe
    DisplayName    REG_SZ    fnm
    DisplayVersion    REG_SZ    1.37.1
    Publisher    REG_SZ    Schniz
`

func newWinPkgMock() *executor.Mock {
	m := executor.NewMock()
	m.SetGOOS(model.PlatformWindows)
	m.SetHomeDir("/C/Users/dev")
	m.SetEnv("ProgramData", "/C/ProgramData")
	m.SetEnv("LOCALAPPDATA", "/C/Users/dev/AppData/Local")
	m.SetCommand(regQueryHKLM64, "", 0, "reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s")
	m.SetCommand(regQueryHKLM32, "", 0, "reg", "query", `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "/s")
	m.SetCommand(regQueryHKCU, "", 0, "reg", "query", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s")
	return m
}

func scanByType(results []model.SystemPackageScanResult) map[string]model.SystemPackageScanResult {
	out := map[string]model.SystemPackageScanResult{}
	for _, r := range results {
		out[r.ScanType] = r
	}
	return out
}

func TestWindowsPkgARP(t *testing.T) {
	m := newWinPkgMock()
	res := scanByType(NewWindowsPkgDetector(m).Scan(context.Background()))
	arp, ok := res["arp"]
	if !ok {
		t.Fatal("no arp result")
	}
	byName := map[string]model.SystemPackage{}
	for _, p := range arp.Packages {
		byName[p.Name] = p
	}
	if len(arp.Packages) != 5 || arp.PackagesCount != 5 {
		t.Fatalf("arp packages = %d, want 5 (hidden/update/no-name filtered): %+v", len(arp.Packages), arp.Packages)
	}
	node := byName["Node.js"]
	if node.Version != "18.20.4" || node.Vendor != "Node.js Foundation" || node.Source != "msi" ||
		node.Scope != "machine" || node.InstallPath != `C:\Program Files\nodejs\` ||
		node.InstalledSize != 0x13c68*1024 || node.InstallTimeUnix != 1710460800 {
		t.Errorf("node = %+v", node)
	}
	if p := byName["7-Zip 23.01"]; p.Arch != "x86" || p.Source != "exe" {
		t.Errorf("7-zip = %+v", p)
	}
	if p := byName["Microsoft Visual Studio Code (User)"]; p.Scope != "user" {
		t.Errorf("vscode = %+v", p)
	}
	for _, hidden := range []string{"Microsoft Visual C++ 2022 X64 Minimum Runtime", "Security Update for Windows (KB5034441)"} {
		if _, ok := byName[hidden]; ok {
			t.Errorf("%q should be filtered", hidden)
		}
	}
	if _, ok := res["choco"]; ok {
		t.Error("choco reported without a choco install")
	}
}

func TestWindowsPkgChocoScoopWinget(t *testing.T) {
	m := newWinPkgMock()
	// Chocolatey.
	m.SetDirEntries("/C/ProgramData/chocolatey/lib", []os.DirEntry{
		executor.MockDirEntry("nodejs.install", true),
		executor.MockDirEntry("broken", true),
	})
	m.SetFile("/C/ProgramData/chocolatey/lib/nodejs.install/nodejs.install.nuspec", []byte(`<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>nodejs.install</id>
    <version>20.11.1</version>
    <authors>Node.js Foundation</authors>
    <owners>chocolatey-community</owners>
    <projectUrl>https://nodejs.org/</projectUrl>
  </metadata>
</package>`))
	m.SetFile("/C/ProgramData/chocolatey/lib/broken/broken.nuspec", []byte(`not xml`))
	// Scoop (user).
	m.SetDirEntries("/C/Users/dev/scoop/apps", []os.DirEntry{
		executor.MockDirEntry("php", true),
		executor.MockDirEntry("nodejs-lts", true),
	})
	m.SetFile("/C/Users/dev/scoop/apps/php/current/manifest.json", []byte(`{"version":"8.3.1","homepage":"https://php.net","license":"PHP-3.01"}`))
	m.SetFile("/C/Users/dev/scoop/apps/php/current/install.json", []byte(`{"bucket":"main","architecture":"64bit"}`))
	m.SetSymlink("/C/Users/dev/scoop/apps/php/current", "/C/Users/dev/scoop/apps/php/8.3.1")
	// Scoop 0.6 names its files scoop-manifest.json / scoop-install.json.
	m.SetFile("/C/Users/dev/scoop/apps/nodejs-lts/current/scoop-manifest.json", []byte(`{"version":"20.11.1","license":{"identifier":"MIT"}}`))
	m.SetFile("/C/Users/dev/scoop/apps/nodejs-lts/current/scoop-install.json", []byte(`{"bucket":"main"}`))
	// winget portable.
	m.SetDirEntries("/C/Users/dev/AppData/Local/Microsoft/WinGet/Packages", []os.DirEntry{
		executor.MockDirEntry("Schniz.fnm_Microsoft.Winget.Source_8wekyb3d8bbwe", true),
	})

	res := scanByType(NewWindowsPkgDetector(m).Scan(context.Background()))

	choco := res["choco"]
	if len(choco.Packages) != 1 || choco.Packages[0].Name != "nodejs.install" || choco.Packages[0].Version != "20.11.1" ||
		choco.Packages[0].Vendor != "Node.js Foundation" || choco.Packages[0].Maintainer != "chocolatey-community" {
		t.Errorf("choco = %+v", choco.Packages)
	}
	scoop := res["scoop"]
	if len(scoop.Packages) != 2 {
		t.Fatalf("scoop = %+v", scoop.Packages)
	}
	for _, p := range scoop.Packages {
		switch p.Name {
		case "php":
			if p.Version != "8.3.1" || p.Source != "main" || p.Arch != "64bit" || p.License != "PHP-3.01" ||
				p.InstallPath != "/C/Users/dev/scoop/apps/php/8.3.1" || p.Scope != "user" {
				t.Errorf("scoop php = %+v", p)
			}
		case "nodejs-lts":
			if p.Version != "20.11.1" || p.License != "MIT" || p.Source != "main" {
				t.Errorf("scoop node = %+v", p)
			}
		}
	}
	winget := res["winget"]
	if len(winget.Packages) != 1 {
		t.Fatalf("winget = %+v", winget.Packages)
	}
	if p := winget.Packages[0]; p.Name != "Schniz.fnm" || p.Version != "1.37.1" || p.Vendor != "Schniz" ||
		p.Source != "Microsoft.Winget.Source_8wekyb3d8bbwe" || p.Scope != "user" {
		t.Errorf("winget = %+v", p)
	}
}

func TestWindowsPkgNonWindowsIsNil(t *testing.T) {
	m := executor.NewMock()
	m.SetGOOS(model.PlatformLinux)
	if got := NewWindowsPkgDetector(m).Scan(context.Background()); got != nil {
		t.Fatalf("got %+v on linux", got)
	}
}

// A winget portable package installed for both machine and user keeps each
// scope's own ARP version/publisher; same-label ARP entries in different
// install dirs stay separate.
func TestWindowsPkgScopeAndIdentity(t *testing.T) {
	m := executor.NewMock()
	m.SetGOOS(model.PlatformWindows)
	m.SetHomeDir("/C/Users/dev")
	m.SetEnv("ProgramData", "/C/ProgramData")
	m.SetEnv("LOCALAPPDATA", "/C/Users/dev/AppData/Local")
	m.SetEnv("ProgramFiles", "/C/Program Files")
	m.SetCommand(`
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tool.X_Microsoft.Winget.Source_8wekyb3d8bbwe
    DisplayName    REG_SZ    Tool X
    DisplayVersion    REG_SZ    1.0.0
    Publisher    REG_SZ    Machine Pub

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppA
    DisplayName    REG_SZ    App
    DisplayVersion    REG_SZ    5.0
    Publisher    REG_SZ    Vendor
    InstallLocation    REG_SZ    C:\Program Files\App

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppB
    DisplayName    REG_SZ    App
    DisplayVersion    REG_SZ    5.0
    Publisher    REG_SZ    Vendor
    InstallLocation    REG_SZ    D:\Tools\App
`, "", 0, "reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s")
	m.SetCommand(`
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Tool.X_Microsoft.Winget.Source_8wekyb3d8bbwe
    DisplayName    REG_SZ    Tool X
    DisplayVersion    REG_SZ    2.0.0
    Publisher    REG_SZ    User Pub
`, "", 0, "reg", "query", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s")
	m.SetDirEntries("/C/Users/dev/AppData/Local/Microsoft/WinGet/Packages", []os.DirEntry{executor.MockDirEntry("Tool.X_Microsoft.Winget.Source_8wekyb3d8bbwe", true)})
	m.SetDirEntries("/C/Program Files/WinGet/Packages", []os.DirEntry{executor.MockDirEntry("Tool.X_Microsoft.Winget.Source_8wekyb3d8bbwe", true)})

	res := scanByType(NewWindowsPkgDetector(m).Scan(context.Background()))
	for _, p := range res["winget"].Packages {
		want := map[string][2]string{"user": {"2.0.0", "User Pub"}, "machine": {"1.0.0", "Machine Pub"}}[p.Scope]
		if p.Version != want[0] || p.Vendor != want[1] {
			t.Errorf("winget %s scope got %s/%s, want %v", p.Scope, p.Version, p.Vendor, want)
		}
	}
	if n := len(res["winget"].Packages); n != 2 {
		t.Fatalf("winget packages = %d, want 2", n)
	}
	apps := 0
	for _, p := range res["arp"].Packages {
		if p.Name == "App" {
			apps++
		}
	}
	if apps != 2 {
		t.Errorf("same-label installs in different dirs collapsed: %d App entries, want 2", apps)
	}
}
