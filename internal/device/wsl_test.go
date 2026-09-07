package device

import (
	"context"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// utf16le encodes s as UTF-16LE bytes wrapped in a Go string, mimicking what
// wsl.exe writes to stdout when WSL_UTF8 is unset.
func utf16le(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return string(b)
}

const (
	lxssKey  = `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss`
	svcWSL   = `HKLM\SYSTEM\CurrentControlSet\Services\WslService`
	svcLxss  = `HKLM\SYSTEM\CurrentControlSet\Services\LxssManager`
	unKey    = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	unWOWKey = `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
)

func winMock() *executor.Mock {
	m := executor.NewMock()
	m.SetGOOS(model.PlatformWindows)
	return m
}

func TestGatherWSL_NilOffWindows(t *testing.T) {
	m := executor.NewMock() // default GOOS is this host (non-Windows in CI)
	m.SetGOOS(model.PlatformLinux)
	if got := GatherWSL(context.Background(), m); got != nil {
		t.Fatalf("expected nil off Windows, got %+v", got)
	}
}

func TestGatherWSL_PresentRunningWSL1(t *testing.T) {
	m := winMock()
	m.SetCommand(`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss
    DefaultDistribution    REG_SZ    {guid-a}
    DefaultVersion    REG_DWORD    0x1

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\{guid-a}
    DistributionName    REG_SZ    Ubuntu-24.04
    Version    REG_DWORD    0x2
    Flags    REG_DWORD    0x7
    BasePath    REG_SZ    C:\Users\Administrator\AppData\Local\wsl\{guid-a}
`, "", 0, "reg", "query", lxssKey, "/s")
	m.SetCommand("", "", 0, "reg", "query", svcWSL) // WslService present
	m.SetCommand(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{497CB23D}
    DisplayName    REG_SZ    Windows Subsystem for Linux
    DisplayVersion    REG_SZ    2.7.11.0
`, "", 0, "reg", "query", unKey, "/s")
	// distro is running (UTF-16LE, as the real wsl.exe emits)
	m.SetCommand(utf16le("Ubuntu-24.04\r\n"), "", 0, "wsl.exe", "--list", "--running", "--quiet")

	info := GatherWSL(context.Background(), m)
	if info == nil {
		t.Fatal("expected WSLInfo, got nil")
	}
	if info.Presence != model.WSLPresenceYes {
		t.Errorf("presence = %q, want yes", info.Presence)
	}
	if !info.Installed {
		t.Error("installed = false, want true")
	}
	if info.Version != "2.7.11.0" {
		t.Errorf("version = %q, want 2.7.11.0", info.Version)
	}
	if !info.Active {
		t.Error("active = false, want true (distro running)")
	}
	if len(info.Distros) != 1 {
		t.Fatalf("distros = %d, want 1", len(info.Distros))
	}
	d := info.Distros[0]
	if d.Name != "Ubuntu-24.04" || d.WSLVersion != 1 || !d.Default || !d.Running {
		t.Errorf("distro = %+v, want {Ubuntu-24.04 v1 default running}", d)
	}
	if d.BasePath == "" {
		t.Error("base path not captured")
	}
}

func TestGatherWSL_PresentWSL2NotRunning(t *testing.T) {
	m := winMock()
	m.SetCommand(`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss
    DefaultDistribution    REG_SZ    {guid-b}

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\{guid-b}
    DistributionName    REG_SZ    Debian
    Flags    REG_DWORD    0xf
`, "", 0, "reg", "query", lxssKey, "/s")
	m.SetCommand("", "", 0, "reg", "query", svcWSL)
	m.SetCommand("", "", 1, "reg", "query", unKey, "/s")
	m.SetCommand("", "", 1, "reg", "query", unWOWKey, "/s")
	m.SetCommand("", "", 0, "wsl.exe", "--list", "--running", "--quiet") // nothing running

	info := GatherWSL(context.Background(), m)
	if info.Presence != model.WSLPresenceYes {
		t.Fatalf("presence = %q, want yes", info.Presence)
	}
	if info.Active {
		t.Error("active = true, want false")
	}
	if info.Version != "unknown" {
		t.Errorf("version = %q, want unknown floor", info.Version)
	}
	if len(info.Distros) != 1 || info.Distros[0].WSLVersion != 2 {
		t.Fatalf("distros = %+v, want one v2", info.Distros)
	}
	if info.Distros[0].Running {
		t.Error("distro marked running, want stopped")
	}
}

func TestGatherWSL_AbsentIsNoNotUnknown(t *testing.T) {
	m := winMock()
	m.SetCommand("", "", 1, "reg", "query", lxssKey, "/s") // key absent, probe worked
	m.SetCommand("", "", 1, "reg", "query", svcWSL)        // service absent
	m.SetCommand("", "", 1, "reg", "query", svcLxss)       // legacy absent

	info := GatherWSL(context.Background(), m)
	if info.Presence != model.WSLPresenceNo {
		t.Errorf("presence = %q, want no", info.Presence)
	}
	if info.Installed || info.Active {
		t.Error("installed/active should be false when absent")
	}
}

func TestGatherWSL_ProbeFailureIsUnknown(t *testing.T) {
	m := winMock() // nothing stubbed → reg/wsl invocations error out
	info := GatherWSL(context.Background(), m)
	if info.Presence != model.WSLPresenceUnknown {
		t.Errorf("presence = %q, want unknown when the registry can't be read", info.Presence)
	}
}

func TestDecodeWinCLI(t *testing.T) {
	if got := decodeWinCLI(utf16le("Ubuntu-24.04\r\n")); got != "Ubuntu-24.04\n" {
		t.Errorf("utf16le decode = %q, want %q", got, "Ubuntu-24.04\n")
	}
	if got := decodeWinCLI("Ubuntu\r\n"); got != "Ubuntu\n" { // already UTF-8
		t.Errorf("utf8 passthrough = %q", got)
	}
	// UTF-16LE with BOM
	if got := decodeWinCLI("\xff\xfe" + utf16le("x")); got != "x" {
		t.Errorf("bom-stripped decode = %q, want x", got)
	}
}

func TestWSLVersionFromFlags(t *testing.T) {
	if wslVersionFromFlags(0x7) != 1 {
		t.Error("0x7 should map to WSL1")
	}
	if wslVersionFromFlags(0xF) != 2 {
		t.Error("0xF should map to WSL2")
	}
}

// TestGatherWSL_CapturesDistroIDAndDefaultUID pins the two fields the WSL-guest
// identity work depends on: the registry key GUID, and the uid `wsl -e` will run
// as. Both come from the same read, so a regression in one usually breaks both.
func TestGatherWSL_CapturesDistroIDAndDefaultUID(t *testing.T) {
	m := winMock()
	m.SetCommand(`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss
    DefaultDistribution    REG_SZ    {guid-a}

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\{guid-a}
    DistributionName    REG_SZ    Debian
    Flags    REG_DWORD    0xf
    DefaultUid    REG_DWORD    0x3e8
    BasePath    REG_SZ    C:\Users\dev\AppData\Local\wsl\{guid-a}

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\{guid-b}
    DistributionName    REG_SZ    Alpine-WSL1
    Flags    REG_DWORD    0x7
    BasePath    REG_SZ    C:\wsl1\Alpine-WSL1
`, "", 0, "reg", "query", lxssKey, "/s")
	m.SetCommand("", "", 0, "reg", "query", svcWSL)
	m.SetCommand(utf16le(""), "", 0, "wsl.exe", "--list", "--running", "--quiet")

	info := GatherWSL(context.Background(), m)
	if info == nil {
		t.Fatal("expected WSLInfo, got nil")
	}
	byName := map[string]model.WSLDistro{}
	for _, d := range info.Distros {
		byName[d.Name] = d
	}
	if len(byName) != 2 {
		t.Fatalf("distros = %d, want 2", len(byName))
	}

	deb := byName["Debian"]
	if deb.DistroID != "{guid-a}" {
		t.Errorf("Debian distro_id = %q, want {guid-a}", deb.DistroID)
	}
	if deb.DefaultUID == nil || *deb.DefaultUID != 1000 {
		t.Errorf("Debian default_uid = %v, want 1000", deb.DefaultUID)
	}

	// An imported distro carries no GUID in its BasePath — the whole reason the
	// id must come from the key name and never from the path.
	alp := byName["Alpine-WSL1"]
	if alp.DistroID != "{guid-b}" {
		t.Errorf("Alpine distro_id = %q, want {guid-b} (imported distro: path has no GUID)", alp.DistroID)
	}
	if strings.Contains(alp.BasePath, "{") {
		t.Fatalf("test fixture no longer exercises the no-GUID-in-path case: %q", alp.BasePath)
	}
	if alp.DefaultUID != nil {
		t.Errorf("Alpine default_uid = %v, want nil (value absent)", *alp.DefaultUID)
	}
}

// TestGatherWSL_RootOnlyDistroIsDistinguishable guards the difference between
// "runs as root" and "we could not read the uid". Only the first justifies
// skipping a scan.
func TestGatherWSL_RootOnlyDistroIsDistinguishable(t *testing.T) {
	m := winMock()
	m.SetCommand(`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\{guid-a}
    DistributionName    REG_SZ    Imported
    Flags    REG_DWORD    0xf
    DefaultUid    REG_DWORD    0x0
`, "", 0, "reg", "query", lxssKey, "/s")
	m.SetCommand("", "", 0, "reg", "query", svcWSL)
	m.SetCommand(utf16le(""), "", 0, "wsl.exe", "--list", "--running", "--quiet")

	info := GatherWSL(context.Background(), m)
	if info == nil || len(info.Distros) != 1 {
		t.Fatalf("expected one distro, got %+v", info)
	}
	uid := info.Distros[0].DefaultUID
	if uid == nil {
		t.Fatal("default_uid = nil, want 0 — an explicit 0 must not read as unknown")
	}
	if *uid != 0 {
		t.Errorf("default_uid = %d, want 0", *uid)
	}
}

// TestWSLMayHaveRunningDistro_UnknownServiceStateStillProbes covers the gate's
// fail-open direction. Off Windows the service state is unknowable, and we would
// rather spend the probe than under-report "active".
func TestWSLMayHaveRunningDistro_UnknownServiceStateStillProbes(t *testing.T) {
	if !wslMayHaveRunningDistro(winMock()) {
		t.Error("gate closed on unknown service state; want open (probe anyway)")
	}
}

func ptrU32(v uint32) *uint32 { return &v }
