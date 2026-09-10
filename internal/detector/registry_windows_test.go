//go:build windows

package detector

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// TestReal_KiroCLIRegistryKey runs the production Kiro CLI key reader against
// a scratch HKCU key, since the mocked CLI tables only exercise the
// non-Windows `reg query` twin. Same scratch-hive pattern as
// devicepolicy/probe_windows_test.go.
func TestReal_KiroCLIRegistryKey(t *testing.T) {
	base := fmt.Sprintf(`SOFTWARE\StepSecurityTest\kiro-cli-%d`, os.Getpid())
	path := base + `\CLI`
	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	t.Cleanup(func() {
		_ = k.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, path)
		_ = registry.DeleteKey(registry.CURRENT_USER, base)
	})

	if _, _, ok := readKiroCLIKey(registry.CURRENT_USER, path+`\absent`); ok {
		t.Error("an absent key must not read as installed")
	}
	if _, _, ok := readKiroCLIKey(registry.CURRENT_USER, path); ok {
		t.Error("a key without InstallPath must not read as installed")
	}
	if err := k.SetStringValue("InstallPath", `C:\Users\u\AppData\Local\Kiro-Cli`); err != nil {
		t.Fatal(err)
	}
	install, version, ok := readKiroCLIKey(registry.CURRENT_USER, path)
	if !ok || install != `C:\Users\u\AppData\Local\Kiro-Cli` || version != "" {
		t.Errorf("InstallPath only: got (%q, %q, %v)", install, version, ok)
	}
	if err := k.SetStringValue("ProductVersion", "2.21.1.0"); err != nil {
		t.Fatal(err)
	}
	if install, version, ok = readKiroCLIKey(registry.CURRENT_USER, path); !ok || version != "2.21.1.0" {
		t.Errorf("with ProductVersion: got (%q, %q, %v)", install, version, ok)
	}
}
