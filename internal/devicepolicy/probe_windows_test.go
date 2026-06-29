//go:build windows

package devicepolicy

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// testPolicyKeyPath is a disposable key under HKCU (no elevation needed) used
// to exercise the same probe logic ProbeManagedPolicy runs against the real
// HKLM/HKCU policy paths.
const testPolicyKeyPath = `SOFTWARE\StepSecurityTest\DevicePolicyProbe`

func hkcuProbe(name, path string) registryProbe {
	return registryProbe{root: registry.CURRENT_USER, name: name, path: path}
}

func stageTestPolicyKey(t *testing.T) registry.Key {
	t.Helper()
	k, _, err := registry.CreateKey(registry.CURRENT_USER, testPolicyKeyPath,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("create test key: %v", err)
	}
	t.Cleanup(func() {
		k.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, testPolicyKeyPath)
		_ = registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\StepSecurityTest`)
	})
	return k
}

func TestProbeRegistry(t *testing.T) {
	// Absent key → not managed.
	if managed, _ := probeRegistry(hkcuProbe("HKCU", testPolicyKeyPath)); managed {
		t.Fatal("absent key: want managed=false")
	}

	k := stageTestPolicyKey(t)

	// Key exists but value absent → not managed.
	if managed, _ := probeRegistry(hkcuProbe("HKCU", testPolicyKeyPath)); managed {
		t.Fatal("key without value: want managed=false")
	}

	// String value present → managed.
	if err := k.SetStringValue(allowedExtensionsName, `{"a":true}`); err != nil {
		t.Fatal(err)
	}
	managed, detail := probeRegistry(hkcuProbe("HKCU", testPolicyKeyPath))
	if !managed || !strings.HasPrefix(detail, `HKCU\`) {
		t.Fatalf("string value present: want managed=true with HKCU detail, got (%v, %q)", managed, detail)
	}

	// Wrong-typed value still counts: VS Code claims the setting on existence.
	if err := k.DeleteValue(allowedExtensionsName); err != nil {
		t.Fatal(err)
	}
	if err := k.SetDWordValue(allowedExtensionsName, 1); err != nil {
		t.Fatal(err)
	}
	if managed, _ := probeRegistry(hkcuProbe("HKCU", testPolicyKeyPath)); !managed {
		t.Fatal("dword value present: want managed=true")
	}
}

func TestProbeRegistryLocationsFallsBackToSecond(t *testing.T) {
	// Mirrors vscode-policy-watcher's HKLM→HKCU fallback: the first location
	// has no policy key, the second holds the value — the probe must walk past
	// the miss and find it (this is the user-scope GPO / user-targeted Intune
	// case). Both locations live under HKCU so the test needs no elevation;
	// production differs only in the hives probed.
	k := stageTestPolicyKey(t)
	if err := k.SetStringValue(allowedExtensionsName, `{"a":true}`); err != nil {
		t.Fatal(err)
	}

	locs := []registryProbe{
		hkcuProbe("FIRST", testPolicyKeyPath+`\Missing`),
		hkcuProbe("SECOND", testPolicyKeyPath),
	}
	managed, detail := probeRegistryLocations(locs)
	if !managed || !strings.HasPrefix(detail, `SECOND\`) {
		t.Fatalf("want fallback hit (true, SECOND\\...), got (%v, %q)", managed, detail)
	}

	// First location wins when both hold the value (precedence order).
	locs[0] = hkcuProbe("FIRST", testPolicyKeyPath)
	managed, detail = probeRegistryLocations(locs)
	if !managed || !strings.HasPrefix(detail, `FIRST\`) {
		t.Fatalf("want precedence hit (true, FIRST\\...), got (%v, %q)", managed, detail)
	}

	// No location holds a policy → not managed.
	if managed, _ := probeRegistryLocations([]registryProbe{
		hkcuProbe("FIRST", testPolicyKeyPath+`\Missing`),
	}); managed {
		t.Fatal("all locations missing: want managed=false")
	}
}
