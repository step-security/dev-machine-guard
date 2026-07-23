//go:build windows

package devicepolicy

import (
	"encoding/json"
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

// stageTestPolicyKeyAt creates a disposable HKCU key at an arbitrary path (for
// the multi-hive fallback tests) and deletes it on cleanup.
func stageTestPolicyKeyAt(t *testing.T, path string) registry.Key {
	t.Helper()
	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("create test key %s: %v", path, err)
	}
	t.Cleanup(func() {
		k.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, path)
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

	// Wrong-typed value does NOT count: vscode-policy-watcher honors only REG_SZ
	// and REG_MULTI_SZ, so a DWORD is dropped (nullopt) and does not outrank user
	// settings.
	if err := k.DeleteValue(allowedExtensionsName); err != nil {
		t.Fatal(err)
	}
	if err := k.SetDWordValue(allowedExtensionsName, 1); err != nil {
		t.Fatal(err)
	}
	if managed, _ := probeRegistry(hkcuProbe("HKCU", testPolicyKeyPath)); managed {
		t.Fatal("dword value: want managed=false (VS Code ignores non-string types)")
	}

	// REG_EXPAND_SZ is likewise not honored.
	if err := k.SetExpandStringValue(allowedExtensionsName, `%APPDATA%\Code`); err != nil {
		t.Fatal(err)
	}
	if managed, _ := probeRegistry(hkcuProbe("HKCU", testPolicyKeyPath)); managed {
		t.Fatal("expand-sz value: want managed=false")
	}

	// REG_MULTI_SZ IS honored.
	if err := k.SetStringsValue(allowedExtensionsName, []string{`{"a":true}`}); err != nil {
		t.Fatal(err)
	}
	if managed, _ := probeRegistry(hkcuProbe("HKCU", testPolicyKeyPath)); !managed {
		t.Fatal("multi_sz value: want managed=true")
	}

	// Gallery-only: remove AllowedExtensions, set ExtensionGalleryServiceUrl →
	// still managed (either key yields), reported under the gallery name.
	if err := k.DeleteValue(allowedExtensionsName); err != nil {
		t.Fatal(err)
	}
	if err := k.SetStringValue(galleryServiceURLName, "https://mkt.example/api/v1"); err != nil {
		t.Fatal(err)
	}
	managed, detail = probeRegistry(hkcuProbe("HKCU", testPolicyKeyPath))
	if !managed || !strings.Contains(detail, galleryServiceURLName) {
		t.Fatalf("gallery-only: want managed=true with gallery detail, got (%v, %q)", managed, detail)
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

	// A present-but-unsupported-type value in the first location must NOT count:
	// the probe skips it and finds the honored value in the second (HKLM→HKCU).
	wrong := stageTestPolicyKeyAt(t, testPolicyKeyPath+`\WrongType`)
	if err := wrong.SetDWordValue(allowedExtensionsName, 1); err != nil {
		t.Fatal(err)
	}
	managed, detail = probeRegistryLocations([]registryProbe{
		hkcuProbe("FIRST", testPolicyKeyPath+`\WrongType`),
		hkcuProbe("SECOND", testPolicyKeyPath), // holds the valid REG_SZ set above
	})
	if !managed || !strings.HasPrefix(detail, `SECOND\`) {
		t.Fatalf("unsupported first location must not mask valid second: got (%v, %q)", managed, detail)
	}
}

// An absent key is a clean absence; a present-but-unsupported-type value is an
// error (never a silent absence).
func TestProbeRegistryContent(t *testing.T) {
	locs := []registryProbe{hkcuProbe("HKCU", testPolicyKeyPath)}

	// Absent policy key → present=false, no error.
	if present, observed, err := probeRegistryContent(locs); err != nil || present || len(observed) != 0 {
		t.Fatalf("absent: got present=%v observed=%v err=%v", present, observed, err)
	}

	k := stageTestPolicyKey(t)
	// AllowedExtensions as a stringified JSON object (REG_SZ) + gallery URL.
	if err := k.SetStringValue(allowedExtensionsName, `{"*":false,"ms-python.python":"stable"}`); err != nil {
		t.Fatal(err)
	}
	if err := k.SetStringValue(galleryServiceURLName, "https://mkt.example/api/v1"); err != nil {
		t.Fatal(err)
	}
	present, observed, err := probeRegistryContent(locs)
	if err != nil || !present {
		t.Fatalf("present: got present=%v err=%v", present, err)
	}
	got, _ := json.Marshal(observed)
	want := `{"extensions.allowed":{"*":false,"ms-python.python":"stable"},"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"}`
	if string(got) != want {
		t.Fatalf("observed = %s, want %s", got, want)
	}

	// REG_MULTI_SZ is honored too (lines joined).
	if err := k.DeleteValue(galleryServiceURLName); err != nil {
		t.Fatal(err)
	}
	if err := k.SetStringsValue(galleryServiceURLName, []string{"https://mkt.example/api/v1"}); err != nil {
		t.Fatal(err)
	}
	if present, observed, err := probeRegistryContent(locs); err != nil || !present || len(observed[galleryServiceURLSettingKey]) == 0 {
		t.Fatalf("multi_sz gallery: present=%v observed=%v err=%v", present, observed, err)
	}

	// Unsupported type (DWORD) present at the winning hive → verification_failed.
	if err := k.DeleteValue(allowedExtensionsName); err != nil {
		t.Fatal(err)
	}
	if err := k.SetDWordValue(allowedExtensionsName, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := probeRegistryContent(locs); err == nil {
		t.Fatal("unsupported-type AllowedExtensions must be verification_failed (error)")
	}

	// REG_EXPAND_SZ is NOT honored by vscode-policy-watcher (supportedTypes is
	// {REG_SZ, REG_MULTI_SZ}), so a value of that type must not read as applied.
	if err := k.DeleteValue(allowedExtensionsName); err != nil {
		t.Fatal(err)
	}
	if err := k.SetExpandStringValue(allowedExtensionsName, `%APPDATA%\Code`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := probeRegistryContent(locs); err == nil {
		t.Fatal("REG_EXPAND_SZ AllowedExtensions must be verification_failed (VS Code ignores it)")
	}
}

// TestResolveRegistryPolicyFallbackAndMasking proves each value resolves with
// its own HKLM→HKCU fallback and that an unsupported-type value never masks a
// valid value in a later hive.
func TestResolveRegistryPolicyFallbackAndMasking(t *testing.T) {
	_ = stageTestPolicyKey(t) // owns cleanup of the shared parent key
	first := stageTestPolicyKeyAt(t, testPolicyKeyPath+`\First`)
	second := stageTestPolicyKeyAt(t, testPolicyKeyPath+`\Second`)

	// First hive holds an unsupported type; second holds a valid string.
	if err := first.SetDWordValue(allowedExtensionsName, 1); err != nil {
		t.Fatal(err)
	}
	if err := second.SetStringValue(allowedExtensionsName, `{"*":false}`); err != nil {
		t.Fatal(err)
	}
	locs := []registryProbe{
		hkcuProbe("FIRST", testPolicyKeyPath+`\First`),
		hkcuProbe("SECOND", testPolicyKeyPath+`\Second`),
	}
	if v, st := resolveRegistryPolicy(allowedExtensionsName, locs); st != keyFound || v != `{"*":false}` {
		t.Fatalf("unsupported first hive must not mask valid second: got st=%v v=%q", st, v)
	}

	// Only an unsupported-type value anywhere → keyUnreadable.
	if _, st := resolveRegistryPolicy(allowedExtensionsName, locs[:1]); st != keyUnreadable {
		t.Fatalf("want keyUnreadable, got %v", st)
	}

	// Absent everywhere → keyAbsent.
	if _, st := resolveRegistryPolicy(galleryServiceURLName, locs); st != keyAbsent {
		t.Fatalf("want keyAbsent, got %v", st)
	}
}
