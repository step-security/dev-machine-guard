//go:build !windows

package device

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

const winIDFile = `C:\ProgramData\StepSecurity\device-id`

func systemMock() *executor.Mock {
	m := executor.NewMock()
	m.SetGOOS("windows")
	m.SetIsRoot(true)
	m.SetFile(winIDFile, []byte("PLANTED-BY-USER\n"))
	return m
}

func stubProbe(t *testing.T, id string, hardware bool) {
	t.Helper()
	old := systemProbe
	systemProbe = func(context.Context, executor.Executor) (string, bool) { return id, hardware }
	t.Cleanup(func() { systemProbe = old })
}

func noConfiguredID(t *testing.T) {
	old := config.DeviceID
	config.DeviceID = ""
	t.Cleanup(func() { config.DeviceID = old })
}

// R-C2-2: the SYSTEM id never comes from the user-writable shared file; a
// hardware result is written to both the SYSTEM cache and the shared file.
func TestSystemIDHardwareWritesBoth(t *testing.T) {
	noConfiguredID(t)
	cache := filepath.Join(`C:\Program Files\StepSecurity\state`, "device-id")
	m := systemMock()
	stubProbe(t, "HW-SERIAL-1", true)
	if got := SystemID(context.Background(), m, cache, SystemProbeTimeout); got != "HW-SERIAL-1" {
		t.Fatalf("SystemID = %q", got)
	}
	if b, _ := m.ReadFile(winIDFile); string(b) != "HW-SERIAL-1\n" {
		t.Fatalf("shared file = %q", b)
	}
	if b, _ := m.ReadFile(cache); len(b) == 0 {
		t.Fatal("SYSTEM cache not written")
	}
}

// R-C2-10: a failed hardware probe uses the SYSTEM cache (from an earlier
// hardware result) and leaves the shared file alone.
func TestSystemIDProbeFailureUsesCache(t *testing.T) {
	noConfiguredID(t)
	cache := `C:\Program Files\StepSecurity\state\device-id`
	m := systemMock()
	m.SetFile(cache, []byte(`{"device_id":"HW-CACHED","source":"hardware"}`))
	stubProbe(t, "guid-1", false) // WMI failed: only MachineGuid
	if got := SystemID(context.Background(), m, cache, SystemProbeTimeout); got != "HW-CACHED" {
		t.Fatalf("SystemID = %q, want the cached hardware id", got)
	}
	if b, _ := m.ReadFile(winIDFile); string(b) != "PLANTED-BY-USER\n" {
		t.Fatalf("shared file rewritten from a fallback: %q", b)
	}
}

// R-C2-10: a first run that only reaches MachineGuid reports it but writes
// neither the shared file nor the cache.
func TestSystemIDMachineGuidWritesNothing(t *testing.T) {
	noConfiguredID(t)
	cache := `C:\Program Files\StepSecurity\state\device-id`
	m := systemMock()
	m.SetFile(winIDFile, nil)
	stubProbe(t, "guid-1", false)
	if got := SystemID(context.Background(), m, cache, SystemProbeTimeout); got != "guid-1" {
		t.Fatalf("SystemID = %q", got)
	}
	if b, _ := m.ReadFile(winIDFile); len(b) != 0 {
		t.Fatalf("shared file written from MachineGuid: %q", b)
	}
	if b, err := m.ReadFile(cache); err == nil && len(b) != 0 {
		t.Fatalf("cache written from MachineGuid: %q", b)
	}
}

func TestSystemIDConfiguredWins(t *testing.T) {
	old := config.DeviceID
	config.DeviceID = "configured-1"
	t.Cleanup(func() { config.DeviceID = old })
	stubProbe(t, "HW-1", true)
	if got := SystemID(context.Background(), systemMock(), `C:\x\device-id`, SystemProbeTimeout); got != "configured-1" {
		t.Fatalf("SystemID = %q", got)
	}
}

// FR1-1: a wedged WMI probe is bounded by the caller's timeout, then the
// SYSTEM cache answers (the self-check passes a short one).
func TestSystemIDProbeTimeoutFallsBackToCache(t *testing.T) {
	noConfiguredID(t)
	cache := `C:\Program Files\StepSecurity\state\device-id`
	m := systemMock()
	m.SetFile(cache, []byte(`{"device_id":"HW-CACHED","source":"hardware"}`))
	old := systemProbe
	systemProbe = func(ctx context.Context, _ executor.Executor) (string, bool) {
		<-ctx.Done() // WMI never answers
		return "guid-1", false
	}
	t.Cleanup(func() { systemProbe = old })
	start := time.Now()
	if got := SystemID(context.Background(), m, cache, 200*time.Millisecond); got != "HW-CACHED" {
		t.Fatalf("SystemID = %q", got)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("probe not bounded by the caller's timeout: %s", d)
	}
}

// FR1-4: a configured id cached earlier is not used once the config no
// longer carries it.
func TestSystemIDDropsStaleConfiguredCache(t *testing.T) {
	noConfiguredID(t)
	cache := `C:\Program Files\StepSecurity\state\device-id`
	m := systemMock()
	m.SetFile(cache, []byte(`{"device_id":"OLD-CONFIGURED","source":"configured"}`))
	stubProbe(t, "guid-1", false)
	if got := SystemID(context.Background(), m, cache, SystemProbeTimeout); got != "guid-1" {
		t.Fatalf("SystemID = %q, want the chain past the stale configured id", got)
	}
}
