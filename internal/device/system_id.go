package device

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// SystemProbeTimeout bounds the hardware probe (the WMI subprocess) for the
// update task, which isn't latency-sensitive.
const SystemProbeTimeout = 60 * time.Second

// systemProbe is probeSerial; tests stub it.
var systemProbe = probeSerial

// systemIDCache is the SYSTEM-only identity cache (state\device-id).
type systemIDCache struct {
	DeviceID string `json:"device_id"`
	Source   string `json:"source"` // "hardware" | "configured"
}

// SystemID is the device identity for the SYSTEM self-updater. probeTimeout
// bounds the hardware probe (the self-check passes a short one so its
// smoke test can't time out on a wedged WMI). It never
// reads the shared ProgramData device-id file, which users can write (M-9).
// Order: the configured device_id; the hardware probe (BIOS serial from the
// registry, then WMI); cachePath (state\device-id: protected, written only
// by SYSTEM, only from a hardware or configured result); MachineGuid. Only
// a hardware or configured result is cached, and only a hardware result
// rewrites the shared file, so a probe that fell back to MachineGuid never
// changes the identity user scans read (U4). "" when nothing is usable.
func SystemID(ctx context.Context, exec executor.Executor, cachePath string, probeTimeout time.Duration) string {
	w, canWrite := exec.(idWriter)
	cache := func(id, source string) {
		if canWrite && cachePath != "" {
			if b, err := json.Marshal(systemIDCache{DeviceID: id, Source: source}); err == nil {
				_ = w.WriteFileAtomic(cachePath, b, 0o644) // best-effort
			}
		}
	}
	if id := strings.TrimSpace(config.DeviceID); id != "" {
		cache(id, "configured")
		return id
	}
	if probeTimeout <= 0 {
		probeTimeout = SystemProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	id, hardware := systemProbe(ctx, exec)
	if hardware && usableSerial(id) {
		cache(id, "hardware")
		if canWrite {
			_ = w.WriteFileAtomic(machineIDFile(exec.GOOS()), []byte(id+"\n"), 0o644) // best-effort
		}
		return id
	}
	if cachePath != "" {
		if data, err := exec.ReadFile(cachePath); err == nil && len(data) <= 4096 {
			var c systemIDCache
			// A configured id is only valid while the config still has it
			// (config.DeviceID is empty here, so it was removed).
			if json.Unmarshal(data, &c) == nil && usableSerial(c.DeviceID) && c.Source == "hardware" {
				return c.DeviceID
			}
		}
	}
	if usableSerial(id) {
		return id // MachineGuid: reported, never persisted
	}
	return ""
}
