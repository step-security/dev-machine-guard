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
// A configured device_id is resolved the way the scan resolves it: a literal
// as given; a template expanded with the host name and the machine identity
// (systemMachineID). {user} has no expansion under SYSTEM, so such a template
// yields "" (incomplete) and device-scoped posts are skipped rather than sent
// under a literal or a guessed id; the scan reports under each user's id.
// Only a hardware or configured result is cached. "" when nothing is usable.
func SystemID(ctx context.Context, exec executor.Executor, cachePath string, probeTimeout time.Duration) string {
	template := strings.TrimSpace(config.DeviceID)
	if template != "" && !strings.Contains(template, "{") {
		writeSystemIDCache(exec, cachePath, template, "configured")
		return template
	}
	lower := strings.ToLower(template)
	if strings.Contains(lower, TokenUser) {
		return ""
	}
	hostname := ""
	if strings.Contains(lower, TokenHostname) {
		hostname = getHostname(ctx, exec, exec.GOOS())
	}
	// The machine identity is probed only when the template needs it: the
	// machine identity itself, {serial}, or {hostname} on a nameless host.
	machine := ""
	if template == "" || strings.Contains(lower, TokenSerial) ||
		(strings.Contains(lower, TokenHostname) && hostnameToken(hostname, "") == "") {
		machine = systemMachineID(ctx, exec, cachePath, probeTimeout)
	}
	if template == "" {
		return machine
	}
	id := resolveWith(template, IdentitySourceConfig, machine, hostname, "", exec.GOOS(), false)
	if id.Source == IdentitySourceSerial && machine == "" {
		// An unknown token falls back to the machine identity, as the scan does.
		machine = systemMachineID(ctx, exec, cachePath, probeTimeout)
		id = resolveWith(template, IdentitySourceConfig, machine, hostname, "", exec.GOOS(), false)
	}
	if id.Incomplete || id.DeviceID == "" {
		return ""
	}
	writeSystemIDCache(exec, cachePath, id.DeviceID, "configured")
	return id.DeviceID
}

// writeSystemIDCache records the SYSTEM identity in cachePath (best-effort).
func writeSystemIDCache(exec executor.Executor, cachePath, id, source string) {
	w, canWrite := exec.(idWriter)
	if !canWrite || cachePath == "" {
		return
	}
	if b, err := json.Marshal(systemIDCache{DeviceID: id, Source: source}); err == nil {
		_ = w.WriteFileAtomic(cachePath, b, 0o644)
	}
}

// systemMachineID is the SYSTEM machine identity. Order: the hardware probe
// (BIOS serial from the registry, then WMI); cachePath (state\device-id:
// protected, written only by SYSTEM, only from a hardware result);
// MachineGuid. Only a hardware result is cached and rewrites the shared file,
// so a probe that fell back to MachineGuid never changes the identity user
// scans read (U4). "" when nothing is usable.
func systemMachineID(ctx context.Context, exec executor.Executor, cachePath string, probeTimeout time.Duration) string {
	w, canWrite := exec.(idWriter)
	if probeTimeout <= 0 {
		probeTimeout = SystemProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	id, hardware := systemProbe(ctx, exec)
	if hardware && usableSerial(id) {
		writeSystemIDCache(exec, cachePath, id, "hardware")
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
