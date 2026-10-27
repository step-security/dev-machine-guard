package device

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/paths"
)

// machineIDFile is the machine-wide identity: written by privileged runs,
// readable by every user. Without it Linux user contexts (no DMI access)
// would report /etc/machine-id while root reports the hardware serial.
func machineIDFile(goos string) string {
	if goos == model.PlatformWindows {
		return `C:\ProgramData\StepSecurity\device-id`
	}
	return "/etc/stepsecurity/device-id"
}

// userIDFile holds a generated ID for unprivileged runs; "" disables it.
var userIDFile = func() string {
	if home := paths.Home(); home != "" {
		return filepath.Join(home, "device-id")
	}
	return ""
}

type idWriter interface {
	WriteFileAtomic(path string, data []byte, perm os.FileMode) error
	CreateFileOnce(path string, data []byte, perm os.FileMode) error
}

// resolveID: privileged runs probe the hardware and refresh the shared file
// (healing a stale or planted one); everyone else reads the file first and
// only probes when it is absent. Unprivileged runs never write it. A probe
// that only reached a per-install fallback doesn't displace a stored ID, so a
// transient hardware-probe failure can't flip the identity.
func resolveID(ctx context.Context, exec executor.Executor) string {
	path := machineIDFile(exec.GOOS())
	root := exec.IsRoot()
	if !root {
		if stored := readIDFile(exec, path); stored != "" {
			return stored
		}
	}
	id, hardware := probeSerial(ctx, exec)
	if !usableSerial(id) {
		return generatedID(ctx, exec, root, path)
	}
	if root {
		stored := readIDFile(exec, path)
		if hardware && exec.GOOS() == model.PlatformLinux {
			switch mid := linuxMachineID(exec); {
			case stored == "":
				id = keepReportedLinuxID(exec, id, mid)
			case stored == mid, mid == "":
				// Persisted by a root run, or machine-id is unreadable so a
				// stale file can't be told apart: keep the stored identity.
				id = stored
			}
		}
		switch {
		case stored == id:
		case hardware || stored == "":
			if w, ok := exec.(idWriter); ok {
				_ = w.WriteFileAtomic(path, []byte(id+"\n"), 0o644) // best-effort
			}
		default:
			return stored
		}
	}
	return id
}

// keepReportedLinuxID picks the ID the first privileged run persists on
// Linux. Only root can read the DMI serial, so the serial can only be this
// machine's identity if root reported it before (its own run-gate cache).
// Otherwise use /etc/machine-id, which user-context runs have been reporting
// all along: persisting the serial would give the device a second identity.
func keepReportedLinuxID(exec executor.Executor, serial, machineID string) string {
	for _, f := range rootRunGateCaches() {
		if reportedDeviceID(exec, f) == serial {
			return serial
		}
	}
	if machineID != "" {
		return machineID
	}
	return serial
}

// linuxMachineID returns /etc/machine-id when usable, else "".
func linuxMachineID(exec executor.Executor) string {
	data, err := exec.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	if id := strings.TrimSpace(string(data)); usableSerial(id) {
		return id
	}
	return ""
}

// rootRunGateCaches lists the last-run.json files a root run would have
// written: under root's default home and this process's install home.
func rootRunGateCaches() []string {
	files := []string{"/root/.stepsecurity/last-run.json"}
	if own := paths.HeartbeatFile(); own != "" && own != files[0] {
		files = append(files, own)
	}
	return files
}

// reportedDeviceID returns the device_id a run-gate cache recorded, or ""
// when absent or when it came from a configured device ID override.
func reportedDeviceID(exec executor.Executor, path string) string {
	data, err := exec.ReadFile(path)
	if err != nil || len(data) > 1<<20 {
		return ""
	}
	var cache struct {
		RunGate *struct {
			ConfiguredDeviceID string `json:"configured_device_id"`
			DeviceID           string `json:"device_id"`
		} `json:"run_gate"`
	}
	if json.Unmarshal(data, &cache) != nil || cache.RunGate == nil || cache.RunGate.ConfiguredDeviceID != "" {
		return ""
	}
	return strings.TrimSpace(cache.RunGate.DeviceID)
}

// generatedID is the last resort when no source yields an ID: a random UUID,
// accepted only once persisted so later runs (and racing processes) agree on
// it. A probe cut short by the deadline isn't proof there is no ID, so nothing
// is minted then.
func generatedID(ctx context.Context, exec executor.Executor, root bool, machinePath string) string {
	path := userIDFile()
	if root {
		path = machinePath
	}
	w, ok := exec.(idWriter)
	if path == "" || !ok {
		return "unknown"
	}
	if stored := readIDFile(exec, path); stored != "" {
		return stored
	}
	if ctx.Err() != nil {
		return "unknown"
	}
	id := uuid.NewString()
	err := w.CreateFileOnce(path, []byte(id+"\n"), 0o644)
	if err == nil {
		return id
	}
	if errors.Is(err, os.ErrExist) {
		if stored := readIDFile(exec, path); stored != "" {
			return stored // another process won the race
		}
	}
	return "unknown"
}

// readIDFile returns the trimmed ID at path, or "" if missing or unusable.
func readIDFile(exec executor.Executor, path string) string {
	data, err := exec.ReadFile(path)
	if err != nil || len(data) > 256 {
		return ""
	}
	if id := strings.TrimSpace(string(data)); usableSerial(id) {
		return id
	}
	return ""
}
