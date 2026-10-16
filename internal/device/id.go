package device

import (
	"context"
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
		switch stored := readIDFile(exec, path); {
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
