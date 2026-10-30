package telemetry

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// The backend keys a device by device_id, so a changed ID (configure, a hand
// edit, the loader, a resolver change) registers a second device and leaves the
// old one's inventory behind. The agent remembers the ID it last uploaded under
// and sends it as previous_device_id when the current one differs; the backend
// decides whether the old registration is this machine's and retires it.
//
// The file lives in the per-user config dir (~/.stepsecurity), which
// --install-dir and STEPSECURITY_HOME never move, so relocating the install dir
// can't lose it. Only uploads the backend accepted advance it: an ID that never
// reached the backend has nothing to retire.
const lastUploadedDeviceIDName = "last-uploaded-device-id"

// maxDeviceIDLen bounds what is read back; real IDs are far shorter.
const maxDeviceIDLen = 256

var lastUploadedDeviceIDPath = func() string {
	dir := config.LegacyDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, lastUploadedDeviceIDName)
}

type atomicWriter interface {
	WriteFileAtomic(path string, data []byte, perm os.FileMode) error
}

// previousDeviceID returns the ID this context last uploaded under when it
// differs from current, else "". A missing or unreadable file means no history.
func previousDeviceID(exec executor.Executor, current string) string {
	path := lastUploadedDeviceIDPath()
	if path == "" {
		return ""
	}
	data, err := exec.ReadFile(path)
	if err != nil || len(data) > maxDeviceIDLen {
		return ""
	}
	prev := strings.TrimSpace(string(data))
	if !usableDeviceID(prev) || prev == strings.TrimSpace(current) {
		return ""
	}
	return prev
}

// recordUploadedDeviceID stores id as the last accepted upload's identity.
func recordUploadedDeviceID(exec executor.Executor, id string) error {
	id = strings.TrimSpace(id)
	path := lastUploadedDeviceIDPath()
	if path == "" || !usableDeviceID(id) {
		return nil
	}
	if data, err := exec.ReadFile(path); err == nil && strings.TrimSpace(string(data)) == id {
		return nil
	}
	w, ok := exec.(atomicWriter)
	if !ok {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return w.WriteFileAtomic(path, []byte(id+"\n"), 0o600)
}

func usableDeviceID(id string) bool {
	return id != "" && id != "unknown" && len(id) <= maxDeviceIDLen
}
