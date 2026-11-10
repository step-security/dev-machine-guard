package device

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/paths"
)

// imageBuilderMarkerFile is the machine-bound "this is the master-image
// builder" switch. While it names this machine, enterprise scans exit before
// any beacon or upload, so an image team can sign in to the imaging machine
// and update it without registering it as a device. Clones built from the
// image inherit the file but carry another machine id, so they ignore it and
// scan normally, which is why the switch never travels through
// bootstrap.json: a bootstrap file is copied into the image and replayed by
// provisioning scripts on every host.
const imageBuilderMarkerFile = "image-builder.json"

type imageBuilderMarker struct {
	// MachineID is the machine identity of the host the switch was set on,
	// compared the way multi-user.json's is (markerFor). A marker without one
	// is ignored: scans stay on rather than off on every clone.
	MachineID string `json:"machine_id"`
	Since     int64  `json:"since"`
}

// imageBuilderDir is where the switch lives: the machine-wide state dir on
// Windows (C:\ProgramData\StepSecurity), else the install dir.
func imageBuilderDir() string {
	if dir := machineStateDir(); dir != "" {
		return dir
	}
	return paths.Home()
}

// SetImageBuilder turns the switch on (write the marker bound to this
// machine) or off (empty it). Refuses to switch on when this machine has no
// usable hardware id: an unbound marker could not be told from a clone's own
// and would stop every host built from the image from scanning.
func SetImageBuilder(exec executor.Executor, on bool) error {
	dir := imageBuilderDir()
	if dir == "" {
		return errors.New("image builder: no state directory to record the switch in")
	}
	path := filepath.Join(dir, imageBuilderMarkerFile)
	if !on {
		// Emptied in place rather than removed: an empty marker reads as
		// none, and the file keeps the owner and grants the state-directory
		// hardening gave it, so no signed-in user can put one in its place
		// (the directory lets users create files; see hardenStateDirACLs).
		if err := os.Truncate(path, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("image builder: clearing %s: %w", path, err)
		}
		return nil
	}
	machineID := currentMachineID(exec)
	if machineID == "" {
		return errors.New("image builder: this machine has no usable hardware id to bind the switch to; scans stay on")
	}
	data, err := json.Marshal(imageBuilderMarker{MachineID: machineID, Since: time.Now().Unix()})
	if err != nil {
		return err
	}
	return writeMarkerFile(dir, imageBuilderMarkerFile, ".image-builder-*.tmp", data)
}

// ImageBuilderActive reports whether scans are switched off on this machine:
// the marker exists and names this machine. A marker from another machine
// (the builder, seen from a clone) or one with no machine id is ignored.
func ImageBuilderActive(exec executor.Executor) bool {
	dir := imageBuilderDir()
	if dir == "" {
		return false
	}
	data, ok := readBounded(filepath.Join(dir, imageBuilderMarkerFile), maxSeenUsersBytes)
	if !ok || len(bytes.TrimSpace(data)) == 0 {
		return false // absent, or the empty slot hardening keeps for it
	}
	var m imageBuilderMarker
	if err := json.Unmarshal(data, &m); err != nil {
		logger.Debug("image-builder marker is not valid JSON; ignoring it")
		return false
	}
	machineID := currentMachineID(exec)
	if m.MachineID == "" || machineID == "" || !strings.EqualFold(m.MachineID, machineID) {
		logger.Debug("image-builder marker was written on another machine (%q); ignoring it on this one", m.MachineID)
		return false
	}
	return true
}

// writeMarkerFile writes data to dir/name atomically (temp file + rename; the
// Windows rename cannot overwrite, so the old file is removed first).
func writeMarkerFile(dir, name, tmpPattern string, data []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- shared install dir
		return err
	}
	tmp, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(data)
	_ = tmp.Sync()
	_ = tmp.Close()
	if werr != nil {
		_ = os.Remove(tmpName)
		return werr
	}
	dest := filepath.Join(dir, name)
	_ = os.Remove(dest)
	if err := os.Rename(tmpName, dest); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
