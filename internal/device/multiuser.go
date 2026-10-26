package device

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Automatic per-user identity.
//
// With no identity template configured (no STEPSEC_DEVICE_ID, no config.json
// device_id), a host that is known to be shared by several people switches to
// the per-user template on its own, so each person on a pooled desktop is a
// separate device without any provisioning change. "Known to be shared" is
// STICKY — once true it never flips back — and Windows-only in this iteration:
//
//  1. the Windows edition is multi-session (EnterpriseMultiSession, ServerRdsh)
//     or the Remote Desktop Session Host role is installed (TSAppCompat=1);
//  2. the marker file multi-user.json exists in the machine-wide state dir;
//  3. two or more distinct developers have run scans here (seen-users.txt in
//     the machine-wide state dir).
//
// The machine-wide state dir is the elevated install dir
// (C:\ProgramData\StepSecurity), shared by every user's scheduled run; on
// other platforms it is "" and the feature is off.
const (
	// IdentitySourceAuto is the device_id_source reported when the automatic
	// per-user identity is in force.
	IdentitySourceAuto = "auto"
	// AutoIdentityTemplate is the template the automatic mode applies: the
	// host name survives a VDI rebuild (a new serial does not), and the user
	// token keeps each person's inventory on their own row.
	AutoIdentityTemplate = "{hostname}-{user}"

	seenUsersFile       = "seen-users.txt"
	multiUserMarkerFile = "multi-user.json"
	// maxSeenUsersBytes bounds the file the agent reads: a planted or runaway
	// file beyond this is ignored rather than parsed.
	maxSeenUsersBytes = 64 << 10

	autoReasonEdition = "edition"
	autoReasonUsers   = "users"
)

// multiUserMarker is the sticky "this host is shared" record. RetiredSerialID
// is set once the previous machine-identity row has been retired (see
// SerialRowRetirePending), so the switch retires it exactly once.
type multiUserMarker struct {
	Since           int64  `json:"since"`
	Reason          string `json:"reason"` // "edition" | "users"
	RetiredSerialID string `json:"retired_serial_id,omitempty"`
}

// machineStateDir is where the shared-host files live. A var so tests can
// point it at a temp dir; production reads the elevated install dir.
var machineStateDir = func() string { return config.MachineInstallDir() }

// MachineStateDir returns the machine-wide state dir in force ("" when the
// shared-host features are off).
func MachineStateDir() string { return machineStateDir() }

// SetMachineStateDirForTest overrides the machine-wide state dir and returns
// a func restoring the previous one. Tests only.
func SetMachineStateDirForTest(dir string) (restore func()) {
	prev := machineStateDir
	machineStateDir = func() string { return dir }
	return func() { machineStateDir = prev }
}

// probeWindowsEdition reads the edition facts (multiuser_windows.go); the
// non-Windows stub reports nothing. A var so tests on any OS can stub it.
var probeWindowsEdition = readWindowsEdition

// multiUserHost is the pure decision: any one rule makes the host shared.
// The reason is "marker" when the sticky file already decided, else the rule
// that fired now.
func multiUserHost(edition string, tsAppCompat bool, seenUsers []string, markerExists bool) (bool, string) {
	if markerExists {
		return true, "marker"
	}
	if isMultiSessionEdition(edition) || tsAppCompat {
		return true, autoReasonEdition
	}
	if len(seenUsers) >= 2 {
		return true, autoReasonUsers
	}
	return false, ""
}

// isMultiSessionEdition matches the Windows editions built for concurrent
// interactive sessions: Windows 10/11 Enterprise multi-session (AVD) and the
// Server RDSH SKU.
func isMultiSessionEdition(edition string) bool {
	switch strings.ToLower(strings.TrimSpace(edition)) {
	case "enterprisemultisession", "serverrdsh":
		return true
	}
	return false
}

// autoIdentity reports the template the automatic mode applies on this host
// ("" when the host is not shared, the feature is off, or the OS is not
// Windows) and the display reason. The first positive decision writes the
// sticky marker; every later call reads it back.
func autoIdentity(exec executor.Executor) (template, reason string) {
	dir := machineStateDir()
	if dir == "" || exec.GOOS() != model.PlatformWindows {
		return "", ""
	}
	marker, exists := readMultiUserMarker(dir)
	edition, tsAppCompat := "", false
	if !exists {
		edition, tsAppCompat = probeWindowsEdition()
	}
	on, why := multiUserHost(edition, tsAppCompat, readSeenUsers(dir), exists)
	if !on {
		return "", ""
	}
	if exists {
		why = marker.Reason
	} else {
		// Best effort: a failed write just means the rule is re-evaluated
		// next run, which yields the same answer.
		_ = writeMultiUserMarker(dir, multiUserMarker{Since: time.Now().Unix(), Reason: why})
	}
	return AutoIdentityTemplate, autoReasonDisplay(why)
}

// AutoIdentityReason returns the human-readable reason the automatic
// per-user identity is in force on this host, or "" when it is not.
func AutoIdentityReason(exec executor.Executor) string {
	_, reason := autoIdentity(exec)
	return reason
}

func autoReasonDisplay(reason string) string {
	switch reason {
	case autoReasonEdition:
		return "multi-session edition"
	case autoReasonUsers:
		return "2+ users seen"
	}
	return reason
}

// RecordScanUser notes the developer running this scan in the machine-wide
// seen-users file so a second person's scan can flip the host to per-user
// identities. Service accounts are never recorded. No-op where the machine
// dir is unavailable (non-Windows, per-user installs).
func RecordScanUser(exec executor.Executor) {
	dir := machineStateDir()
	if dir == "" || exec.GOOS() != model.PlatformWindows {
		return
	}
	token := SanitizeDeviceID(userToken(exec.GOOS(), exec.IsRoot(), getDeveloperIdentity(exec)))
	if token == "" {
		return
	}
	_ = appendSeenUser(dir, token)
}

// readSeenUsers returns the distinct user tokens recorded so far, in first-seen
// order. An unreadable or oversized file reads as empty.
func readSeenUsers(dir string) []string {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, seenUsersFile)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > maxSeenUsersBytes {
		return nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed basename under the install dir
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var users []string
	for _, line := range strings.Split(string(data), "\n") {
		u := strings.ToLower(strings.TrimSpace(line))
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		users = append(users, u)
	}
	return users
}

// appendSeenUser adds token to the file unless it is already there.
func appendSeenUser(dir, token string) error {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return nil
	}
	for _, u := range readSeenUsers(dir) {
		if u == token {
			return nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- shared install dir
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, seenUsersFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) // #nosec G302 G304 -- readable by every user's run
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString(token + "\n")
	return err
}

// readMultiUserMarker returns the sticky marker when a valid one exists.
func readMultiUserMarker(dir string) (*multiUserMarker, bool) {
	if dir == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(dir, multiUserMarkerFile)) // #nosec G304 -- fixed basename under the install dir
	if err != nil || len(data) > maxSeenUsersBytes {
		return nil, false
	}
	var m multiUserMarker
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	return &m, true
}

// writeMultiUserMarker writes the marker atomically (temp file + rename; the
// Windows rename cannot overwrite, so the old file is removed first).
func writeMultiUserMarker(dir string, m multiUserMarker) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- shared install dir
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".multi-user-*.tmp")
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
	dest := filepath.Join(dir, multiUserMarkerFile)
	_ = os.Remove(dest)
	if err := os.Rename(tmpName, dest); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// SerialRowRetirePending reports whether the switch to the automatic per-user
// identity still owes the backend a retire of the previous machine-identity
// row (serialID). True when the marker exists, has not recorded a retire yet,
// and a row under serialID plausibly exists: the switch was triggered by a
// second user (so the first scanned under the serial), or the machine-wide
// last-run.json last checked in as serialID (an upgraded host).
func SerialRowRetirePending(serialID, lastRunDeviceID string) bool {
	dir := machineStateDir()
	if dir == "" || !usableSerial(serialID) {
		return false
	}
	m, ok := readMultiUserMarker(dir)
	if !ok || m.RetiredSerialID != "" {
		return false
	}
	return m.Reason == autoReasonUsers || (lastRunDeviceID != "" && lastRunDeviceID == serialID)
}

// MarkSerialRowRetired records that serialID was retired, so the switch never
// retires it again.
func MarkSerialRowRetired(serialID string) error {
	dir := machineStateDir()
	m, ok := readMultiUserMarker(dir)
	if !ok {
		return nil
	}
	m.RetiredSerialID = serialID
	return writeMultiUserMarker(dir, *m)
}
