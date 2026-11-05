package device

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
//  3. with config multi_user_detection = "users": two or more distinct
//     developers have each run scans here on two different days
//     (seen-users.txt in the machine-wide state dir). A single visit (a
//     technician, a one-off session) never counts, and the rule is opt-in
//     because an ordinary workstation must not change identity because
//     someone else signed in once; "off" disables automatic mode entirely.
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
	// seenUserDaysNeeded is how many distinct days a developer must have
	// scanned on before the users rule counts them.
	seenUserDaysNeeded = 2
	// legacySeenDay stands for the unknown day of a token recorded by an
	// earlier agent (a line without day stamps).
	legacySeenDay = 0
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
// a func restoring the previous one. Tests only. Each override starts a fresh
// automatic-mode snapshot (a test stands for a new process).
func SetMachineStateDirForTest(dir string) (restore func()) {
	prev := machineStateDir
	machineStateDir = func() string { return dir }
	ResetAutoIdentityForTest()
	return func() { machineStateDir = prev; ResetAutoIdentityForTest() }
}

// autoDecision is the automatic-mode answer snapshotted once per process.
// main reads the mode before choosing the state scope and the lock target;
// a second user's scan can flip the shared files at any moment afterwards,
// and if the mode changed between the run gate, Gather and the upload, one
// run would check in and report under two different ids while keeping the
// shared state and the machine-wide lock. A flip takes effect on the next
// run of any user instead.
var autoDecision struct {
	mu       sync.Mutex
	done     bool
	template string
	reason   string
}

// ResetAutoIdentityForTest drops the per-process automatic-mode snapshot so a
// test can act as the next run. Tests only.
func ResetAutoIdentityForTest() {
	autoDecision.mu.Lock()
	defer autoDecision.mu.Unlock()
	autoDecision.done = false
	autoDecision.template, autoDecision.reason = "", ""
}

// probeWindowsEdition reads the edition facts (multiuser_windows.go); the
// non-Windows stub reports nothing. A var so tests on any OS can stub it.
var probeWindowsEdition = readWindowsEdition

// multiUserHost is the pure decision: any one rule makes the host shared.
// The reason is "marker" when the sticky file already decided, else the rule
// that fired now. establishedUsers are the developers the users rule counts
// (seen on seenUserDaysNeeded different days); the rule applies only when
// usersRule is set (config multi_user_detection = "users").
func multiUserHost(edition string, tsAppCompat bool, establishedUsers []string, markerExists, usersRule bool) (bool, string) {
	if markerExists {
		return true, "marker"
	}
	if isMultiSessionEdition(edition) || tsAppCompat {
		return true, autoReasonEdition
	}
	if usersRule && len(establishedUsers) >= 2 {
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
// sticky marker; every later call reads it back. The answer is taken once
// per process (autoDecision): main evaluates it right after RecordScanUser,
// and everything else in the run reuses that snapshot.
func autoIdentity(exec executor.Executor) (template, reason string) {
	autoDecision.mu.Lock()
	defer autoDecision.mu.Unlock()
	if !autoDecision.done {
		autoDecision.template, autoDecision.reason = autoIdentityUncached(exec)
		autoDecision.done = true
	}
	return autoDecision.template, autoDecision.reason
}

func autoIdentityUncached(exec executor.Executor) (template, reason string) {
	dir := machineStateDir()
	if dir == "" || exec.GOOS() != model.PlatformWindows {
		return "", ""
	}
	mode := config.MultiUserDetectionMode()
	if mode == config.MultiUserDetectionOff {
		return "", ""
	}
	marker, exists := readMultiUserMarker(dir)
	edition, tsAppCompat := "", false
	if !exists {
		edition, tsAppCompat = probeWindowsEdition()
	}
	usersRule := mode == config.MultiUserDetectionUsers
	var established []string
	if usersRule && !exists {
		established = establishedSeenUsers(dir)
	}
	on, why := multiUserHost(edition, tsAppCompat, established, exists, usersRule)
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

// AutoIdentitySuperseded reports whether a process that snapshotted the
// machine identity (automatic mode off at startup) has since been overtaken:
// another user's run switched the host to per-user identities and wrote the
// sticky marker while this one was waiting for the run gate or the instance
// lock. Such a run must not proceed under the machine identity, or its upload
// would restore the serial row the switch just retired, and the marker would
// then keep that row from being retired again. Only a serial-mode snapshot
// can be superseded; a configured template, or a snapshot already in
// automatic mode, never is.
func AutoIdentitySuperseded(exec executor.Executor) bool {
	autoDecision.mu.Lock()
	done, snapshot := autoDecision.done, autoDecision.template
	autoDecision.mu.Unlock()
	if !done || snapshot != "" || exec.GOOS() != model.PlatformWindows {
		return false
	}
	dir := machineStateDir()
	if dir == "" {
		return false
	}
	_, exists := readMultiUserMarker(dir)
	return exists
}

// AutoSerialRowRetired reports whether the switch to automatic per-user
// identities has already removed this host's machine-identity row (the
// sticky marker records the retire). A service-account run in automatic mode
// reports under the machine identity until then and is skipped afterwards
// (Identity.AutoFallback).
func AutoSerialRowRetired(exec executor.Executor) bool {
	if exec.GOOS() != model.PlatformWindows {
		return false
	}
	dir := machineStateDir()
	if dir == "" {
		return false
	}
	m, ok := readMultiUserMarker(dir)
	return ok && m.RetiredSerialID != ""
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

// RecordScanUser notes the developer running this scan, and the day, in the
// machine-wide seen-users file so the users rule can flip the host to
// per-user identities once two developers have each scanned on two
// different days. Only with config multi_user_detection = "users"; service
// accounts are never recorded. No-op where the machine dir is unavailable
// (non-Windows, per-user installs).
func RecordScanUser(exec executor.Executor) {
	dir := machineStateDir()
	if dir == "" || exec.GOOS() != model.PlatformWindows || config.MultiUserDetectionMode() != config.MultiUserDetectionUsers {
		return
	}
	token := SanitizeDeviceID(userToken(exec.GOOS(), exec.IsRoot(), developerIdentity(context.Background(), exec)))
	if token == "" {
		return
	}
	_ = appendSeenUser(dir, token)
}

// seenUser is one line of seen-users.txt: a developer token and the UTC day
// numbers (unix seconds / 86400) of the first distinct days it scanned on,
// at most seenUserDaysNeeded of them. A line with no days (written by an
// earlier agent) counts as one visit on an unknown day (legacySeenDay).
type seenUser struct {
	token string
	days  []int64
}

// seenUserDay is today's UTC day number; a var so tests can move the clock.
var seenUserDay = func() int64 { return time.Now().Unix() / 86400 }

// parseSeenUsers reads "<token> <day>[,<day>]" lines; tokens are lowercased
// and deduplicated in first-seen order, unparsable days are dropped.
func parseSeenUsers(data []byte) []seenUser {
	index := map[string]int{}
	var users []seenUser
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) == 0 {
			continue
		}
		token := fields[0]
		var days []int64
		if len(fields) > 1 {
			for _, d := range strings.Split(fields[1], ",") {
				if n, err := strconv.ParseInt(d, 10, 64); err == nil && n >= 0 {
					days = appendDay(days, n)
				}
			}
		}
		if len(days) == 0 {
			// A line written by an earlier agent: one visit on an unknown
			// day, kept as day 0 so one real day establishes the token.
			days = []int64{legacySeenDay}
		}
		if i, ok := index[token]; ok {
			for _, d := range days {
				users[i].days = appendDay(users[i].days, d)
			}
			continue
		}
		index[token] = len(users)
		users = append(users, seenUser{token: token, days: days})
	}
	return users
}

// appendDay adds day to days unless present, keeping at most
// seenUserDaysNeeded entries (more never changes the decision).
func appendDay(days []int64, day int64) []int64 {
	for _, d := range days {
		if d == day {
			return days
		}
	}
	if len(days) >= seenUserDaysNeeded {
		return days
	}
	return append(days, day)
}

func (u seenUser) established() bool { return len(u.days) >= seenUserDaysNeeded }

func formatSeenUsers(users []seenUser) string {
	var b strings.Builder
	for _, u := range users {
		b.WriteString(u.token)
		if len(u.days) > 0 {
			parts := make([]string, 0, len(u.days))
			for _, d := range u.days {
				parts = append(parts, strconv.FormatInt(d, 10))
			}
			b.WriteString(" " + strings.Join(parts, ","))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// readSeenUserRecords returns the seen-users records. An unreadable or
// oversized file reads as empty.
func readSeenUserRecords(dir string) []seenUser {
	if dir == "" {
		return nil
	}
	data, ok := readBounded(filepath.Join(dir, seenUsersFile), maxSeenUsersBytes)
	if !ok {
		return nil
	}
	return parseSeenUsers(data)
}

// establishedSeenUsers returns the tokens the users rule counts: developers
// seen scanning on seenUserDaysNeeded different days.
func establishedSeenUsers(dir string) []string {
	var out []string
	for _, u := range readSeenUserRecords(dir) {
		if u.established() {
			out = append(out, u.token)
		}
	}
	return out
}

// readBounded reads at most limit bytes of a shared-host file and reports
// false when the file is missing, unreadable or larger than limit. Every
// user of the host can write these files, so the bound is applied while
// reading, never after an unbounded read.
func readBounded(path string, limit int64) ([]byte, bool) {
	f, err := os.Open(path) // #nosec G304 -- fixed basename under the install dir
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || info.IsDir() {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, false
	}
	return data, true
}

// readSeenUsers returns the distinct user tokens recorded so far, in first-seen
// order, whatever their day count. An unreadable or oversized file reads as
// empty.
func readSeenUsers(dir string) []string {
	records := readSeenUserRecords(dir)
	if records == nil {
		return nil
	}
	users := make([]string, 0, len(records))
	for _, u := range records {
		users = append(users, u.token)
	}
	return users
}

// appendSeenUser records token as seen today (seenUserDay). A token already
// recorded for today is left alone; a new token, or a known one on a new
// day, rewrites the file atomically (every user's run writes it).
func appendSeenUser(dir, token string) error {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return nil
	}
	day := seenUserDay()
	users := readSeenUserRecords(dir)
	found := false
	for i := range users {
		if users[i].token != token {
			continue
		}
		found = true
		before := len(users[i].days)
		users[i].days = appendDay(users[i].days, day)
		if len(users[i].days) == before {
			return nil
		}
	}
	if !found {
		users = append(users, seenUser{token: token, days: []int64{day}})
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- shared install dir
		return err
	}
	path := filepath.Join(dir, seenUsersFile)
	tmp, err := os.CreateTemp(dir, ".seen-users-*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(formatSeenUsers(users)); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	_ = tmp.Close()
	_ = os.Chmod(tmp.Name(), 0o644) // #nosec G302 -- readable by every user's run
	_ = os.Remove(path)             // Windows Rename won't overwrite; no-op on POSIX
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// readMultiUserMarker returns the sticky marker when a valid one exists.
func readMultiUserMarker(dir string) (*multiUserMarker, bool) {
	if dir == "" {
		return nil, false
	}
	data, ok := readBounded(filepath.Join(dir, multiUserMarkerFile), maxSeenUsersBytes)
	if !ok {
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
