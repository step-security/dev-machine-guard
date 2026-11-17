package device

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Per-session scanning on shared Windows hosts.
//
// A device is always the machine. A host that is known to be shared by several
// people scans every signed-in session separately: each session's scheduled
// run keeps its own state directory and lock (paths.StateDir, lock.Acquire),
// the task policy lets the sessions' instances overlap, and every upload
// reports under the one machine device with the session's user_identity and
// user_token, so the backend files each user's inventory inside that device.
// "Known to be shared" is STICKY (once true it never flips back) and
// Windows-only in this iteration:
//
//  1. the Windows edition is multi-session (EnterpriseMultiSession, ServerRdsh)
//     or the Remote Desktop Session Host role is installed (TSAppCompat=1);
//  2. the marker file multi-user.json exists in the machine-wide state dir;
//  3. with config multi_user_detection = "users": two or more distinct
//     developers have each run scans here on two different days
//     (seen-users.txt in the machine-wide state dir). A single visit (a
//     technician, a one-off session) never counts, and the rule is opt-in
//     because an ordinary workstation must not change how it scans because
//     someone else signed in once; "off" disables per-session scanning.
//
// The machine-wide state dir is the elevated install dir
// (C:\ProgramData\StepSecurity), shared by every user's scheduled run; on
// other platforms it is "" and the feature is off.
const (
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

// multiUserMarker is the sticky "this host is shared" record: per-session
// scanning is on here. An earlier build also recorded a retired serial row in
// it; that field is ignored when present.
type multiUserMarker struct {
	Since  int64  `json:"since"`
	Reason string `json:"reason"` // "edition" | "users"
	// MachineID is the machine identity of the host the marker was written
	// on. A marker captured into an image names the image builder; on a
	// clone it is ignored (markerFor), so the builder's decision never
	// carries over. Absent in markers written by earlier agents, which are
	// honoured as they are.
	MachineID string `json:"machine_id,omitempty"`
}

// markerMachineIDTimeout bounds the machine-identity probe a marker
// comparison may need (the process-wide SerialNumber, probed once).
const markerMachineIDTimeout = 10 * time.Second

// currentMachineID is the machine identity markers and visit files are
// compared with: the identity this process already resolved, else the
// process-wide hardware probe (cachedProbeSerial, so SerialNumber reuses the
// answer rather than probing again). It never mints or persists an id for a
// comparison, so it is "" on a host without a readable serial; such a
// host's marker is then honoured as it is, which is why a cloned image of
// one needs the marker removed before capture. A var so tests pin it
// without a probe.
var currentMachineID = func(exec executor.Executor) string {
	idMu.Lock()
	cached := cachedID
	idMu.Unlock()
	if cached != "" {
		return cached
	}
	ctx, cancel := context.WithTimeout(context.Background(), markerMachineIDTimeout)
	defer cancel()
	if id, hardware := cachedProbeSerial(ctx, exec); hardware && usableSerial(id) {
		return id
	}
	return ""
}

// markerFor returns the sticky marker when a valid one exists for this
// machine. A marker that names another machine was inherited from the image
// this host was cloned from: it is reported absent, so the rules are
// evaluated afresh here and the first positive decision writes this
// machine's own marker. A marker without a machine id predates the field,
// and a host whose own identity is unknown cannot tell a marker foreign;
// both are honoured as they are.
func markerFor(dir, machineID string) (*multiUserMarker, bool) {
	m, ok := readMultiUserMarker(dir)
	if !ok {
		return nil, false
	}
	if m.MachineID != "" && machineID != "" && !strings.EqualFold(m.MachineID, machineID) {
		logger.Debug("multi-user marker was written on another machine (%s); ignoring it on this one", m.MachineID)
		return nil, false
	}
	return m, true
}

// machineStateDir is where the shared-host files live. A var so tests can
// point it at a temp dir; production reads the elevated install dir.
var machineStateDir = func() string { return config.MachineInstallDir() }

// MachineStateDir returns the machine-wide state dir in force ("" when the
// shared-host features are off).
func MachineStateDir() string { return machineStateDir() }

// SetMachineStateDirForTest overrides the machine-wide state dir and returns
// a func restoring the previous one. Tests only. Each override starts a fresh
// per-session snapshot (a test stands for a new process).
func SetMachineStateDirForTest(dir string) (restore func()) {
	prev := machineStateDir
	machineStateDir = func() string { return dir }
	ResetPerSessionForTest()
	return func() { machineStateDir = prev; ResetPerSessionForTest() }
}

// perSession is the per-session scanning answer snapshotted once per process.
// main reads it before choosing the state scope and the lock target; a second
// user's scan can flip the shared files at any moment afterwards, and if the
// answer changed between the run gate, Gather and the upload, one run would
// keep shared state while reporting a session scope. A flip takes effect on
// the next run of any user instead.
var perSession struct {
	mu     sync.Mutex
	done   bool
	on     bool
	reason string
}

// ResetPerSessionForTest drops the per-process per-session snapshot so a
// test can act as the next run. Tests only.
func ResetPerSessionForTest() {
	perSession.mu.Lock()
	defer perSession.mu.Unlock()
	perSession.done = false
	perSession.on, perSession.reason = false, ""
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

// PerSessionScanning reports whether this host scans every signed-in session
// separately (false when the host is not shared, the feature is off, or the
// OS is not Windows) and the display reason. The first positive decision
// writes the sticky marker; every later call reads it back. The answer is
// taken once per process (perSession): main evaluates it right after
// RecordScanUser, and everything else in the run reuses that snapshot.
func PerSessionScanning(exec executor.Executor) (on bool, reason string) {
	perSession.mu.Lock()
	defer perSession.mu.Unlock()
	if !perSession.done {
		perSession.on, perSession.reason = perSessionUncached(exec)
		perSession.done = true
	}
	return perSession.on, perSession.reason
}

func perSessionUncached(exec executor.Executor) (on bool, reason string) {
	dir := machineStateDir()
	if dir == "" || exec.GOOS() != model.PlatformWindows {
		return false, ""
	}
	mode := config.MultiUserDetectionMode()
	if mode == config.MultiUserDetectionOff {
		return false, ""
	}
	marker, exists := readMultiUserMarker(dir)
	machineID := ""
	if exists && marker.MachineID != "" {
		// Only a marker that names a machine needs the comparison; the
		// probe behind it is the process-wide one every run makes anyway.
		machineID = currentMachineID(exec)
		marker, exists = markerFor(dir, machineID)
	}
	edition, tsAppCompat := "", false
	if !exists {
		edition, tsAppCompat = probeWindowsEdition()
	}
	usersRule := mode == config.MultiUserDetectionUsers
	var established []string
	if usersRule && !exists {
		if machineID == "" {
			machineID = currentMachineID(exec)
		}
		established = establishedSeenUsers(dir, machineID)
	}
	shared, why := multiUserHost(edition, tsAppCompat, established, exists, usersRule)
	if !shared {
		return false, ""
	}
	if exists {
		why = marker.Reason
	} else if !prospectiveQuery() {
		// Best effort: a failed write just means the rule is re-evaluated
		// next run, which yields the same answer. A diagnostic query keeps
		// its decision to itself: the scan that follows writes the marker
		// from the visits it records.
		if machineID == "" {
			machineID = currentMachineID(exec)
		}
		_ = writeMultiUserMarker(dir, multiUserMarker{Since: time.Now().Unix(), Reason: why, MachineID: machineID})
	}
	return true, autoReasonDisplay(why)
}

// PerSessionReason returns the human-readable reason per-session scanning is
// on for this host, or "" when it is not.
func PerSessionReason(exec executor.Executor) string {
	_, reason := PerSessionScanning(exec)
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
// machine-wide seen-users file so the users rule can switch the host to
// per-session scanning once two developers have each scanned on two
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
	_ = recordSeenUser(dir, token, currentMachineID(exec))
}

// pendingVisit is a visit the `identity` verb assumes without recording it:
// a scan records its user before the per-session decision is taken, so the
// answer a diagnostic query gives must include today's visit of the querying
// user, or it could report shared state on the very scan that establishes
// the second developer.
var pendingVisit struct {
	mu          sync.Mutex
	prospective bool // this process is a diagnostic query; its decision is never persisted
	token       string
	day         int64
}

func prospectiveQuery() bool {
	pendingVisit.mu.Lock()
	defer pendingVisit.mu.Unlock()
	return pendingVisit.prospective
}

// ProspectiveScanUser makes the per-session decision of this process count
// the current user's visit today as a scan would, without writing it: for
// `identity`, which must answer what send-telemetry would do.
func ProspectiveScanUser(exec executor.Executor) {
	pendingVisit.mu.Lock()
	pendingVisit.prospective = true
	pendingVisit.mu.Unlock()
	if machineStateDir() == "" || exec.GOOS() != model.PlatformWindows || config.MultiUserDetectionMode() != config.MultiUserDetectionUsers {
		return
	}
	token := SanitizeDeviceID(userToken(exec.GOOS(), exec.IsRoot(), developerIdentity(context.Background(), exec)))
	if token == "" {
		return
	}
	pendingVisit.mu.Lock()
	pendingVisit.token, pendingVisit.day = token, seenUserDay()
	pendingVisit.mu.Unlock()
}

// resetPendingVisitForTest clears the prospective visit. Tests only.
func resetPendingVisitForTest() {
	pendingVisit.mu.Lock()
	pendingVisit.prospective, pendingVisit.token, pendingVisit.day = false, "", 0
	pendingVisit.mu.Unlock()
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

// seenUsersMachinePrefix starts the header line that binds seen-users.txt
// to the machine that wrote it ("# machine <id>"). A file whose header
// names another machine was captured into an image: its visits are the
// builder's and are discarded on the clone before a visit is recorded or
// the users rule is applied, so two developers established on the builder
// never switch a clone to per-session scanning. A file without a header
// (earlier agents) is taken as this machine's.
const seenUsersMachinePrefix = "# machine "

// seenUsersMachine returns the machine the file is bound to ("" when it is
// not bound).
func seenUsersMachine(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if m, ok := strings.CutPrefix(line, seenUsersMachinePrefix); ok {
			return strings.TrimSpace(m)
		}
	}
	return ""
}

// seenUsersInherited reports whether a file bound to another machine is in
// hand: machineID known, the file bound, and the two differ.
func seenUsersInherited(data []byte, machineID string) bool {
	bound := seenUsersMachine(data)
	return machineID != "" && bound != "" && !strings.EqualFold(bound, machineID)
}

// parseSeenUsers reads "<token> <day>[,<day>]" lines; tokens are lowercased
// and deduplicated in first-seen order, unparsable days are dropped. Header
// lines ("# ...") carry no visit.
func parseSeenUsers(data []byte) []seenUser {
	index := map[string]int{}
	var users []seenUser
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
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
// seen scanning on seenUserDaysNeeded different days, the prospective visit
// of this process (ProspectiveScanUser) included. A history another machine
// wrote (an image builder's) counts for nothing here.
func establishedSeenUsers(dir, machineID string) []string {
	var records []seenUser
	if dir != "" {
		if data, ok := readBounded(filepath.Join(dir, seenUsersFile), maxSeenUsersBytes); ok && !seenUsersInherited(data, machineID) {
			records = parseSeenUsers(data)
		}
	}
	pendingVisit.mu.Lock()
	token, day := pendingVisit.token, pendingVisit.day
	pendingVisit.mu.Unlock()
	if token != "" {
		records = withVisit(records, token, day)
	}
	var out []string
	for _, u := range records {
		if u.established() {
			out = append(out, u.token)
		}
	}
	return out
}

// withVisit returns records with a visit of token on day added (the legacy
// visit carried along as appendSeenUser would).
func withVisit(records []seenUser, token string, day int64) []seenUser {
	out := make([]seenUser, len(records))
	copy(out, records)
	for i := range out {
		if out[i].token == token {
			out[i].days = appendDay(append([]int64(nil), out[i].days...), day)
			return out
		}
	}
	days := []int64{}
	if legacyVisitCarriable(records, token) {
		days = append(days, legacySeenDay)
	}
	return append(out, seenUser{token: token, days: appendDay(days, day)})
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

// appendSeenUser records token as seen today (seenUserDay). The file is
// append-only: every user's run writes it, before the instance lock, so a
// rewrite could drop a visit another session appended meanwhile, while an
// O_APPEND write of one short line is atomic. A token already recorded for
// today, or already established, appends nothing. A developer whose visits
// an earlier agent recorded under the bare short name (legacyVisitCarriable)
// gets that visit carried over first. An oversized file is compacted under
// the machine-wide lock (compactSeenUsers).
func appendSeenUser(dir, token string) error { return recordSeenUser(dir, token, "") }

// recordSeenUser records token's visit today in the file bound to machineID
// ("" records without binding). Everything happens under the visit-file
// lock, the read included: the file is never written without it, and a
// visit that cannot take the lock in time is left for a later run (every
// scan records its user), which costs a delay, never the visit. A file
// another machine wrote is replaced, not appended to.
func recordSeenUser(dir, token, machineID string) error {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- shared install dir
		return err
	}
	release, locked := lockSeenUsers()
	if !locked {
		logger.Debug("seen-users: the visit file is busy; %s's visit today is recorded by a later run", token)
		return nil
	}
	defer release()
	path := filepath.Join(dir, seenUsersFile)
	data, exists := readBounded(path, maxSeenUsersBytes)
	inherited := exists && seenUsersInherited(data, machineID)
	var records []seenUser
	if exists && !inherited {
		records = parseSeenUsers(data)
	}
	day := seenUserDay()
	var lines []string
	known := false
	for _, u := range records {
		if u.token != token {
			continue
		}
		known = true
		if u.established() || hasDay(u.days, day) {
			return nil
		}
	}
	if !known && legacyVisitCarriable(records, token) {
		lines = append(lines, formatVisit(token, legacySeenDay))
	}
	lines = append(lines, formatVisit(token, day))
	if inherited {
		logger.Debug("seen-users: the visit file was written on another machine (%s); starting this machine's own", seenUsersMachine(data))
		return replaceSeenUsers(dir, seenUsersHeader(machineID)+strings.Join(lines, ""))
	}
	if !exists && machineID != "" {
		lines = append([]string{seenUsersHeader(machineID)}, lines...)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) // #nosec G302 G304 -- readable by every user's run
	if err != nil {
		return err
	}
	_, err = f.WriteString(strings.Join(lines, ""))
	_ = f.Close()
	if err != nil {
		return err
	}
	compactSeenUsersLocked(dir)
	return nil
}

// seenUsersHeader is the binding line for machineID ("" when unknown).
func seenUsersHeader(machineID string) string {
	if machineID == "" {
		return ""
	}
	return seenUsersMachinePrefix + machineID + "\n"
}

// replaceSeenUsers writes the whole file, in place: the file is truncated
// and rewritten, never replaced by a rename. On a shared Windows host it is
// the SYSTEM-owned file every signed-in user may modify but not replace,
// and a file renamed into place would belong to the session that wrote it
// and be unwritable to the others. The caller holds the visit-file lock,
// which every writer takes; a reader outside it may see the file
// half-written once and reads it whole on the next run, and a crash in
// between loses visits the next runs record again. A missing file is
// created the same way.
func replaceSeenUsers(dir, content string) error {
	f, err := os.OpenFile(filepath.Join(dir, seenUsersFile), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G302 G304 -- readable by every user's run
	if err != nil {
		return err
	}
	_, werr := f.WriteString(content)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// seenUsersLockName names the visit-file lock: a sibling of the instance
// lock (lock.AcquireSibling), so it is an OS lock the kernel drops with its
// holder and there is never a stale lock to reclaim.
const seenUsersLockName = "visits"

// seenUsersLockWait bounds how long a writer waits for the visit-file lock.
var seenUsersLockWait = 2 * time.Second

// lockSeenUsers takes the visit-file lock, waiting up to seenUsersLockWait.
// The release func is always safe to call; locked reports whether the lock
// is actually held.
func lockSeenUsers() (release func(), locked bool) {
	deadline := time.Now().Add(seenUsersLockWait)
	for {
		held, err := lock.AcquireSibling(seenUsersLockName)
		if err == nil {
			return held.Release, true
		}
		if !errors.Is(err, lock.ErrHeld) || time.Now().After(deadline) {
			return func() {}, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func formatVisit(token string, day int64) string {
	return token + " " + strconv.FormatInt(day, 10) + "\n"
}

func hasDay(days []int64, day int64) bool {
	for _, d := range days {
		if d == day {
			return true
		}
	}
	return false
}

// tokenShortName returns the readable part of a fingerprinted user token
// ("jdoe" for "jdoe-<12 hex>"), "" for any other token.
func tokenShortName(token string) string {
	if len(token) <= UserTokenFingerprintLen+1 || token[len(token)-UserTokenFingerprintLen-1] != '-' {
		return ""
	}
	fp := token[len(token)-UserTokenFingerprintLen:]
	for _, r := range fp {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return token[:len(token)-UserTokenFingerprintLen-1]
}

// legacyVisitCarriable reports whether a visit an earlier agent recorded
// under the bare short name of token can be credited to token: exactly one
// such legacy record exists and no other fingerprinted token shares the
// short name, so the legacy visit cannot belong to someone else. Anything
// ambiguous is not carried; those developers start over.
func legacyVisitCarriable(records []seenUser, token string) bool {
	short := tokenShortName(token)
	if short == "" {
		return false
	}
	legacy := 0
	for _, u := range records {
		switch {
		case u.token == short:
			for _, d := range u.days {
				if d != legacySeenDay {
					return false
				}
			}
			legacy++
		case u.token != token && tokenShortName(u.token) == short:
			return false
		}
	}
	return legacy == 1
}

// compactSeenUsersBytes is the size past which the append-only file is
// rewritten as one line per token, well under the read bound.
const compactSeenUsersBytes = maxSeenUsersBytes / 2

// compactSeenUsersLocked rewrites an oversized seen-users file as one line
// per token. The caller holds the visit-file lock (lockSeenUsers), which
// every append takes too, so no visit can land between the snapshot and
// the replacement. Best effort.
func compactSeenUsersLocked(dir string) {
	path := filepath.Join(dir, seenUsersFile)
	info, err := os.Stat(path)
	if err != nil || info.Size() <= compactSeenUsersBytes {
		return
	}
	data, ok := readBounded(path, maxSeenUsersBytes)
	if !ok {
		return
	}
	records := parseSeenUsers(data)
	if records == nil {
		return
	}
	// The binding survives the rewrite.
	_ = replaceSeenUsers(dir, seenUsersHeader(seenUsersMachine(data))+formatSeenUsers(records))
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
