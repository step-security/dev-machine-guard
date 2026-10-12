package browserext

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/safepath"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// Detector inventories the extensions installed in this machine's browsers. It
// reads the browsers' own state files and nothing else: no browser is launched,
// no store is asked what it published, and no extension's code is opened.
type Detector struct {
	exec      executor.Executor
	skipper   *tcc.Skipper
	osVersion string

	// serviceSession reports whether this process runs with no interactive user
	// behind it. A function field because the answer comes from the process rather
	// than from any value a caller can pass, and a test has to be able to state it.
	serviceSession func() bool
}

// New builds a detector.
func New(exec executor.Executor) *Detector {
	return &Detector{exec: exec, serviceSession: serviceSession}
}

// WithSkipper attaches the consent guard. A nil skipper is a no-op.
func (d *Detector) WithSkipper(s *tcc.Skipper) *Detector {
	d.skipper = s
	return d
}

// WithOSVersion uses the OS version already gathered for this run.
func (d *Detector) WithOSVersion(version string) *Detector {
	d.osVersion = version
	return d
}

// Detect returns the inventory for one run, for the account named by target.
//
// It returns nil, the "did not run" sentinel, when there is no interactive account
// to describe. Reading a service account's home would find no browser at all and
// report every browser missing, which a reader honours by deleting the device's real
// inventory. Never an error: a browser that could not be read is a coverage status,
// and a per-extension failure degrades one finding.
func (d *Detector) Detect(ctx context.Context, target *user.User) (info *model.BrowserExtensionScanInfo) {
	home, ok := d.resolveTarget(target)
	if !ok {
		return nil
	}

	started := time.Now()
	info = &model.BrowserExtensionScanInfo{
		PayloadSchemaVersion: model.CurrentBrowserExtensionSchemaVersion,
		CatalogVersion:       catalogVersion,
		ScanComplete:         true,
		Browsers:             []model.BrowserCoverage{},
		Findings:             []model.BrowserExtensionFinding{},
	}
	defer func() {
		info.CollectedAt = time.Now().Unix()
		info.DurationMs = time.Since(started).Milliseconds()
	}()

	// The detector's own deadline, inside the phase budget. It bounds the work this
	// phase takes on; it cannot interrupt a syscall, which is why every read is built
	// so that it cannot block.
	ctx, cancel := context.WithTimeout(ctx, browserExtPhaseBudget)
	defer cancel()

	platform := d.exec.GOOS()
	scan := &scanState{
		info:     info,
		platform: platform,
		// Every path is opened through descriptors that follow no symlink. A link
		// anywhere on the path refuses, which costs a visible gap in one scan;
		// following one could read somewhere this has no business being.
		resolver: safepath.NewNoFollow(home, d.consentGuard(platform, home)),
	}

	for _, spec := range catalog {
		roots := spec.roots(platform, home)
		if len(roots) == 0 {
			// Not attempted is silence: a browser this platform's catalog does
			// not carry appears nowhere rather than as an absence.
			continue
		}
		if scan.stopped != "" {
			// A cap or the deadline already bounded the payload. Every remaining
			// browser reports the same cause and ships nothing, so its stored
			// rows survive.
			scan.commit(spec.ID, browserResult{status: model.BrowserCoverageFailed, reason: scan.stopped})
			continue
		}
		scan.commit(spec.ID, d.scanBrowser(ctx, scan, spec, roots))
	}
	return info
}

// resolveTarget establishes whose browsers this run describes, and refuses every
// identity that is not a person at a keyboard. Nothing comes from the environment:
// the agent commonly runs as a system account, so an inherited home names the
// service profile.
func (d *Detector) resolveTarget(target *user.User) (string, bool) {
	if target == nil || target.Username == "" {
		return "", false
	}
	if d.serviceSession != nil && d.serviceSession() {
		// Windows carries the answer in the process rather than in the account:
		// a service running under a custom or domain account has an ordinary SID
		// that no allowlist can enumerate, while its session is always 0.
		return "", false
	}
	if isServiceIdentity(d.exec.GOOS(), target) {
		return "", false
	}
	home := target.HomeDir
	if home == "" {
		resolved, err := d.exec.HomeDir(target.Username)
		if err != nil || resolved == "" {
			return "", false
		}
		home = resolved
	}
	return home, true
}

// Well-known Windows service accounts. A backstop only: the session check above is
// the predicate that catches a service under a custom account, and localized account
// names make a name comparison a sieve in either direction.
var windowsServiceSIDs = map[string]bool{
	"S-1-5-18": true, // LocalSystem
	"S-1-5-19": true, // LocalService
	"S-1-5-20": true, // NetworkService
}

// isServiceIdentity reports whether the resolved account is a machine identity
// rather than a person. Compared by identity, never by name: a renamed UID-0
// account is still root.
func isServiceIdentity(platform string, u *user.User) bool {
	if platform == model.PlatformWindows {
		return windowsServiceSIDs[strings.ToUpper(u.Uid)]
	}
	return u.Uid == "0"
}

// consentGuard is what the resolver asks before it touches a path, answering in this
// phase's own reason code so a refusal reads like every other one.
//
// Known browser roots keep their historical exemption before macOS 27.
// On macOS 27 and unknown versions, the ordinary protected-path policy applies.
// Configured profile paths outside those roots remain guarded on every version.
func (d *Detector) consentGuard(platform, home string) safepath.Guard {
	if d.skipper == nil {
		return nil
	}
	var exempt []string
	parts := strings.Split(d.osVersion, ".")
	validVersion := len(parts) <= 3
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			validVersion = false
			break
		}
	}
	major, _ := strconv.ParseUint(parts[0], 10, 32)
	// macOS 27 protects these browser roots. Unknown versions fail closed.
	if platform != model.PlatformDarwin || (validVersion && major > 0 && major < 27) {
		for _, spec := range catalog {
			exempt = append(exempt, spec.roots(platform, home)...)
		}
	}
	return func(path string) string {
		cleaned := filepath.Clean(path)
		for _, ex := range exempt {
			if atOrUnder(cleaned, ex) || atOrUnder(ex, cleaned) {
				return ""
			}
		}
		if d.skipper.WithinProtected(cleaned) {
			return model.BrowserExtReasonRefusedTCC
		}
		return ""
	}
}

// atOrUnder reports whether path is dir or sits under it, compared on a
// separator boundary so a sibling directory cannot pass for a nested one.
func atOrUnder(path, dir string) bool {
	if path == dir {
		return true
	}
	return strings.HasPrefix(path, dir) && len(path) > len(dir) && path[len(dir)] == filepath.Separator
}

// scanState carries what every browser's scan needs, plus the payload being built
// and whether a bound has already cut it short.
type scanState struct {
	info     *model.BrowserExtensionScanInfo
	platform string
	resolver *safepath.Resolver

	// stopped is the reason every browser after this point reports. Set when a
	// cap or the deadline bounds the whole payload rather than one browser.
	stopped string
}

// browserResult is one browser's whole contribution: its coverage status and the
// findings that status vouches for.
type browserResult struct {
	status   string
	reason   string
	profiles int
	findings []model.BrowserExtensionFinding
}

// commit records one browser's coverage entry and its findings together. A finding
// whose browser has no coverage entry is a payload a reader rejects whole.
func (s *scanState) commit(browserID string, r browserResult) {
	if r.status == model.BrowserCoverageFailed || r.status == model.BrowserCoverageNotPresent {
		// A browser whose membership is not known complete ships nothing: half a
		// list under an authoritative status would retire the extensions it left
		// out.
		r.findings = nil
	}
	if len(s.info.Findings)+len(r.findings) > maxExtensionsTotal {
		// The cap cuts at a browser boundary. This browser and every later one
		// report the cause and ship nothing.
		s.stop(model.BrowserExtReasonCapped, model.BrowserExtTruncatedFindingCap)
		r = browserResult{status: model.BrowserCoverageFailed, reason: model.BrowserExtReasonCapped, profiles: r.profiles}
	}
	if r.status == model.BrowserCoverageFailed {
		s.info.ScanComplete = false
	}
	s.info.Browsers = append(s.info.Browsers, model.BrowserCoverage{
		BrowserID:      browserID,
		Status:         r.status,
		ReasonCode:     r.reason,
		ProfileCount:   r.profiles,
		ExtensionCount: len(r.findings),
	})
	s.info.Findings = append(s.info.Findings, r.findings...)
}

// truncate records that a bound cut something out of the payload. Truncation and
// incompleteness travel together, because a reader validates the pair in both
// directions, and the first cause is kept because the bound that hit first shaped
// the result.
func (s *scanState) truncate(truncatedReason string) {
	s.info.Truncated = true
	if s.info.TruncatedReason == "" {
		s.info.TruncatedReason = truncatedReason
	}
	s.info.ScanComplete = false
}

// stop is a bound that ends the run rather than one browser: the total cap and the
// deadline apply to the payload as a whole, so every browser after this point reports
// the same cause and ships nothing. A bound on one browser's own list calls truncate
// instead, so a machine with twenty-one profiles in one browser still has a readable
// answer for the others.
func (s *scanState) stop(reason, truncatedReason string) {
	s.stopped = reason
	s.truncate(truncatedReason)
}

// scanBrowser runs one browser across every data directory it has on this platform
// and reduces the result to one coverage status.
//
// The union of two directories that both exist, a native install and a snap, is the
// answer, which is why a failure in either fails the whole browser: half a union that
// read as complete would retire the missing half's rows.
func (d *Detector) scanBrowser(ctx context.Context, scan *scanState, spec browserSpec, roots []string) browserResult {
	b := &browserScan{occurrences: map[string][]occurrence{}}
	existing := 0
	for _, root := range roots {
		if ctx.Err() != nil {
			b.failPayload(model.BrowserExtReasonTimedOut, model.BrowserExtTruncatedDeadline)
		} else if d.scanRoot(ctx, scan, spec, root, b) {
			existing++
		}
		if b.failure != "" {
			switch {
			case b.payloadWide:
				scan.stop(b.failure, b.truncatedReason)
			case b.truncatedReason != "":
				scan.truncate(b.truncatedReason)
			}
			return browserResult{status: model.BrowserCoverageFailed, reason: b.failure, profiles: b.profiles}
		}
	}
	if existing == 0 {
		// No data directory for this browser, or one holding no installation.
		// Authoritative, and safely so: the only rows it can retire are rows a
		// previous scan of these same directories wrote.
		return browserResult{status: model.BrowserCoverageNotPresent}
	}
	status := model.BrowserCoverageScanned
	if b.degraded != "" {
		// Membership is still complete; an attribute is not.
		status = model.BrowserCoveragePartial
	}
	return browserResult{status: status, reason: b.degraded, profiles: b.profiles, findings: b.fold(spec.ID)}
}

// scanRoot dispatches one data directory to its engine's parser and reports
// whether the directory held an installation.
func (d *Detector) scanRoot(ctx context.Context, scan *scanState, spec browserSpec, root string, b *browserScan) bool {
	if spec.Engine == engineGecko {
		return d.scanGeckoRoot(ctx, scan, root, b)
	}
	return d.scanChromiumRoot(ctx, scan, root, b)
}

// occurrence is one extension as one profile recorded it. Profiles never reach the
// wire, since their names are user-chosen text, so they exist only to drive
// enumeration and this reduction.
type occurrence struct {
	// sortKey is the last tiebreak between the occurrences of one extension: the
	// data directory and then the profile directory. Arbitrary but fixed, which is
	// what makes two runs over an unchanged machine emit identical findings.
	sortKey    string
	enabled    string
	disabledBy string
	// block is taken whole from the winning occurrence, never merged field by field:
	// pairing one profile's version with another's permission set would describe an
	// extension that exists nowhere.
	block model.BrowserExtensionFinding
}

// browserScan accumulates one browser's occurrences and the first thing that went
// wrong with it.
type browserScan struct {
	occurrences map[string][]occurrence
	profiles    int

	// degraded is the headline reason for a partial status: an attribute this scan
	// could not recover. The first cause wins, because a reader is given one reason
	// per browser.
	degraded string

	// failure is the headline reason for a failed status. Set once, and after it
	// nothing more is claimed about this browser.
	failure string
	// truncatedReason is set when failure is a bound being reached rather than a
	// document that could not be read, so the payload says it was cut.
	truncatedReason string
	// payloadWide separates a bound that ends the run from one that ends this
	// browser: the deadline is shared by everything after it, while a cap on this
	// browser's own list says nothing about the next one.
	payloadWide bool
}

func (b *browserScan) degrade(reason string) {
	if b.degraded == "" {
		b.degraded = reason
	}
}

// fail records a browser-local failure: this browser's membership is not known
// complete, and the rest of the scan carries on.
func (b *browserScan) fail(reason string) {
	if b.failure == "" {
		b.failure = reason
	}
}

// failBounded records that a bound on this browser's own list was reached. The
// browser's membership is not known complete and the payload says it was cut, while
// the browsers after it are scanned as usual.
func (b *browserScan) failBounded(reason, truncatedReason string) {
	if b.failure == "" {
		b.failure = reason
		b.truncatedReason = truncatedReason
	}
}

// failPayload records a bound that ends the run, the deadline, so every later
// browser reports it too.
func (b *browserScan) failPayload(reason, truncatedReason string) {
	if b.failure == "" {
		b.failBounded(reason, truncatedReason)
		b.payloadWide = true
	}
}

// add records one occurrence, reporting whether the browser may continue. The
// per-browser cap fails the browser rather than shortening its list, because the list
// is read as the complete set.
func (b *browserScan) add(id string, occ occurrence) bool {
	if _, seen := b.occurrences[id]; !seen && len(b.occurrences) >= maxExtensionsPerBrowser {
		b.failBounded(model.BrowserExtReasonCapped, model.BrowserExtTruncatedFindingCap)
		return false
	}
	b.occurrences[id] = append(b.occurrences[id], occ)
	return true
}

// stateRank orders the states the way the fold's union loop resolves them:
// enabled in any profile wins, and a disabled profile still beats one whose
// state could not be read.
func stateRank(state string) int {
	switch state {
	case model.BrowserExtEnabled:
		return 2
	case model.BrowserExtDisabled:
		return 1
	default:
		return 0
	}
}

// lessOccurrence orders one extension's occurrences so the first describes access the
// machine really has. The block is taken whole from the first, so these keys rank
// whole profiles and never a field.
//
// State ranks first, by the same rule the union loop uses: the first occurrence is a
// maximum by state, so its own state equals the state the loop resolves and the
// version, store and permissions under it belong to a profile that really is in it.
func lessOccurrence(a, b occurrence) bool {
	if ra, rb := stateRank(a.enabled), stateRank(b.enabled); ra != rb {
		return ra > rb
	}
	// Breadth, not count: <all_urls> granted in one profile outranks twenty
	// narrow patterns in another.
	if ba, bb := hasBroadHosts(a.block.HostPermissions), hasBroadHosts(b.block.HostPermissions); ba != bb {
		return ba
	}
	// Content scripts come from the manifest and usually match across profiles, but
	// profiles can sit on different versions. A nil list is nothing read rather than
	// nothing injected, and ranks as not broad either way.
	sa := a.block.ScriptableHostPermissions != nil && hasBroadHosts(*a.block.ScriptableHostPermissions)
	sb := b.block.ScriptableHostPermissions != nil && hasBroadHosts(*b.block.ScriptableHostPermissions)
	if sa != sb {
		return sa
	}
	if la, lb := len(a.block.HostPermissions), len(b.block.HostPermissions); la != lb {
		return la > lb
	}
	if la, lb := len(a.block.Permissions), len(b.block.Permissions); la != lb {
		return la > lb
	}
	// Last and total: this is what makes two runs over an unchanged machine
	// emit identical findings.
	return a.sortKey < b.sortKey
}

// fold reduces every extension's occurrences to one finding.
func (b *browserScan) fold(browserID string) []model.BrowserExtensionFinding {
	ids := make([]string, 0, len(b.occurrences))
	for id := range b.occurrences {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]model.BrowserExtensionFinding, 0, len(ids))
	for _, id := range ids {
		occs := b.occurrences[id]
		sort.SliceStable(occs, func(i, j int) bool { return lessOccurrence(occs[i], occs[j]) })

		f := occs[0].block
		f.BrowserID = browserID
		f.ExtensionID = id
		// Enabled in any one profile means the extension can run on this
		// machine, which is the question being asked.
		f.EnabledState = model.BrowserExtStateUnknown
		for _, occ := range occs {
			if occ.enabled == model.BrowserExtEnabled {
				f.EnabledState = model.BrowserExtEnabled
				break
			}
			if occ.enabled == model.BrowserExtDisabled {
				f.EnabledState = model.BrowserExtDisabled
			}
		}
		// The cause follows the resolved state rather than the winning occurrence,
		// which may well be an enabled one: reading it off that occurrence would
		// attach an enabled profile's empty cause to a disabled row.
		f.DisabledBy = ""
		if f.EnabledState == model.BrowserExtDisabled {
			f.DisabledBy = model.BrowserExtDisabledByUnknown
			for _, occ := range occs {
				if occ.enabled == model.BrowserExtDisabled && occ.disabledBy != "" {
					f.DisabledBy = occ.disabledBy
					break
				}
			}
		}
		if f.Permissions == nil {
			f.Permissions = []string{}
		}
		if f.HostPermissions == nil {
			f.HostPermissions = []string{}
		}
		out = append(out, f)
	}
	return out
}

// readState reads one of a browser's state files through the no-follow resolver.
//
// A file that is simply absent is reported as missing rather than as a failure: a
// browser that has never had a second profile has no second profile's preferences.
// Everything else comes back as a reason code, because a library's own message quotes
// the document it choked on and these documents are the browser's private state.
func (s *scanState) readState(path string, limit int64) (data []byte, missing bool, reason string) {
	raw, _, info, truncated, err := s.resolver.Read(path, limit)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		return nil, true, ""
	default:
		return nil, false, refusalReason(err)
	}
	if !info.Mode().IsRegular() {
		// A directory, device or FIFO where a state file belongs. The open already
		// refused to block on it, and reading it would describe something other than
		// the browser's state.
		return nil, false, model.BrowserExtReasonParseError
	}
	if truncated {
		// The file outgrew its cap. Its prefix is not a shorter version of the
		// document: it either fails to parse for the wrong reason or, worse, parses
		// and reports a fraction of the extensions as the whole set.
		return nil, false, model.BrowserExtReasonCapped
	}
	if hasUTF16BOM(raw) {
		// These parsers are byte-oriented, so a two-byte encoding decodes to almost
		// nothing rather than failing and a profile full of extensions would read as
		// empty.
		return nil, false, model.BrowserExtReasonUnsupportedEncoding
	}
	return stripUTF8BOM(raw), false, ""
}

// listNames returns at most limit immediate entries of a directory. Names only, so
// nothing can accidentally descend, and the bound is applied at the read because
// these directories are exactly the ones a local process can fill.
func (s *scanState) listNames(path string, limit int) (names []string, missing bool, reason string) {
	entries, _, more, err := s.resolver.ReadDirNames(path, limit)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		return nil, true, ""
	default:
		return nil, false, refusalReason(err)
	}
	if more {
		return nil, false, model.BrowserExtReasonCapped
	}
	sort.Strings(entries)
	return entries, false, ""
}

// statEntry reports what a discovered path is without opening it, so a file
// found where a profile directory was expected can be skipped rather than read.
func (s *scanState) statEntry(path string) (isDir, missing bool, reason string) {
	_, info, err := s.resolver.Stat(path)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		return false, true, ""
	default:
		return false, false, refusalReason(err)
	}
	return info.IsDir(), false, ""
}

// refusalReason maps a refused read to one of this phase's codes. Never a
// library's own message: those quote the input they choked on.
func refusalReason(err error) string {
	switch safepath.ReasonOf(err) {
	case safepath.ReasonSymlink:
		return model.BrowserExtReasonSymlinkRejected
	case safepath.ReasonDenied:
		return model.BrowserExtReasonPermissionDenied
	case model.BrowserExtReasonRefusedTCC:
		// The consent guard's own answer, travelling back as the refusal.
		return model.BrowserExtReasonRefusedTCC
	case safepath.ReasonOutsideRoots:
		// A location outside the account's own tree, named by a config file
		// rather than by the catalog. Reported as a refusal rather than as a
		// permission error because nothing was ever asked of the filesystem.
		return model.BrowserExtReasonRefusedTCC
	}
	if os.IsPermission(err) {
		return model.BrowserExtReasonPermissionDenied
	}
	return model.BrowserExtReasonParseError
}

// hasUTF16BOM reports whether data starts with a UTF-16 byte order mark.
func hasUTF16BOM(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return (data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)
}

// stripUTF8BOM removes a leading UTF-8 byte order mark. Windows-authored state files
// carry them, and a BOM in front of a JSON document makes every parser reject the
// whole thing, so a profile full of extensions would report as empty.
func stripUTF8BOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
}

// capBytes shortens a display string to a byte budget at a rune boundary, so a capped
// value is still valid UTF-8. Only for the fields a human reads: an identity or a
// permission is matched rather than read, and a shortened one is a different value.
func capBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
