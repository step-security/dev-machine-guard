package credentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/detector"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/safepath"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// envProbe reads the variables that can relocate a credential file. A function
// field for the same reason the program runner is an interface: both reach
// outside this process, into a session no test host can be made to have.
type envProbe func(ctx context.Context, paths userPaths) (userEnv, bool)

// userEnv is what one environment probe established. A variable set but not
// resolvable is a third state: the location moved somewhere this run cannot
// name, so the default is not the answer and its absence proves nothing.
type userEnv struct {
	Values     map[string]string
	Unresolved map[string]bool
}

// Detector inventories the developer's credential locations.
type Detector struct {
	exec    executor.Executor
	skipper *tcc.Skipper
	runner  ghRunner
	readEnv envProbe
	mcp     *detector.MCPDetector
}

// New builds a detector.
func New(exec executor.Executor) *Detector {
	d := &Detector{
		exec:   exec,
		runner: execRunner{},
		mcp:    detector.NewMCPDetector(exec),
	}
	d.readEnv = d.resolveEnv
	return d
}

// WithSkipper attaches the consent guard. A nil skipper is a no-op.
func (d *Detector) WithSkipper(s *tcc.Skipper) *Detector {
	d.skipper = s
	return d
}

// withRunner replaces the program runner. Tests use it to exercise the fence
// around the one child process this phase starts.
func (d *Detector) withRunner(r ghRunner) *Detector {
	d.runner = r
	return d
}

// withEnv replaces the environment probe.
func (d *Detector) withEnv(p envProbe) *Detector {
	d.readEnv = p
	return d
}

// Detect returns the inventory for one run. Never nil and never an error: an
// unreadable source becomes an entry in the result's own error list, so one bad
// file does not discard the sources that succeeded.
func (d *Detector) Detect(ctx context.Context) *model.CredentialScanInfo {
	started := time.Now()
	info := &model.CredentialScanInfo{
		Findings:             []model.CredentialFinding{},
		Errors:               []model.CredentialError{},
		ScanComplete:         true,
		PayloadSchemaVersion: model.CurrentCredentialSchemaVersion,
		CatalogVersion:       catalogVersion,
		// Every read is made by the agent's own process, so the run describes
		// one principal. Stating it here too lets a reader reject a snapshot it
		// cannot honour before looking at a single finding.
		CollectionPrincipal: model.CredentialPrincipalAgentEffective,
	}
	defer func() {
		info.CollectedAt = time.Now().Unix()
		info.DurationMs = time.Since(started).Milliseconds()
	}()

	paths, ok := d.resolveUser()
	if !ok {
		// Without a resolved account there is no root set to contain reads to
		// and no home to look under. Guessing at a home would put the boundary
		// under the control of whatever environment the agent inherited.
		//
		// The error carries no source: nothing was attempted, so there is no
		// source to name. This is the one reason code that reports the run
		// rather than a source.
		info.ScanComplete = false
		info.Errors = append(info.Errors, model.CredentialError{ReasonCode: model.CredentialReasonSkippedNoUser})
		return info
	}

	env, envOK := d.readEnv(ctx, paths)
	if env.Values == nil {
		env.Values = map[string]string{}
	}
	paths = paths.withXDGConfig(env.Values["XDG_CONFIG_HOME"])

	// Two resolvers, differing only in whether the consent guard applies. The
	// guarded one is the default and runs before the first syscall on every path,
	// on every hop of every symlink along it. That ordering is the mitigation and
	// there is no other: a read that blocks on a consent prompt does not observe
	// the phase deadline, so the only way not to hang is not to make the call. The
	// targeted one is for locations this agent's own policy declines wholesale
	// while the platform does not gate reading them; containment still applies.
	guarded := safepath.New(paths.Home, d.consentGuard())
	targeted := safepath.New(paths.Home, nil)

	scan := &scanState{
		info:          info,
		paths:         paths,
		env:           env,
		envOK:         envOK,
		platform:      d.exec.GOOS(),
		guarded:       guarded,
		targeted:      targeted,
		cappedSources: map[string]bool{},
		gitRepos:      map[string]bool{},
	}

	for _, s := range sources {
		if !s.applies(scan.platform) {
			continue
		}
		// Checked here rather than relied on inside the reads, because a file
		// read does not observe a context. A source the remaining time cannot
		// cover is reported as not completed instead of started and abandoned.
		if ctx.Err() != nil {
			scan.addError(s.ID, model.CredentialReasonTimedOut)
			break
		}
		d.collectSource(ctx, scan, s)
		if scan.capped {
			break
		}
	}
	return info
}

// scanState carries the per-run values every source needs, so the collectors
// take one argument rather than eight.
type scanState struct {
	info     *model.CredentialScanInfo
	paths    userPaths
	env      userEnv
	envOK    bool
	platform string
	guarded  *safepath.Resolver
	targeted *safepath.Resolver
	capped   bool
	// Which sources have already reported a cap, so a bound that bites
	// repeatedly contributes one entry rather than one per item.
	cappedSources map[string]bool
	// Per directory, whether it sits inside a working tree. Every key in one
	// directory shares the answer, and the walk that establishes it costs one
	// lstat per level up to the home.
	gitRepos map[string]bool
}

// resolveUser resolves the developer whose credentials this run describes, from
// the operating system's own record of who is signed in. Nothing comes from the
// environment: the agent runs as a system account, so an inherited home points at
// a service account, and a boundary derived from a value the scanned session
// controls bounds nothing. Console-user detection engages only on macOS;
// elsewhere the agent already runs as the account being described.
func (d *Detector) resolveUser() (userPaths, bool) {
	u, err := d.exec.LoggedInUser()
	if err != nil || u == nil || u.Username == "" {
		return userPaths{}, false
	}
	home := u.HomeDir
	if home == "" {
		home, err = d.exec.HomeDir(u.Username)
		if err != nil || home == "" {
			return userPaths{}, false
		}
	}
	paths := newUserPaths(u.Username, home, d.exec.GOOS())
	// Containment holds the home in both spellings, so tokenisation is told about
	// the second one too. A failure here is not a refusal: the written spelling
	// still bounds and labels every path, and the resolved one only lets a path
	// that arrived in the filesystem's spelling be recognised as the same place.
	if resolved, err := d.exec.EvalSymlinks(home); err == nil {
		paths = paths.withResolvedHome(resolved)
	}
	return paths, true
}

// collectSource runs one catalog entry.
func (d *Detector) collectSource(ctx context.Context, scan *scanState, s source) {
	// A source whose relocation could not be read is incomplete before anything is
	// probed. The default path is still tried, but it must not be presented as an
	// authoritative absence while the setting that could have moved it is unknown.
	if !scan.relocationKnown(s) {
		scan.addError(s.ID, model.CredentialReasonLocationUnresolved)
	}

	if s.Mode == readDelegated {
		d.collectDelegated(ctx, scan, s)
		return
	}

	for _, c := range candidatesFor(s, scan.paths, scan.env.Values, scan.platform) {
		found := d.collectCandidate(ctx, scan, s, c, scan.guarded)
		if scan.capped {
			return
		}
		if found && s.Match == matchFirst {
			return
		}
	}
}

// collectDelegated runs a source whose paths another component declares.
func (d *Detector) collectDelegated(ctx context.Context, scan *scanState, s source) {
	for _, declared := range d.mcp.DetectKnownUserConfigs(scan.paths.Home, scan.paths.AppData) {
		path, rewritten := applyPrefixOverrides(declared, s, scan.paths, scan.env.Values)
		// A declared location is one of a fixed set this agent already reads:
		// named files in per-application configuration directories its own
		// policy declines as a group even though the platform serves them
		// without prompting. Reading one is a targeted read, not a traversal.
		// A rewritten location is not that — its leading directory came from a
		// variable in the scanned session, and a value naming a consent-gated
		// tree would block the read past any deadline.
		resolver := scan.targeted
		if rewritten {
			resolver = scan.guarded
		}
		d.collectCandidate(ctx, scan, s, path, resolver)
		if scan.capped {
			return
		}
	}
}

// collectCandidate probes one location and records what it finds, reporting
// whether it produced a finding — what a first-match source needs to stop.
func (d *Detector) collectCandidate(ctx context.Context, scan *scanState, s source, path string, resolver *safepath.Resolver) bool {
	if scan.atFindingCap() {
		scan.markCapped(s.ID)
		return false
	}

	obs, hosts, resolved, info, truncated, err := d.observe(s, path, resolver)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		// Neither a finding nor a failure: a path name is not evidence that a
		// credential exists, so nothing is recorded.
		return false
	default:
		scan.addError(s.ID, refusalReason(err))
		return false
	}
	if info.IsDir() != (s.Mode == readKeyDir) {
		// The wrong kind of object for this source, so nothing here is the
		// thing being looked for.
		return false
	}
	if s.Mode == readKeyDir {
		return d.collectKeyDir(ctx, scan, s, path, resolver)
	}
	if truncated {
		// The parse saw a prefix of a longer document, so its count is a lower
		// bound. Recorded before the count is looked at: a document whose
		// credentials sit past the cap would otherwise read as empty and complete.
		scan.markCapped(s.ID)
	}
	if obs.Count == 0 {
		// The file is there and holds no credential and no reference to one. A
		// finding would assert something is in it.
		return false
	}

	index := scan.addFinding(d.buildFinding(ctx, scan, s, path, resolved, info, obs))
	if index >= 0 && len(hosts) > 0 {
		d.enrichGitHubHosts(ctx, scan, hosts, path, index)
	}
	return true
}

// observe resolves a location, reads it if its source is read by content, and
// classifies whatever came back. One resolution and one read serve the whole
// candidate: the metadata is that of the bytes read, not of a second look.
func (d *Detector) observe(s source, path string, resolver *safepath.Resolver) (obs observation, hosts []githubHostConfig, resolved string, info os.FileInfo, truncated bool, err error) {
	if s.Mode == readStat {
		// The file is the credential in its entirety, so its existence and size
		// are the observation. Nothing here opens it.
		resolved, info, err = resolver.Stat(path)
		if err != nil {
			return observation{}, nil, "", nil, false, err
		}
		if info.IsDir() || info.Size() == 0 {
			// An empty one holds nothing, and a directory is the wrong shape —
			// the caller reports that from info.
			return observation{}, nil, resolved, info, false, nil
		}
		return observation{Count: 1, Protection: model.CredentialProtectionPlaintext}, nil, resolved, info, false, nil
	}

	data, resolved, info, truncated, err := resolver.Read(path, s.MaxBytes)
	if err != nil {
		return observation{}, nil, "", nil, false, err
	}
	if info.IsDir() {
		// Nothing was read because there was nothing to read; the caller reports
		// the shape mismatch from info.
		return observation{}, nil, resolved, info, false, nil
	}
	if hasUTF16BOM(data) {
		// These parsers are byte-oriented, so a two-byte encoding parses to
		// almost nothing rather than failing, and a file holding credentials
		// would read as holding none. Reporting the encoding is the only
		// outcome that does not under-report.
		return observation{}, nil, "", nil, false, errUnsupportedEncoding
	}
	obs, hosts = parseSource(s, resolved, data)
	return obs, hosts, resolved, info, truncated, nil
}

// collectKeyDir lists the key directory and classifies each key in it. Each key
// becomes its own finding: two keys in one directory routinely differ in mode and
// in repository status, the only two things a customer acts on.
func (d *Detector) collectKeyDir(ctx context.Context, scan *scanState, s source, path string, resolver *safepath.Resolver) bool {
	names, _, more, err := resolver.ReadDirNames(path, maxKeyDirEntries)
	if err != nil {
		scan.addError(s.ID, refusalReason(err))
		return false
	}
	if more {
		// The listing stopped at its bound, so the keys below are a subset and
		// the absence of a finding for a name past it is not evidence.
		scan.markCapped(s.ID)
	}

	any := false
	for _, name := range names {
		if !looksLikeKeyFile(name) {
			continue
		}
		if scan.atFindingCap() {
			scan.markCapped(s.ID)
			return any
		}

		entry := filepath.Join(path, name)
		// The cap here is the header, not the file: the fields that decide
		// protection are at the front, so a capped read is a whole observation
		// and does not mark the snapshot partial.
		data, resolved, info, _, err := resolver.Read(entry, s.MaxBytes)
		if err != nil {
			if !os.IsNotExist(err) {
				scan.addError(s.ID, refusalReason(err))
			}
			continue
		}
		if info.IsDir() {
			continue
		}
		state, isKey := classifySSHKey(data)
		if !isKey {
			continue
		}
		scan.addFinding(d.buildFinding(ctx, scan, s, entry, resolved, info, observation{Count: 1, Protection: state}))
		any = true
	}
	return any
}

// buildFinding assembles one record.
func (d *Detector) buildFinding(ctx context.Context, scan *scanState, s source, path string, resolved string, info os.FileInfo, obs observation) model.CredentialFinding {
	finding := model.CredentialFinding{
		SourceID:   s.ID,
		Category:   s.Category,
		Location:   scan.paths.tokenise(path),
		Count:      obs.Count,
		Protection: obs.Protection,
		Mode:       permissionMode(info, scan.platform),
		// Size and modification time together cover change detection without
		// hashing: for a short, low-entropy credential a digest would be a
		// guessing oracle rather than a fingerprint.
		Size:  info.Size(),
		MTime: info.ModTime().Unix(),
		// The user-aware executor redirects commands, not file reads, so a
		// fixed-path read describes the agent's access rather than the
		// developer's, and a record silent on that would mean two things.
		CollectionPrincipal: model.CredentialPrincipalAgentEffective,
	}
	if tokenised := scan.paths.tokenise(resolved); tokenised != finding.Location {
		finding.ResolvedLocation = tokenised
	}
	if scan.platform == model.PlatformWindows {
		finding.BroadReadAllowACEPresent = broadReadAllowACE(resolved)
	}
	finding.InGitRepo = scan.inGitRepo(resolved)
	if finding.InGitRepo {
		finding.GitTracked = gitTracked(ctx, d.exec, resolved)
	}
	return finding
}

// enrichGitHubHosts attaches the CLI's own report to the finding just recorded.
// Every way the report can fail becomes a scope status on the hosts it describes,
// never an error on the source: the configuration itself was read successfully.
func (d *Detector) enrichGitHubHosts(ctx context.Context, scan *scanState, hosts []githubHostConfig, configPath string, index int) {
	scan.info.Findings[index].GitHub = d.githubScopeReports(ctx, scan, hosts, configPath)
}

// githubScopeReports runs the probe when it can run at all, and returns one
// entry per configured host either way.
func (d *Detector) githubScopeReports(ctx context.Context, scan *scanState, hosts []githubHostConfig, configPath string) []model.CredentialGitHubHost {
	// The permissions a token carries are not on disk, so establishing them means
	// asking the tool that holds it — and as a system account there is no way to
	// reach the developer's keystore, so the child would answer for the wrong one.
	if scan.platform == model.PlatformWindows && d.exec.IsRoot() {
		return githubHostReports(hosts, nil, model.CredentialScopeUnavailable)
	}

	binary, err := d.exec.LookPath("gh")
	if err != nil || binary == "" {
		return githubHostReports(hosts, nil, model.CredentialScopeUnavailable)
	}
	configDir := filepath.Dir(configPath)
	if !scan.guarded.Contains(configDir) {
		// The child is pointed at this directory. Outside the developer's own
		// tree, pointing the tool at it would have it read a configuration this
		// run has no business reading.
		return githubHostReports(hosts, nil, model.CredentialScopeUnavailable)
	}

	out, runErr := d.runner.Run(ctx, ghRequest{
		Binary:         binary,
		ConfigDir:      configDir,
		Username:       scan.paths.Username,
		DropPrivileges: d.exec.IsRoot(),
	})
	byHost, parsed := parseGHStatus(out)
	switch {
	case parsed:
	case runErr != nil:
		// The child did not complete — a timeout, or a refused privilege drop.
		// Only whether it failed is used; its diagnostics are never read.
		return githubHostReports(hosts, nil, model.CredentialScopeUnavailable)
	default:
		// It produced something that is not the document asked for, which an
		// older build does. Success is judged on the document, not the exit
		// status: this command exits successfully even when authentication fails.
		return githubHostReports(hosts, nil, model.CredentialScopeUnsupportedCLI)
	}
	return githubHostReports(hosts, byHost, model.CredentialScopeUnavailable)
}

// errUnsupportedEncoding marks a file whose bytes are not in an encoding these
// parsers read. It carries no detail because the outcome is one reason code
// either way.
var errUnsupportedEncoding = errors.New(model.CredentialReasonUnsupportedEncoding)

// consentGuard is what the resolver asks before it touches a path, answering in
// this phase's own reason code so a refusal reads like every other one. A nil
// guard is the whole answer with no skipper: the access has been granted.
func (d *Detector) consentGuard() safepath.Guard {
	if d.skipper == nil {
		return nil
	}
	return func(path string) string {
		if d.skipper.WithinProtected(path) {
			return model.CredentialReasonRefusedTCC
		}
		return ""
	}
}

// refusalReason maps a refused or failed read to one of a closed set of codes,
// never a parser's or library's own message: those quote the input they choked
// on, and the input here is a credential file.
func refusalReason(err error) string {
	if errors.Is(err, errUnsupportedEncoding) {
		return model.CredentialReasonUnsupportedEncoding
	}
	if reason := safepath.ReasonOf(err); reason != "" {
		return reason
	}
	if os.IsPermission(err) {
		return model.CredentialReasonPermissionDenied
	}
	return model.CredentialReasonLocationUnresolved
}

// addFinding records a finding, honouring the result-size cap, and returns where
// it landed so a caller with more to attach can reach it. A finding the cap
// swallowed returns -1.
func (s *scanState) addFinding(f model.CredentialFinding) int {
	if s.atFindingCap() {
		return -1
	}
	s.info.Findings = append(s.info.Findings, f)
	return len(s.info.Findings) - 1
}

// atFindingCap reports whether the result is full, marking the run truncated the
// first time it is.
func (s *scanState) atFindingCap() bool {
	if len(s.info.Findings) < maxFindings {
		return false
	}
	s.markTruncated()
	s.capped = true
	return true
}

// markCapped records that a bound stopped a source short. One entry per source:
// a bound biting on every item of a listing describes one incomplete source, not
// two hundred.
func (s *scanState) markCapped(sourceID string) {
	s.markTruncated()
	if s.cappedSources[sourceID] {
		return
	}
	s.cappedSources[sourceID] = true
	s.addError(sourceID, model.CredentialReasonCapped)
}

// relocationKnown reports whether every variable that could move this source's
// location was established. Asked per source: marking every source would spend
// the snapshot's completeness on sources read exactly as configured.
func (s *scanState) relocationKnown(src source) bool {
	if len(src.Overrides) == 0 {
		return true
	}
	if !s.envOK {
		return false
	}
	for _, o := range src.Overrides {
		if s.env.Unresolved[o.Var] {
			return false
		}
	}
	return true
}

// addError records a source that was attempted and could not be collected. Any
// entry here means the snapshot is incomplete.
func (s *scanState) addError(sourceID, reason string) {
	s.info.ScanComplete = false
	if len(s.info.Errors) >= maxErrors {
		s.markTruncated()
		return
	}
	s.info.Errors = append(s.info.Errors, model.CredentialError{SourceID: sourceID, ReasonCode: reason})
}

// markTruncated records that a cap bounded the result, clearing completeness as
// well: this snapshot replaces its predecessor wholesale, so it is the only
// thing left to carry the fact that it is partial.
func (s *scanState) markTruncated() {
	s.info.Truncated = true
	s.info.ScanComplete = false
}
