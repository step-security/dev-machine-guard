package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	pathpkg "path"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

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

// Detector inventories the developer's credential locations. No tool is ever
// asked what credentials it holds: every finding comes from bytes in a file at a
// path the catalog names, so a tool's own account of a secret it keeps elsewhere
// is not this inventory's evidence and not its business to ask for. The one
// command a run makes is the environment probe, which reads the variables that
// move those paths and is told nothing about what is being looked for.
type Detector struct {
	exec     executor.Executor
	skipper  *tcc.Skipper
	readEnv  envProbe
	projects ProjectCandidates
	// Whether the tenant opted in to key fragments for this run.
	keyFragments bool
}

// New builds a detector.
func New(exec executor.Executor) *Detector {
	d := &Detector{exec: exec}
	d.readEnv = d.resolveEnv
	return d
}

// WithSkipper attaches the consent guard. A nil skipper is a no-op.
func (d *Detector) WithSkipper(s *tcc.Skipper) *Detector {
	d.skipper = s
	return d
}

// WithProjects supplies the project files the inventory walk found, which the
// AI-tool and MCP sources probe alongside their fixed locations.
func (d *Detector) WithProjects(p ProjectCandidates) *Detector {
	d.projects = p
	return d
}

// WithKeyFragments has recognized provider keys in the AI-tool and MCP sources
// leave a bounded fragment on their finding. Off unless the tenant opted in.
func (d *Detector) WithKeyFragments(on bool) *Detector {
	d.keyFragments = on
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
	paths = paths.withXDGConfig(env.Values["XDG_CONFIG_HOME"]).withXDGData(env.Values["XDG_DATA_HOME"])

	// One resolver for every read. The consent guard runs before the first syscall
	// on every path, on every hop of every symlink along it. That ordering is the
	// mitigation and there is no other: a read that blocks on a consent prompt does
	// not observe the phase deadline, so the only way not to hang is not to make
	// the call.
	guarded := safepath.New(paths.Home, d.consentGuard())

	scan := &scanState{
		info:     info,
		paths:    paths,
		env:      env,
		envOK:    envOK,
		platform: d.exec.GOOS(),
		guarded:  guarded,
		reported: map[string]bool{},
		gitRepos: map[string]bool{},
		projects: d.projects,
		visited:  map[string]bool{},
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
	capped   bool
	// Which source-and-reason pairs have already been recorded, for the
	// conditions that hold per item of a listing rather than per source. An
	// error names only its source, so repeating one describes nothing further
	// and spends the error budget a genuinely different failure needs.
	reported map[string]bool
	// Per directory, whether it sits inside a working tree. Every key in one
	// directory shares the answer, and the walk that establishes it costs one
	// lstat per level up to the home.
	gitRepos map[string]bool
	projects ProjectCandidates
	// Which source-and-path pairs the AI-tool and MCP sources have read, by both
	// the probed and the resolved spelling, so a file several routes lead to
	// is counted once for its source.
	visited map[string]bool
	// Files taken from directory listings so far, against maxListedCandidates.
	listed int
	// Encoded key fragments attached so far, against maxFragmentBytes.
	fragmentBytes int
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

	guarded := scan.guarded
	if fixed := libraryFiles(s, scan.paths, scan.platform); len(fixed) > 0 {
		// Only catalog paths are exempt, never directories supplied by an override.
		guarded = safepath.New(scan.paths.Home, d.consentGuard(fixed...))
	}
	if retained(s) {
		d.collectRetainedSource(ctx, scan, s, guarded)
		return
	}
	for _, c := range candidatesFor(s, scan.paths, scan.env.Values, scan.platform) {
		found := d.collectCandidate(ctx, scan, s, c.path(), guarded)
		if scan.capped {
			return
		}
		if found && s.Match == matchFirst {
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

	obs, resolved, info, truncated, err := d.observe(s, path, resolver)
	switch {
	case err == nil:
	case os.IsNotExist(err):
		// Neither a finding nor a failure: a path name is not evidence that a
		// credential exists, so nothing is recorded.
		return false
	default:
		// Once per source: a directory override relocating several files fails
		// them all for the one reason.
		scan.addErrorOnce(s.ID, refusalReason(err))
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
	if truncated || obs.Capped {
		// The parse saw a prefix of a longer document, or stopped counting at a
		// bound of its own, so its count is a lower bound. Recorded before the
		// count is looked at: a document whose credentials sit past the cap would
		// otherwise read as empty and complete.
		scan.markCapped(s.ID)
	}
	if obs.Unrecognized {
		// Recorded before the count, and independently of it: a file can hold one
		// confirmed credential and one entry this build cannot read, and reporting
		// only the finding would present the rest of the file as clean.
		scan.addErrorOnce(s.ID, model.CredentialReasonUnrecognizedFormat)
	}
	if obs.Count == 0 {
		// The file is there and holds no credential material. A finding would
		// assert something is in it.
		return false
	}

	scan.addFinding(d.buildFinding(ctx, scan, s, path, resolved, info, obs))
	return true
}

// observe resolves a location, reads it, and classifies whatever came back. One
// resolution and one read serve the whole candidate: the metadata is that of the
// bytes read, not of a second look.
func (d *Detector) observe(s source, path string, resolver *safepath.Resolver) (obs observation, resolved string, info os.FileInfo, truncated bool, err error) {
	data, resolved, info, truncated, err := resolver.Read(path, s.MaxBytes)
	if err != nil {
		return observation{}, "", nil, false, err
	}
	if info.IsDir() {
		// Nothing was read because there was nothing to read; the caller reports
		// the shape mismatch from info.
		return observation{}, resolved, info, false, nil
	}
	if hasUTF16BOM(data) {
		// These parsers are byte-oriented, so a two-byte encoding parses to
		// almost nothing rather than failing, and a file holding credentials
		// would read as holding none. Reporting the encoding is the only
		// outcome that does not under-report.
		return observation{}, "", nil, false, errUnsupportedEncoding
	}
	return parseSource(s, data), resolved, info, truncated, nil
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
		data, resolved, info, truncated, err := resolver.Read(entry, s.MaxBytes)
		if err != nil {
			if !os.IsNotExist(err) {
				// One entry per refusal however many keys it turned away: the
				// record names no file, so a directory the account cannot read
				// would otherwise spend the whole error budget restating one
				// fact and leave no room for the sources read after it.
				scan.addErrorOnce(s.ID, refusalReason(err))
			}
			continue
		}
		if info.IsDir() {
			continue
		}
		if truncated {
			// A key is validated over its complete bytes, so a prefix is not
			// something to classify: it would be indistinguishable from the
			// truncated container this validation exists to reject.
			scan.markCapped(s.ID)
			continue
		}
		state, isKey, malformed := classifySSHKey(data)
		if malformed {
			// One entry for the source however many candidates are damaged, and
			// the siblings are still classified: a key this build cannot confirm
			// must not take the readable keys beside it out of the inventory.
			scan.addErrorOnce(s.ID, model.CredentialReasonUnrecognizedFormat)
		}
		if !isKey {
			continue
		}
		scan.addFinding(d.buildFinding(ctx, scan, s, entry, resolved, info, observation{Count: 1, Protection: state}))
		any = true
	}
	return any
}

// retained reports whether a source is one of the AI-tool and MCP sources, which
// report every file holding material, list catalog directories and probe the
// project files the inventory walk found.
func retained(s source) bool {
	return s.Category == model.CredentialCategoryAITools || s.Category == model.CredentialCategoryMCPServers
}

// collectRetainedSource runs one AI-tool or MCP source: its catalog and project
// candidates are expanded into files first, so a parser can be told which other
// files of the same source exist, then each file is read once.
func (d *Detector) collectRetainedSource(ctx context.Context, scan *scanState, s source, resolver *safepath.Resolver) {
	var files []candidate
	for _, c := range append(candidatesFor(s, scan.paths, scan.env.Values, scan.platform), scan.projectFiles(s)...) {
		files = append(files, scan.expand(s, c, resolver)...)
		if scan.capped {
			return
		}
	}
	var companions []candidate
	for _, c := range files {
		if !c.SQLite {
			companions = append(companions, c)
		}
	}
	for _, c := range files {
		if ctx.Err() != nil {
			scan.addErrorOnce(s.ID, model.CredentialReasonTimedOut)
			return
		}
		d.collectRetained(ctx, scan, s, c, companions, resolver)
		if scan.capped {
			return
		}
	}
}

// expand turns a candidate whose catalog part holds "*" elements into the files
// it names, one bounded nonrecursive listing per element. Only names in the
// listing alphabet are taken, so a listing cannot steer a read into a hidden or
// oddly spelled entry.
func (s *scanState) expand(src source, c candidate, resolver *safepath.Resolver) []candidate {
	if !strings.Contains(c.Rel, "*") {
		return []candidate{c}
	}
	elems := strings.Split(c.Rel, "/")
	dirs := []string{c.Base}
	for i, elem := range elems {
		var next []string
		for _, dir := range dirs {
			if !strings.Contains(elem, "*") {
				next = append(next, filepath.Join(dir, elem))
				continue
			}
			next = append(next, s.listMatches(src, dir, elem, i == len(elems)-1, resolver)...)
			if s.capped {
				return nil
			}
		}
		dirs = next
	}
	out := make([]candidate, 0, len(dirs))
	for _, dir := range dirs {
		out = append(out, candidate{Base: dir, SQLite: c.SQLite})
	}
	return out
}

// listMatches lists one directory and returns the entries matching one catalog
// element, in name order so a capped listing stops at the same place every run.
// An entry that is not the last element must be a directory to be descended.
func (s *scanState) listMatches(src source, dir, elem string, last bool, resolver *safepath.Resolver) []string {
	names, _, more, err := resolver.ReadDirNames(dir, maxKeyDirEntries)
	if err != nil {
		if !os.IsNotExist(err) {
			s.addErrorOnce(src.ID, refusalReason(err))
		}
		return nil
	}
	if more {
		s.markCapped(src.ID)
	}
	slices.Sort(names)
	var out []string
	for _, name := range names {
		if matched, _ := filepath.Match(elem, name); !matched || !listedName(name) {
			continue
		}
		entry := filepath.Join(dir, name)
		if !last {
			if _, info, err := resolver.Stat(entry); err != nil || !info.IsDir() {
				continue
			}
		}
		if s.listed >= maxListedCandidates {
			s.markCapped(src.ID)
			return out
		}
		s.listed++
		out = append(out, entry)
	}
	return out
}

// listedName reports whether a listed entry is spelled the way the tools name
// the files and directories this phase reads: letters and digits of any
// script, '.', '_' and '-', and not hidden. Server names keep their own script
// when a tool turns them into file names.
func listedName(name string) bool {
	if name == "" || name[0] == '.' {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// projectFiles returns the walk's project files this source reads, and records
// once per source whatever kept the walk from covering every project. Files
// outside the home are dropped: the resolver would refuse them, and a refusal
// for a path the catalog never named describes nothing about the source.
func (s *scanState) projectFiles(src source) []candidate {
	if len(src.Project) == 0 {
		return nil
	}
	switch {
	case s.projects.Capped:
		s.markCapped(src.ID)
	case s.projects.TimedOut:
		s.addErrorOnce(src.ID, model.CredentialReasonTimedOut)
	}
	if s.projects.Unreadable {
		s.addErrorOnce(src.ID, model.CredentialReasonPermissionDenied)
	}
	var out []candidate
	for _, file := range s.projects.Files {
		if !s.underHome(file) {
			continue
		}
		for _, pattern := range src.Project {
			if projectMatch(pattern, file) {
				out = append(out, candidate{Base: file})
				break
			}
		}
	}
	return out
}

// underHome reports whether a path lies below either spelling of the home.
func (s *scanState) underHome(path string) bool {
	if _, ok := trimPathPrefix(path, s.paths.Home); ok {
		return true
	}
	if s.paths.HomeResolved == "" {
		return false
	}
	_, ok := trimPathPrefix(path, s.paths.HomeResolved)
	return ok
}

// collectRetained reads one file of an AI-tool or MCP source, parses it, and
// follows the references the parse found one hop.
func (d *Detector) collectRetained(ctx context.Context, scan *scanState, s source, c candidate, companions []candidate, resolver *safepath.Resolver) {
	path := c.path()
	if !scan.firstVisit(s.ID, path) {
		return
	}
	if scan.atFindingCap() {
		scan.markCapped(s.ID)
		return
	}
	in := fileInput{Path: path, SQLite: c.SQLite, Config: c.Config, Home: scan.paths.Home, Companions: companions, Read: scan.associatedReader(s, resolver), Fragments: d.keyFragments}
	var (
		resolved  string
		info      os.FileInfo
		truncated bool
		err       error
	)
	if c.SQLite {
		in.Rows, resolved, info, truncated, err = readDB(ctx, resolver, path, dbSpecs[s.ID])
	} else {
		limit := s.MaxBytes
		if s.RawSuffix != "" && strings.HasSuffix(path, s.RawSuffix) {
			limit = capToken
		}
		in.Data, resolved, info, truncated, err = resolver.Read(path, limit)
		if err == nil && hasUTF16BOM(in.Data) {
			err = errUnsupportedEncoding
		}
	}
	switch {
	case err == nil:
	case os.IsNotExist(err):
		return
	default:
		scan.addErrorOnce(s.ID, refusalReason(err))
		return
	}
	if info.IsDir() || (resolved != path && !scan.firstVisit(s.ID, resolved)) {
		return
	}
	result := fileParsers[s.ID](in)
	d.record(ctx, scan, s, path, resolved, info, truncated, result)
	for _, ref := range result.Refs {
		d.collectRef(ctx, scan, s, ref, resolver)
	}
}

// collectRef reads a file another file names as the holder of its secret. Only
// one hop: what the referenced file names in turn is not followed, so a chain of
// references cannot walk the read anywhere the catalog did not lead.
func (d *Detector) collectRef(ctx context.Context, scan *scanState, s source, ref fileRef, resolver *safepath.Resolver) {
	if !scan.firstVisit(s.ID, ref.Path) {
		return
	}
	if scan.atFindingCap() {
		scan.markCapped(s.ID)
		return
	}
	limit := int64(capConfig)
	if ref.Raw {
		limit = capToken
	}
	data, resolved, info, truncated, err := resolver.Read(ref.Path, limit)
	if err == nil && hasUTF16BOM(data) {
		err = errUnsupportedEncoding
	}
	switch {
	case err == nil:
	case os.IsNotExist(err):
		return
	default:
		scan.addErrorOnce(s.ID, refusalReason(err))
		return
	}
	if info.IsDir() || (resolved != ref.Path && !scan.firstVisit(s.ID, resolved)) {
		return
	}
	var p parsed
	if ref.Raw {
		p = rawSecret(data, d.keyFragments && ref.Key)
	} else {
		p = parseDotenv(data, d.keyFragments)
	}
	d.record(ctx, scan, s, ref.Path, resolved, info, truncated, p)
}

// record turns one parse into the source's errors and, when the file holds
// material, its finding. The errors are recorded before the count is looked at,
// so a file whose material sits past a bound or in an unreadable entry is never
// presented as complete.
func (d *Detector) record(ctx context.Context, scan *scanState, s source, path, resolved string, info os.FileInfo, truncated bool, p parsed) {
	if p.Opaque {
		scan.addErrorOnce(s.ID, model.CredentialReasonUnsupportedEncoding)
	}
	if truncated || p.Capped {
		scan.markCapped(s.ID)
	}
	if p.Unrecognized {
		scan.addErrorOnce(s.ID, model.CredentialReasonUnrecognizedFormat)
	}
	if p.Unresolved {
		scan.addErrorOnce(s.ID, model.CredentialReasonLocationUnresolved)
	}
	if p.Count == 0 {
		return
	}
	finding := d.buildFinding(ctx, scan, s, path, resolved, info, p.observation)
	if s.Category == model.CredentialCategoryAITools {
		finding.Kinds = new(p.Kinds)
	}
	at := scan.addFinding(finding)
	if at >= 0 {
		scan.attachFragments(at, p)
	}
}

// maxFragmentBytes bounds the encoded fragments of one run, so the optional
// fragments can never crowd out the inventory they annotate.
const maxFragmentBytes = 16 << 10

// attachFragments puts a file's fragments on its finding while the run's
// fragment budget lasts. Any left out mark the run's fragments truncated.
func (s *scanState) attachFragments(at int, p parsed) {
	if p.HintsDropped {
		s.info.KeyFragmentsTruncated = true
	}
	for _, hint := range p.Hints {
		encoded, err := json.Marshal(hint)
		if err != nil || s.fragmentBytes+len(encoded) > maxFragmentBytes {
			s.info.KeyFragmentsTruncated = true
			continue
		}
		s.fragmentBytes += len(encoded)
		s.info.Findings[at].KeyFragments = append(s.info.Findings[at].KeyFragments, hint)
	}
}

// associatedReader returns the read a parser uses for a file that qualifies the
// one being parsed, such as the configuration declaring which entries of a
// database are providers. It records its own refusals and bounds, so a parser
// only ever sees bytes or nothing.
func (s *scanState) associatedReader(src source, resolver *safepath.Resolver) func(path string, limit int64) []byte {
	return func(path string, limit int64) []byte {
		data, _, info, truncated, err := resolver.Read(path, limit)
		if err != nil {
			if !os.IsNotExist(err) {
				s.addErrorOnce(src.ID, refusalReason(err))
			}
			return nil
		}
		if info.IsDir() || hasUTF16BOM(data) {
			return nil
		}
		if truncated {
			s.markCapped(src.ID)
		}
		return data
	}
}

// firstVisit reports whether this source has not yet read a path, and records
// that it now has.
func (s *scanState) firstVisit(sourceID, path string) bool {
	key := sourceID + "\x00" + filepath.Clean(path)
	if s.visited[key] {
		return false
	}
	s.visited[key] = true
	return true
}

// libraryPath is a catalog file below the macOS per-user Library, the one place
// the consent guard admits without asking: these are the tools' own fixed
// locations, and refusing them would leave the sources unreadable on every Mac.
// The relative part is kept as elements so a "*" element matches one listed
// name and nothing else.
type libraryPath struct {
	base string
	rel  []string
}

// libraryFiles returns the catalog's own files below the Library for a source,
// ignoring every relocation: a directory a variable supplies is not one the
// catalog vouches for. A database brings the journal files the engine opens
// beside it, and a per-workspace database brings the file naming its workspace.
func libraryFiles(s source, paths userPaths, platform string) []libraryPath {
	if platform != model.PlatformDarwin {
		return nil
	}
	library := filepath.Join(paths.Home, "Library")
	var out []libraryPath
	for _, c := range candidatesFor(s, paths, nil, platform) {
		if _, ok := trimPathPrefix(c.path(), library); !ok {
			continue
		}
		rels := []string{c.Rel}
		if c.SQLite {
			rels = append(rels, c.Rel+"-wal", c.Rel+"-journal")
		}
		if elems := strings.Split(c.Rel, "/"); len(elems) >= 3 && elems[len(elems)-3] == "workspaceStorage" {
			rels = append(rels, pathpkg.Join(pathpkg.Dir(c.Rel), "workspace.json"))
		}
		for _, rel := range rels {
			out = append(out, libraryPath{base: c.Base, rel: strings.Split(rel, "/")})
		}
	}
	return out
}

// admits reports whether a path is this file or one of its ancestors. Siblings
// and descendants are not admitted, so the exemption cannot be widened into a
// listing of the protected directory around the file.
func (l libraryPath) admits(path string) bool {
	rest, ok := trimPathPrefix(path, l.base)
	if !ok {
		_, ancestor := trimPathPrefix(l.base, path)
		return ancestor
	}
	if rest == "" {
		return true
	}
	elems := strings.Split(filepath.ToSlash(rest), "/")
	if len(elems) > len(l.rel) {
		return false
	}
	for i, elem := range elems {
		want := l.rel[i]
		if !strings.Contains(want, "*") {
			if !pathsEqual(elem, want) {
				return false
			}
			continue
		}
		if matched, _ := filepath.Match(want, elem); !matched || !listedName(elem) {
			return false
		}
	}
	return true
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

// errUnsupportedEncoding marks a file whose bytes are not in an encoding these
// parsers read. It carries no detail because the outcome is one reason code
// either way.
var errUnsupportedEncoding = errors.New(model.CredentialReasonUnsupportedEncoding)

// errUnrecognizedFormat marks a file whose structure this build cannot safely
// interpret, such as a database of another schema or one changing under the read.
var errUnrecognizedFormat = errors.New(model.CredentialReasonUnrecognizedFormat)

// consentGuard is what the resolver asks before it touches a path, answering in
// this phase's own reason code so a refusal reads like every other one. A nil
// guard is the whole answer with no skipper: the access has been granted.
func (d *Detector) consentGuard(fixedFiles ...libraryPath) safepath.Guard {
	if d.skipper == nil {
		return nil
	}
	return func(path string) string {
		cleaned := filepath.Clean(path)
		for _, file := range fixedFiles {
			// Allow the exact file and its ancestors, not siblings or descendants.
			// The resolver applies this again to every symlink target before access.
			if file.admits(cleaned) {
				return ""
			}
		}
		if d.skipper.WithinProtected(cleaned) {
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
	if errors.Is(err, errUnrecognizedFormat) {
		return model.CredentialReasonUnrecognizedFormat
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return model.CredentialReasonTimedOut
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

// markCapped records that a bound stopped a source short.
func (s *scanState) markCapped(sourceID string) {
	s.markTruncated()
	s.addErrorOnce(sourceID, model.CredentialReasonCapped)
}

// addErrorOnce records a reason at most once for a source, for the conditions
// that can hold for every item of one listing: a directory of damaged keys, or a
// bound that bites on each of two hundred candidates, describes one source that
// could not be fully read rather than two hundred failures.
func (s *scanState) addErrorOnce(sourceID, reason string) {
	key := sourceID + "\x00" + reason
	if s.reported[key] {
		return
	}
	s.reported[key] = true
	s.addError(sourceID, reason)
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
