package detector

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Cargo collection limits.
// ponytail: unmeasured on fleet data; tune after VM lab measurements.
var (
	maxCargoWalkEntries       = 100_000 // per discovery or cache root
	maxCargoWalkDepth         = 128
	maxCargoRecords           = 50_000   // sources + projects + workspaces + packages
	maxCargoOutputBytes       = 16 << 20 // both Cargo sections, serialized
	maxCargoMarkerBytes int64 = 4096     // .cargo-ok and Git HEAD/ref files
)

// CargoScanner statically collects Rust package inventory and the Cargo
// config audit for one developer. It never runs a command, sources a shell or
// touches the network: every path goes through a guarded, bounded executor
// file method.
type CargoScanner struct {
	exec executor.Executor
	log  *progress.Logger
	// protection builds the path guards; a seam so tests can place protected
	// directories and network volumes under a temp home.
	protection func(home string, includeNetworkVolumes *bool) (protected func(string) string, volume func(string) bool)
}

// NewCargoScanner must be given the raw executor, never a UserAwareExecutor,
// whose Getenv sources a login shell.
func NewCargoScanner(exec executor.Executor, log *progress.Logger) *CargoScanner {
	return &CargoScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

// cargoScan is the state of one Scan call.
type cargoScan struct {
	ctx       context.Context
	exec      executor.Executor
	goos      string
	identity  string
	home      string
	roots     []string // approved walk scope: home plus every absolute search root
	guard     func(string) string
	volume    func(string) bool
	projFS    executor.Executor
	verified  bool
	homes     []string // default Cargo home, then a distinct effective one
	cargoHome string   // effective Cargo home; empty when unresolved
	snap      configaudit.CargoConfigSnapshot
	reasons   []string // global, not tied to a source
	sources   []*model.CargoSource
	byID      map[string]*model.CargoSource
	budget    int // record rows left; see charge

	states     []*cargoManifestState
	byManifest map[string]*cargoManifestState // manifest path key
	vendorDirs []cargoFound                   // directory sources detected by the walk
	projects   []model.CargoProject
	workspaces []model.CargoWorkspace
	packages   []model.CargoPackage
}

// cargoFound is a path found under a discovery source.
type cargoFound struct{ path, parentID string }

// cargoManifestState is one Cargo.toml read for the inventory. Its source is
// registered only once the manifest is known not to belong to a vendored or
// configured source directory.
type cargoManifestState struct {
	src        *model.CargoSource
	path, dir  string
	m          *cargoManifest // nil when unreadable or malformed
	root       *cargoManifestState
	unresolved bool                  // workspace membership could not be established
	members    []*cargoManifestState // on a workspace root, itself included when it is a package
	missing    []model.CargoWorkspaceMember
	override   bool // named only by a config paths or patch entry, outside any observed context
}

// Scan returns both Cargo sections, always non-nil. An unresolvable or
// service identity is declined with user_unresolved and no filesystem
// access: a root account's home is never a silent substitute for the
// developer's.
func (s *CargoScanner) Scan(ctx context.Context, target *user.User, searchDirs []string, includeNetworkVolumes *bool) (*model.CargoInventory, *model.CargoConfigAudit) {
	start := time.Now()
	detector := configaudit.NewCargoConfigDetector(s.exec)
	if target == nil || target.Username == "" || target.HomeDir == "" || isGoServiceIdentity(s.exec.GOOS(), target) {
		inv := newCargoInventory()
		inv.Status, inv.Reasons = model.CargoStatusPartial, []string{model.CargoReasonUserUnresolved}
		audit, _ := detector.Detect(ctx, configaudit.CargoConfigScope{})
		s.log.Debug("cargo scan: declined, no developer identity")
		return &inv, &audit
	}

	home := filepath.Clean(target.HomeDir)
	guard, volume := s.protection(home, includeNetworkVolumes)
	g := &cargoScan{
		ctx: ctx, exec: s.exec, goos: s.exec.GOOS(), identity: target.Username, home: home, guard: guard, volume: volume,
		roots: []string{home}, byID: map[string]*model.CargoSource{}, budget: maxCargoRecords,
		byManifest: map[string]*cargoManifestState{},
	}
	searchDirs = slices.Clone(searchDirs)
	for i, d := range searchDirs {
		if d != "" {
			searchDirs[i] = canonicalNoStat(d, home)
		}
		if filepath.IsAbs(searchDirs[i]) {
			g.roots = append(g.roots, searchDirs[i])
		}
	}
	g.projFS = s.exec.GuardedFiles(g.roots, guard, maxCargoMetadataBytes)
	current, err := s.exec.CurrentUser()
	g.verified = err == nil && target.Uid != "" && current.Uid == target.Uid
	g.resolveHomes()

	walk := g.searchRoots(searchDirs)
	for _, r := range walk {
		g.walkRoot(r)
	}
	var audit model.CargoConfigAudit
	for {
		g.readQueued()
		g.associate()
		for g.enqueueInherited() {
			g.readQueued()
			g.associate()
		}
		audit, g.snap = detector.Detect(ctx, configaudit.CargoConfigScope{
			Username: g.identity, Home: home, Roots: g.roots, Protected: guard, Volume: volume,
			ProcessVerified: g.verified, CargoHome: g.cargoHome, Contexts: g.contexts(), RegistryNames: g.registryNames(),
		})
		before := len(g.states)
		for _, p := range g.snap.LocalPaths() {
			if s := g.enqueue(filepath.Join(p, "Cargo.toml"), ""); s != nil {
				s.override = true
			}
		}
		if len(g.states) == before {
			break
		}
		// Config overrides need the same workspace and inherited-path handling
		// as walked manifests. enqueue deduplicates and bounds the queue.
	}

	g.registerManifests()
	g.emitProjects()
	g.emitLockfiles()
	g.scanDirectorySources()
	g.scanLocalRegistries()
	for _, h := range g.homes {
		g.scanRegistryCache(h)
		g.scanGitCheckouts(h)
	}
	g.scanInstallRoots()
	inv := g.finish()

	if size := goJSONSize(inv) + goJSONSize(&audit); size > maxCargoOutputBytes {
		envelope := newCargoInventory()
		envelope.Status, envelope.Reasons = model.CargoStatusPartial, []string{model.CargoReasonOutputSizeLimit}
		inv = &envelope
	}
	s.log.Debug("cargo scan: inventory=%s (%d sources, %d projects, %d workspaces, %d packages) audit=%s (%d files, %d findings) in %dms",
		inv.Status, len(inv.Sources), len(inv.Projects), len(inv.Workspaces), len(inv.Packages),
		audit.Status, len(audit.Files), len(audit.Findings), time.Since(start).Milliseconds())
	return inv, &audit
}

func newCargoInventory() model.CargoInventory {
	return model.CargoInventory{
		SchemaVersion: model.CargoInventorySchemaVersion, Status: model.CargoStatusComplete, Reasons: []string{},
		Sources: []model.CargoSource{}, Projects: []model.CargoProject{}, Workspaces: []model.CargoWorkspace{},
		Packages: []model.CargoPackage{},
	}
}

// resolveHomes picks the default ~/.cargo and, from a verified process
// environment, a distinct absolute CARGO_HOME. A relative CARGO_HOME depends
// on an unknown working directory, so the effective home is unresolved.
func (g *cargoScan) resolveHomes() {
	def := filepath.Join(g.home, ".cargo")
	g.homes, g.cargoHome = []string{def}, def
	if !g.verified {
		return
	}
	switch v := g.exec.Getenv("CARGO_HOME"); {
	case v == "":
	case !filepath.IsAbs(v):
		g.cargoHome = ""
		g.globalReason(model.CargoReasonPathUnresolved)
	default:
		g.cargoHome = filepath.Clean(v)
		if g.key(g.cargoHome) != g.key(def) {
			g.homes = append(g.homes, g.cargoHome)
		}
	}
}

func (g *cargoScan) key(path string) string { return configaudit.GoPathKey(g.goos, path) }

func (g *cargoScan) globalReason(reason string) {
	if !slices.Contains(g.reasons, reason) {
		g.reasons = append(g.reasons, reason)
	}
}

// newSource builds a source without registering or charging it.
func (g *cargoScan) newSource(kind, path, parent string) *model.CargoSource {
	return &model.CargoSource{
		SourceID: configaudit.GoSourceID(g.identity, kind, path), Kind: kind, Path: path,
		Status: model.CargoStatusComplete, Presence: model.CargoPresencePresent, Reasons: []string{},
		ParentSourceID: parent, DiscoveredSources: []string{},
	}
}

// register adds src once, charging one row. It returns the registered source
// for that ID, or nil once the record budget is spent. A parent that was
// never registered is dropped rather than left dangling.
func (g *cargoScan) register(src *model.CargoSource) *model.CargoSource {
	if existing := g.byID[src.SourceID]; existing != nil {
		return existing
	}
	if g.byID[src.ParentSourceID] == nil {
		src.ParentSourceID = ""
	}
	if !g.charge(g.byID[src.ParentSourceID], 1) {
		return nil
	}
	g.sources = append(g.sources, src)
	g.byID[src.SourceID] = src
	return src
}

func (g *cargoScan) addSource(kind, path, parent string) *model.CargoSource {
	return g.register(g.newSource(kind, path, parent))
}

// charge spends n rows on a record owned by src. The first record that does
// not fit spends the rest, so nothing after it is collected, and marks src and
// every enclosing source partial; a miss with no owner is a global reason.
// Collection keeps charging each remaining owner once, without reading, so no
// owner whose records were dropped is left complete.
func (g *cargoScan) charge(src *model.CargoSource, n int) bool {
	if n <= g.budget {
		g.budget -= n
		return true
	}
	g.budget = 0
	if src == nil {
		g.globalReason(model.CargoReasonRecordLimit)
	}
	for ; src != nil; src = g.byID[src.ParentSourceID] {
		cargoDegrade(src, model.CargoReasonRecordLimit)
	}
	return false
}

func cargoDegrade(src *model.CargoSource, reason string) {
	src.Status = model.CargoStatusPartial
	if reason != "" && !slices.Contains(src.Reasons, reason) {
		src.Reasons = append(src.Reasons, reason)
	}
}

// expired marks src when the phase deadline has passed. A blocked syscall is
// not interrupted; the check runs between entries, reads and parses.
func (g *cargoScan) expired(src *model.CargoSource) bool {
	if g.ctx.Err() == nil {
		return false
	}
	cargoDegrade(src, model.CargoReasonDeadlineExceeded)
	return true
}

func (g *cargoScan) reason(err error, path string) string {
	return configaudit.CargoReadReason(err, path, g.volume)
}

// readFile stats then reads path within limit. It reports a missing file
// separately from every other failure, which carries a reason.
func (g *cargoScan) readFile(files executor.Executor, path string, limit int64) (data []byte, missing bool, reason string) {
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, true, ""
	case err != nil:
		return nil, false, g.reason(err, path)
	case !info.Mode().IsRegular():
		return nil, false, model.CargoReasonUnsupportedEntry
	case info.Size() > limit:
		return nil, false, model.CargoReasonSizeLimit
	}
	data, err = files.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, model.CargoReasonChangedDuringScan
	} else if err != nil {
		return nil, false, g.reason(err, path)
	}
	return data, false, ""
}

// read reads the file a source stands for. A missing targeted file is a
// complete absence; a discovered file that vanished changed during the scan.
func (g *cargoScan) read(src *model.CargoSource, files executor.Executor, path string, limit int64, targeted bool) ([]byte, bool) {
	data, missing, reason := g.readFile(files, path, limit)
	switch {
	case missing && targeted:
		src.Presence = model.CargoPresenceAbsent
		return nil, false
	case missing:
		src.Presence = model.CargoPresenceUnknown
		cargoDegrade(src, model.CargoReasonChangedDuringScan)
		return nil, false
	case reason != "":
		if reason != model.CargoReasonSizeLimit && reason != model.CargoReasonUnsupportedEntry {
			src.Presence = model.CargoPresenceUnknown
		}
		cargoDegrade(src, reason)
		return nil, false
	}
	return data, true
}

// fileFS reads a metadata file inside the approved roots, or as one exact
// targeted file outside them; the protection guard applies either way.
func (g *cargoScan) fileFS(path string) executor.Executor {
	if configaudit.GoWithinRoots(g.goos, path, g.roots) {
		return g.projFS
	}
	return g.exec.GuardedFiles([]string{path}, g.guard, maxCargoMetadataBytes)
}

// rootFS resolves a directory source and returns a reader rooted at its
// physical path, so a redirected root can be neither left nor swapped.
func (g *cargoScan) rootFS(src *model.CargoSource, limit int64) (executor.Executor, string, bool) {
	if g.expired(src) {
		src.Presence = model.CargoPresenceUnknown
		return nil, "", false
	}
	if g.guard(src.Path) != "" {
		src.Presence = model.CargoPresenceUnknown
		cargoDegrade(src, g.guardReason(src.Path))
		return nil, "", false
	}
	phys, err := g.exec.GuardedFiles([]string{src.Path}, g.guard, 0).EvalSymlinks(src.Path)
	if errors.Is(err, fs.ErrNotExist) {
		src.Presence = model.CargoPresenceAbsent
		return nil, "", false
	} else if err != nil {
		src.Presence = model.CargoPresenceUnknown
		cargoDegrade(src, g.reason(err, src.Path))
		return nil, "", false
	}
	return g.exec.GuardedFiles([]string{phys}, g.guard, limit), phys, true
}

// guardReason is the reason a guard refusal of path is reported with.
func (g *cargoScan) guardReason(path string) string {
	if g.volume(path) {
		return model.CargoReasonRefusedNetworkVolume
	}
	return model.CargoReasonSkippedProtected
}

// cargoRoot is a search root that resolved and will be walked.
type cargoRoot struct {
	src        *model.CargoSource
	path, phys string
}

// searchRoots registers each approved search root once. The outermost
// walkable root owns what it contains, and the first configured spelling of
// a physical directory is kept.
func (g *cargoScan) searchRoots(searchDirs []string) []cargoRoot {
	type candidate struct {
		path, phys, presence, reason string
	}
	var cands []candidate
	seen := map[string]bool{}
	for _, dir := range searchDirs {
		if !filepath.IsAbs(dir) {
			g.globalReason(model.CargoReasonPathUnresolved)
			continue
		}
		if seen[g.key(dir)] {
			continue
		}
		seen[g.key(dir)] = true
		c := candidate{path: dir, presence: model.CargoPresencePresent}
		if g.guard(dir) != "" {
			c.presence, c.reason = model.CargoPresenceUnknown, g.guardReason(dir)
		} else if g.ctx.Err() != nil {
			c.presence, c.reason = model.CargoPresenceUnknown, model.CargoReasonDeadlineExceeded
		} else if phys, err := g.exec.GuardedFiles([]string{dir}, g.guard, 0).EvalSymlinks(dir); errors.Is(err, fs.ErrNotExist) {
			c.presence = model.CargoPresenceAbsent
		} else if err != nil {
			c.presence, c.reason = model.CargoPresenceUnknown, g.reason(err, dir)
		} else {
			c.phys = phys
		}
		cands = append(cands, c)
	}
	var walk []cargoRoot
	for i, c := range cands {
		folded := slices.ContainsFunc(cands[:i], func(o candidate) bool {
			return c.phys != "" && o.phys != "" && g.key(o.phys) == g.key(c.phys)
		}) || slices.ContainsFunc(cands, func(o candidate) bool {
			return c.phys != "" && o.phys != "" && goPathWithin(g.key(c.phys), g.key(o.phys))
		})
		if folded {
			continue
		}
		src := g.addSource(model.CargoSourceProjectSearchRoot, c.path, "")
		if src == nil {
			break
		}
		src.Presence = c.presence
		if c.reason != "" {
			cargoDegrade(src, c.reason)
		}
		if c.phys != "" {
			walk = append(walk, cargoRoot{src: src, path: c.path, phys: c.phys})
		}
	}
	return walk
}

var cargoSkippedDirNames = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "target": true, ".rustup": true,
}

// walkRoot is a bounded breadth-first listing of one root for Cargo.toml.
// Directory symlinks are never followed; Cargo's own caches, build output and
// toolchains are skipped. A directory holding both Cargo.toml and
// .cargo-checksum.json is a vendored package: its parent is recorded as a
// directory source and it is not descended into.
func (g *cargoScan) walkRoot(r cargoRoot) {
	skip := map[string]bool{}
	for _, h := range g.homes {
		skip[g.key(filepath.Join(h, "registry"))] = true
		skip[g.key(filepath.Join(h, "git"))] = true
	}
	if g.verified {
		if v := g.exec.Getenv("RUSTUP_HOME"); filepath.IsAbs(v) {
			skip[g.key(v)] = true
		}
	}
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{r.path, 0}}
	budget := maxCargoWalkEntries
	for len(queue) > 0 {
		if g.expired(r.src) {
			return
		}
		d := queue[0]
		queue = queue[1:]
		entries, more, err := g.projFS.ReadDirLimit(d.path, budget)
		if err != nil {
			if d.depth == 0 {
				r.src.Presence = model.CargoPresenceUnknown
			}
			cargoDegrade(r.src, g.reason(err, d.path))
			continue
		}
		budget -= len(entries)
		hasFile := func(name string) bool {
			return slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return !e.IsDir() && e.Name() == name })
		}
		if d.depth > 0 && hasFile("Cargo.toml") && hasFile(".cargo-checksum.json") {
			g.vendorDirs = append(g.vendorDirs, cargoFound{filepath.Dir(d.path), r.src.SourceID})
			continue
		}
		for _, e := range entries {
			p := filepath.Join(d.path, e.Name())
			if !e.IsDir() {
				if e.Name() == "Cargo.toml" {
					g.enqueue(p, r.src.SourceID)
				}
				continue
			}
			switch {
			case cargoSkippedDirNames[e.Name()], skip[g.key(p)]:
				continue
			case g.guard(p) != "":
				// Protected directories are deliberate scope; an excluded mount
				// depends on configuration, so it must not read as deletion.
				if g.volume(p) {
					cargoDegrade(r.src, model.CargoReasonRefusedNetworkVolume)
				}
				continue
			case d.depth+1 > maxCargoWalkDepth:
				cargoDegrade(r.src, model.CargoReasonDepthLimit)
				continue
			}
			queue = append(queue, dir{p, d.depth + 1})
		}
		if more {
			cargoDegrade(r.src, model.CargoReasonEntryLimit)
			return
		}
	}
}

// enqueue adds a manifest to read once and returns it, or nil when it is
// already queued. parent is the discovery source or the manifest that
// references it. The queue never outgrows the record budget.
func (g *cargoScan) enqueue(path, parent string) *cargoManifestState {
	path = filepath.Clean(path)
	if g.byManifest[g.key(path)] != nil {
		return nil
	}
	if len(g.states) >= maxCargoRecords {
		g.globalReason(model.CargoReasonRecordLimit)
		return nil
	}
	s := &cargoManifestState{src: g.newSource(model.CargoSourceManifest, path, parent), path: path, dir: filepath.Dir(path)}
	g.states = append(g.states, s)
	g.byManifest[g.key(path)] = s
	return s
}

// readQueued reads every manifest not yet read. A walked manifest may
// reference others: a workspace root its literal members, a package its
// explicit workspace root, and path dependencies and overrides their
// directories. Those are read as exact targeted files.
func (g *cargoScan) readQueued() {
	for i := 0; i < len(g.states); i++ {
		s := g.states[i]
		if s.m != nil || s.src.Status != model.CargoStatusComplete || s.src.Presence != model.CargoPresencePresent {
			continue
		}
		if g.expired(s.src) {
			s.src.Presence = model.CargoPresenceUnknown
			continue
		}
		targeted := s.src.ParentSourceID == "" || g.byID[s.src.ParentSourceID] == nil
		data, ok := g.read(s.src, g.fileFS(s.path), s.path, maxCargoMetadataBytes, targeted)
		if !ok {
			continue
		}
		m, err := parseCargoManifest(data)
		if err != nil {
			cargoDegrade(s.src, model.CargoReasonParseError)
			continue
		}
		if m.invalid {
			cargoDegrade(s.src, model.CargoReasonParseError)
		}
		s.m = m
		ref := func(dir string) {
			if dir == "" {
				return
			}
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(s.dir, filepath.FromSlash(dir))
			}
			g.enqueue(filepath.Join(dir, "Cargo.toml"), s.src.SourceID)
		}
		if m.workspace != nil {
			for _, member := range m.workspace.members {
				if !cargoIsGlob(member) {
					ref(member)
				}
			}
		}
		ref(m.workspaceRef)
		for _, d := range slices.Concat(m.deps, m.overrides) {
			ref(cargoPathDepDir(s, nil, d)) // inherited entries wait for association
		}
	}
}

// enqueueInherited queues the directory of each path dependency a member
// inherits from its workspace root, reporting whether any is new. An entry of
// workspace.dependencies that no member inherits is never followed.
func (g *cargoScan) enqueueInherited() bool {
	queued := false
	for _, s := range g.states {
		if s.m == nil || s.root == nil {
			continue
		}
		for _, d := range s.m.deps {
			if dir := cargoPathDepDir(s, s.root, d); d.inherit && dir != "" && g.enqueue(filepath.Join(dir, "Cargo.toml"), s.src.SourceID) != nil {
				queued = true
			}
		}
	}
	return queued
}

// cargoPathDepDir is the directory a path dependency of s names, or empty for
// any other dependency. An inherited entry takes its path from root's
// workspace.dependencies, relative to the root; it is empty when root is nil.
func cargoPathDepDir(s, root *cargoManifestState, d cargoDep) string {
	base := s.dir
	if d.inherit {
		if root == nil || root.m == nil || root.m.workspace == nil {
			return ""
		}
		d, base = root.m.workspace.deps[d.decl.DeclaredName], root.dir
	}
	if d.sel.path == "" {
		return ""
	}
	dir := filepath.FromSlash(d.sel.path)
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(base, dir)
	}
	return filepath.Clean(dir)
}

// associate links packages to workspace roots the way Cargo finds one: an
// explicit package.workspace, else the nearest ancestor [workspace] that does
// not exclude the package. The root must then admit it as a member; anything
// Cargo would reject, or this collector cannot evaluate, is left unresolved.
// It is rerun after more manifests are read, so it starts from scratch.
func (g *cargoScan) associate() {
	for _, s := range g.states {
		s.root, s.unresolved, s.members, s.missing = nil, false, nil, nil
		if s.m != nil && s.m.workspace != nil {
			s.root = s
		}
	}
	for _, s := range g.states {
		if s.m == nil || s.root == s || !s.m.isPackage() {
			continue
		}
		var root *cargoManifestState
		if ref := s.m.workspaceRef; ref != "" {
			dir := filepath.FromSlash(ref)
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(s.dir, dir)
			}
			root = g.byManifest[g.key(filepath.Join(dir, "Cargo.toml"))]
			if root == nil || root.m == nil || root.m.workspace == nil {
				s.unresolved = true
				continue
			}
		} else {
			for dir := filepath.Dir(s.dir); ; dir = filepath.Dir(dir) {
				if a := g.byManifest[g.key(filepath.Join(dir, "Cargo.toml"))]; a != nil {
					if a.m == nil && a.src.Presence != model.CargoPresenceAbsent {
						s.unresolved = true // an unreadable ancestor may be the root
						break
					}
					if a.m != nil && a.m.workspace != nil && !g.excludes(a, s) {
						root = a
						break
					}
				}
				if filepath.Dir(dir) == dir {
					break
				}
			}
		}
		if root != nil {
			s.root = root
		}
	}
	for _, root := range g.states {
		if root.root == root {
			g.resolveMembers(root)
		}
	}
	for _, s := range g.states {
		if s.root != nil && s.root != s && !slices.Contains(s.root.members, s) {
			s.root, s.unresolved = nil, true
		}
	}
}

// excludes applies Cargo's exclusion: a path under an exclude entry that is
// not also under a literal members entry.
func (g *cargoScan) excludes(root, s *cargoManifestState) bool {
	under := func(entries []string) bool {
		return slices.ContainsFunc(entries, func(e string) bool {
			return cargoInside(g.goos, s.dir, filepath.Join(root.dir, filepath.FromSlash(e)))
		})
	}
	return under(root.m.workspace.exclude) && !under(root.m.workspace.members)
}

// resolveMembers finds the packages a workspace root admits: itself when it
// is a package, members entries, then in-root path dependencies of members,
// repeatedly. A members entry this collector cannot evaluate, or a literal one
// that could not be read, is reported as partial.
func (g *cargoScan) resolveMembers(root *cargoManifestState) {
	ws := root.m.workspace
	admit := func(s *cargoManifestState) bool {
		if s.m == nil || !s.m.isPackage() || slices.Contains(root.members, s) || (s != root && g.excludes(root, s)) {
			return false
		}
		if s.root != nil && s.root != root {
			return false // an explicit or nearer root owns it
		}
		root.members = append(root.members, s)
		s.root = root
		return true
	}
	if root.m.isPackage() {
		admit(root)
	}
	for _, pattern := range ws.members {
		if !cargoIsGlob(pattern) {
			path := filepath.Join(root.dir, filepath.FromSlash(pattern), "Cargo.toml")
			switch s := g.byManifest[g.key(path)]; {
			case s != nil && s.m != nil && s.m.isPackage():
				admit(s)
			case s != nil && s.src.Presence != model.CargoPresenceAbsent && len(s.src.Reasons) > 0:
				root.missing = append(root.missing, model.CargoWorkspaceMember{ManifestPath: path, Status: model.CargoStatusPartial, Reason: s.src.Reasons[0]})
			default:
				root.missing = append(root.missing, model.CargoWorkspaceMember{ManifestPath: path, Status: model.CargoStatusPartial, Reason: model.CargoReasonWorkspaceUnresolved})
			}
			continue
		}
		evaluable := true
		for _, s := range g.states {
			if s == root || !cargoInside(g.goos, s.dir, root.dir) {
				continue
			}
			rel, err := filepath.Rel(root.dir, s.dir)
			if err != nil {
				continue
			}
			match, ok := cargoMemberMatch(pattern, filepath.ToSlash(rel))
			evaluable = evaluable && ok
			if match {
				admit(s)
			}
		}
		if !evaluable {
			cargoDegrade(root.src, model.CargoReasonWorkspaceUnresolved)
		}
	}
	for changed := true; changed; {
		changed = false
		for _, m := range slices.Clone(root.members) {
			for _, d := range m.m.deps {
				dir := cargoPathDepDir(m, root, d)
				if dir == "" {
					continue
				}
				if s := g.byManifest[g.key(filepath.Join(dir, "Cargo.toml"))]; s != nil && cargoInside(g.goos, dir, root.dir) && admit(s) {
					changed = true
				}
			}
		}
	}
}

// contexts are the invocation directories the config audit describes: every
// package and workspace root read.
func (g *cargoScan) contexts() []configaudit.CargoContextDir {
	var out []configaudit.CargoContextDir
	for _, s := range g.states {
		if s.m == nil || (!s.m.isPackage() && s.m.workspace == nil) {
			continue
		}
		c := configaudit.CargoContextDir{Project: s.dir}
		if s.root != nil {
			c.Workspace = s.root.dir
		}
		out = append(out, c)
	}
	return out
}

func (g *cargoScan) registryNames() []string {
	var out []string
	for _, s := range g.states {
		if s.m == nil {
			continue
		}
		for _, d := range s.m.deps {
			if d.sel.registry != "" {
				out = append(out, d.sel.registry)
			}
		}
		if s.m.workspace != nil {
			for _, d := range s.m.workspace.deps {
				if d.sel.registry != "" {
					out = append(out, d.sel.registry)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// cargoInside reports whether path is dir or below it, as goos compares names.
func cargoInside(goos, path, dir string) bool {
	path, dir = configaudit.GoPathKey(goos, path), configaudit.GoPathKey(goos, dir)
	return path == dir || goPathWithin(path, dir)
}

// registerManifests keeps every manifest that is not package source inside a
// vendored or configured source directory, then charges its source.
func (g *cargoScan) registerManifests() {
	sourceDirs := slices.Concat(g.snap.DirectorySources(), g.snap.LocalRegistries())
	for _, v := range g.vendorDirs {
		sourceDirs = append(sourceDirs, v.path)
	}
	kept := g.states[:0]
	for _, s := range g.states {
		if slices.ContainsFunc(sourceDirs, func(d string) bool { return cargoInside(g.goos, s.dir, d) }) {
			delete(g.byManifest, g.key(s.path))
			continue
		}
		src := g.register(s.src)
		if src == nil {
			delete(g.byManifest, g.key(s.path))
			continue
		}
		s.src = src
		if s.unresolved {
			cargoDegrade(src, model.CargoReasonWorkspaceUnresolved)
		}
		kept = append(kept, s)
	}
	g.states = kept
	for _, s := range g.states {
		if s.root != nil && g.byManifest[g.key(s.root.path)] == nil {
			s.root, s.unresolved = nil, true
			cargoDegrade(s.src, model.CargoReasonWorkspaceUnresolved)
		}
	}
}

// packageVersion is the version written in, or inherited by, a manifest.
func (s *cargoManifestState) packageVersion() string {
	if s.m.versionInherited {
		if s.root != nil && s.root.m.workspace != nil {
			return s.root.m.workspace.packageVersion
		}
		return ""
	}
	return s.m.version
}

// lockVersion is the version Cargo records for a package, which defaults to
// 0.0.0 when the manifest omits it.
func (s *cargoManifestState) lockVersion() string {
	if v := s.packageVersion(); v != "" || s.m.versionInherited {
		return v
	}
	return "0.0.0"
}

// emitProjects records each read manifest, each workspace and each
// declaration. Declarations inherited from workspace.dependencies resolve
// their paths against the workspace root.
func (g *cargoScan) emitProjects() {
	for _, s := range g.states {
		if s.m == nil || !g.charge(s.src, 1) {
			continue
		}
		p := model.CargoProject{
			ManifestSourceID: s.src.SourceID, ManifestPath: s.path, ProjectPath: s.dir,
			PackageName: s.m.name, PackageVersion: s.packageVersion(), LockfilePaths: []string{},
		}
		if s.root != nil {
			p.WorkspaceManifestPath = s.root.path
		}
		g.projects = append(g.projects, p)
	}
	for _, s := range g.states {
		if s.root != s {
			continue
		}
		w := model.CargoWorkspace{ManifestSourceID: s.src.SourceID, ManifestPath: s.path, RootPackageName: s.m.name, Members: slices.Clone(s.missing)}
		if w.Members == nil {
			w.Members = []model.CargoWorkspaceMember{}
		}
		for _, m := range s.members {
			if g.byManifest[g.key(m.path)] != nil {
				w.Members = append(w.Members, model.CargoWorkspaceMember{ManifestPath: m.path, Status: model.CargoStatusComplete})
			}
		}
		if len(s.missing) > 0 {
			cargoDegrade(s.src, model.CargoReasonWorkspaceUnresolved)
		}
		if g.charge(s.src, 1) {
			g.workspaces = append(g.workspaces, w)
		}
	}
	for _, s := range g.states {
		if s.m == nil || !s.m.isPackage() {
			continue
		}
		for _, d := range s.m.deps {
			if !g.emitDeclaration(s, d) {
				break
			}
		}
	}
}

func (g *cargoScan) emitDeclaration(s *cargoManifestState, d cargoDep) bool {
	base, reasons := s.dir, []string{}
	if d.inherit {
		ws, ok := cargoDep{}, false
		if s.root != nil {
			ws, ok = s.root.m.workspace.deps[d.decl.DeclaredName]
		}
		if !ok {
			return g.addPackage(s.src, model.CargoPackage{
				Evidence: model.CargoEvidenceDeclaredRequirement, PackageName: d.packageName,
				Reasons:    []string{model.CargoReasonOriginUnresolved, model.CargoReasonWorkspaceUnresolved},
				Origin:     model.CargoOrigin{Kind: model.CargoOriginRegistryUnknown, Path: s.dir},
				SourcePath: s.path, ProjectPath: s.dir, Declaration: &d.decl,
			})
		}
		d, base = cargoInherit(d, ws), s.root.dir
	}
	origin := g.declarationOrigin(&d, base, s.dir)
	if origin.Kind == model.CargoOriginRegistryUnknown {
		reasons = append(reasons, model.CargoReasonOriginUnresolved)
	}
	p := model.CargoPackage{
		Evidence: model.CargoEvidenceDeclaredRequirement, PackageName: d.packageName, Reasons: reasons,
		RequestedVersion: d.requested, Origin: origin, SourcePath: s.path, ProjectPath: s.dir, Declaration: &d.decl,
	}
	if s.root != nil {
		p.WorkspacePath = s.root.dir
	}
	return g.addPackage(s.src, p)
}

// declarationOrigin resolves a declaration's selectors. A registry alias maps
// through the declaring directory's observed config; registry.default never
// redirects an unqualified dependency away from crates.io.
func (g *cargoScan) declarationOrigin(d *cargoDep, base, contextDir string) model.CargoOrigin {
	sel := d.sel
	switch {
	case sel.git != "":
		u, _ := configaudit.SanitizeCargoURL(sel.git)
		d.decl.PublishingRegistry = sel.registry
		return model.CargoOrigin{Kind: model.CargoOriginGit, URL: u, Branch: sel.branch, Tag: sel.tag, Rev: sel.rev}
	case sel.path != "":
		p := filepath.FromSlash(sel.path)
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		return model.CargoOrigin{Kind: model.CargoOriginLocal, Path: filepath.Clean(p), IsLocal: true}
	case sel.registryIndex != "":
		u, _ := configaudit.SanitizeCargoURL(sel.registryIndex)
		return model.CargoOrigin{Kind: model.CargoOriginRegistry, URL: u}
	case sel.registry != "" && sel.registry != "crates-io":
		if u, ok := g.snap.RegistryIndex(contextDir, sel.registry); ok {
			return model.CargoOrigin{Kind: model.CargoOriginRegistry, URL: u, RegistryName: sel.registry}
		}
		return model.CargoOrigin{Kind: model.CargoOriginRegistryUnknown, RegistryName: sel.registry, Path: contextDir}
	}
	return model.CargoOrigin{Kind: model.CargoOriginRegistry, URL: cargoCratesIOIndex, RegistryName: "crates-io"}
}

// addPackage charges and appends one package record, filling the fields
// every record carries.
func (g *cargoScan) addPackage(src *model.CargoSource, p model.CargoPackage) bool {
	if !g.charge(src, 1) {
		return false
	}
	p.SourceID = src.SourceID
	if p.Reasons == nil {
		p.Reasons = []string{}
	}
	slices.Sort(p.Reasons)
	if p.Artifacts == nil {
		p.Artifacts = []model.CargoArtifact{}
	}
	if p.RecordedChecksums == nil {
		p.RecordedChecksums = []model.CargoRecordedChecksum{}
	}
	if p.ChecksumStatus == "" {
		p.ChecksumStatus = model.CargoChecksumAbsent
	}
	if p.IdentityStatus == "" {
		p.IdentityStatus = model.CargoIdentityMetadata
	}
	p.DependencyRelation = model.CargoRelationUnknown
	if p.Evidence == model.CargoEvidenceDeclaredRequirement {
		p.DependencyRelation = model.CargoRelationDirect
	}
	p.VersionStatus = model.CargoVersionUnknown
	if p.ObservedVersion != "" {
		p.VersionStatus = model.CargoVersionKnown
	}
	g.packages = append(g.packages, p)
	return true
}

// cargoLockGroup is one workspace root or standalone package and the
// manifests whose contexts select its lockfiles.
type cargoLockGroup struct {
	root    *cargoManifestState
	members []*cargoManifestState
	locals  []*cargoManifestState
}

// emitLockfiles reads the lockfile each context selects, once per path, and
// emits its packages against the workspace root rather than each member.
func (g *cargoScan) emitLockfiles() {
	var groups []cargoLockGroup
	for _, s := range g.states {
		switch {
		case s.m == nil:
		case s.root == s:
			groups = append(groups, cargoLockGroup{root: s, members: slices.Concat([]*cargoManifestState{s}, s.members)})
		case s.root == nil && s.m.isPackage() && !s.unresolved && !s.override:
			groups = append(groups, cargoLockGroup{root: s, members: []*cargoManifestState{s}})
		}
	}
	projects := map[string]*model.CargoProject{}
	for i := range g.projects {
		projects[g.projects[i].ManifestSourceID] = &g.projects[i]
	}
	for _, grp := range groups {
		grp.locals = g.lockLocalPackages(grp.members)
		unresolved := map[string]bool{}
		var paths []string
		for _, m := range grp.members {
			if g.byManifest[g.key(m.path)] == nil {
				continue // reclassified as vendored source
			}
			path, u := g.snap.LockfilePath(m.dir)
			if path == "" {
				path = filepath.Join(grp.root.dir, "Cargo.lock")
			}
			path = filepath.Clean(path)
			unresolved[g.key(path)] = unresolved[g.key(path)] || u
			if !slices.ContainsFunc(paths, func(p string) bool { return g.key(p) == g.key(path) }) {
				paths = append(paths, path)
			}
			if p := projects[m.src.SourceID]; p != nil && !slices.Contains(p.LockfilePaths, path) {
				p.LockfilePaths = append(p.LockfilePaths, path)
			}
		}
		for _, path := range paths {
			g.readLockfile(grp, path, unresolved[g.key(path)])
		}
	}
}

// readLockfile emits one lockfile's packages, stopping once the record budget
// is spent.
func (g *cargoScan) readLockfile(grp cargoLockGroup, path string, unresolved bool) {
	if g.byID[configaudit.GoSourceID(g.identity, model.CargoSourceLockfile, path)] != nil {
		return // another root already selected this lockfile
	}
	src := g.addSource(model.CargoSourceLockfile, path, grp.root.src.SourceID)
	if src == nil {
		return
	}
	if unresolved {
		cargoDegrade(src, model.CargoReasonPathUnresolved)
	}
	if g.expired(src) {
		src.Presence = model.CargoPresenceUnknown
		return
	}
	data, ok := g.read(src, g.fileFS(path), path, maxCargoMetadataBytes, true)
	if !ok {
		return
	}
	entries, reason := parseCargoLock(data)
	if reason != "" {
		cargoDegrade(src, reason)
	}
	project, workspace := grp.root.dir, ""
	if grp.root.root == grp.root {
		workspace = grp.root.dir
	}
	for _, e := range entries {
		p := model.CargoPackage{
			Evidence: model.CargoEvidenceLockedPackage, PackageName: e.name, ObservedVersion: e.version,
			Reasons: slices.Clone(e.reasons), SourcePath: path, ProjectPath: project, WorkspacePath: workspace,
		}
		if e.source == "" {
			origin, keep := g.localLockOrigin(grp, e, path)
			if !keep {
				continue
			}
			p.Origin = origin
		} else if origin, ok := cargoOrigin(e.source); ok {
			p.Origin = origin
		} else {
			p.Origin = model.CargoOrigin{Kind: model.CargoOriginRegistryUnknown, Path: path}
			p.Reasons = append(p.Reasons, model.CargoReasonOriginUnresolved)
		}
		for _, sum := range e.checksums {
			p.RecordedChecksums = append(p.RecordedChecksums, model.CargoRecordedChecksum{
				Algorithm: model.CargoChecksumSHA256, Value: sum, SourceKind: model.CargoChecksumSourceLockfile,
				SourcePath: path, SourceID: src.SourceID, Verification: model.CargoChecksumNotVerified,
			})
		}
		switch {
		case len(e.reasons) > 0:
			p.ChecksumStatus = model.CargoChecksumPartial
		case len(e.checksums) > 0:
			p.ChecksumStatus = model.CargoChecksumRecorded
		}
		if !g.addPackage(src, p) {
			return
		}
	}
}

// lockLocalPackages follows already-read path dependencies and overrides from
// this lockfile's manifests. Unrelated checkouts cannot establish its origins.
func (g *cargoScan) lockLocalPackages(members []*cargoManifestState) []*cargoManifestState {
	queue := slices.Clone(members)
	seen := map[*cargoManifestState]bool{}
	for _, s := range queue {
		seen[s] = true
	}
	var out []*cargoManifestState
	for i := 0; i < len(queue); i++ {
		s := queue[i]
		for _, d := range slices.Concat(s.m.deps, s.m.overrides) {
			dir := cargoPathDepDir(s, s.root, d)
			if dir == "" {
				continue
			}
			dep := g.byManifest[g.key(filepath.Join(dir, "Cargo.toml"))]
			if dep == nil || dep.m == nil || seen[dep] {
				continue
			}
			seen[dep] = true
			queue = append(queue, dep)
			out = append(out, dep)
		}
	}
	return out
}

// localLockOrigin places a source-less lock entry. A workspace member or root
// package is context, kept only when a declaration references it. Otherwise a
// single referenced path package with that name and version is its origin;
// anything else stays local_unknown, scoped to the lockfile.
func (g *cargoScan) localLockOrigin(grp cargoLockGroup, e cargoLockEntry, lockPath string) (model.CargoOrigin, bool) {
	same := func(s *cargoManifestState) bool {
		return s.m != nil && s.m.name == e.name && s.lockVersion() == e.version
	}
	if i := slices.IndexFunc(grp.members, same); i >= 0 {
		member := grp.members[i]
		referenced := slices.ContainsFunc(grp.members, func(s *cargoManifestState) bool {
			return slices.ContainsFunc(s.m.deps, func(d cargoDep) bool {
				dir := cargoPathDepDir(s, s.root, d)
				return dir != "" && g.key(dir) == g.key(member.dir)
			})
		})
		return model.CargoOrigin{Kind: model.CargoOriginLocal, Path: member.dir, IsLocal: true}, referenced
	}
	var match *cargoManifestState
	for _, s := range grp.locals {
		if same(s) {
			if match != nil {
				return model.CargoOrigin{Kind: model.CargoOriginLocalUnknown, Path: lockPath, IsLocal: true}, true
			}
			match = s
		}
	}
	if match != nil {
		return model.CargoOrigin{Kind: model.CargoOriginLocal, Path: match.dir, IsLocal: true}, true
	}
	return model.CargoOrigin{Kind: model.CargoOriginLocalUnknown, Path: lockPath, IsLocal: true}, true
}

// listDir lists dir on a shared entry budget, degrading src on failure or
// truncation.
func (g *cargoScan) listDir(src *model.CargoSource, files executor.Executor, dir string, budget *int) ([]fs.DirEntry, bool) {
	entries, more, err := files.ReadDirLimit(dir, *budget)
	if err != nil {
		cargoDegrade(src, g.reason(err, dir))
		return nil, false
	}
	*budget -= len(entries)
	if more {
		cargoDegrade(src, model.CargoReasonEntryLimit)
	}
	return entries, true
}

// scanDirectorySources reads every vendored package directory below each
// detected or configured directory source.
func (g *cargoScan) scanDirectorySources() {
	found := slices.Clone(g.vendorDirs)
	for _, d := range g.snap.DirectorySources() {
		found = append(found, cargoFound{path: d})
	}
	seen := map[string]bool{}
	for _, f := range found {
		if seen[g.key(f.path)] {
			continue
		}
		seen[g.key(f.path)] = true
		src := g.addSource(model.CargoSourceDirectorySource, f.path, f.parentID)
		if src == nil {
			continue
		}
		files, phys, ok := g.rootFS(src, maxCargoChecksumBytes)
		if !ok {
			continue
		}
		budget := maxCargoWalkEntries
		entries, _ := g.listDir(src, files, phys, &budget)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if g.expired(src) || !g.readVendored(src, files, phys, e.Name()) {
				break
			}
		}
	}
}

// readVendored emits one vendored package from its Cargo.toml and the
// package checksum of its .cargo-checksum.json. It returns false once the
// record budget is spent.
func (g *cargoScan) readVendored(src *model.CargoSource, files executor.Executor, phys, name string) bool {
	dir := filepath.Join(src.Path, name)
	data, missing, reason := g.readFile(files, filepath.Join(phys, name, "Cargo.toml"), maxCargoMetadataBytes)
	if missing {
		return true
	}
	var m *cargoManifest
	if reason == "" {
		var err error
		if m, err = parseCargoManifest(data); err != nil || !m.isPackage() {
			reason = model.CargoReasonParseError
		}
	}
	if reason != "" {
		cargoDegrade(src, reason)
		return true
	}
	p := model.CargoPackage{
		Evidence: model.CargoEvidenceVendoredPackage, PackageName: m.name, ObservedVersion: m.version,
		Origin:     model.CargoOrigin{Kind: model.CargoOriginVendorUnknown, Path: src.Path},
		SourcePath: dir,
		Artifacts: []model.CargoArtifact{{
			Kind: model.CargoArtifactVendor, Path: dir, Presence: model.CargoPresencePresent,
			Status: model.CargoStatusComplete, Reasons: []string{},
		}},
	}
	checksumPath := filepath.Join(dir, ".cargo-checksum.json")
	switch data, missing, reason := g.readFile(files, filepath.Join(phys, name, ".cargo-checksum.json"), maxCargoChecksumBytes); {
	case missing:
	case reason != "":
		p.ChecksumStatus = model.CargoChecksumUnreadable
		cargoDegrade(src, reason)
	default:
		sum, invalid, err := parseCargoChecksumJSON(data)
		switch {
		case err != nil:
			p.ChecksumStatus = model.CargoChecksumUnreadable
			cargoDegrade(src, model.CargoReasonParseError)
		case invalid:
			p.ChecksumStatus = model.CargoChecksumPartial
			p.Reasons = []string{model.CargoReasonChecksumInvalid}
		case sum != "":
			p.ChecksumStatus = model.CargoChecksumRecorded
			p.RecordedChecksums = []model.CargoRecordedChecksum{{
				Algorithm: model.CargoChecksumSHA256, Value: sum, SourceKind: model.CargoChecksumSourceVendorChecksum,
				SourcePath: checksumPath, SourceID: src.SourceID, Verification: model.CargoChecksumNotVerified,
			}}
		}
	}
	return g.addPackage(src, p)
}

// scanLocalRegistries reads the .crate archives at the top of each
// configured local registry.
func (g *cargoScan) scanLocalRegistries() {
	for _, root := range g.snap.LocalRegistries() {
		src := g.addSource(model.CargoSourceLocalRegistry, root, "")
		if src == nil {
			continue
		}
		files, phys, ok := g.rootFS(src, maxCargoArchiveBytes)
		if !ok {
			continue
		}
		budget := maxCargoWalkEntries
		entries, _ := g.listDir(src, files, phys, &budget)
		for _, e := range entries {
			base, isCrate := strings.CutSuffix(e.Name(), ".crate")
			if e.IsDir() || !isCrate {
				continue
			}
			name, version, ok := splitCargoFilename(base)
			if !ok {
				cargoDegrade(src, model.CargoReasonUnsupportedEntry)
				continue
			}
			if g.expired(src) {
				break
			}
			path := filepath.Join(root, e.Name())
			art, identity := g.archiveArtifact(src, files, filepath.Join(phys, e.Name()), path, name, version)
			if !g.addPackage(src, model.CargoPackage{
				Evidence: model.CargoEvidenceCachedPackage, PackageName: name, ObservedVersion: version,
				IdentityStatus: identity, Origin: model.CargoOrigin{Kind: model.CargoOriginVendorUnknown, Path: root},
				SourcePath: path, Artifacts: []model.CargoArtifact{art},
			}) {
				break
			}
		}
	}
}

// archiveArtifact confirms a .crate archive from its manifest member. When
// that cannot be read the name and version stay inferred from the file name.
func (g *cargoScan) archiveArtifact(src *model.CargoSource, files executor.Executor, readPath, path, name, version string) (model.CargoArtifact, string) {
	art := model.CargoArtifact{
		Kind: model.CargoArtifactArchive, Path: path, Presence: model.CargoPresencePresent,
		Status: model.CargoStatusComplete, Reasons: []string{},
	}
	data, missing, reason := g.readFile(files, readPath, maxCargoArchiveBytes)
	switch {
	case missing:
		art.Presence, reason = model.CargoPresenceUnknown, model.CargoReasonChangedDuringScan
	case reason == "":
		reason = cargoArchiveManifest(g.ctx, data, name, version)
	}
	if reason == "" {
		return art, model.CargoIdentityMetadata
	}
	art.Status, art.Reasons = model.CargoStatusPartial, []string{reason}
	cargoDegrade(src, reason)
	return art, model.CargoIdentityFilenameInferred
}

// cargoCacheSlot is one registry ID, name and version in a Cargo home's
// registry cache, from its archive and/or extracted source.
type cargoCacheSlot struct {
	id, name, version  string
	archive, extracted bool
}

// scanRegistryCache enumerates registry/cache/<id>/*.crate and
// registry/src/<id>/<name-version>/ for every registry ID present. The ID
// directory is opaque: its origin stays unknown, scoped to the cache.
func (g *cargoScan) scanRegistryCache(home string) {
	root := filepath.Join(home, "registry")
	src := g.addSource(model.CargoSourceRegistryCache, root, "")
	if src == nil {
		return
	}
	files, phys, ok := g.rootFS(src, maxCargoArchiveBytes)
	if !ok {
		return
	}
	budget := maxCargoWalkEntries
	slots := map[[3]string]*cargoCacheSlot{}
	slot := func(id, name, version string) *cargoCacheSlot {
		k := [3]string{id, name, version}
		if slots[k] == nil {
			slots[k] = &cargoCacheSlot{id: id, name: name, version: version}
		}
		return slots[k]
	}
	for _, kind := range []string{"cache", "src"} {
		ids := g.cacheList(src, files, filepath.Join(phys, kind), &budget)
		for _, id := range ids {
			if !id.IsDir() {
				continue
			}
			entries := g.cacheList(src, files, filepath.Join(phys, kind, id.Name()), &budget)
			for _, e := range entries {
				base, isCrate := strings.CutSuffix(e.Name(), ".crate")
				if (kind == "cache" && (e.IsDir() || !isCrate)) || (kind == "src" && !e.IsDir()) {
					continue
				}
				name, version, ok := splitCargoFilename(base)
				if !ok {
					cargoDegrade(src, model.CargoReasonUnsupportedEntry)
					continue
				}
				if s := slot(id.Name(), name, version); kind == "cache" {
					s.archive = true
				} else {
					s.extracted = true
				}
			}
		}
	}
	keys := slices.SortedFunc(maps.Keys(slots), func(a, b [3]string) int {
		return strings.Compare(a[0]+"\x00"+a[1]+"\x00"+a[2], b[0]+"\x00"+b[1]+"\x00"+b[2])
	})
	for _, k := range keys {
		if g.expired(src) || !g.cacheRecord(src, files, phys, slots[k]) {
			return
		}
	}
}

// cacheList lists one cache directory; a missing one is not a failure.
func (g *cargoScan) cacheList(src *model.CargoSource, files executor.Executor, dir string, budget *int) []fs.DirEntry {
	entries, more, err := files.ReadDirLimit(dir, *budget)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		cargoDegrade(src, g.reason(err, dir))
		return nil
	}
	*budget -= len(entries)
	if more {
		cargoDegrade(src, model.CargoReasonEntryLimit)
	}
	return entries
}

// cacheRecord emits one cache slot. Extracted Cargo.toml establishes the
// identity, and the archive is then only probed; without it the archive's
// manifest member is read.
func (g *cargoScan) cacheRecord(src *model.CargoSource, files executor.Executor, phys string, s *cargoCacheSlot) bool {
	nv := s.name + "-" + s.version
	p := model.CargoPackage{
		Evidence: model.CargoEvidenceCachedPackage, PackageName: s.name, ObservedVersion: s.version,
		IdentityStatus: model.CargoIdentityFilenameInferred,
		Origin:         model.CargoOrigin{Kind: model.CargoOriginCacheUnknown, CacheRoot: src.Path, CacheID: s.id},
	}
	if s.extracted {
		dir := filepath.Join(src.Path, "src", s.id, nv)
		art := model.CargoArtifact{
			Kind: model.CargoArtifactExtracted, Path: dir, Presence: model.CargoPresencePresent,
			Status: model.CargoStatusComplete, Reasons: []string{},
		}
		fail := func(reason string) {
			art.Status = model.CargoStatusPartial
			if !slices.Contains(art.Reasons, reason) {
				art.Reasons = append(art.Reasons, reason)
			}
			cargoDegrade(src, reason)
		}
		readDir := filepath.Join(phys, "src", s.id, nv)
		switch data, missing, reason := g.readFile(files, filepath.Join(readDir, "Cargo.toml"), maxCargoMetadataBytes); {
		case missing:
			fail(model.CargoReasonExtractionIncomplete)
		case reason != "":
			fail(reason)
		default:
			if m, err := parseCargoManifest(data); err != nil || m.name != s.name || m.version != s.version {
				fail(model.CargoReasonParseError)
			} else {
				p.IdentityStatus = model.CargoIdentityMetadata
			}
		}
		if data, missing, reason := g.readFile(files, filepath.Join(readDir, ".cargo-ok"), maxCargoMarkerBytes); missing || reason != "" || !parseCargoOK(data) {
			fail(model.CargoReasonExtractionIncomplete)
		}
		p.SourcePath = dir
		p.Artifacts = append(p.Artifacts, art)
	}
	if s.archive {
		path := filepath.Join(src.Path, "cache", s.id, nv+".crate")
		readPath := filepath.Join(phys, "cache", s.id, nv+".crate")
		var art model.CargoArtifact
		if p.IdentityStatus == model.CargoIdentityMetadata {
			art = g.probeArchive(src, files, readPath, path)
		} else {
			var identity string
			art, identity = g.archiveArtifact(src, files, readPath, path, s.name, s.version)
			p.IdentityStatus = identity
		}
		if p.SourcePath == "" {
			p.SourcePath = path
		}
		p.Artifacts = append(p.Artifacts, art)
	}
	return g.addPackage(src, p)
}

// probeArchive checks an archive's presence without opening it.
func (g *cargoScan) probeArchive(src *model.CargoSource, files executor.Executor, readPath, path string) model.CargoArtifact {
	art := model.CargoArtifact{
		Kind: model.CargoArtifactArchive, Path: path, Presence: model.CargoPresencePresent,
		Status: model.CargoStatusComplete, Reasons: []string{},
	}
	info, err := files.Stat(readPath)
	reason := ""
	switch {
	case errors.Is(err, fs.ErrNotExist):
		art.Presence, reason = model.CargoPresenceAbsent, model.CargoReasonChangedDuringScan
	case err != nil:
		art.Presence, reason = model.CargoPresenceUnknown, g.reason(err, readPath)
	case !info.Mode().IsRegular():
		reason = model.CargoReasonUnsupportedEntry
	}
	if reason != "" {
		art.Status, art.Reasons = model.CargoStatusPartial, []string{reason}
		cargoDegrade(src, reason)
	}
	return art
}

// scanGitCheckouts reads package manifests in each git/checkouts/<repo>/<rev>
// working copy. Their dependencies are not project requirements, and the
// repository URL is not recorded locally, so origin stays git_unknown scoped
// to the checkout.
func (g *cargoScan) scanGitCheckouts(home string) {
	root := filepath.Join(home, "git", "checkouts")
	src := g.addSource(model.CargoSourceGitCheckoutRoot, root, "")
	if src == nil {
		return
	}
	files, phys, ok := g.rootFS(src, maxCargoMetadataBytes)
	if !ok {
		return
	}
	budget := maxCargoWalkEntries
	repos, _ := g.listDir(src, files, phys, &budget)
	for _, repo := range repos {
		if !repo.IsDir() {
			continue
		}
		revs, _ := g.listDir(src, files, filepath.Join(phys, repo.Name()), &budget)
		for _, rev := range revs {
			if !rev.IsDir() {
				continue
			}
			if g.expired(src) || !g.readCheckout(src, files, phys, repo.Name(), rev.Name(), &budget) {
				return
			}
		}
	}
}

// readCheckout emits the packages of one checkout. It returns false once the
// record budget is spent.
func (g *cargoScan) readCheckout(src *model.CargoSource, files executor.Executor, phys, repo, rev string, budget *int) bool {
	rel := filepath.Join(repo, rev)
	checkout, readDir := filepath.Join(src.Path, rel), filepath.Join(phys, rel)
	origin := model.CargoOrigin{
		Kind: model.CargoOriginGitUnknown, CacheRoot: src.Path, CacheID: repo + "/" + rev,
		ResolvedRevision: g.checkoutRevision(files, readDir),
	}
	art := model.CargoArtifact{Kind: model.CargoArtifactGitCheckout, Path: checkout, Presence: model.CargoPresencePresent, Status: model.CargoStatusComplete, Reasons: []string{}}
	if data, missing, reason := g.readFile(files, filepath.Join(readDir, ".cargo-ok"), maxCargoMarkerBytes); missing || reason != "" || !parseCargoOK(data) {
		art.Status, art.Reasons = model.CargoStatusPartial, []string{model.CargoReasonExtractionIncomplete}
		cargoDegrade(src, model.CargoReasonExtractionIncomplete)
	}

	type found struct {
		rel string // slash path of the package directory below the checkout
		m   *cargoManifest
	}
	var manifests []found
	type dir struct {
		rel   string
		depth int
	}
	queue := []dir{{"", 0}}
	for len(queue) > 0 {
		if g.expired(src) {
			break
		}
		d := queue[0]
		queue = queue[1:]
		entries, ok := g.listDir(src, files, filepath.Join(readDir, filepath.FromSlash(d.rel)), budget)
		if !ok {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				switch {
				case e.Name() == ".git" || e.Name() == "target":
				case d.depth+1 > maxCargoWalkDepth:
					cargoDegrade(src, model.CargoReasonDepthLimit)
				default:
					queue = append(queue, dir{pathJoinSlash(d.rel, e.Name()), d.depth + 1})
				}
				continue
			}
			if e.Name() != "Cargo.toml" {
				continue
			}
			data, _, reason := g.readFile(files, filepath.Join(readDir, filepath.FromSlash(d.rel), "Cargo.toml"), maxCargoMetadataBytes)
			m, err := parseCargoManifest(data)
			if reason == "" && err != nil {
				reason = model.CargoReasonParseError
			}
			if reason != "" {
				cargoDegrade(src, reason)
				continue
			}
			manifests = append(manifests, found{d.rel, m})
		}
		if *budget <= 0 {
			break
		}
	}
	slices.SortFunc(manifests, func(a, b found) int { return strings.Compare(a.rel, b.rel) })
	for _, f := range manifests {
		if !f.m.isPackage() {
			continue
		}
		version := f.m.version
		if f.m.versionInherited {
			// The nearest enclosing workspace inside the checkout supplies it.
			best := -1
			for _, w := range manifests {
				if w.m.workspace != nil && len(w.rel) > best && (w.rel == "" || f.rel == w.rel || strings.HasPrefix(f.rel, w.rel+"/")) {
					best, version = len(w.rel), w.m.workspace.packageVersion
				}
			}
		}
		pkgDir := filepath.Join(checkout, filepath.FromSlash(f.rel))
		p := model.CargoPackage{
			Evidence: model.CargoEvidenceGitCachedPackage, PackageName: f.m.name, ObservedVersion: version,
			Origin: origin, SourcePath: pkgDir, Artifacts: []model.CargoArtifact{art},
		}
		p.Artifacts[0].Path = pkgDir
		if origin.ResolvedRevision == "" {
			p.Reasons = []string{model.CargoReasonOriginUnresolved}
		}
		if !g.addPackage(src, p) {
			return false
		}
	}
	return true
}

// checkoutRevision reads the full commit a checkout's .git/HEAD records,
// following a gitdir indirection file and a symbolic ref through loose or
// packed refs. The shortened directory name is never used as a revision.
func (g *cargoScan) checkoutRevision(files executor.Executor, checkout string) string {
	gitDir := filepath.Join(checkout, ".git")
	if data, _, reason := g.readFile(files, gitDir, maxCargoMarkerBytes); reason == "" && data != nil {
		p, ok := parseGitDirFile(data)
		if !ok {
			return ""
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(checkout, filepath.FromSlash(p))
		}
		gitDir = filepath.Clean(p)
	}
	data, _, reason := g.readFile(files, filepath.Join(gitDir, "HEAD"), maxCargoMarkerBytes)
	if reason != "" || data == nil {
		return ""
	}
	sha, ref := parseGitHead(data)
	if sha != "" || !strings.HasPrefix(ref, "refs/") || slices.Contains(strings.Split(ref, "/"), "..") {
		return sha
	}
	if data, _, reason := g.readFile(files, filepath.Join(gitDir, filepath.FromSlash(ref)), maxCargoMarkerBytes); reason == "" && data != nil {
		sha, _ = parseGitHead(data)
		return sha
	}
	if data, _, reason := g.readFile(files, filepath.Join(gitDir, "packed-refs"), maxCargoMetadataBytes); reason == "" && data != nil {
		return parsePackedRef(data, ref)
	}
	return ""
}

// scanInstallRoots reads the install receipts of each Cargo home and each
// observed install.root or CARGO_INSTALL_ROOT.
func (g *cargoScan) scanInstallRoots() {
	var roots []string
	for _, r := range slices.Concat(g.homes, g.snap.InstallRoots()) {
		if !slices.ContainsFunc(roots, func(o string) bool { return g.key(o) == g.key(r) }) {
			roots = append(roots, r)
		}
	}
	for _, root := range roots {
		if src := g.addSource(model.CargoSourceInstallRoot, root, ""); src != nil {
			g.readInstallRoot(src)
		}
	}
}

// readInstallRoot emits one record per package tracked by .crates.toml v1,
// which is authoritative for membership; .crates2.json only adds detail. It
// stops once the record budget is spent.
func (g *cargoScan) readInstallRoot(src *model.CargoSource) {
	files, phys, ok := g.rootFS(src, maxCargoMetadataBytes)
	if !ok {
		return
	}
	receipt := filepath.Join(src.Path, ".crates.toml")
	data, missing, reason := g.readFile(files, filepath.Join(phys, ".crates.toml"), maxCargoMetadataBytes)
	switch {
	case missing:
		return // no tracked installs
	case reason != "":
		cargoDegrade(src, reason)
		return
	}
	v1, err := parseCratesToml(data)
	if err != nil {
		cargoDegrade(src, model.CargoReasonParseError)
		return
	}
	var v2 map[string]cargoInstallInfo
	switch data, missing, reason := g.readFile(files, filepath.Join(phys, ".crates2.json"), maxCargoMetadataBytes); {
	case missing:
	case reason != "":
		cargoDegrade(src, reason)
	default:
		if v2, err = parseCrates2JSON(data); err != nil {
			cargoDegrade(src, model.CargoReasonParseError)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(v1)) {
		name, version, source, ok := parseCargoPackageID(id)
		if !ok {
			cargoDegrade(src, model.CargoReasonParseError)
			continue
		}
		p := model.CargoPackage{
			Evidence: model.CargoEvidenceInstalledTool, PackageName: name, ObservedVersion: version, SourcePath: receipt,
		}
		if p.Origin, ok = cargoOrigin(source); !ok {
			p.Origin = model.CargoOrigin{Kind: model.CargoOriginRegistryUnknown, Path: src.Path}
			p.Reasons = []string{model.CargoReasonOriginUnresolved}
		}
		p.Installation = g.installation(src, files, phys, v1[id])
		if info, ok := v2[id]; ok {
			info.apply(p.Installation)
		}
		if !g.addPackage(src, p) {
			return
		}
	}
}

// installation probes each recorded bin under the root's bin directory by
// Stat alone; binaries are never opened or run.
func (g *cargoScan) installation(src *model.CargoSource, files executor.Executor, phys string, bins []string) *model.CargoInstallation {
	inst := &model.CargoInstallation{RootPath: src.Path, Bins: []model.CargoBin{}}
	present, absent := 0, 0
	for _, name := range bins {
		if !cargoBinName(name) {
			cargoDegrade(src, model.CargoReasonParseError)
			continue
		}
		b := model.CargoBin{Name: name, Path: filepath.Join(src.Path, "bin", name), Presence: model.CargoPresencePresent}
		switch _, err := files.Stat(filepath.Join(phys, "bin", name)); {
		case err == nil:
			present++
		case errors.Is(err, fs.ErrNotExist):
			b.Presence = model.CargoPresenceAbsent
			absent++
		default:
			b.Presence = model.CargoBinUnreadable
		}
		inst.Bins = append(inst.Bins, b)
	}
	slices.SortFunc(inst.Bins, func(a, b model.CargoBin) int { return strings.Compare(a.Name, b.Name) })
	switch {
	case present == len(inst.Bins) && present > 0:
		inst.Status = model.CargoInstallComplete
	case absent == len(inst.Bins):
		inst.Status = model.CargoInstallReceiptOnly
	default:
		inst.Status = model.CargoInstallPartial
	}
	return inst
}

// finish links discovered sources, rolls up status and sorts everything so an
// unchanged machine yields identical bytes. The record budget was spent
// during collection, in deterministic order.
func (g *cargoScan) finish() *model.CargoInventory {
	inv := newCargoInventory()
	inv.Projects = append(inv.Projects, g.projects...)
	inv.Workspaces = append(inv.Workspaces, g.workspaces...)
	inv.Packages = append(inv.Packages, g.packages...)

	for i := range inv.Projects {
		slices.Sort(inv.Projects[i].LockfilePaths)
	}
	slices.SortFunc(inv.Projects, func(a, b model.CargoProject) int { return strings.Compare(a.ManifestPath, b.ManifestPath) })
	for i := range inv.Workspaces {
		slices.SortFunc(inv.Workspaces[i].Members, func(a, b model.CargoWorkspaceMember) int {
			return strings.Compare(a.ManifestPath, b.ManifestPath)
		})
	}
	slices.SortFunc(inv.Workspaces, func(a, b model.CargoWorkspace) int { return strings.Compare(a.ManifestPath, b.ManifestPath) })
	slices.SortStableFunc(inv.Packages, func(a, b model.CargoPackage) int { return strings.Compare(cargoPackageKey(a), cargoPackageKey(b)) })

	for _, s := range g.sources {
		if parent := g.byID[s.ParentSourceID]; parent != nil {
			parent.DiscoveredSources = append(parent.DiscoveredSources, s.SourceID)
		}
	}
	reasons := append([]string{}, g.reasons...)
	for _, s := range g.sources {
		slices.Sort(s.Reasons)
		slices.Sort(s.DiscoveredSources)
		s.DiscoveredSources = slices.Compact(s.DiscoveredSources)
		if s.Status != model.CargoStatusComplete {
			reasons = append(reasons, s.Reasons...)
		}
		inv.Sources = append(inv.Sources, *s)
	}
	slices.SortFunc(inv.Sources, func(a, b model.CargoSource) int {
		return strings.Compare(a.Path+"\x00"+a.Kind, b.Path+"\x00"+b.Kind)
	})
	slices.Sort(reasons)
	inv.Reasons = slices.Compact(reasons)
	if len(inv.Reasons) > 0 {
		inv.Status = model.CargoStatusPartial
	}
	return &inv
}

// cargoPackageKey orders records by every field that distinguishes them.
func cargoPackageKey(p model.CargoPackage) string {
	o := p.Origin
	parts := []string{
		p.Evidence, p.PackageName, p.ObservedVersion, p.RequestedVersion, p.SourcePath, p.ProjectPath,
		o.Kind, o.URL, o.RegistryName, o.Path, o.CacheRoot, o.CacheID, o.Branch, o.Tag, o.Rev, o.ResolvedRevision,
	}
	if d := p.Declaration; d != nil {
		parts = append(parts, d.DependencyKind, d.Target, d.DeclaredName)
	}
	return strings.Join(parts, "\x00")
}
