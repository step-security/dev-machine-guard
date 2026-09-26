package detector

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/module"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Go collection limits, all named in the spec as starting values.
// ponytail: unmeasured on fleet data; tune after VM lab measurements.
var (
	maxGoManifestBytes int64 = 2 << 20 // go.mod, go.work, go.sum, go.work.sum
	maxGoVendorBytes   int64 = 8 << 20
	maxGoBinaryBytes   int64 = 128 << 20
	maxGoZipBytes      int64 = 32 << 20
	maxGoZiphashBytes  int64 = 256
	maxGoWalkEntries         = 100_000 // per discovery root; the cache shares one budget
	maxGoWalkDepth           = 128
	maxGoVendorProbes        = 10_000 // package-directory stats per vendor root
	maxGoRecords             = 50_000
	maxGoOutputBytes         = 16 << 20 // both Go sections, serialized
)

const goToolchainModule = "golang.org/toolchain"

// GoScanner statically collects Go module inventory and the Go config audit
// for one developer. It never runs a command, sources a shell or touches the
// network: every read goes through a guarded, bounded executor file method.
type GoScanner struct {
	exec executor.Executor
	log  *progress.Logger
	// protection builds the Go path guards; a seam so tests can place protected
	// directories and network volumes under a temp home.
	protection func(home string, includeNetworkVolumes *bool) (protected func(string) string, volume func(string) bool)
}

// NewGoScanner must be given the raw executor, never a UserAwareExecutor,
// whose Getenv sources a login shell.
func NewGoScanner(exec executor.Executor, log *progress.Logger) *GoScanner {
	return &GoScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

// goScan is the state of one Scan call.
type goScan struct {
	ctx      context.Context
	exec     executor.Executor
	identity string
	home     string
	roots    []string // approved scope: home plus every absolute search root
	guard    func(string) string
	volume   func(string) bool
	snap     configaudit.GoEnvSnapshot
	projFS   executor.Executor
	reasons  []string // global, not tied to a source
	sources  []*model.GoSource
	byID     map[string]*model.GoSource

	projects   []*goProjectState
	manifests  map[string]*goProjectState // default go.mod path -> project
	vendorDirs map[string]bool            // a go.work beside a go.mod owns the shared vendor dir
	workspaces []model.GoWorkspace
	vendored   []model.GoVendoredModule
	cached     []model.GoCachedModule
	tools      []model.GoInstalledTool
}

// goProjectState is a parsed manifest with the checksum sources that apply to
// it: its own sum file plus the go.work.sum of each workspace naming it.
type goProjectState struct {
	project model.GoProject
	sums    []goSumSource
}

// Scan returns both Go sections, always non-nil. An unresolvable or service
// identity is declined with user_unresolved and no filesystem access: a root
// account's home is never a silent substitute for the developer's.
func (s *GoScanner) Scan(ctx context.Context, target *user.User, searchDirs []string, includeNetworkVolumes *bool) (*model.GoInventory, *model.GoConfigAudit) {
	start := time.Now()
	envDetector := configaudit.NewGoEnvDetector(s.exec)
	if target == nil || target.Username == "" || target.HomeDir == "" || isGoServiceIdentity(s.exec.GOOS(), target) {
		inv := newGoInventory()
		inv.Status, inv.Reasons = model.GoStatusPartial, []string{model.GoReasonUserUnresolved}
		audit, _ := envDetector.Detect(ctx, configaudit.GoEnvScope{})
		s.log.Debug("go scan: declined, no developer identity")
		return &inv, &audit
	}

	home := filepath.Clean(target.HomeDir)
	guard, volume := s.protection(home, includeNetworkVolumes)
	g := &goScan{
		ctx: ctx, exec: s.exec, identity: target.Username, home: home, guard: guard, volume: volume,
		roots: []string{home}, byID: map[string]*model.GoSource{}, manifests: map[string]*goProjectState{},
		vendorDirs: map[string]bool{},
	}
	// Configured roots are normalized before any containment check; only Go's
	// own relative location values stay unresolved.
	searchDirs = slices.Clone(searchDirs)
	for i, d := range searchDirs {
		if d != "" {
			searchDirs[i] = canonicalNoStat(d, home)
		}
		if filepath.IsAbs(searchDirs[i]) {
			g.roots = append(g.roots, searchDirs[i])
		}
	}
	g.projFS = s.exec.GuardedFiles(g.roots, guard, maxGoManifestBytes)

	// The agent's own environment describes the developer only when it runs as them.
	current, err := s.exec.CurrentUser()
	verified := err == nil && target.Uid != "" && current.Uid == target.Uid
	audit, snap := envDetector.Detect(ctx, configaudit.GoEnvScope{
		Username: g.identity, Home: home, Roots: g.roots, Protected: guard, Volume: volume, ProcessVerified: verified,
	})
	g.snap = snap

	g.scanProjects(searchDirs)
	g.scanBin()
	g.scanCache()
	inv := g.finish()

	if size := goJSONSize(inv) + goJSONSize(&audit); size > maxGoOutputBytes {
		envelope := newGoInventory()
		envelope.Status, envelope.Reasons = model.GoStatusPartial, []string{model.GoReasonOutputSizeLimit}
		inv = &envelope
	}
	s.log.Debug("go scan: inventory=%s (%d sources, %d projects, %d workspaces, %d vendored, %d cached, %d tools) audit=%s (%d files, %d findings) in %dms",
		inv.Status, len(inv.Sources), len(inv.Projects), len(inv.Workspaces), len(inv.VendoredModules), len(inv.CachedModules),
		len(inv.InstalledTools), audit.Status, len(audit.Files), len(audit.Findings), time.Since(start).Milliseconds())
	return inv, &audit
}

func newGoInventory() model.GoInventory {
	return model.GoInventory{
		SchemaVersion: model.GoInventorySchemaVersion, Status: model.GoStatusComplete, Reasons: []string{},
		Sources: []model.GoSource{}, Projects: []model.GoProject{}, Workspaces: []model.GoWorkspace{},
		VendoredModules: []model.GoVendoredModule{}, CachedModules: []model.GoCachedModule{}, InstalledTools: []model.GoInstalledTool{},
	}
}

func goJSONSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// Well-known Windows service SIDs; mirrors browserext.isServiceIdentity,
// which is unexported in its own package.
var goWindowsServiceSIDs = map[string]bool{"S-1-5-18": true, "S-1-5-19": true, "S-1-5-20": true}

func isGoServiceIdentity(platform string, u *user.User) bool {
	if platform == model.PlatformWindows {
		return goWindowsServiceSIDs[strings.ToUpper(u.Uid)]
	}
	return u.Uid == "0"
}

// addSource registers a source once; the same kind and path is one source.
func (g *goScan) addSource(kind, path, parent string) *model.GoSource {
	id := configaudit.GoSourceID(g.identity, kind, path)
	if src := g.byID[id]; src != nil {
		return src
	}
	src := &model.GoSource{
		SourceID: id, Kind: kind, Path: path,
		Status: model.GoStatusComplete, Presence: model.GoPresencePresent, Reasons: []string{},
		ParentSourceID: parent, DiscoveredSources: []string{},
	}
	g.sources = append(g.sources, src)
	g.byID[src.SourceID] = src
	return src
}

func (g *goScan) globalReason(reason string) {
	if !slices.Contains(g.reasons, reason) {
		g.reasons = append(g.reasons, reason)
	}
}

// goDegrade lowers src to status with reason; a skipped source (never read)
// stays skipped.
func goDegrade(src *model.GoSource, status, reason string) {
	if src.Status != model.GoStatusSkipped {
		src.Status = status
	}
	if reason != "" && !slices.Contains(src.Reasons, reason) {
		src.Reasons = append(src.Reasons, reason)
	}
}

// expired marks src when the phase deadline has passed. A blocked syscall is
// not interrupted; the check runs between entries, reads and parses.
func (g *goScan) expired(src *model.GoSource, status string) bool {
	if g.ctx.Err() == nil {
		return false
	}
	goDegrade(src, status, model.GoReasonDeadlineExceeded)
	return true
}

// goRead stats then reads path (as served by files) within limit, recording
// any failure on src. A missing targeted file is a complete absence; a
// discovered file that vanished changed during the scan.
func goRead(src *model.GoSource, files executor.Executor, path string, limit int64, targeted bool) ([]byte, bool) {
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && targeted:
		src.Presence = model.GoPresenceAbsent
		return nil, false
	case errors.Is(err, fs.ErrNotExist):
		src.Presence = model.GoPresenceUnknown
		goDegrade(src, model.GoStatusPartial, model.GoReasonChangedDuringScan)
		return nil, false
	case err != nil:
		src.Presence = model.GoPresenceUnknown
		goDegrade(src, goRefusalStatus(err), configaudit.GoReadReason(err))
		return nil, false
	case !info.Mode().IsRegular():
		goDegrade(src, model.GoStatusPartial, model.GoReasonUnsupportedEntry)
		return nil, false
	case info.Size() > limit:
		goDegrade(src, model.GoStatusPartial, model.GoReasonSizeLimit)
		return nil, false
	}
	data, err := files.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		goDegrade(src, model.GoStatusPartial, model.GoReasonChangedDuringScan)
		return nil, false
	} else if err != nil {
		goDegrade(src, model.GoStatusPartial, configaudit.GoReadReason(err))
		return nil, false
	}
	return data, true
}

// goRefusalStatus: a scope or protection refusal means the path was never
// read; a permission failure is an incomplete read.
func goRefusalStatus(err error) string {
	if configaudit.GoReadReason(err) == model.GoReasonPermissionDenied {
		return model.GoStatusPartial
	}
	return model.GoStatusSkipped
}

// checksumFile reads a targeted checksum file into a lookup source, reported
// as a checksum_file source owned by parent. Its failures degrade only
// checksum coverage, never the owning source.
func (g *goScan) checksumFile(files executor.Executor, readPath, path, parentID, kind string, limit int64, parse func([]byte) (goSumIndex, []string)) goSumSource {
	src := g.addSource(model.GoSourceChecksumFile, path, parentID)
	out := goSumSource{kind: kind, id: src.SourceID, path: path, index: goSumIndex{}}
	data, ok := goRead(src, files, readPath, limit, true)
	switch {
	case ok:
		var reasons []string
		out.index, reasons = parse(data)
		out.failure = goSumFailure(reasons)
		for _, r := range reasons {
			goDegrade(src, model.GoStatusPartial, r)
		}
	case src.Presence == model.GoPresenceAbsent:
	case src.Status == model.GoStatusSkipped:
		out.failure = model.GoChecksumSkipped
	case slices.Contains(src.Reasons, model.GoReasonSizeLimit):
		out.failure = model.GoChecksumPartial
	default:
		out.failure = model.GoChecksumUnreadable
	}
	return out
}

func (g *goScan) goSum(path, parentID, kind string) goSumSource {
	return g.checksumFile(g.projFS, path, path, parentID, kind, maxGoManifestBytes, parseGoSum)
}

// goRoot is a search root that resolved and will be walked.
type goRoot struct {
	src        *model.GoSource
	path, phys string
}

// scanProjects walks each approved search root once for go.mod and go.work,
// then reads what it found.
func (g *goScan) scanProjects(searchDirs []string) {
	type candidate struct {
		path, phys string
		status     string
		presence   string
		reason     string
	}
	var cands []candidate
	seen := map[string]bool{}
	for _, dir := range searchDirs {
		if !filepath.IsAbs(dir) {
			g.globalReason(model.GoReasonPathUnresolved) // no working directory to resolve against
			continue
		}
		if seen[dir] {
			continue
		}
		seen[dir] = true
		c := candidate{path: dir, status: model.GoStatusComplete, presence: model.GoPresencePresent}
		if reason := g.guard(dir); reason != "" {
			c.status, c.presence, c.reason = model.GoStatusSkipped, model.GoPresenceUnknown, reason
		} else if g.ctx.Err() != nil {
			c.status, c.presence, c.reason = model.GoStatusSkipped, model.GoPresenceUnknown, model.GoReasonDeadlineExceeded
		} else if phys, err := g.exec.GuardedFiles([]string{dir}, g.guard, 0).EvalSymlinks(dir); errors.Is(err, fs.ErrNotExist) {
			c.presence = model.GoPresenceAbsent
		} else if err != nil {
			c.status, c.presence, c.reason = goRefusalStatus(err), model.GoPresenceUnknown, configaudit.GoReadReason(err)
		} else {
			c.phys = phys
		}
		cands = append(cands, c)
	}

	// Overlapping roots: the outermost walkable root owns what it contains, and
	// the first configured spelling of a physical directory is kept.
	var walk []goRoot
	for i, c := range cands {
		folded := false
		for j, o := range cands {
			if i == j || c.phys == "" || o.phys == "" {
				continue
			}
			if (o.phys == c.phys && j < i) || (o.phys != c.phys && goPathWithin(c.phys, o.phys)) {
				folded = true
				break
			}
		}
		if folded {
			continue
		}
		src := g.addSource(model.GoSourceProjectSearchRoot, c.path, "")
		src.Status, src.Presence = c.status, c.presence
		if c.reason != "" {
			src.Reasons = append(src.Reasons, c.reason)
		}
		if c.phys != "" {
			walk = append(walk, goRoot{src: src, path: c.path, phys: c.phys})
		}
	}

	var mods, works []goDiscovered
	for _, r := range walk {
		m, w := g.walkRoot(r)
		mods, works = append(mods, m...), append(works, w...)
	}
	for _, d := range mods {
		g.readManifest(d)
	}
	for _, d := range works {
		g.readWorkspace(d)
	}
	g.readAlternateManifest(walk)
	for _, p := range g.projects {
		goEnrichProject(&p.project, p.sums...)
	}
	for _, p := range g.projects {
		if p.project.ManifestPath == filepath.Join(p.project.Path, "go.mod") {
			g.readVendor(p.project.Path, p.project.SourceID, &p.project, p.sums[:1])
		}
	}
}

// goDiscovered is a manifest found by a walk and the root that found it.
type goDiscovered struct{ path, rootID string }

// walkRoot is a bounded breadth-first listing of one root. Directory
// symlinks are never followed, dependency stores and version-control
// internals are skipped, and discovery continues below a manifest.
func (g *goScan) walkRoot(r goRoot) (mods, works []goDiscovered) {
	skipDirs := map[string]bool{}
	if c, ok := g.snap.ModCacheRoot(g.home); ok {
		skipDirs[c] = true
	}
	if c, ok := g.snap.DefaultModCacheRoot(g.home); ok {
		skipDirs[c] = true
	}
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{r.path, 0}}
	budget := maxGoWalkEntries
	for len(queue) > 0 {
		if g.expired(r.src, model.GoStatusPartial) {
			return mods, works
		}
		d := queue[0]
		queue = queue[1:]
		entries, more, err := g.projFS.ReadDirLimit(d.path, budget)
		if err != nil {
			if d.depth == 0 {
				r.src.Presence = model.GoPresenceUnknown
			}
			goDegrade(r.src, model.GoStatusPartial, configaudit.GoReadReason(err))
			continue
		}
		budget -= len(entries)
		manifestHere := slices.ContainsFunc(entries, func(e fs.DirEntry) bool {
			return !e.IsDir() && (e.Name() == "go.mod" || e.Name() == "go.work")
		})
		for _, e := range entries {
			p := filepath.Join(d.path, e.Name())
			if !e.IsDir() {
				switch e.Name() {
				case "go.mod":
					mods = append(mods, goDiscovered{p, r.src.SourceID})
				case "go.work":
					works = append(works, goDiscovered{p, r.src.SourceID})
				}
				continue
			}
			switch {
			case goSkippedDirNames[e.Name()], e.Name() == "vendor" && manifestHere, skipDirs[p]:
				continue
			case g.guard(p) != "":
				// Protected directories are deliberate scope; an excluded mount
				// depends on configuration, so it must not read as deletion.
				if g.volume(p) {
					goDegrade(r.src, model.GoStatusPartial, model.GoReasonSkippedProtected)
				}
				continue
			case d.depth+1 > maxGoWalkDepth:
				goDegrade(r.src, model.GoStatusPartial, model.GoReasonDepthLimit)
				continue
			}
			queue = append(queue, dir{p, d.depth + 1})
		}
		if more {
			goDegrade(r.src, model.GoStatusPartial, model.GoReasonEntryLimit)
			return mods, works
		}
	}
	return mods, works
}

var goSkippedDirNames = map[string]bool{".git": true, ".hg": true, ".svn": true, "node_modules": true}

// goPathWithin reports whether path is strictly below dir, lexically.
func goPathWithin(path, dir string) bool {
	return len(path) > len(dir) && strings.HasPrefix(path, dir) &&
		(path[len(dir)] == filepath.Separator || strings.HasSuffix(dir, string(filepath.Separator)))
}

func (g *goScan) readManifest(d goDiscovered) {
	src := g.addSource(model.GoSourceProjectManifest, d.path, d.rootID)
	if g.expired(src, model.GoStatusSkipped) {
		return
	}
	data, ok := goRead(src, g.projFS, d.path, maxGoManifestBytes, false)
	if !ok {
		return
	}
	p, err := goProjectFromModfile(d.path, data)
	if err != nil {
		goDegrade(src, model.GoStatusPartial, model.GoReasonParseError)
		return
	}
	p.SourceID, p.Path, p.ManifestPath = src.SourceID, filepath.Dir(d.path), d.path
	state := &goProjectState{project: p}
	state.sums = []goSumSource{g.goSum(filepath.Join(p.Path, "go.sum"), src.SourceID, model.GoChecksumSourceProjectGoSum)}
	g.projects = append(g.projects, state)
	g.manifests[d.path] = state
}

func (g *goScan) readWorkspace(d goDiscovered) {
	src := g.addSource(model.GoSourceWorkspace, d.path, d.rootID)
	if g.expired(src, model.GoStatusSkipped) {
		return
	}
	data, ok := goRead(src, g.projFS, d.path, maxGoManifestBytes, false)
	if !ok {
		return
	}
	w, err := goWorkspaceFromModfile(d.path, data)
	if err != nil {
		goDegrade(src, model.GoStatusPartial, model.GoReasonParseError)
		return
	}
	w.SourceID, w.Path = src.SourceID, d.path
	dir := filepath.Dir(d.path)
	workSum := g.goSum(filepath.Join(dir, "go.work.sum"), src.SourceID, model.GoChecksumSourceWorkspaceGoWorkSum)

	// A manifest cannot grant access: members resolve only inside the approved
	// roots, and only an already discovered go.mod is linked.
	sums := []goSumSource{workSum}
	var memberReqs []model.GoRequirement
	for i := range w.Members {
		m := &w.Members[i]
		p := filepath.FromSlash(m.DeclaredPath)
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		m.ResolvedPath = filepath.Clean(p)
		state := g.manifests[filepath.Join(m.ResolvedPath, "go.mod")]
		switch {
		case g.guard(m.ResolvedPath) != "":
			m.Reason = model.GoReasonSkippedProtected
		case !slices.ContainsFunc(g.roots, func(r string) bool { return r == m.ResolvedPath || goPathWithin(m.ResolvedPath, r) }):
			m.Reason = model.GoReasonOutsideApprovedRoots
		case state == nil:
			m.Reason = model.GoReasonMemberNotDiscovered
		default:
			m.ProjectSourceID = state.project.SourceID
			if !slices.Contains(state.project.WorkspacePaths, d.path) {
				state.project.WorkspacePaths = append(state.project.WorkspacePaths, d.path)
				state.sums = append(state.sums, workSum)
			}
			sums = append(sums, state.sums[0])
			memberReqs = append(memberReqs, state.project.Requirements...)
		}
	}
	for i := range w.Replacements {
		goEnrichReplacement(&w.Replacements[i], memberReqs, sums...)
	}
	g.workspaces = append(g.workspaces, w)
	g.readVendor(dir, src.SourceID, nil, sums)
}

// readAlternateManifest reads an absolute, in-scope GOFLAGS -modfile as its
// own declaration beside the default go.mod, with its matching .sum.
func (g *goScan) readAlternateManifest(walk []goRoot) {
	name, ok := g.snap.Modfile()
	if !ok {
		g.globalReason(model.GoReasonAlternateManifestUnresolved) // GOFLAGS Go itself would reject
		return
	}
	if name == "" {
		return
	}
	if !filepath.IsAbs(name) {
		g.globalReason(model.GoReasonAlternateManifestUnresolved) // relative to an unknown working directory
		return
	}
	name = filepath.Clean(name)
	if g.manifests[name] != nil {
		return // the default go.mod, already read
	}
	if g.guard(name) != "" || !slices.ContainsFunc(g.roots, func(r string) bool { return goPathWithin(name, r) }) {
		g.globalReason(model.GoReasonAlternateManifestUnresolved)
		return
	}
	// Owned by the nearest enclosing project, else the search root holding it.
	parent, projectDir := "", filepath.Dir(name)
	for _, r := range walk {
		if goPathWithin(name, r.path) {
			parent = r.src.SourceID
		}
	}
	best := ""
	for _, p := range g.projects {
		if dir := p.project.Path; goPathWithin(name, dir) && len(dir) > len(best) &&
			p.project.ManifestPath == filepath.Join(dir, "go.mod") {
			best, parent, projectDir = dir, p.project.SourceID, dir
		}
	}
	src := g.addSource(model.GoSourceAlternateManifest, name, parent)
	if g.expired(src, model.GoStatusSkipped) {
		return
	}
	data, ok := goRead(src, g.projFS, name, maxGoManifestBytes, true)
	if !ok {
		return
	}
	p, err := goProjectFromModfile(name, data)
	if err != nil {
		goDegrade(src, model.GoStatusPartial, model.GoReasonParseError)
		return
	}
	p.SourceID, p.Path, p.ManifestPath = src.SourceID, projectDir, name
	state := &goProjectState{project: p}
	// Go rejects a -modfile without the .mod extension, so no .sum is implied.
	if base, ok := strings.CutSuffix(name, ".mod"); ok {
		state.sums = []goSumSource{g.goSum(base+".sum", src.SourceID, model.GoChecksumSourceProjectGoSum)}
	} else {
		goDegrade(src, model.GoStatusPartial, model.GoReasonUnsupportedModfileName)
	}
	g.projects = append(g.projects, state)
}

// goEnrichProject attaches exact-match checksums to a project's
// requirements and to the versioned providers it actually requires.
func goEnrichProject(p *model.GoProject, sums ...goSumSource) {
	if len(sums) == 0 {
		return
	}
	for i := range p.Requirements {
		r := &p.Requirements[i]
		goChecksums(&r.GoChecksumEvidence, module.Version{Path: r.ModulePath, Version: r.RequestedVersion}, sums...)
	}
	for i := range p.Replacements {
		goEnrichReplacement(&p.Replacements[i], p.Requirements, sums...)
	}
}

// goEnrichReplacement: a local replacement has no checksum; a versioned
// provider is looked up only when a requirement establishes the replacement
// is used, never from the directive alone.
func goEnrichReplacement(r *model.GoReplacement, reqs []model.GoRequirement, sums ...goSumSource) {
	if r.Kind == model.GoReplaceLocal {
		r.ChecksumStatus = model.GoChecksumNotApplicable
		return
	}
	used := slices.ContainsFunc(reqs, func(q model.GoRequirement) bool {
		return q.ModulePath == r.FromPath && (r.FromVersion == "" || q.RequestedVersion == r.FromVersion)
	})
	if used && len(sums) > 0 {
		goChecksums(&r.GoChecksumEvidence, module.Version{Path: r.ToModulePath, Version: r.ToVersion}, sums...)
	}
}

// readVendor reads dir/vendor/modules.txt when it exists. A module becomes a
// vendored record only when one of its package directories is on disk.
func (g *goScan) readVendor(dir, parentID string, owner *model.GoProject, sums []goSumSource) {
	vendorDir := filepath.Join(dir, "vendor")
	listPath := filepath.Join(vendorDir, "modules.txt")
	if g.vendorDirs[vendorDir] {
		return
	}
	if _, err := g.projFS.Stat(listPath); errors.Is(err, fs.ErrNotExist) {
		return
	}
	g.vendorDirs[vendorDir] = true
	src := g.addSource(model.GoSourceVendorRoot, vendorDir, parentID)
	if g.expired(src, model.GoStatusSkipped) {
		return
	}
	vendorFS := g.exec.GuardedFiles(g.roots, g.guard, maxGoVendorBytes)
	data, ok := goRead(src, vendorFS, listPath, maxGoVendorBytes, false)
	if !ok {
		return
	}
	list := parseVendorModules(data)
	if owner != nil && list.mismatches(*owner) {
		src.Reasons = append(src.Reasons, model.GoReasonVendorMismatch) // context only; the read was complete
	}
	probes := maxGoVendorProbes
	for _, m := range list.modules {
		if g.expired(src, model.GoStatusPartial) {
			return
		}
		pkg, failure := "", ""
		for _, candidate := range m.packages {
			if probes == 0 {
				goDegrade(src, model.GoStatusPartial, model.GoReasonEntryLimit)
				return
			}
			probes--
			info, err := g.projFS.Stat(filepath.Join(vendorDir, filepath.FromSlash(candidate)))
			if err == nil && info.IsDir() {
				pkg = candidate
				break
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				failure = configaudit.GoReadReason(err)
			}
		}
		if pkg == "" {
			// Only a genuinely missing directory is absence; an unchecked one
			// must not retire the module.
			if failure != "" {
				goDegrade(src, model.GoStatusPartial, failure)
			}
			continue
		}
		v := model.GoVendoredModule{
			SourceID: src.SourceID, ModulePath: m.mod.Path, ObservedVersion: m.mod.Version,
			VendorRoot: vendorDir, PackagePaths: []string{pkg},
		}
		if m.replace != nil {
			r := goReplacement(m.mod, *m.replace)
			goEnrichReplacement(&r, []model.GoRequirement{{ModulePath: m.mod.Path, RequestedVersion: m.mod.Version}}, sums...)
			v.Replacement = &r
			v.ChecksumStatus = model.GoChecksumNotApplicable
		} else if m.mod.Version == "" {
			v.ChecksumStatus = model.GoChecksumNotApplicable
		} else {
			goChecksums(&v.GoChecksumEvidence, m.mod, sums...)
		}
		g.vendored = append(g.vendored, v)
	}
}

// goRootFS resolves a bin or cache root inside the approved scope and
// returns a reader rooted at its physical path, so a redirected root can
// neither leave scope nor be swapped afterwards.
func (g *goScan) goRootFS(src *model.GoSource, limit int64) (executor.Executor, string, bool) {
	if reason := g.guard(src.Path); reason != "" {
		src.Presence = model.GoPresenceUnknown
		goDegrade(src, model.GoStatusSkipped, reason)
		return nil, "", false
	}
	phys, err := g.exec.GuardedFiles(g.roots, g.guard, 0).EvalSymlinks(src.Path)
	if errors.Is(err, fs.ErrNotExist) {
		src.Presence = model.GoPresenceAbsent
		return nil, "", false
	} else if err != nil {
		src.Presence = model.GoPresenceUnknown
		goDegrade(src, goRefusalStatus(err), configaudit.GoReadReason(err))
		return nil, "", false
	}
	if g.snap.RedirectUnknown {
		goDegrade(src, model.GoStatusPartial, model.GoReasonRootRedirectUnknown)
	}
	return g.exec.GuardedFiles([]string{phys}, g.guard, limit), phys, true
}

// scanBin reads immediate executable candidates in the resolved install bin
// directory. Every candidate is listed; only usable BuildInfo becomes a tool.
func (g *goScan) scanBin() {
	root, ok := g.snap.BinRoot(g.home)
	if !ok {
		g.globalReason(model.GoReasonPathUnresolved)
		return
	}
	src := g.addSource(model.GoSourceBinRoot, root, "")
	if g.expired(src, model.GoStatusSkipped) {
		src.Presence = model.GoPresenceUnknown
		return
	}
	binFS, phys, ok := g.goRootFS(src, maxGoBinaryBytes)
	if !ok {
		return
	}
	entries, more, err := binFS.ReadDirLimit(phys, maxGoWalkEntries)
	if err != nil {
		src.Presence = model.GoPresenceUnknown
		goDegrade(src, model.GoStatusPartial, configaudit.GoReadReason(err))
		return
	}
	if more {
		goDegrade(src, model.GoStatusPartial, model.GoReasonEntryLimit)
	}
	goos := g.exec.GOOS()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if g.expired(src, model.GoStatusPartial) {
			return
		}
		readPath, path := filepath.Join(phys, e.Name()), filepath.Join(root, e.Name())
		// Mode and size come from the guarded Stat, never DirEntry.Info's lstat.
		info, err := binFS.Stat(readPath)
		if errors.Is(err, fs.ErrNotExist) {
			continue // dangling link
		} else if err != nil {
			b := g.addSource(model.GoSourceBinary, path, src.SourceID)
			b.Presence = model.GoPresenceUnknown
			goDegrade(b, goRefusalStatus(err), configaudit.GoReadReason(err))
			continue
		}
		if !info.Mode().IsRegular() || !goBinaryCandidate(goos, e.Name(), info.Mode()) {
			continue
		}
		b := g.addSource(model.GoSourceBinary, path, src.SourceID)
		data, ok := goRead(b, binFS, readPath, maxGoBinaryBytes, false)
		if !ok {
			continue
		}
		bi, notGo := goBuildInfo(data)
		switch {
		case notGo:
		case bi == nil:
			goDegrade(b, model.GoStatusPartial, model.GoReasonBuildInfoUnusable)
		default:
			g.tools = append(g.tools, goToolFromBuildInfo(bi, path, b.SourceID))
		}
	}
}

func goBinaryCandidate(goos, name string, mode fs.FileMode) bool {
	if goos == model.PlatformWindows {
		return strings.EqualFold(filepath.Ext(name), ".exe")
	}
	return mode&0o111 != 0
}

// goCacheEntry is one module version seen in a cache root, from its
// extracted directory and/or its cache/download/.../@v files.
type goCacheEntry struct {
	mod                     module.Version
	extracted               string // slash path below the root
	escPath, escVer         string
	zip, ziphash, inProcess bool
}

// scanCache enumerates the module cache without descending into modules:
// cache/download @v listings first, then the extracted module@version tree,
// on one shared entry budget.
func (g *goScan) scanCache() {
	root, ok := g.snap.ModCacheRoot(g.home)
	if !ok {
		g.globalReason(model.GoReasonPathUnresolved)
		return
	}
	src := g.addSource(model.GoSourceCacheRoot, root, "")
	if g.expired(src, model.GoStatusSkipped) {
		src.Presence = model.GoPresenceUnknown
		return
	}
	cacheFS, phys, ok := g.goRootFS(src, maxGoZipBytes)
	if !ok {
		return
	}
	c := &goCacheWalk{g: g, fs: cacheFS, phys: phys, src: src, budget: maxGoWalkEntries,
		entries: map[module.Version]*goCacheEntry{}, listed: map[string]bool{}}
	c.walk("", func(rel string, e fs.DirEntry) bool { // extracted tree
		if !e.IsDir() || (rel == "" && e.Name() == "cache") {
			return false
		}
		if !strings.Contains(e.Name(), "@") {
			return true
		}
		mod, err := goCacheModuleDir(pathJoinSlash(rel, e.Name()))
		switch {
		case errors.Is(err, errGoTempName):
		case err != nil:
			goDegrade(src, model.GoStatusPartial, model.GoReasonUnsupportedEntry)
		default:
			c.entry(mod).extracted = pathJoinSlash(rel, e.Name())
		}
		return false
	})
	downloadComplete := c.walk("cache/download", func(rel string, e fs.DirEntry) bool {
		if !e.IsDir() || (rel == "cache/download" && e.Name() == "sumdb") {
			return false
		}
		if e.Name() == "@v" {
			c.listVersions(strings.TrimPrefix(rel, "cache/download/"))
			return false
		}
		return true
	})

	keys := slices.SortedFunc(maps.Keys(c.entries), func(a, b module.Version) int {
		return strings.Compare(a.Path+"\x00"+a.Version, b.Path+"\x00"+b.Version)
	})
	for _, k := range keys {
		e := c.entries[k]
		if e.extracted == "" && !e.zip {
			continue // metadata-only (.mod/.info/.ziphash) is not module evidence
		}
		if g.expired(src, model.GoStatusPartial) {
			break
		}
		// A module whose own listing failed is unknown even when the rest of
		// the download tree was listed.
		known, listed := c.listed[e.mod.Path]
		if !listed {
			known = downloadComplete
		}
		g.cached = append(g.cached, c.record(e, root, known))
	}
}

func pathJoinSlash(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

type goCacheWalk struct {
	g       *goScan
	fs      executor.Executor
	phys    string
	src     *model.GoSource
	budget  int
	entries map[module.Version]*goCacheEntry
	listed  map[string]bool // module path -> its @v listing completed (false: failed or capped)
}

func (c *goCacheWalk) entry(mod module.Version) *goCacheEntry {
	e, ok := c.entries[mod]
	if !ok {
		e = &goCacheEntry{mod: mod}
		c.entries[mod] = e
	}
	return e
}

// walk lists the tree below start (slash path relative to the cache root),
// descending wherever visit returns true. It reports whether every
// directory was listed.
func (c *goCacheWalk) walk(start string, visit func(rel string, e fs.DirEntry) bool) bool {
	type dir struct {
		rel   string
		depth int
	}
	complete := true
	queue := []dir{{start, 0}}
	for len(queue) > 0 {
		if c.g.expired(c.src, model.GoStatusPartial) {
			return false
		}
		d := queue[0]
		queue = queue[1:]
		entries, more, err := c.fs.ReadDirLimit(filepath.Join(c.phys, filepath.FromSlash(d.rel)), c.budget)
		switch {
		case errors.Is(err, fs.ErrNotExist) && d.depth == 0:
			return true // no download cache yet
		case err != nil:
			goDegrade(c.src, model.GoStatusPartial, configaudit.GoReadReason(err))
			complete = false
			continue
		}
		c.budget -= len(entries)
		for _, e := range entries {
			if !visit(d.rel, e) {
				continue
			}
			if d.depth+1 > maxGoWalkDepth {
				goDegrade(c.src, model.GoStatusPartial, model.GoReasonDepthLimit)
				complete = false
				continue
			}
			queue = append(queue, dir{pathJoinSlash(d.rel, e.Name()), d.depth + 1})
		}
		if more {
			goDegrade(c.src, model.GoStatusPartial, model.GoReasonEntryLimit)
			return false
		}
	}
	return complete
}

// listVersions reads one cache/download/<escaped-path>/@v directory.
func (c *goCacheWalk) listVersions(escPath string) {
	modPath, pathErr := module.UnescapePath(escPath)
	entries, more, err := c.fs.ReadDirLimit(filepath.Join(c.phys, "cache", "download", filepath.FromSlash(escPath), "@v"), c.budget)
	if pathErr == nil {
		c.listed[modPath] = err == nil && !more
	}
	if err != nil {
		goDegrade(c.src, model.GoStatusPartial, configaudit.GoReadReason(err))
		return
	}
	c.budget -= len(entries)
	for _, e := range entries {
		mod, ext, ok := goCacheDownloadFile(escPath, e.Name())
		if !ok || e.IsDir() {
			continue
		}
		ce := c.entry(mod)
		ce.escPath, ce.escVer = escPath, strings.TrimSuffix(e.Name(), ext)
		switch ext {
		case ".zip":
			ce.zip = true
		case ".ziphash":
			ce.ziphash = true
		case ".partial":
			ce.inProcess = true
		}
	}
	if more {
		goDegrade(c.src, model.GoStatusPartial, model.GoReasonEntryLimit)
	}
}

// record builds the cache record. Extracted source is present only as Go's
// DownloadDir would accept it: no .partial marker and a .ziphash.
func (c *goCacheWalk) record(e *goCacheEntry, root string, known bool) model.GoCachedModule {
	rec := model.GoCachedModule{
		SourceID: c.src.SourceID, ModulePath: e.mod.Path, ObservedVersion: e.mod.Version, Root: root,
		Artifacts: []model.GoCacheArtifact{},
	}
	toolchain := e.mod.Path == goToolchainModule
	if e.extracted != "" {
		// An unknown listing already degraded the root; the others are
		// incomplete extraction, which a later scan may still complete.
		status := model.GoArtifactPresent
		if !toolchain && (!known || e.inProcess || (!e.ziphash && e.mod.Path != "golang.org/fips140")) {
			status = model.GoArtifactPartial
			if known {
				goDegrade(c.src, model.GoStatusPartial, model.GoReasonExtractionIncomplete)
			}
		}
		rec.Artifacts = append(rec.Artifacts, model.GoCacheArtifact{
			Kind: model.GoArtifactExtractedSource, Path: filepath.Join(root, filepath.FromSlash(e.extracted)), Status: status,
		})
	}
	vDir := filepath.Join("cache", "download", filepath.FromSlash(e.escPath), "@v")
	if e.zip {
		rel := filepath.Join(vDir, e.escVer+".zip")
		rec.Artifacts = append(rec.Artifacts, model.GoCacheArtifact{
			Kind: model.GoArtifactArchivePresent, Path: filepath.Join(root, rel), Status: c.zipStatus(e, filepath.Join(c.phys, rel), toolchain),
		})
	}
	switch {
	case e.ziphash:
		rel := filepath.Join(vDir, e.escVer+".ziphash")
		sum := c.g.checksumFile(c.fs, filepath.Join(c.phys, rel), filepath.Join(root, rel), c.src.SourceID,
			model.GoChecksumSourceCacheZiphash, maxGoZiphashBytes, func(data []byte) (goSumIndex, []string) {
				v, ok := parseZiphash(data)
				if !ok {
					return goSumIndex{}, []string{model.GoReasonMalformedChecksumLine}
				}
				return goSumIndex{e.mod: {{model.GoChecksumKindModuleContent, v}}}, nil
			})
		goChecksums(&rec.GoChecksumEvidence, e.mod, sum)
	case known:
		rec.ChecksumStatus = model.GoChecksumAbsent
	default:
		rec.ChecksumStatus = model.GoChecksumUnreadable
	}
	return rec
}

// zipStatus checks archive metadata; any failure also degrades the cache root.
// Toolchain archives (~70 MB) are deliberately never opened, so they stay
// unverified without making every cache partial.
func (c *goCacheWalk) zipStatus(e *goCacheEntry, readPath string, toolchain bool) string {
	if toolchain {
		return model.GoArtifactPartial
	}
	fail := func(status, reason string) string {
		goDegrade(c.src, model.GoStatusPartial, reason)
		return status
	}
	info, err := c.fs.Stat(readPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fail(model.GoArtifactUnreadable, model.GoReasonChangedDuringScan)
	case err != nil:
		return fail(model.GoArtifactUnreadable, configaudit.GoReadReason(err))
	case !info.Mode().IsRegular():
		return fail(model.GoArtifactUnreadable, model.GoReasonUnsupportedEntry)
	case info.Size() > maxGoZipBytes:
		return fail(model.GoArtifactPartial, model.GoReasonSizeLimit)
	}
	data, err := c.fs.ReadFile(readPath)
	if err != nil {
		return fail(model.GoArtifactUnreadable, configaudit.GoReadReason(err))
	}
	switch status := zipArchiveStatus(data, e.mod); status {
	case model.GoArtifactUnreadable:
		return fail(status, model.GoReasonParseError) // corrupt, or entries outside path@version/
	case model.GoArtifactPartial:
		return fail(status, model.GoReasonEntryLimit)
	default:
		return status
	}
}

// finish links discovered sources, applies the record budget, rolls up
// status and sorts everything so an unchanged machine yields identical bytes.
func (g *goScan) finish() *model.GoInventory {
	inv := newGoInventory()
	for _, p := range g.projects {
		inv.Projects = append(inv.Projects, p.project)
	}
	inv.Workspaces = append(inv.Workspaces, g.workspaces...)
	inv.VendoredModules = append(inv.VendoredModules, g.vendored...)
	inv.CachedModules = append(inv.CachedModules, g.cached...)
	inv.InstalledTools = append(inv.InstalledTools, g.tools...)

	slices.SortFunc(inv.Projects, func(a, b model.GoProject) int {
		return strings.Compare(a.Path+"\x00"+a.ManifestPath, b.Path+"\x00"+b.ManifestPath)
	})
	for i := range inv.Projects {
		slices.Sort(inv.Projects[i].WorkspacePaths)
	}
	slices.SortFunc(inv.Workspaces, func(a, b model.GoWorkspace) int { return strings.Compare(a.Path, b.Path) })
	for i := range inv.Workspaces {
		slices.SortFunc(inv.Workspaces[i].Members, func(a, b model.GoWorkspaceMember) int {
			return strings.Compare(a.DeclaredPath, b.DeclaredPath)
		})
	}
	slices.SortFunc(inv.VendoredModules, func(a, b model.GoVendoredModule) int {
		return strings.Compare(a.VendorRoot+"\x00"+a.ModulePath+"\x00"+a.ObservedVersion, b.VendorRoot+"\x00"+b.ModulePath+"\x00"+b.ObservedVersion)
	})
	slices.SortFunc(inv.CachedModules, func(a, b model.GoCachedModule) int {
		return strings.Compare(a.ModulePath+"\x00"+a.ObservedVersion, b.ModulePath+"\x00"+b.ObservedVersion)
	})
	slices.SortFunc(inv.InstalledTools, func(a, b model.GoInstalledTool) int { return strings.Compare(a.BinaryPath, b.BinaryPath) })

	// Record budget, in sorted order so the same records survive every run.
	// Dropped rows always mark their owning source incomplete.
	budget := maxGoRecords
	inv.Projects = goWithinBudget(g, &budget, inv.Projects, func(p model.GoProject) (string, int) {
		n := 1 + len(p.Exclusions) + len(p.Tools) + len(p.WorkspacePaths)
		for _, r := range p.Requirements {
			n += 1 + len(r.RecordedChecksums)
		}
		for _, r := range p.Replacements {
			n += 1 + len(r.RecordedChecksums)
		}
		return p.SourceID, n
	})
	inv.Workspaces = goWithinBudget(g, &budget, inv.Workspaces, func(w model.GoWorkspace) (string, int) {
		n := 1 + len(w.Members)
		for _, r := range w.Replacements {
			n += 1 + len(r.RecordedChecksums)
		}
		return w.SourceID, n
	})
	inv.InstalledTools = goWithinBudget(g, &budget, inv.InstalledTools, func(t model.GoInstalledTool) (string, int) {
		n := 1 + len(t.RecordedChecksums) + goReplacementRows(t.Replacement)
		for _, d := range t.Dependencies {
			n += 1 + len(d.RecordedChecksums) + goReplacementRows(d.Replacement)
		}
		return t.SourceID, n
	})
	inv.VendoredModules = goWithinBudget(g, &budget, inv.VendoredModules, func(v model.GoVendoredModule) (string, int) {
		return v.SourceID, 1 + len(v.PackagePaths) + len(v.RecordedChecksums) + goReplacementRows(v.Replacement)
	})
	inv.CachedModules = goWithinBudget(g, &budget, inv.CachedModules, func(c model.GoCachedModule) (string, int) {
		return c.SourceID, 1 + len(c.Artifacts) + len(c.RecordedChecksums)
	})

	for _, s := range g.sources {
		if parent := g.byID[s.ParentSourceID]; parent != nil {
			parent.DiscoveredSources = append(parent.DiscoveredSources, s.SourceID)
		}
	}
	reasons := slices.Clone(g.reasons)
	for _, s := range g.sources {
		slices.Sort(s.Reasons)
		slices.Sort(s.DiscoveredSources)
		s.DiscoveredSources = slices.Compact(s.DiscoveredSources)
		if s.Status != model.GoStatusComplete {
			reasons = append(reasons, s.Reasons...)
		}
		inv.Sources = append(inv.Sources, *s)
	}
	slices.SortFunc(inv.Sources, func(a, b model.GoSource) int {
		return strings.Compare(a.Path+"\x00"+a.Kind, b.Path+"\x00"+b.Kind)
	})
	slices.Sort(reasons)
	inv.Reasons = slices.Compact(reasons)
	if len(inv.Reasons) > 0 {
		inv.Status = model.GoStatusPartial
	}
	return &inv
}

func goReplacementRows(r *model.GoReplacement) int {
	if r == nil {
		return 0
	}
	return 1 + len(r.RecordedChecksums)
}

// goWithinBudget keeps records while they fit; the first that does not
// exhausts the budget for everything after it.
func goWithinBudget[T any](g *goScan, budget *int, records []T, rows func(T) (string, int)) []T {
	kept := records[:0]
	for _, r := range records {
		id, n := rows(r)
		if n > *budget {
			*budget = 0
			if src := g.byID[id]; src != nil {
				goDegrade(src, model.GoStatusPartial, model.GoReasonRecordLimit)
			}
			continue
		}
		*budget -= n
		kept = append(kept, r)
	}
	return kept
}
