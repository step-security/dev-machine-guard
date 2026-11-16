package detector

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
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

var (
	maxSwiftWalkEntries = 100_000
	maxSwiftWalkDepth   = 128
	maxSwiftRecords     = 50_000
	maxSwiftOutputBytes = 16 << 20
	maxSwiftListEntries = 10_000
)

// SwiftScanner reads SwiftPM and Xcode package metadata only: no swift, git
// or xcodebuild runs, no manifest evaluation and no network access.
type SwiftScanner struct {
	exec       executor.Executor
	log        *progress.Logger
	protection func(string, *bool) (func(string) string, func(string) bool)
}

func NewSwiftScanner(exec executor.Executor, log *progress.Logger) *SwiftScanner {
	if log == nil {
		log = progress.NewNoop()
	}
	return &SwiftScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

// swiftRoot is one shared SwiftPM cache or the Xcode DerivedData folder.
type swiftRoot struct {
	path, scope string
	derived     bool
}

// swiftState is the context of one workspace-state.json: its scratch
// directory, the package directory whose Packages folder holds edited
// dependencies (only proven for <package>/.build), and its owning project.
type swiftState struct {
	scratch, editRoot           string
	project, tool, scope, owner string
}

type swiftScan struct {
	ctx                  context.Context
	exec                 executor.Executor
	home, identity, goos string
	roots                []string
	guard, libGuard      func(string) string
	libRoots             []string
	volume               func(string) bool
	files                executor.Executor
	config               *configaudit.SwiftConfigSnapshot
	inv                  model.SwiftInventory
	sources              []*model.SwiftSource
	byID                 map[string]*model.SwiftSource
	incomplete           map[string]bool // listing owners whose discovery was cut short
	cacheRoots           []swiftRoot
	rootKeys             map[string]bool
	pruned               map[string]bool
	owners               map[string]string             // pruned path → walk source that reached it
	projects             map[string]model.SwiftProject // by project path key
	seen                 map[string]bool
	remaining            int
	bytes                int
	limited, full        bool // a record was refused for output size or count
}

func emptySwiftInventory() model.SwiftInventory {
	return model.SwiftInventory{SchemaVersion: model.SwiftInventorySchemaVersion, Status: "complete", Reasons: []string{}, Sources: []model.SwiftSource{}, Projects: []model.SwiftProject{}, Packages: []model.SwiftPackage{}}
}

func (s *SwiftScanner) Scan(ctx context.Context, target *user.User, searchDirs []string, includeNetworkVolumes *bool) (*model.SwiftInventory, *model.SwiftConfigAudit) {
	start := time.Now()
	inv := emptySwiftInventory()
	configDetector := configaudit.NewSwiftConfigDetector(s.exec)
	if target == nil || target.Username == "" || target.HomeDir == "" || !filepath.IsAbs(target.HomeDir) || isGoServiceIdentity(s.exec.GOOS(), target) {
		inv.Status, inv.Reasons = "partial", []string{"user_unresolved"}
		audit := configDetector.Detect(ctx, configaudit.SwiftConfigScope{}).Finish()
		return &inv, &audit
	}
	guard, volume := s.protection(target.HomeDir, includeNetworkVolumes)
	// Reserve the audit's separate 256 KiB allowance before collecting inventory.
	c := &swiftScan{ctx: ctx, exec: s.exec, home: filepath.Clean(target.HomeDir), identity: target.Username, goos: s.exec.GOOS(), guard: guard, volume: volume, inv: inv,
		byID: map[string]*model.SwiftSource{}, incomplete: map[string]bool{}, rootKeys: map[string]bool{}, pruned: map[string]bool{}, owners: map[string]string{},
		projects: map[string]model.SwiftProject{}, seen: map[string]bool{}, remaining: maxSwiftRecords, bytes: goJSONSize(&inv) + (256 << 10)}
	c.roots = []string{c.home}
	dirs := []string{}
	for _, dir := range searchDirs {
		if dir == "" {
			continue
		}
		dir = canonicalNoStat(dir, c.home)
		if !filepath.IsAbs(dir) || !composerText(dir, 4096) {
			c.degrade(nil, "path_unresolved")
			continue
		}
		dirs = append(dirs, dir)
		c.roots = append(c.roots, dir)
	}
	// macOS keeps SwiftPM's state under ~/Library, which the walk never
	// enters. Readers rooted at exactly these folders may; nothing else there.
	if c.goos == model.PlatformDarwin {
		lib := filepath.Join(c.home, "Library")
		c.libRoots = []string{filepath.Join(lib, "Caches", "org.swift.swiftpm"), filepath.Join(lib, "org.swift.swiftpm"), filepath.Join(lib, "Developer", "Xcode", "DerivedData")}
	}
	current, err := s.exec.CurrentUser()
	verified := err == nil && current != nil && target.Uid != "" && current.Uid == target.Uid
	c.config = configDetector.Detect(ctx, configaudit.SwiftConfigScope{Username: target.Username, Home: c.home, Roots: c.roots, Protected: guard,
		Library: configaudit.SwiftLibraryGuard(guard, volume, c.libRoots), LibraryRoots: c.libRoots, Volume: volume, ProcessVerified: verified})
	for _, r := range c.config.InventoryReasons {
		c.degrade(nil, r)
	}
	c.guard = c.config.ContentGuard
	c.libGuard = c.config.LibraryGuard
	c.files = s.exec.GuardedFiles(c.roots, c.guard, maxSwiftMetadataBytes)
	// Register every known tool-state location before the walk so it is
	// pruned, not walked: its checkouts hold manifests that are not projects.
	for _, base := range c.config.DotSwiftPM {
		c.pruned[c.key(base)] = true
	}
	switch c.goos {
	case model.PlatformDarwin:
		c.cacheRoot(c.libRoots[0], "user", false, false)
		c.cacheRoot(c.libRoots[2], "user", true, false)
		c.pruned[c.key(c.libRoots[1])] = true
	case model.PlatformLinux:
		c.cacheRoot(filepath.Join(c.home, ".cache", "org.swift.swiftpm"), "user", false, false)
	case model.PlatformWindows:
		c.cacheRoot(filepath.Join(c.home, "AppData", "Local", "Temp", "org.swift.swiftpm"), "user", false, false)
	}
	for _, p := range c.config.CacheLeads {
		c.cacheRoot(p, "custom", false, false)
	}
	for _, base := range c.config.DotSwiftPM {
		c.cacheRoot(filepath.Join(base, "cache"), "user", false, true)
	}
	for _, p := range c.config.ScratchLeads {
		c.pruned[c.key(p)] = true
		if phys, ok := c.resolve(p); ok {
			c.pruned[c.key(phys)] = true
		}
	}
	c.walkRoots(dirs)
	// A build-directory lead is a custom location with no proven project.
	for _, p := range c.config.ScratchLeads {
		c.workspaceState(filepath.Join(p, "workspace-state.json"), false, swiftState{scratch: p, tool: "swiftpm", scope: "custom", owner: c.ownerOf(p)})
	}
	for _, r := range c.cacheRoots {
		if r.derived {
			c.derivedData(r)
		} else {
			c.sharedCache(r)
		}
	}
	if reason := c.stopReason(); reason != "" {
		c.degrade(nil, reason)
	}
	audit := c.config.Finish()
	c.finish()
	s.log.Debug("swift scan: inventory=%s (%d sources, %d projects, %d packages) audit=%s (%d files) in %dms",
		c.inv.Status, len(c.inv.Sources), len(c.inv.Projects), len(c.inv.Packages), audit.Status, len(audit.Files), time.Since(start).Milliseconds())
	return &c.inv, &audit
}

func (c *swiftScan) key(p string) string { return configaudit.GoPathKey(c.goos, p) }
func (c *swiftScan) reason(err error, p string) string {
	return configaudit.CargoReadReason(err, p, c.volume)
}
func (c *swiftScan) degrade(src *model.SwiftSource, reason string) {
	c.inv.Status = "partial"
	if !slices.Contains(c.inv.Reasons, reason) {
		c.inv.Reasons = append(c.inv.Reasons, reason)
	}
	for ; src != nil; src = c.byID[src.ParentSourceID] {
		src.Status = "partial"
		if !slices.Contains(src.Reasons, reason) {
			src.Reasons = append(src.Reasons, reason)
		}
	}
}

// cut records an incomplete listing, so the owner reports no discovery
// coverage and its unseen children are never retired.
func (c *swiftScan) cut(owner *model.SwiftSource, reason string) {
	c.degrade(owner, reason)
	if owner != nil {
		c.incomplete[owner.SourceID] = true
	}
}

// discovery records a cut-short project walk, which also leaves the
// configuration audit without every project it could have observed.
func (c *swiftScan) discovery(src *model.SwiftSource, reason string) {
	c.cut(src, reason)
	c.config.Partial(reason)
}
func (c *swiftScan) charge(src *model.SwiftSource, record any) bool {
	if c.full || c.remaining <= 0 {
		c.full = true
		c.degrade(src, "record_limit")
		return false
	}
	// Reserve later coverage reasons, child IDs and separators per record.
	size := goJSONSize(record) + 128
	if c.limited || c.bytes+size > maxSwiftOutputBytes {
		c.limited = true
		c.degrade(src, "output_size_limit")
		return false
	}
	c.remaining--
	c.bytes += size
	return true
}
func (c *swiftScan) stopReason() string {
	switch {
	case c.ctx.Err() != nil:
		return "deadline_exceeded"
	case c.limited:
		return "output_size_limit"
	case c.full:
		return "record_limit"
	}
	return ""
}
func (c *swiftScan) stopped(src *model.SwiftSource) bool {
	if reason := c.stopReason(); reason != "" {
		c.cut(src, reason)
		return true
	}
	return false
}

// source creates or returns one inventory source. Only sources that own a
// directory listing carry discovered_sources; metadata files never do.
func (c *swiftScan) source(kind, path, parent string) *model.SwiftSource {
	if !filepath.IsAbs(path) || !composerText(path, 4096) {
		c.degrade(c.byID[parent], "path_unresolved")
		return nil
	}
	id := configaudit.GoSourceID(c.identity, kind, path)
	if src := c.byID[id]; src != nil {
		return src
	}
	owner := c.byID[parent]
	if owner == nil {
		parent = ""
	}
	src := &model.SwiftSource{SourceID: id, Kind: kind, Path: path, ParentSourceID: parent, Status: "complete", Presence: "present", Reasons: []string{}}
	switch kind {
	case "project_search_root", "project", "cache_root":
		src.DiscoveredSources = []string{}
	}
	if !c.charge(owner, src) {
		return nil
	}
	c.byID[id] = src
	c.sources = append(c.sources, src)
	return src
}

// libRoot returns the macOS Library root holding path, or "".
func (c *swiftScan) libRoot(path string) string {
	for _, root := range c.libRoots {
		if configaudit.GoWithinRoots(c.goos, path, []string{root}) {
			return root
		}
	}
	return ""
}

func (c *swiftScan) fs(path string, limit int64) executor.Executor {
	if root := c.libRoot(path); root != "" {
		return c.exec.GuardedFiles([]string{root}, c.libGuard, limit)
	}
	if configaudit.GoWithinRoots(c.goos, path, c.roots) {
		return c.exec.GuardedFiles(c.roots, c.guard, limit)
	}
	// Roots outside the search roots permit access below themselves only.
	return c.exec.GuardedFiles([]string{path}, c.guard, limit)
}

// resolve returns path's physical location. A compatibility alias may lead
// into a Library root, but never elsewhere under ~/Library.
func (c *swiftScan) resolve(path string) (string, bool) {
	if c.stopReason() != "" {
		return "", false
	}
	phys, err := c.exec.GuardedFiles(append([]string{path}, c.libRoots...), c.libGuard, 0).EvalSymlinks(path)
	return phys, err == nil
}

// fetch reads one bounded file. absent reports a missing file; reason is
// the coverage reason for any other failure.
func (c *swiftScan) fetch(path string, limit int64) (data []byte, reason string, absent bool) {
	if reason := c.stopReason(); reason != "" {
		return nil, reason, false
	}
	files := c.fs(path, limit)
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "", true
	case err != nil:
		return nil, c.reason(err, path), false
	case !info.Mode().IsRegular():
		return nil, "unsupported_entry", false
	case info.Size() > limit:
		return nil, "size_limit", false
	}
	if reason := c.stopReason(); reason != "" {
		return nil, reason, false
	}
	data, err = files.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "changed_during_scan", false
	case err != nil:
		return nil, c.reason(err, path), false
	}
	return data, "", false
}

// read loads a file a listing named. One that is now missing changed during
// the scan.
func (c *swiftScan) read(src *model.SwiftSource, path string) ([]byte, bool) {
	data, reason, absent := c.fetch(path, maxSwiftMetadataBytes)
	if absent {
		reason = "changed_during_scan"
	}
	if reason != "" {
		c.fail(src, reason)
		return nil, false
	}
	return data, true
}

func (c *swiftScan) fail(src *model.SwiftSource, reason string) {
	if reason != "size_limit" && reason != "unsupported_entry" {
		src.Presence = "unknown"
	}
	c.degrade(src, reason)
}

// list enumerates one directory for its owner and returns the coverage
// reason when the listing is incomplete. A missing directory is complete with
// no children; any other failure or truncation cuts the owner's discovery.
func (c *swiftScan) list(owner *model.SwiftSource, files executor.Executor, dir string, budget *int) ([]fs.DirEntry, string) {
	if c.stopped(owner) {
		return nil, c.stopReason()
	}
	if *budget <= 0 {
		c.cut(owner, "entry_limit")
		return nil, "entry_limit"
	}
	entries, more, err := files.ReadDirLimit(dir, min(*budget, maxSwiftListEntries))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ""
	}
	if err != nil {
		reason := c.reason(err, dir)
		c.cut(owner, reason)
		return nil, reason
	}
	*budget -= len(entries)
	if more {
		c.cut(owner, "entry_limit")
		return entries, "entry_limit"
	}
	return entries, ""
}

func swiftHas(entries []fs.DirEntry, name string, isDir bool) bool {
	return slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name && e.IsDir() == isDir })
}

// cacheRoot registers one cache root once, by physical path, so an alias
// never duplicates its evidence. An alias is reported only when it resolves,
// and then at its target.
func (c *swiftScan) cacheRoot(path, scope string, derived, alias bool) {
	if !filepath.IsAbs(path) || !composerText(path, 4096) {
		c.degrade(nil, "path_unresolved")
		return
	}
	path = filepath.Clean(path)
	phys, resolved := c.resolve(path)
	if !resolved {
		phys = path
	}
	if alias {
		if !resolved {
			return
		}
		// A compatibility link cannot grant access to another user's cache.
		// Keep home relocations and roots independently established above.
		if !configaudit.GoWithinRoots(c.goos, phys, []string{c.home}) && !c.rootKeys[c.key(phys)] {
			c.degrade(nil, "skipped_protected")
			return
		}
		path = phys
	}
	c.pruned[c.key(path)], c.pruned[c.key(phys)] = true, true
	if c.rootKeys[c.key(path)] || c.rootKeys[c.key(phys)] {
		return
	}
	c.rootKeys[c.key(path)], c.rootKeys[c.key(phys)] = true, true
	c.cacheRoots = append(c.cacheRoots, swiftRoot{path, scope, derived})
	// Preserve known roots even when earlier facts fill the budget.
	c.source("cache_root", path, "")
}

func (c *swiftScan) skip(path string) bool {
	path = c.key(path)
	for root := range c.pruned {
		if path == root || goPathWithin(path, root) {
			return true
		}
	}
	return false
}

// adopt remembers the walk source that physically reached a pruned
// location, so its source can be attached after discovery.
func (c *swiftScan) adopt(path string, owner *model.SwiftSource) {
	if owner != nil {
		if _, ok := c.owners[c.key(path)]; !ok {
			c.owners[c.key(path)] = owner.SourceID
		}
	}
}

// ownerOf returns the walk source covering path, or "" when no walk reached it.
func (c *swiftScan) ownerOf(path string) string {
	best, key := "", ""
	for k, id := range c.owners {
		if (c.key(path) == k || goPathWithin(c.key(path), k)) && len(k) > len(key) {
			best, key = id, k
		}
	}
	return best
}
func (c *swiftScan) reasonForGuard(path string) string {
	if c.volume != nil && c.volume(path) {
		return "refused_network_volume"
	}
	return "skipped_protected"
}

func (c *swiftScan) walkRoots(dirs []string) {
	// Outermost logical/physical roots own discovery. Identical physical roots
	// retain the first spelling and never get walked twice.
	type root struct {
		path, phys string
		src        *model.SwiftSource
	}
	roots := []root{}
	seen := map[string]bool{}
	for _, dir := range dirs {
		if seen[c.key(dir)] {
			continue
		}
		seen[c.key(dir)] = true
		src := c.source("project_search_root", dir, "")
		if src == nil {
			c.config.Partial("output_size_limit")
			continue
		}
		if c.stopped(src) {
			src.Presence = "unknown"
			c.config.Partial(c.stopReason())
			continue
		}
		phys, err := c.fs(dir, 0).EvalSymlinks(dir)
		if errors.Is(err, fs.ErrNotExist) {
			src.Presence = "absent"
			continue
		}
		if err != nil {
			src.Presence = "unknown"
			c.discovery(src, c.reason(err, dir))
			continue
		}
		roots = append(roots, root{dir, phys, src})
	}
	for i, r := range roots {
		duplicate := slices.ContainsFunc(roots[:i], func(other root) bool { return c.key(other.phys) == c.key(r.phys) })
		nested := slices.ContainsFunc(roots, func(other root) bool { return goPathWithin(c.key(r.phys), c.key(other.phys)) })
		if duplicate || nested {
			delete(c.byID, r.src.SourceID)
			continue
		}
		c.walk(r.path, r.src)
	}
}

func (c *swiftScan) walk(root string, src *model.SwiftSource) {
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{root, 0}}
	budget := maxSwiftWalkEntries
	for len(queue) > 0 {
		if c.stopped(src) {
			c.config.Partial(c.stopReason())
			return
		}
		d := queue[0]
		queue = queue[1:]
		if c.skip(d.path) {
			c.adopt(d.path, src)
			continue
		}
		entries, more, err := c.files.ReadDirLimit(d.path, min(budget, maxSwiftListEntries))
		if err != nil {
			c.discovery(src, c.reason(err, d.path))
			continue
		}
		// A selected bundle is the project itself; the walk never enters one.
		if ext := filepath.Ext(root); d.depth == 0 && (ext == ".xcodeproj" || ext == ".xcworkspace") && !swiftAuxiliaryWorkspace(root) {
			c.xcode(root, ext == ".xcodeproj", src)
			return
		}
		budget -= len(entries)
		if more {
			c.discovery(src, "entry_limit")
		}
		skip, descend := c.visit(d.path, entries, src, more)
		for _, e := range entries {
			if !descend || !e.IsDir() || skip[e.Name()] {
				continue
			}
			p := filepath.Join(d.path, e.Name())
			if c.skip(p) {
				c.adopt(p, src)
				continue
			}
			switch e.Name() {
			case ".git", ".hg", ".svn", "node_modules", "target", ".rustup", ".cache", "__pycache__", ".bundle", ".m2", ".gradle", ".swiftpm":
				continue
			}
			if c.guard(p) != "" {
				// A policy skip is the same every run, so it hides nothing the
				// walk saw before: coverage is partial but discovery stands.
				reason := c.reasonForGuard(p)
				c.degrade(src, reason)
				c.config.Partial(reason)
				continue
			}
			if d.depth+1 > maxSwiftWalkDepth {
				c.discovery(src, "depth_limit")
				continue
			}
			queue = append(queue, dir{p, d.depth + 1})
		}
		if budget <= 0 {
			if len(queue) > 0 {
				c.discovery(src, "entry_limit")
			}
			return
		}
	}
}

// swiftAuxiliaryWorkspace reports a workspace that belongs to another
// project: one embedded in an Xcode project or generated for a package.
func swiftAuxiliaryWorkspace(path string) bool {
	parent := filepath.Dir(path)
	return filepath.Ext(parent) == ".xcodeproj" || filepath.Base(parent) == "xcode" && filepath.Base(filepath.Dir(parent)) == ".swiftpm"
}

func swiftManifest(name string) bool {
	return name == "Package.swift" || strings.HasPrefix(name, "Package@swift-") && strings.HasSuffix(name, ".swift")
}

// visit recognizes Swift projects and detached scratch state in one
// directory listing. It returns the child folders the walk must not enter,
// and whether it may descend at all.
func (c *swiftScan) visit(dir string, entries []fs.DirEntry, walk *model.SwiftSource, truncated bool) (map[string]bool, bool) {
	pkg := slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return !e.IsDir() && swiftManifest(e.Name()) })
	if !pkg && swiftHas(entries, "workspace-state.json", false) {
		// A custom scratch or cloned-source directory: its checkouts are
		// dependencies, and nothing proves which project it belongs to.
		c.workspaceState(filepath.Join(dir, "workspace-state.json"), true, swiftState{scratch: dir, tool: "unknown", scope: "unknown", owner: walk.SourceID})
		return nil, false
	}
	skip := map[string]bool{}
	for _, e := range entries {
		// The walk never enters a bundle, so an embedded project.xcworkspace
		// is never a second project.
		if ext := filepath.Ext(e.Name()); e.IsDir() && (ext == ".xcodeproj" || ext == ".xcworkspace") {
			skip[e.Name()] = true
			c.xcode(filepath.Join(dir, e.Name()), ext == ".xcodeproj", walk)
		}
	}
	if pkg {
		skip[".build"], skip["Packages"] = true, true
		c.swiftPackage(dir, entries, walk, truncated)
	}
	return skip, true
}

func (c *swiftScan) project(path, tool string, walk *model.SwiftSource) *model.SwiftSource {
	src := c.source("project", path, walk.SourceID)
	if src == nil {
		c.config.Partial(cmp.Or(c.stopReason(), "path_unresolved"))
		return nil
	}
	project := model.SwiftProject{SourceID: src.SourceID, ProjectPath: path, Tool: tool}
	if c.charge(src, project) {
		c.inv.Projects = append(c.inv.Projects, project)
	}
	c.projects[c.key(path)] = project
	return src
}

// configFiles lists one SwiftPM configuration folder pair for its project:
// dir holds the legacy config file and the configuration folder.
func (c *swiftScan) configFiles(src *model.SwiftSource, dir string, entries []fs.DirEntry, budget *int) (configaudit.SwiftProjectFiles, string) {
	files := configaudit.SwiftProjectFiles{}
	if swiftHas(entries, "config", false) {
		files.Legacy = filepath.Join(dir, "config")
	}
	if !swiftHas(entries, "configuration", true) {
		return files, ""
	}
	cfg, reason := c.list(src, c.files, filepath.Join(dir, "configuration"), budget)
	if swiftHas(cfg, "mirrors.json", false) {
		files.Mirrors = filepath.Join(dir, "configuration", "mirrors.json")
	}
	if swiftHas(cfg, "registries.json", false) {
		files.Registries = filepath.Join(dir, "configuration", "registries.json")
	}
	return files, reason
}

// swiftPackage reads an ordinary package directory. Manifests are markers
// only and are never read.
func (c *swiftScan) swiftPackage(dir string, entries []fs.DirEntry, walk *model.SwiftSource, truncated bool) {
	src := c.project(dir, "swiftpm", walk)
	if src == nil {
		return
	}
	if truncated {
		c.cut(src, "entry_limit")
		c.config.Unlisted(dir, "entry_limit")
	}
	for _, e := range entries {
		if !e.IsDir() && swiftManifest(e.Name()) {
			c.source("manifest", filepath.Join(dir, e.Name()), src.SourceID)
		}
	}
	if swiftHas(entries, "Package.resolved", false) {
		c.resolved(src, dir, "swiftpm", filepath.Join(dir, "Package.resolved"))
	}
	if swiftHas(entries, ".build", true) {
		scratch := filepath.Join(dir, ".build")
		c.workspaceState(filepath.Join(scratch, "workspace-state.json"), false, swiftState{scratch: scratch, editRoot: dir, project: dir, tool: "swiftpm", scope: "project", owner: src.SourceID})
	}
	files := configaudit.SwiftProjectFiles{}
	if swiftHas(entries, ".swiftpm", true) {
		budget := maxSwiftListEntries
		local := filepath.Join(dir, ".swiftpm")
		list, reason := c.list(src, c.files, local, &budget)
		var cfgReason string
		files, cfgReason = c.configFiles(src, local, list, &budget)
		if reason = cmp.Or(reason, cfgReason); reason != "" {
			c.config.Unlisted(dir, reason)
		}
	}
	c.config.Project(dir, files)
}

// xcode reads an Xcode project or standalone workspace bundle's shared
// SwiftPM folder. Project files are never interpreted.
func (c *swiftScan) xcode(bundle string, embedded bool, walk *model.SwiftSource) {
	src := c.project(bundle, "xcode", walk)
	if src == nil {
		return
	}
	base := filepath.Join(bundle, "xcshareddata", "swiftpm")
	if embedded {
		base = filepath.Join(bundle, "project.xcworkspace", "xcshareddata", "swiftpm")
	}
	budget := maxSwiftListEntries
	list, reason := c.list(src, c.files, base, &budget)
	if swiftHas(list, "Package.resolved", false) {
		c.resolved(src, bundle, "xcode", filepath.Join(base, "Package.resolved"))
	}
	files, cfgReason := c.configFiles(src, base, list, &budget)
	if reason = cmp.Or(reason, cfgReason); reason != "" {
		c.config.Unlisted(bundle, reason)
	}
	c.config.Project(bundle, files)
}

func (c *swiftScan) pkg(identity, evidence, tool, scope, project string) model.SwiftPackage {
	return model.SwiftPackage{PackageName: identity, Evidence: evidence, Tool: tool, Scope: scope, ProjectPath: project, VersionStatus: "unknown",
		Origin: model.SwiftOrigin{Kind: "unknown"}, RecordedChecksums: []model.SwiftRecordedChecksum{}, Reasons: []string{}}
}

// release sets the recorded release; a branch or revision alone is never a version.
func swiftRelease(p *model.SwiftPackage, version, revision, branch string) {
	p.Version, p.Revision, p.Branch = version, revision, branch
	if version != "" {
		p.VersionStatus = "known"
	}
}

func swiftSetOrigin(p *model.SwiftPackage, kind, location string) {
	origin, reason := swiftOrigin(kind, location)
	p.Origin = origin
	if reason != "" {
		p.Reasons = append(p.Reasons, reason)
	}
}

// swiftOriginal keeps a recorded SCM location a registry mapping replaced,
// only when it sanitizes without loss.
func swiftOriginal(p *model.SwiftPackage, location string) {
	if location == "" {
		return
	}
	if display, literal, ok := configaudit.SwiftURL(location); ok && !literal {
		p.OriginalLocation = display
		return
	}
	p.Reasons = append(p.Reasons, "origin_unresolved")
}

func (c *swiftScan) add(src *model.SwiftSource, p model.SwiftPackage, locator string) {
	p.SourceID, p.SourcePath = src.SourceID, src.Path
	for i := range p.RecordedChecksums {
		h := &p.RecordedChecksums[i]
		h.SourceID, h.SourcePath, h.SourceKind = src.SourceID, src.Path, src.Kind
	}
	slices.Sort(p.Reasons)
	p.Reasons = slices.Compact(p.Reasons)
	key := strings.Join([]string{src.SourceID, p.Evidence, p.ProjectPath, p.PackageName, locator}, "\x00")
	if c.seen[key] {
		return
	}
	if c.charge(src, p) {
		c.seen[key] = true
		c.inv.Packages = append(c.inv.Packages, p)
	}
}

// resolved reads one Package.resolved. Its pins are selections, not proof
// that anything was materialized.
func (c *swiftScan) resolved(project *model.SwiftSource, dir, tool, path string) {
	src := c.source("lockfile", path, project.SourceID)
	if src == nil {
		return
	}
	data, ok := c.read(src, path)
	if !ok {
		return
	}
	pins, reasons, err := parseSwiftResolved(data)
	if errors.Is(err, errSwiftUnsupported) {
		c.degrade(src, "unsupported_format")
		return
	}
	if err != nil {
		c.degrade(src, "parse_error")
		return
	}
	for _, r := range reasons {
		c.degrade(src, r)
	}
	for _, pin := range pins {
		if c.stopped(src) {
			return
		}
		p := c.pkg(pin.identity, "locked_package", tool, "project", dir)
		swiftRelease(&p, pin.version, pin.revision, pin.branch)
		swiftSetOrigin(&p, pin.kind, pin.location)
		swiftOriginal(&p, pin.originalLocation)
		c.add(src, p, "")
	}
}

// workspaceState reads one workspace-state.json. listed reports that a
// directory listing named it; otherwise a missing file is no source.
func (c *swiftScan) workspaceState(path string, listed bool, st swiftState) *model.SwiftSource {
	if !listed && c.stopped(c.byID[st.owner]) {
		return nil
	}
	data, reason, absent := c.fetch(path, maxSwiftMetadataBytes)
	if absent && !listed {
		return nil
	}
	src := c.source("workspace_state", path, st.owner)
	if src == nil {
		return nil
	}
	if absent {
		reason = "changed_during_scan"
	}
	if reason != "" {
		c.fail(src, reason)
		return src
	}
	deps, artifacts, reasons, err := parseSwiftWorkspace(data)
	if errors.Is(err, errSwiftUnsupported) {
		c.degrade(src, "unsupported_format")
		return src
	}
	if err != nil {
		c.degrade(src, "parse_error")
		return src
	}
	for _, r := range reasons {
		c.degrade(src, r)
	}
	origins := make([]model.SwiftOrigin, len(deps))
	for i, d := range deps {
		if c.stopped(src) {
			return src
		}
		p := c.pkg(d.identity, "managed_dependency", st.tool, st.scope, st.project)
		p.ManagedState = d.state
		// Filesystem, edited and custom states do not carry a release.
		if d.state == "checkout" || d.state == "registry" {
			swiftRelease(&p, d.version, d.revision, d.branch)
		}
		p.BasedOn = d.basedOn
		install := c.install(src, &p, d, st)
		if d.state == "registry" {
			c.receipt(src, &p, install)
			swiftOriginal(&p, d.scmURL)
		} else {
			swiftSetOrigin(&p, d.refKind, d.location)
		}
		origins[i] = p.Origin
		c.add(src, p, strings.Join([]string{d.refKind, d.location, d.state, d.subpath}, "\x00"))
	}
	for _, a := range artifacts {
		if c.stopped(src) {
			return src
		}
		// A root package's own binary target has no third-party coordinates.
		if a.refKind == "root" {
			continue
		}
		p := c.pkg(a.identity, "artifact_reference", st.tool, st.scope, st.project)
		p.Artifact = &model.SwiftArtifact{TargetName: a.target, Kind: a.kind}
		if display, literal, ok := configaudit.SwiftURL(a.url); a.url != "" && ok && !literal {
			p.Artifact.URL = display
		}
		if a.checksum != "" {
			if swiftSHA256(a.checksum) {
				p.RecordedChecksums = append(p.RecordedChecksums, model.SwiftRecordedChecksum{Algorithm: "sha256", Value: a.checksum, Verification: "not_verified"})
			} else {
				p.Reasons = append(p.Reasons, "checksum_invalid")
				c.degrade(src, "checksum_invalid")
			}
		}
		// Version and origin join only an unambiguous dependency of the
		// same file; an edited dependency's history never counts.
		match, matches := -1, 0
		for i, d := range deps {
			if d.identity == a.identity && d.refKind == a.refKind && d.location == a.location {
				match, matches = i, matches+1
			}
		}
		if matches == 1 {
			if d := deps[match]; d.state == "checkout" || d.state == "registry" {
				swiftRelease(&p, d.version, d.revision, d.branch)
			}
			p.Origin = origins[match]
		} else {
			swiftSetOrigin(&p, a.refKind, a.location)
		}
		p.Installation = &model.SwiftInstallation{Path: a.path, PathStatus: "resolved", Presence: c.presence(a.path)}
		c.add(src, p, strings.Join([]string{a.refKind, a.location, a.target, a.path}, "\x00"))
	}
	return src
}

func swiftSHA256(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

// install resolves a managed dependency's physical path from its state.
func (c *swiftScan) install(src *model.SwiftSource, p *model.SwiftPackage, d swiftDependency, st swiftState) string {
	under := func(base string, rel ...string) string {
		parts, ok := swiftSubpath(d.subpath)
		if !ok {
			p.Reasons = append(p.Reasons, "path_unresolved")
			c.degrade(src, "path_unresolved")
			return ""
		}
		return filepath.Join(append(append([]string{base}, rel...), parts...)...)
	}
	path := d.path
	switch d.state {
	case "checkout":
		path = under(st.scratch, "checkouts")
	case "registry":
		path = under(st.scratch, "registry", "downloads")
	case "edited":
		// Packages is proven only beside an ordinary package's own .build.
		if path == "" && st.editRoot != "" {
			path = under(st.editRoot, "Packages")
		}
	}
	if path == "" || !composerText(path, 4096) {
		p.Installation = &model.SwiftInstallation{PathStatus: "unresolved", Presence: "unknown"}
		return ""
	}
	p.Installation = &model.SwiftInstallation{Path: path, PathStatus: "resolved", Presence: c.presence(path)}
	return path
}

func (c *swiftScan) presence(path string) string {
	if c.stopReason() != "" {
		return "unknown"
	}
	_, err := c.fs(path, 0).Stat(path)
	switch {
	case err == nil:
		return "present"
	case errors.Is(err, fs.ErrNotExist):
		return "absent"
	}
	return "unknown"
}

// receipt enriches a registry download's origin from its .registry-metadata.
// A missing receipt leaves the origin unknown; author and signature fields
// are never read.
func (c *swiftScan) receipt(src *model.SwiftSource, p *model.SwiftPackage, install string) {
	if install == "" {
		return
	}
	data, reason, absent := c.fetch(filepath.Join(install, ".registry-metadata"), maxSwiftMetadataBytes)
	if absent {
		return
	}
	if reason != "" {
		c.degrade(src, reason)
		return
	}
	registry, err := parseSwiftReceipt(data)
	if err != nil {
		c.degrade(src, "parse_error")
		return
	}
	if origin, ok := swiftRegistryOrigin(registry); ok {
		p.Origin = origin
	} else {
		p.Reasons = append(p.Reasons, "origin_unresolved")
	}
}

// swiftRegistryOrigin accepts only an HTTP(S) registry endpoint without a
// literal credential.
func swiftRegistryOrigin(raw string) (model.SwiftOrigin, bool) {
	display, literal, ok := configaudit.SwiftURL(raw)
	if !ok || literal || !strings.HasPrefix(display, "https://") && !strings.HasPrefix(display, "http://") {
		return model.SwiftOrigin{Kind: "unknown"}, false
	}
	return model.SwiftOrigin{Kind: "registry", URL: display}, true
}

// rootSource creates a cache root's source under the walk source that
// reached it. A missing root is recorded absent so its former facts retire.
func (c *swiftScan) rootSource(r swiftRoot, budget *int) (*model.SwiftSource, executor.Executor, []fs.DirEntry) {
	src := c.source("cache_root", r.path, c.ownerOf(r.path))
	if src == nil {
		return nil, nil, nil
	}
	if src.ParentSourceID == "" {
		src.ParentSourceID = c.ownerOf(r.path)
	}
	if c.stopped(src) {
		src.Presence = "unknown"
		return nil, nil, nil
	}
	files := c.fs(r.path, maxSwiftMetadataBytes)
	entries, more, err := files.ReadDirLimit(r.path, min(*budget, maxSwiftListEntries))
	if errors.Is(err, fs.ErrNotExist) {
		src.Presence = "absent"
		return nil, nil, nil
	}
	if err != nil {
		src.Presence = "unknown"
		c.cut(src, c.reason(err, r.path))
		return nil, nil, nil
	}
	*budget -= len(entries)
	if more {
		c.cut(src, "entry_limit")
	}
	return src, files, entries
}

// sharedCache enumerates a shared cache's bare repositories and released
// registry download layout. Artifacts, manifests and prebuilts are opaque.
func (c *swiftScan) sharedCache(r swiftRoot) {
	budget := maxSwiftWalkEntries
	src, files, entries := c.rootSource(r, &budget)
	if src == nil {
		return
	}
	if swiftHas(entries, "repositories", true) {
		c.repositories(src, files, r, filepath.Join(r.path, "repositories"), &budget)
	}
	if swiftHas(entries, "registry", true) {
		registry, _ := c.list(src, files, filepath.Join(r.path, "registry"), &budget)
		if swiftHas(registry, "downloads", true) {
			c.downloads(src, files, r, filepath.Join(r.path, "registry", "downloads"), &budget)
		}
	}
}

// repositories reads each bare repository's literal origin. Identity comes
// from that origin, never from the hashed folder name.
func (c *swiftScan) repositories(root *model.SwiftSource, files executor.Executor, r swiftRoot, dir string, budget *int) {
	entries, _ := c.list(root, files, dir, budget)
	for _, e := range entries {
		if !e.IsDir() || c.stopped(root) {
			continue
		}
		repo := filepath.Join(dir, e.Name())
		children, reason := c.list(root, files, repo, budget)
		if reason != "" {
			continue
		}
		if !swiftHas(children, "config", false) || !swiftHas(children, "HEAD", false) || !swiftHas(children, "objects", true) || !swiftHas(children, "refs", true) {
			continue // not a repository SwiftPM created
		}
		data, reason, absent := c.fetch(filepath.Join(repo, "config"), maxSwiftGitConfigBytes)
		if absent {
			reason = "changed_during_scan"
		}
		if reason != "" {
			c.degrade(root, reason)
			continue
		}
		bare, location, ok := parseSwiftGitConfig(data)
		if !ok || !bare || location == "" {
			c.degrade(root, "origin_unresolved")
			continue
		}
		origin, why := swiftOrigin("remoteSourceControl", location)
		identity, valid := swiftIdentityFromLocation(location)
		if why != "" || !valid {
			c.degrade(root, "origin_unresolved")
			continue
		}
		src := c.source("cached_repository", repo, root.SourceID)
		if src == nil {
			return
		}
		p := c.pkg(identity, "cached_repository", "unknown", r.scope, "")
		p.Origin = origin
		c.add(src, p, repo)
	}
}

// downloads accepts scope/name/version with an optional registry storage key.
// Only the receipt establishes the registry origin, never the directory key.
func (c *swiftScan) downloads(root *model.SwiftSource, files executor.Executor, r swiftRoot, dir string, budget *int) {
	level := func(parent string, valid func(string) bool) []string {
		entries, _ := c.list(root, files, parent, budget)
		out := []string{}
		for _, e := range entries {
			switch {
			case !e.IsDir():
			case !valid(e.Name()):
				c.degrade(root, "unsupported_layout")
			default:
				out = append(out, e.Name())
			}
		}
		return out
	}
	storageKey := func(key string) bool {
		if i := strings.LastIndexByte(key, '-'); i >= 0 {
			if i == 0 || i > 32 || key[:i] != strings.ToLower(key[:i]) {
				return false
			}
			key = key[i+1:]
		}
		return cargoIsHex(key, 8)
	}
	for _, first := range level(dir, func(s string) bool { return configaudit.SwiftRegistryScope(s) || storageKey(s) }) {
		for _, second := range level(filepath.Join(dir, first), configaudit.SwiftRegistryName) {
			modern := storageKey(first) && configaudit.SwiftRegistryScope(second)
			for _, third := range level(filepath.Join(dir, first, second), func(s string) bool {
				return configaudit.SwiftRegistryScope(first) && swiftVersion(s) || modern && configaudit.SwiftRegistryName(s)
			}) {
				if c.stopped(root) {
					return
				}
				path := filepath.Join(dir, first, second, third)
				if swiftVersion(third) {
					c.download(root, files, r, path, first+"."+second, third)
					continue
				}
				for _, version := range level(path, swiftVersion) {
					if c.stopped(root) {
						return
					}
					c.download(root, files, r, filepath.Join(path, version), second+"."+third, version)
				}
			}
		}
	}
}

func (c *swiftScan) download(root *model.SwiftSource, files executor.Executor, r swiftRoot, dir, identity, version string) {
	// The manifest marker is stat-only; it is never read or evaluated.
	info, err := files.Stat(filepath.Join(dir, "Package.swift"))
	switch {
	case errors.Is(err, fs.ErrNotExist), err == nil && !info.Mode().IsRegular():
		c.degrade(root, "unsupported_layout")
		return
	case err != nil:
		c.degrade(root, c.reason(err, dir))
		return
	}
	path := filepath.Join(dir, ".registry-metadata")
	data, reason, absent := c.fetch(path, maxSwiftMetadataBytes)
	if absent {
		reason = "unsupported_layout"
	}
	if reason != "" {
		c.degrade(root, reason)
		return
	}
	registry, err := parseSwiftReceipt(data)
	if err != nil {
		c.degrade(root, "parse_error")
		return
	}
	src := c.source("cached_registry_package", path, root.SourceID)
	if src == nil {
		return
	}
	p := c.pkg(strings.ToLower(identity), "cached_registry_package", "unknown", r.scope, "")
	swiftRelease(&p, version, "", "")
	if origin, ok := swiftRegistryOrigin(registry); ok {
		p.Origin = origin
	} else {
		p.Reasons = append(p.Reasons, "origin_unresolved")
	}
	c.add(src, p, dir)
}

// derivedData reads each DerivedData folder's SourcePackages state. Only
// info.plist and SourcePackages/workspace-state.json are touched; build
// products, logs and indexes never are.
func (c *swiftScan) derivedData(r swiftRoot) {
	budget := maxSwiftWalkEntries
	src, _, entries := c.rootSource(r, &budget)
	if src == nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if c.stopped(src) {
			return
		}
		dir := filepath.Join(r.path, e.Name())
		scratch := filepath.Join(dir, "SourcePackages")
		state := filepath.Join(scratch, "workspace-state.json")
		if _, err := c.fs(state, 0).Stat(state); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		st := swiftState{scratch: scratch, tool: "xcode", scope: "user", owner: src.SourceID}
		// The plist may be absent until a build; ownership then stays unknown.
		data, plistReason, absent := c.fetch(filepath.Join(dir, "info.plist"), maxSwiftPlistBytes)
		if !absent && plistReason == "" {
			if workspace, err := parseSwiftInfoPlist(data); err != nil {
				plistReason = "parse_error"
			} else if project, ok := c.projects[c.key(workspace)]; ok && workspace != "" {
				st.project, st.tool, st.scope = project.ProjectPath, project.Tool, "project"
			}
		}
		if ws := c.workspaceState(state, false, st); ws != nil && plistReason != "" {
			c.degrade(ws, plistReason)
		}
	}
}

func (c *swiftScan) finish() {
	for _, src := range c.sources {
		if c.byID[src.SourceID] == nil {
			continue
		}
		if parent := c.byID[src.ParentSourceID]; parent != nil {
			parent.DiscoveredSources = append(parent.DiscoveredSources, src.SourceID)
		} else {
			src.ParentSourceID = ""
		}
	}
	for _, src := range c.sources {
		if c.byID[src.SourceID] == nil {
			continue
		}
		slices.Sort(src.Reasons)
		slices.Sort(src.DiscoveredSources)
		src.DiscoveredSources = slices.Compact(src.DiscoveredSources)
		// Only a completed listing of a present directory proves its children.
		if c.incomplete[src.SourceID] || src.Presence != "present" {
			src.DiscoveredSources = nil
		}
		c.inv.Sources = append(c.inv.Sources, *src)
	}
	slices.SortFunc(c.inv.Sources, func(a, b model.SwiftSource) int {
		return strings.Compare(a.Path+"\x00"+a.Kind, b.Path+"\x00"+b.Kind)
	})
	slices.SortFunc(c.inv.Projects, func(a, b model.SwiftProject) int { return strings.Compare(a.ProjectPath, b.ProjectPath) })
	locator := func(p model.SwiftPackage) string {
		s := ""
		if p.Artifact != nil {
			s = p.Artifact.TargetName
		}
		if p.Installation != nil {
			s += "\x00" + p.Installation.Path
		}
		return s
	}
	slices.SortStableFunc(c.inv.Packages, func(a, b model.SwiftPackage) int {
		return cmp.Or(strings.Compare(a.SourcePath, b.SourcePath), strings.Compare(a.Evidence, b.Evidence), strings.Compare(a.PackageName, b.PackageName),
			strings.Compare(a.Version, b.Version), strings.Compare(locator(a), locator(b)))
	})
	slices.Sort(c.inv.Reasons)
}
