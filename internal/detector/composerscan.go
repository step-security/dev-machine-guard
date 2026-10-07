package detector

import (
	"cmp"
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

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

var (
	maxComposerWalkEntries = 100_000
	maxComposerWalkDepth   = 128
	maxComposerRecords     = 50_000
	maxComposerOutputBytes = 16 << 20
)

// ComposerScanner reads metadata only. The raw executor is required because a
// UserAwareExecutor may source a login shell when reading environment values.
type ComposerScanner struct {
	exec       executor.Executor
	log        *progress.Logger
	protection func(string, *bool) (func(string) string, func(string) bool)
}

func NewComposerScanner(exec executor.Executor, log *progress.Logger) *ComposerScanner {
	if log == nil {
		log = progress.NewNoop()
	}
	return &ComposerScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

type composerProjectState struct {
	src      *model.ComposerSource
	manifest *composerManifest
	project  model.ComposerProject
	vendor   string
}
type composerScan struct {
	ctx                  context.Context
	exec                 executor.Executor
	home, identity, goos string
	roots                []string
	guard                func(string) string
	volume               func(string) bool
	files                executor.Executor
	config               *configaudit.ComposerConfigSnapshot
	inv                  model.ComposerInventory
	sources              []*model.ComposerSource
	byID                 map[string]*model.ComposerSource
	manifests            map[string]*composerProjectState
	receipts             map[string]string
	vendors              map[string]bool
	caches               map[string]bool
	remaining            int
}

func emptyComposerInventory() model.ComposerInventory {
	return model.ComposerInventory{SchemaVersion: model.ComposerInventorySchemaVersion, Status: "complete", Reasons: []string{}, Sources: []model.ComposerSource{}, Projects: []model.ComposerProject{}, Packages: []model.ComposerPackage{}}
}

func (s *ComposerScanner) Scan(ctx context.Context, target *user.User, searchDirs []string, includeNetworkVolumes *bool) (*model.ComposerInventory, *model.ComposerConfigAudit) {
	start := time.Now()
	inv := emptyComposerInventory()
	configDetector := configaudit.NewComposerConfigDetector(s.exec)
	if target == nil || target.Username == "" || target.HomeDir == "" || !filepath.IsAbs(target.HomeDir) || isGoServiceIdentity(s.exec.GOOS(), target) {
		inv.Status, inv.Reasons = "partial", []string{"user_unresolved"}
		audit := configDetector.Detect(ctx, configaudit.ComposerConfigScope{}).Finish()
		return &inv, &audit
	}
	guard, volume := s.protection(target.HomeDir, includeNetworkVolumes)
	c := &composerScan{ctx: ctx, exec: s.exec, home: filepath.Clean(target.HomeDir), identity: target.Username, goos: s.exec.GOOS(), guard: guard, volume: volume, inv: inv,
		byID: map[string]*model.ComposerSource{}, manifests: map[string]*composerProjectState{}, receipts: map[string]string{}, vendors: map[string]bool{}, caches: map[string]bool{}, remaining: maxComposerRecords}
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
	c.files = s.exec.GuardedFiles(c.roots, guard, maxComposerMetadataBytes)
	current, err := s.exec.CurrentUser()
	verified := err == nil && current != nil && target.Uid != "" && current.Uid == target.Uid
	c.config = configDetector.Detect(ctx, configaudit.ComposerConfigScope{Username: target.Username, Home: c.home, Protected: guard, Volume: volume, ProcessVerified: verified})
	// Conventional caches never become projects, including inactive homes.
	for _, p := range []string{filepath.Join(c.home, ".cache", "composer"), filepath.Join(c.home, "Library", "Caches", "composer"), filepath.Join(c.home, "AppData", "Local", "Composer")} {
		c.caches[c.key(p)] = true
	}
	for _, path := range c.config.Caches {
		c.caches[c.key(path)] = true
	}
	for _, home := range c.config.Homes {
		c.caches[c.key(filepath.Join(home, "cache"))] = true
		src := c.source("composer_home", home, "")
		if src == nil {
			continue
		}
		if c.stopped(src) {
			src.Presence = "unknown"
			continue
		}
		info, err := c.fs(home, 0).Stat(home)
		if errors.Is(err, fs.ErrNotExist) {
			src.Presence = "absent"
			continue
		}
		if err != nil {
			src.Presence = "unknown"
			c.degrade(src, c.reason(err, home))
			continue
		}
		if !info.IsDir() {
			c.degrade(src, "unsupported_entry")
			continue
		}
		c.manifest(filepath.Join(home, "composer.json"), src.SourceID, "global", home, true)
		// A global receipt also survives deletion of its root manifest.
		if c.manifests[c.key(filepath.Join(home, "composer.json"))] == nil || c.manifests[c.key(filepath.Join(home, "composer.json"))].manifest == nil {
			c.receipt(filepath.Join(home, "vendor", "composer", "installed.json"), src.SourceID)
		}
	}
	if c.config.AlternateManifest != "" {
		c.manifest(c.config.AlternateManifest, "", "project", "", true)
	}
	c.walkRoots(dirs)
	c.emit()
	keep := map[string]bool{}
	for _, m := range c.manifests {
		if !c.skip(filepath.Dir(m.src.Path)) {
			keep[c.key(m.src.Path)] = true
		}
	}
	c.config.KeepProjects(keep)
	audit := c.config.Finish()
	c.finish()
	if goJSONSize(&c.inv)+goJSONSize(&audit) > maxComposerOutputBytes {
		c.inv = emptyComposerInventory()
		c.degrade(nil, "output_size_limit")
	}
	s.log.Debug("composer scan: inventory=%s (%d sources, %d projects, %d packages) audit=%s (%d files, %d findings) in %dms",
		c.inv.Status, len(c.inv.Sources), len(c.inv.Projects), len(c.inv.Packages), audit.Status, len(audit.Files), len(audit.Findings), time.Since(start).Milliseconds())
	return &c.inv, &audit
}
func (c *composerScan) key(p string) string { return configaudit.GoPathKey(c.goos, p) }
func (c *composerScan) reason(err error, p string) string {
	return configaudit.CargoReadReason(err, p, c.volume)
}
func (c *composerScan) degrade(src *model.ComposerSource, reason string) {
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
func (c *composerScan) charge(src *model.ComposerSource) bool {
	if c.remaining <= 0 {
		c.degrade(src, "record_limit")
		return false
	}
	c.remaining--
	return true
}
func (c *composerScan) stopped(src *model.ComposerSource) bool {
	if c.ctx.Err() != nil {
		c.degrade(src, "deadline_exceeded")
		return true
	}
	if c.remaining <= 0 {
		c.degrade(src, "record_limit")
		return true
	}
	return false
}
func (c *composerScan) source(kind, path, parent string) *model.ComposerSource {
	if !filepath.IsAbs(path) || !composerText(path, 4096) {
		c.degrade(c.byID[parent], "path_unresolved")
		return nil
	}
	id := configaudit.GoSourceID(c.identity, kind, path)
	if src := c.byID[id]; src != nil {
		return src
	}
	owner := c.byID[parent]
	if !c.charge(owner) {
		return nil
	}
	if owner == nil {
		parent = ""
	}
	src := &model.ComposerSource{SourceID: id, Kind: kind, Path: path, ParentSourceID: parent, Status: "complete", Presence: "present", Reasons: []string{}, DiscoveredSources: []string{}}
	c.byID[id] = src
	c.sources = append(c.sources, src)
	return src
}
func (c *composerScan) fs(path string, limit int64) executor.Executor {
	if configaudit.GoWithinRoots(c.goos, path, c.roots) {
		return c.exec.GuardedFiles(c.roots, c.guard, limit)
	}
	// An exact metadata reference permits only targeted access, never a new walk.
	return c.exec.GuardedFiles([]string{path}, c.guard, limit)
}
func (c *composerScan) read(src *model.ComposerSource, targeted bool) ([]byte, bool) {
	if c.stopped(src) {
		src.Presence = "unknown"
		return nil, false
	}
	files := c.fs(src.Path, maxComposerMetadataBytes)
	info, err := files.Stat(src.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		src.Presence = "absent"
		if !targeted {
			src.Presence = "unknown"
			c.degrade(src, "changed_during_scan")
		}
		return nil, false
	case err != nil:
		src.Presence = "unknown"
		c.degrade(src, c.reason(err, src.Path))
		return nil, false
	case !info.Mode().IsRegular():
		c.degrade(src, "unsupported_entry")
		return nil, false
	case info.Size() > maxComposerMetadataBytes:
		c.degrade(src, "size_limit")
		return nil, false
	}
	data, err := files.ReadFile(src.Path)
	if err != nil {
		src.Presence = "unknown"
		reason := c.reason(err, src.Path)
		if errors.Is(err, fs.ErrNotExist) {
			reason = "changed_during_scan"
		}
		c.degrade(src, reason)
		return nil, false
	}
	return data, true
}
func (c *composerScan) receipt(path, parent string) {
	key := c.key(path)
	if _, ok := c.receipts[key]; ok {
		return
	}
	if c.source("installed_metadata", path, parent) == nil {
		return
	}
	c.receipts[key] = path
	c.vendors[c.key(filepath.Dir(filepath.Dir(path)))] = true
}
func (c *composerScan) manifest(path, parent, scope, home string, targeted bool) {
	key := c.key(path)
	if c.manifests[key] != nil || c.inVendor(filepath.Dir(path)) {
		return
	}
	src := c.source("manifest", path, parent)
	if src == nil {
		return
	}
	m := &composerProjectState{src: src, project: model.ComposerProject{
		ManifestSourceID: src.SourceID, ManifestPath: path, ProjectPath: filepath.Dir(path),
		Scope: scope, SelectionStatus: "partial", LockfilePath: composerLockPath(path),
	}}
	c.manifests[key] = m
	data, ok := c.read(src, targeted)
	status := "present"
	if !ok {
		status = "unreadable"
		if src.Presence == "absent" {
			status = "absent"
		}
		if slices.Contains(src.Reasons, "skipped_protected") || slices.Contains(src.Reasons, "refused_network_volume") {
			status = "skipped_protected"
		}
	} else {
		var err error
		m.manifest, err = parseComposerManifest(data)
		if err != nil {
			c.degrade(src, "parse_error")
			status = "invalid"
		} else if m.manifest.partial {
			c.degrade(src, "parse_error")
		}
	}
	if c.stopped(src) {
		return
	}
	paths := c.config.Project(path, data, status, src.Reasons, home)
	if paths.Partial {
		c.degrade(c.byID[parent], "path_unresolved")
	}
	m.vendor = paths.Vendor
	if paths.Cache != "" {
		c.caches[c.key(paths.Cache)] = true
	}
	if m.vendor == "" {
		m.vendor = filepath.Join(filepath.Dir(path), "vendor")
	}
	c.receipt(filepath.Join(m.vendor, "composer", "installed.json"), parent)
	m.project.VendorPath, m.project.SelectionStatus = paths.Vendor, "observed"
	if paths.Partial {
		m.project.SelectionStatus = "partial"
	}
	if m.manifest != nil {
		m.project.PackageName, m.project.PackageVersion = m.manifest.name, m.manifest.version
	}
}
func (c *composerScan) inVendor(path string) bool {
	path = c.key(path)
	for vendor := range c.vendors {
		if path == vendor || goPathWithin(path, vendor) {
			return true
		}
	}
	return false
}
func (c *composerScan) skip(path string) bool {
	if c.inVendor(path) {
		return true
	}
	return c.inCache(path)
}
func (c *composerScan) inCache(path string) bool {
	path = c.key(path)
	for root := range c.caches {
		if path == root || goPathWithin(path, root) {
			return true
		}
	}
	return false
}
func (c *composerScan) walkRoots(dirs []string) {
	// Outermost logical/physical roots own discovery. Identical physical roots
	// retain the first spelling, like Cargo, and never get walked twice.
	type root struct {
		path, phys string
		src        *model.ComposerSource
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
			continue
		}
		if c.stopped(src) {
			src.Presence = "unknown"
			continue
		}
		phys, err := c.fs(dir, 0).EvalSymlinks(dir)
		if errors.Is(err, fs.ErrNotExist) {
			src.Presence = "absent"
			continue
		}
		if err != nil {
			src.Presence = "unknown"
			c.degrade(src, c.reason(err, dir))
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
func (c *composerScan) walk(root string, src *model.ComposerSource) {
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{root, 0}}
	budget := maxComposerWalkEntries
	for len(queue) > 0 {
		if c.stopped(src) {
			return
		}
		d := queue[0]
		queue = queue[1:]
		if c.skip(d.path) {
			continue
		}
		entries, more, err := c.files.ReadDirLimit(d.path, budget)
		if err != nil {
			c.degrade(src, c.reason(err, d.path))
			continue
		}
		budget -= len(entries)
		has := func(name string) bool {
			return slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name })
		}
		// A receipt identifies a vendor tree even with an unconventional directory
		// name. Probe before descending or treating package manifests as projects.
		if has("composer") {
			for _, name := range []string{"installed.json", "installed.php"} {
				p := filepath.Join(d.path, "composer", name)
				info, err := c.fs(p, 0).Stat(p)
				if err == nil && info.Mode().IsRegular() {
					c.receipt(filepath.Join(d.path, "composer", "installed.json"), src.SourceID)
					break
				}
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					c.degrade(src, c.reason(err, p))
				}
			}
			if c.inVendor(d.path) {
				continue
			}
		}
		if has("composer.json") {
			c.manifest(filepath.Join(d.path, "composer.json"), src.SourceID, "project", "", false)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(d.path, e.Name())
			switch e.Name() {
			case ".git", ".hg", ".svn", "node_modules", "target", ".rustup", ".cache", "__pycache__":
				continue
			}
			if c.skip(p) {
				continue
			}
			if c.guard(p) != "" {
				c.degrade(src, c.reasonForGuard(p))
				continue
			}
			if d.depth+1 > maxComposerWalkDepth {
				c.degrade(src, "depth_limit")
				continue
			}
			queue = append(queue, dir{p, d.depth + 1})
		}
		if more {
			c.degrade(src, "entry_limit")
			return
		}
	}
}
func (c *composerScan) reasonForGuard(path string) string {
	if c.volume != nil && c.volume(path) {
		return "refused_network_volume"
	}
	return "skipped_protected"
}
func (c *composerScan) emit() {
	manifests := make([]*composerProjectState, 0, len(c.manifests))
	for _, m := range c.manifests {
		manifests = append(manifests, m)
	}
	slices.SortFunc(manifests, func(a, b *composerProjectState) int { return strings.Compare(a.src.Path, b.src.Path) })
	for _, m := range manifests {
		if c.skip(filepath.Dir(m.src.Path)) {
			delete(c.byID, m.src.SourceID)
			continue
		}
		if c.stopped(m.src) {
			continue
		}
		if m.manifest != nil {
			if !c.charge(m.src) {
				continue
			}
			c.inv.Projects = append(c.inv.Projects, m.project)
			for _, p := range m.manifest.packages {
				c.add(m.src, p, "declared_requirement", m.project.ProjectPath, m.project.Scope)
			}
		}
		// The filename establishes the adjacent lock path even when the
		// manifest cannot be read or parsed. Its evidence is independent.
		lock := c.source("lockfile", m.project.LockfilePath, m.src.SourceID)
		if lock != nil {
			c.packages(lock, false, m.project.ProjectPath, m.project.Scope)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(c.receipts)) {
		path := c.receipts[key]
		vendorPath := filepath.Dir(filepath.Dir(path))
		// A later project can identify an earlier candidate as a dependency
		// tree or cache. Its nested receipts are not another installation.
		if c.inVendor(filepath.Dir(vendorPath)) || c.inCache(vendorPath) {
			delete(c.byID, configaudit.GoSourceID(c.identity, "installed_metadata", path))
			continue
		}
		src := c.byID[configaudit.GoSourceID(c.identity, "installed_metadata", path)]
		if src == nil {
			continue
		}
		project, scope := "", "unknown"
		vendor := c.key(vendorPath)
		for _, m := range manifests {
			if m.manifest != nil && !c.inVendor(m.project.ProjectPath) && c.key(m.vendor) == vendor {
				if project != "" && project != m.project.ProjectPath {
					project, scope = "", "unknown"
					break
				}
				project, scope = m.project.ProjectPath, m.project.Scope
			}
		}
		c.packages(src, true, project, scope)
	}
}
func (c *composerScan) packages(src *model.ComposerSource, installed bool, project, scope string) {
	data, ok := c.read(src, true)
	if !ok {
		if installed && src.Presence == "absent" && src.Status == "complete" {
			php := filepath.Join(filepath.Dir(src.Path), "installed.php")
			_, err := c.fs(php, 0).Stat(php)
			if err == nil {
				c.degrade(src, "unsupported_format")
			} else if !errors.Is(err, fs.ErrNotExist) {
				src.Presence = "unknown"
				c.degrade(src, c.reason(err, php))
			}
		}
		return
	}
	entries, partial, err := parseComposerPackages(data, installed)
	if err != nil {
		reason := "parse_error"
		if errors.Is(err, errComposerUnsupportedFormat) {
			reason = "unsupported_format"
		}
		c.degrade(src, reason)
		return
	}
	if partial {
		c.degrade(src, "parse_error")
	}
	evidence := "locked_package"
	if installed {
		evidence = "installed_package"
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if c.stopped(src) {
			return
		}
		p := e.pkg
		p.Origin = c.origin(&p, project)
		if installed {
			p.Installation = c.installation(src.Path, e, &p)
		}
		key := composerPackageKey(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		c.add(src, p, evidence, project, scope)
	}
}
func composerPackageKey(p model.ComposerPackage) string { b, _ := json.Marshal(p); return string(b) }
func (c *composerScan) add(src *model.ComposerSource, p model.ComposerPackage, evidence, project, scope string) {
	if !c.charge(src) {
		return
	}
	p.SourceID, p.SourcePath, p.Evidence, p.ProjectPath, p.Scope = src.SourceID, src.Path, evidence, project, scope
	for i := range p.RecordedChecksums {
		h := &p.RecordedChecksums[i]
		h.SourceID, h.SourcePath, h.SourceKind = src.SourceID, src.Path, src.Kind
	}
	slices.Sort(p.Reasons)
	p.Reasons = slices.Compact(p.Reasons)
	c.inv.Packages = append(c.inv.Packages, p)
}
func (c *composerScan) origin(p *model.ComposerPackage, project string) model.ComposerOrigin {
	for _, d := range []struct {
		kind  string
		value *model.ComposerDescriptor
	}{{"source", p.Source}, {"dist", p.Dist}} {
		if d.value == nil {
			continue
		}
		value := d.value
		if value.URL == "[redacted]" || value.URL == "" {
			continue
		}
		if path, local := composerLocalURL(value.URL, value.Type); local {
			if !filepath.IsAbs(path) {
				if project == "" {
					p.Reasons = append(p.Reasons, "origin_unresolved")
					return model.ComposerOrigin{Kind: "unknown"}
				}
				path = project + string(filepath.Separator) + filepath.FromSlash(path)
			}
			if !composerText(path, 4096) {
				p.Reasons = append(p.Reasons, "path_unresolved")
				return model.ComposerOrigin{Kind: "unknown"}
			}
			resolved, err := c.fs(path, 0).EvalSymlinks(path)
			if err != nil {
				p.Reasons = append(p.Reasons, "origin_unresolved")
				return model.ComposerOrigin{Kind: "unknown"}
			}
			return model.ComposerOrigin{Kind: "local", Type: value.Type, Path: resolved}
		}
		return model.ComposerOrigin{Kind: d.kind, Type: value.Type, URL: value.URL}
	}
	return model.ComposerOrigin{Kind: "unknown"}
}
func (c *composerScan) installation(receipt string, e composerEntry, p *model.ComposerPackage) *model.ComposerInstallation {
	out := &model.ComposerInstallation{PathStatus: "unresolved", Presence: "unknown"}
	if e.pkg.PackageType == "metapackage" && e.installPath == "" {
		out.PathStatus, out.Presence = "not_applicable", "not_applicable"
		return out
	}
	path := e.installPath
	if path != "" {
		out.PathStatus = "resolved"
		if !filepath.IsAbs(path) {
			path = filepath.Dir(receipt) + string(filepath.Separator) + filepath.FromSlash(path)
		}
	} else if !e.pathProvided && (e.pkg.PackageType == "" || e.pkg.PackageType == "library") {
		base := filepath.Join(filepath.Dir(filepath.Dir(receipt)), filepath.FromSlash(e.pkg.PackageName))
		path = base
		if e.targetDir != "" {
			path = filepath.Join(base, filepath.FromSlash(e.targetDir))
			if filepath.IsAbs(e.targetDir) || !configaudit.GoWithinRoots(c.goos, path, []string{base}) {
				p.Reasons = append(p.Reasons, "path_unresolved")
				return out
			}
		}
		out.PathStatus = "inferred"
	} else {
		p.Reasons = append(p.Reasons, "path_unresolved")
		return out
	}
	if !composerText(path, 4096) {
		out.PathStatus = "unresolved"
		p.Reasons = append(p.Reasons, "path_unresolved")
		return out
	}
	out.Path = filepath.Clean(path)
	info, err := c.fs(path, 0).Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		out.Presence = "absent"
	case err != nil:
		p.Reasons = append(p.Reasons, c.reason(err, path))
	case !info.IsDir():
		p.Reasons = append(p.Reasons, "unsupported_entry")
	default:
		out.Presence = "present"
	}
	return out
}
func (c *composerScan) finish() {
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
		c.inv.Sources = append(c.inv.Sources, *src)
	}
	slices.SortFunc(c.inv.Sources, func(a, b model.ComposerSource) int {
		return strings.Compare(a.Path+"\x00"+a.Kind, b.Path+"\x00"+b.Kind)
	})
	slices.SortFunc(c.inv.Projects, func(a, b model.ComposerProject) int { return strings.Compare(a.ManifestPath, b.ManifestPath) })
	slices.SortStableFunc(c.inv.Packages, func(a, b model.ComposerPackage) int {
		return cmp.Or(strings.Compare(a.SourcePath, b.SourcePath), strings.Compare(a.Evidence, b.Evidence), strings.Compare(a.PackageName, b.PackageName), strings.Compare(a.Version, b.Version), strings.Compare(a.DependencyKind, b.DependencyKind))
	})
	slices.Sort(c.inv.Reasons)
}
