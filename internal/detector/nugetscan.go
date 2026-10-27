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
	maxNuGetWalkEntries = 100_000
	maxNuGetWalkDepth   = 128
	maxNuGetRecords     = 50_000
	maxNuGetOutputBytes = 16 << 20
	maxNuGetScriptReads = 2_000 // source files probed for package directives per root
)

// NuGetScanner reads metadata only: no dotnet, nuget, MSBuild or credential
// provider ever runs. The raw executor is required because a UserAwareExecutor
// may source a login shell when reading environment values.
type NuGetScanner struct {
	exec       executor.Executor
	log        *progress.Logger
	protection func(string, *bool) (func(string) string, func(string) bool)
}

func NewNuGetScanner(exec executor.Executor, log *progress.Logger) *NuGetScanner {
	if log == nil {
		log = progress.NewNoop()
	}
	return &NuGetScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

type nugetFound struct{ path, root string }

type nugetProjectState struct {
	src     *model.NuGetSource
	file    *nugetProjectFile
	status  string
	project model.NuGetProject
}

// nugetImportState is a Directory.*.props/targets file read once and shared
// by every project below it.
type nugetImportState struct {
	src      *model.NuGetSource
	file     *nugetProjectFile
	record   *model.NuGetConfigFile
	versions map[string]string // lowercase ID → PackageVersion (central only)
	deferred bool              // carries declarations this reader leaves unparsed
}

// nugetLayer is one MSBuild file in import order; dir anchors
// $(MSBuildThisFileDirectory) while every other path belongs to the consumer.
type nugetLayer struct {
	dir  string
	file *nugetProjectFile
}

// nugetPathProperties take effect in the consuming project's directory no
// matter which imported file declared them.
var nugetPathProperties = []string{"RestorePackagesPath", "NuGetLockFilePath", "RestoreFallbackFolders", "RestoreAdditionalProjectFallbackFolders"}

// nugetImports are the MSBuild directory files discovery records by name.
var nugetImports = []string{"directory.build.props", "directory.packages.props", "directory.build.targets"}

type nugetAssetsState struct {
	src     *model.NuGetSource
	assets  *nugetAssets
	project *nugetProjectState
}

// nugetCached is what a cache directory recorded about one extracted package.
type nugetCached struct{ contentHash, source string }

type nugetScan struct {
	ctx                  context.Context
	exec                 executor.Executor
	home, identity, goos string
	roots                []string
	guard                func(string) string
	volume               func(string) bool
	files                executor.Executor
	config               *configaudit.NuGetConfigSnapshot
	inv                  model.NuGetInventory
	sources              []*model.NuGetSource
	byID                 map[string]*model.NuGetSource
	projects             map[string]*nugetProjectState // key(manifest path)
	projectDirs          map[string]string             // key(dir) → dir
	importPaths          map[string]string             // key(dir)+name → Directory.*.props/targets
	imports              map[string]*nugetImportState  // key(path)
	assets               []*nugetAssetsState
	legacy, deps, tools  []nugetFound
	scripts              []nugetFound
	stores               map[string]string // key(.store dir) → path
	caches               map[string]bool   // pruned from discovery
	cacheRoots           []string
	cachesScanned        int               // prefix of cacheRoots already read
	cacheScope           map[string]string // key(root) → user | custom
	cacheDone            map[string]bool   // root listed completely
	index                map[string]nugetCached
	resolver             map[string][]nugetResolverEntry
	remaining            int
	bytes                int
	limited              bool
}

func emptyNuGetInventory() model.NuGetInventory {
	return model.NuGetInventory{SchemaVersion: model.NuGetInventorySchemaVersion, Status: "complete", Reasons: []string{}, Sources: []model.NuGetSource{}, Projects: []model.NuGetProject{}, Packages: []model.NuGetPackage{}}
}

func (s *NuGetScanner) Scan(ctx context.Context, target *user.User, searchDirs []string, includeNetworkVolumes *bool) (*model.NuGetInventory, *model.NuGetConfigAudit) {
	start := time.Now()
	inv := emptyNuGetInventory()
	configDetector := configaudit.NewNuGetConfigDetector(s.exec)
	if target == nil || target.Username == "" || target.HomeDir == "" || !filepath.IsAbs(target.HomeDir) || isGoServiceIdentity(s.exec.GOOS(), target) {
		inv.Status, inv.Reasons = "partial", []string{"user_unresolved"}
		audit := configDetector.Detect(ctx, configaudit.NuGetConfigScope{}).Finish()
		return &inv, &audit
	}
	guard, volume := s.protection(target.HomeDir, includeNetworkVolumes)
	// Reserve the audit's separate 256 KiB allowance before collecting inventory.
	c := &nugetScan{ctx: ctx, exec: s.exec, home: filepath.Clean(target.HomeDir), identity: target.Username, goos: s.exec.GOOS(), guard: guard, volume: volume, inv: inv,
		byID: map[string]*model.NuGetSource{}, projects: map[string]*nugetProjectState{}, projectDirs: map[string]string{}, importPaths: map[string]string{}, imports: map[string]*nugetImportState{},
		stores: map[string]string{}, caches: map[string]bool{}, cacheScope: map[string]string{}, cacheDone: map[string]bool{}, index: map[string]nugetCached{}, resolver: map[string][]nugetResolverEntry{}, remaining: maxNuGetRecords, bytes: goJSONSize(&inv) + (256 << 10)}
	c.roots = []string{c.home}
	dirs := []string{}
	for _, dir := range searchDirs {
		if dir == "" {
			continue
		}
		dir = canonicalNoStat(dir, c.home)
		if !filepath.IsAbs(dir) || !nugetText(dir, 4096) {
			c.degrade(nil, "path_unresolved")
			continue
		}
		dirs = append(dirs, dir)
		c.roots = append(c.roots, dir)
	}
	c.files = s.exec.GuardedFiles(c.roots, guard, maxNuGetMetadataBytes)
	current, err := s.exec.CurrentUser()
	verified := err == nil && current != nil && target.Uid != "" && current.Uid == target.Uid
	c.config = configDetector.Detect(ctx, configaudit.NuGetConfigScope{Username: target.Username, Home: c.home, Roots: c.roots, Protected: guard, Volume: volume, ProcessVerified: verified})
	// Conventional caches and profiles never become projects; they are read by
	// their own phases below.
	for _, p := range []string{filepath.Join(c.home, ".nuget"), filepath.Join(c.home, ".dotnet"), filepath.Join(c.home, ".templateengine"), filepath.Join(c.home, ".local", "share", "NuGet"),
		filepath.Join(c.home, "AppData", "Local", "NuGet"), filepath.Join(c.config.CLIHome, ".dotnet"), filepath.Join(c.config.CLIHome, ".templateengine")} {
		c.caches[c.key(p)] = true
	}
	c.cacheRoot(c.config.GlobalPackages, "user")
	for _, p := range c.config.PackageRoots {
		c.cacheRoot(p, "custom")
	}
	c.walkRoots(dirs)
	c.discoverProjectAssets()
	c.readAssets()
	c.emitProjects()
	// Project files add their own package roots; scan caches once all are known.
	c.scanCaches()
	for _, f := range c.legacy {
		c.emitLegacy(f)
	}
	for _, st := range c.assets {
		c.emitAssets(st)
	}
	c.toolStore(filepath.Join(c.config.CLIHome, ".dotnet", "tools", ".store"), "user")
	for _, key := range slices.Sorted(maps.Keys(c.stores)) {
		c.toolStore(c.stores[key], "custom")
	}
	for _, f := range c.tools {
		c.emitToolManifest(f)
	}
	c.templates()
	for _, f := range c.deps {
		c.emitDeps(f)
	}
	for _, f := range c.scripts {
		c.emitScript(f)
	}
	// Legacy, tool and script contexts may name caches of their own.
	c.scanCaches()
	audit := c.config.Finish()
	c.finish()
	if goJSONSize(&c.inv)+goJSONSize(&audit) > maxNuGetOutputBytes {
		c.inv = emptyNuGetInventory()
		c.degrade(nil, "output_size_limit")
	}
	s.log.Debug("nuget scan: inventory=%s (%d sources, %d projects, %d packages) audit=%s (%d files, %d findings) in %dms",
		c.inv.Status, len(c.inv.Sources), len(c.inv.Projects), len(c.inv.Packages), audit.Status, len(audit.Files), len(audit.Findings), time.Since(start).Milliseconds())
	return &c.inv, &audit
}
func (c *nugetScan) key(p string) string { return configaudit.GoPathKey(c.goos, p) }
func (c *nugetScan) reason(err error, p string) string {
	return configaudit.CargoReadReason(err, p, c.volume)
}
func (c *nugetScan) degrade(src *model.NuGetSource, reason string) {
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
func (c *nugetScan) charge(src *model.NuGetSource, record any) bool {
	if c.remaining <= 0 {
		c.degrade(src, "record_limit")
		return false
	}
	// Reserve later coverage reasons, child IDs and separators per record.
	size := goJSONSize(record) + 128
	if c.limited || c.bytes+size > maxNuGetOutputBytes {
		c.limited = true
		c.degrade(src, "output_size_limit")
		return false
	}
	c.remaining--
	c.bytes += size
	return true
}
func (c *nugetScan) stopReason() string {
	switch {
	case c.ctx.Err() != nil:
		return "deadline_exceeded"
	case c.limited:
		return "output_size_limit"
	case c.remaining <= 0:
		return "record_limit"
	}
	return ""
}
func (c *nugetScan) stopped(src *model.NuGetSource) bool {
	if reason := c.stopReason(); reason != "" {
		c.degrade(src, reason)
		return true
	}
	return false
}
func (c *nugetScan) source(kind, path, parent string) *model.NuGetSource {
	if !filepath.IsAbs(path) || !nugetText(path, 4096) {
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
	src := &model.NuGetSource{SourceID: id, Kind: kind, Path: path, ParentSourceID: parent, Status: "complete", Presence: "present", Reasons: []string{}, DiscoveredSources: []string{}}
	if !c.charge(owner, src) {
		return nil
	}
	c.byID[id] = src
	c.sources = append(c.sources, src)
	return src
}
func (c *nugetScan) fs(path string, limit int64) executor.Executor {
	if configaudit.GoWithinRoots(c.goos, path, c.roots) {
		return c.exec.GuardedFiles(c.roots, c.guard, limit)
	}
	// An exact metadata reference permits only targeted access, never a new walk.
	return c.exec.GuardedFiles([]string{path}, c.guard, limit)
}
func (c *nugetScan) read(src *model.NuGetSource, targeted bool) ([]byte, bool) {
	if c.stopped(src) {
		src.Presence = "unknown"
		return nil, false
	}
	files := c.fs(src.Path, maxNuGetMetadataBytes)
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
	case info.Size() > maxNuGetMetadataBytes:
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

// status maps a read outcome onto the config audit's file vocabulary.
func nugetReadStatus(src *model.NuGetSource, ok bool) string {
	switch {
	case ok:
		return "read"
	case src.Presence == "absent":
		return "not_found"
	case slices.Contains(src.Reasons, "skipped_protected"), slices.Contains(src.Reasons, "refused_network_volume"):
		return "unsupported"
	}
	return "unreadable"
}

// parseFailure maps a metadata parser error onto a source reason.
func (c *nugetScan) parseFailure(src *model.NuGetSource, err error) {
	if errors.Is(err, errNuGetUnsupportedFormat) {
		c.degrade(src, "unsupported_format")
		return
	}
	c.degrade(src, "parse_error")
}

func (c *nugetScan) cacheRoot(path, scope string) {
	if path == "" || !filepath.IsAbs(path) || !nugetText(path, 4096) {
		return
	}
	key := c.key(path)
	c.caches[key] = true
	if _, seen := c.cacheScope[key]; seen {
		return
	}
	c.cacheScope[key] = scope
	c.cacheRoots = append(c.cacheRoots, filepath.Clean(path))
}

// scanCaches reads every package root registered so far, once each; later
// phases register more through their own config contexts and call it again.
func (c *nugetScan) scanCaches() {
	for _, p := range c.config.PackageRoots {
		c.cacheRoot(p, "custom")
	}
	for ; c.cachesScanned < len(c.cacheRoots); c.cachesScanned++ {
		c.scanCache(c.cacheRoots[c.cachesScanned])
	}
}
func (c *nugetScan) inCache(path string) bool {
	path = c.key(path)
	for root := range c.caches {
		if path == root || goPathWithin(path, root) {
			return true
		}
	}
	return false
}
func (c *nugetScan) walkRoots(dirs []string) {
	// Outermost logical/physical roots own discovery. Identical physical roots
	// retain the first spelling, like Cargo, and never get walked twice.
	type root struct {
		path, phys string
		src        *model.NuGetSource
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
func (c *nugetScan) walk(root string, src *model.NuGetSource) {
	type dir struct {
		path    string
		depth   int
		project bool // an ancestor or this directory holds a project file
	}
	queue := []dir{{root, 0, false}}
	budget, scripts := maxNuGetWalkEntries, maxNuGetScriptReads
	for len(queue) > 0 {
		if c.stopped(src) {
			return
		}
		d := queue[0]
		queue = queue[1:]
		if c.inCache(d.path) {
			continue
		}
		entries, more, err := c.files.ReadDirLimit(d.path, budget)
		if err != nil {
			c.degrade(src, c.reason(err, d.path))
			continue
		}
		budget -= len(entries)
		here, archive := false, false
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			switch name := strings.ToLower(e.Name()); {
			case strings.HasSuffix(name, ".nupkg"):
				archive = true
			case strings.HasSuffix(name, ".csproj"), strings.HasSuffix(name, ".fsproj"), strings.HasSuffix(name, ".vbproj"):
				here = true
			}
		}
		if archive && !here {
			// Extracted package contents are never projects; pack output beside
			// a project file is.
			continue
		}
		project := d.project || here
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(d.path, e.Name())
			found := nugetFound{p, src.SourceID}
			switch name := strings.ToLower(e.Name()); {
			case strings.HasSuffix(name, ".csproj"), strings.HasSuffix(name, ".fsproj"), strings.HasSuffix(name, ".vbproj"):
				c.project(found)
			case slices.Contains(nugetImports, name):
				c.importPaths[c.key(d.path)+"\x00"+name] = p
			case name == "packages.config", strings.HasPrefix(name, "packages.") && strings.HasSuffix(name, ".config"):
				c.legacy = append(c.legacy, found)
			case name == "project.assets.json":
				if store := filepath.Dir(filepath.Dir(d.path)); filepath.Base(store) == ".store" {
					c.stores[c.key(store)] = store
				} else if as := c.source("project_assets", p, src.SourceID); as != nil {
					c.assets = append(c.assets, &nugetAssetsState{src: as})
				}
			case strings.HasSuffix(name, ".deps.json"):
				c.deps = append(c.deps, found)
			case name == "dotnet-tools.json":
				c.tools = append(c.tools, found)
			case strings.HasSuffix(name, ".fsx"), strings.HasSuffix(name, ".cs") && !project:
				if scripts <= 0 {
					c.degrade(src, "entry_limit")
					continue
				}
				scripts--
				c.scripts = append(c.scripts, found)
			}
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
			if c.inCache(p) {
				continue
			}
			if c.guard(p) != "" {
				c.degrade(src, c.reasonForGuard(p))
				continue
			}
			if d.depth+1 > maxNuGetWalkDepth {
				c.degrade(src, "depth_limit")
				continue
			}
			queue = append(queue, dir{p, d.depth + 1, project})
		}
		if more {
			c.degrade(src, "entry_limit")
			return
		}
	}
}
func (c *nugetScan) reasonForGuard(path string) string {
	if c.volume != nil && c.volume(path) {
		return "refused_network_volume"
	}
	return "skipped_protected"
}

// project reads an MSBuild project at discovery; emission waits for the
// restore graphs that attach to it.
func (c *nugetScan) project(f nugetFound) {
	key := c.key(f.path)
	if c.projects[key] != nil {
		return
	}
	src := c.source("project_manifest", f.path, f.root)
	if src == nil {
		return
	}
	dir := filepath.Dir(f.path)
	st := &nugetProjectState{src: src, project: model.NuGetProject{ManifestSourceID: src.SourceID, ManifestPath: f.path, ProjectPath: dir, ProjectKind: "msbuild", TargetFrameworks: []string{}, SelectionStatus: "resolved"}}
	c.projects[key] = st
	c.projectDirs[c.key(dir)] = dir
	data, ok := c.read(src, false)
	st.status = nugetReadStatus(src, ok)
	if !ok {
		return
	}
	var err error
	if st.file, err = parseNuGetProject(data); err != nil {
		c.degrade(src, "parse_error")
		st.status = "unreadable"
	}
}

// owner attributes a path to the nearest discovered project directory.
func (c *nugetScan) owner(dir string) (string, string) {
	for p := dir; configaudit.GoWithinRoots(c.goos, p, c.roots); p = filepath.Dir(p) {
		if d := c.projectDirs[c.key(p)]; d != "" {
			return d, "project"
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return "", "unknown"
}

// nearestImport returns the closest Directory.*.props/targets of that name
// above dir, read once. MSBuild imports only the nearest one of each.
func (c *nugetScan) nearestImport(dir, name, root string) *nugetImportState {
	for p := dir; configaudit.GoWithinRoots(c.goos, p, c.roots); p = filepath.Dir(p) {
		if path := c.importPaths[c.key(p)+"\x00"+name]; path != "" {
			return c.loadImport(path, name, root)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func (c *nugetScan) loadImport(path, name, root string) *nugetImportState {
	key := c.key(path)
	if st := c.imports[key]; st != nil {
		return st
	}
	kind := "project_manifest"
	if name == "directory.packages.props" {
		kind = "central_versions"
	}
	src := c.source(kind, path, root)
	if src == nil {
		return nil
	}
	st := &nugetImportState{src: src, versions: map[string]string{}}
	c.imports[key] = st
	data, ok := c.read(src, false)
	status := nugetReadStatus(src, ok)
	props := map[string]string{}
	if ok {
		var err error
		if st.file, err = parseNuGetProject(data); err != nil {
			c.degrade(src, "parse_error")
			status = "unreadable"
		} else {
			props = st.file.properties
			for _, item := range st.file.items {
				switch {
				case item.kind == "PackageVersion" && !item.conditional:
					st.versions[strings.ToLower(item.id)] = item.version
				case kind == "project_manifest" && item.kind != "PackageVersion":
					st.deferred = true
				}
			}
			if st.deferred || kind == "project_manifest" && len(st.file.sdks) > 0 {
				// Declarations in a shared build file stay unparsed; that is
				// incomplete coverage for every consumer, never absence.
				st.deferred = true
				c.degrade(src, "unsupported_format")
			}
		}
	}
	st.record = c.config.ProjectFile(path, status, src.Reasons, props, "")
	return st
}

// degradeImports marks shared files partial: a consumer that could not be
// read may still consume their declarations, so absence is unproven.
func (c *nugetScan) degradeImports(imports []*nugetImportState, reasons []string) {
	for _, imp := range imports {
		for _, reason := range reasons {
			c.degrade(imp.src, reason)
		}
	}
}

// discoverProjectAssets follows literal restore-output paths outside the walk.
// These are exact guarded reads, not additional project search roots.
func (c *nugetScan) discoverProjectAssets() {
	seen := map[string]bool{}
	for _, st := range c.assets {
		seen[c.key(st.src.Path)] = true
	}
	for _, key := range slices.Sorted(maps.Keys(c.projects)) {
		st := c.projects[key]
		if c.stopped(st.src) || st.file == nil {
			continue
		}
		dir := st.project.ProjectPath
		props := c.nearestImport(dir, "directory.build.props", st.src.ParentSourceID)
		targets := c.nearestImport(dir, "directory.build.targets", st.src.ParentSourceID)
		for _, imp := range []*nugetImportState{props, targets} {
			if imp != nil && imp.file == nil {
				// An unreadable import may still point at the previous assets.
				st.project.SelectionStatus = "partial"
				for _, reason := range imp.src.Reasons {
					c.degrade(st.src, reason)
				}
			}
		}
		layers := []nugetLayer{}
		if props != nil {
			layers = append(layers, nugetLayer{filepath.Dir(props.src.Path), props.file})
		}
		layers = append(layers, nugetLayer{dir, st.file})
		if targets != nil {
			layers = append(layers, nugetLayer{filepath.Dir(targets.src.Path), targets.file})
		}
		effective := nugetEffective(layers...)
		p := effective.properties
		output := cmp.Or(p["MSBuildProjectExtensionsPath"], p["BaseIntermediateOutputPath"])
		if output == "" && !strings.EqualFold(p["UseArtifactsOutput"], "false") && !strings.EqualFold(p["UseArtifactsIntermediateOutput"], "false") && (p["ArtifactsPath"] != "" || strings.EqualFold(p["UseArtifactsOutput"], "true")) {
			artifacts := p["ArtifactsPath"]
			if artifacts == "" && props != nil {
				artifacts = filepath.Join(filepath.Dir(props.src.Path), "artifacts")
			}
			if artifacts != "" {
				output = filepath.Join(artifacts, "obj")
				if !strings.EqualFold(p["IncludeProjectNameInArtifactsPaths"], "false") {
					projectName := cmp.Or(p["ArtifactsProjectName"], strings.TrimSuffix(filepath.Base(st.project.ManifestPath), filepath.Ext(st.project.ManifestPath)))
					output = filepath.Join(output, projectName)
				}
			}
		}
		if output == "" {
			continue
		}
		uncertain := nugetUnresolved(output) || !nugetText(output, 4096)
		for _, property := range []string{"MSBuildProjectExtensionsPath", "BaseIntermediateOutputPath", "UseArtifactsOutput", "ArtifactsPath", "ArtifactsProjectName", "IncludeProjectNameInArtifactsPaths", "UseArtifactsIntermediateOutput"} {
			uncertain = uncertain || effective.conditional[property]
		}
		if uncertain {
			st.project.SelectionStatus = "partial"
			c.degrade(st.src, "path_unresolved")
			continue
		}
		if !filepath.IsAbs(output) {
			output = filepath.Join(dir, filepath.FromSlash(output))
		}
		path := filepath.Join(output, "project.assets.json")
		if seen[c.key(path)] || c.stopped(st.src) {
			continue
		}
		info, err := c.fs(path, 0).Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			c.degrade(st.src, c.reason(err, path))
			continue
		}
		if !info.Mode().IsRegular() {
			c.degrade(st.src, "unsupported_entry")
			continue
		}
		if src := c.source("project_assets", path, st.src.SourceID); src != nil {
			c.assets = append(c.assets, &nugetAssetsState{src: src})
			seen[c.key(path)] = true
		}
	}
}

func (c *nugetScan) readAssets() {
	slices.SortFunc(c.assets, func(a, b *nugetAssetsState) int { return strings.Compare(a.src.Path, b.src.Path) })
	kept := c.assets[:0]
	for _, st := range c.assets {
		if st.src == nil {
			continue
		}
		data, ok := c.read(st.src, false)
		if !ok {
			continue
		}
		a, err := parseNuGetAssets(data)
		if err != nil {
			c.parseFailure(st.src, err)
			continue
		}
		if a.partial {
			c.degrade(st.src, "parse_error")
		}
		st.assets = a
		if pr := c.projects[c.key(a.restore.projectPath)]; pr != nil && pr.project.AssetsPath == "" {
			pr.project.AssetsPath = st.src.Path
			st.project = pr
		}
		for _, folder := range a.folders {
			c.cacheRoot(folder, "custom")
		}
		kept = append(kept, st)
	}
	c.assets = kept
}

// scanCache reads every extracted package under a NuGet package root. Only
// the nuspec identity and the recorded hashes are read; contents stay packed.
func (c *nugetScan) scanCache(root string) {
	src := c.source("package_cache", root, "")
	if src == nil {
		return
	}
	if c.stopped(src) {
		src.Presence = "unknown"
		return
	}
	files := c.fs(root, maxNuGetArchiveBytes)
	budget := maxNuGetWalkEntries
	ids, more, err := files.ReadDirLimit(root, budget)
	if errors.Is(err, fs.ErrNotExist) {
		src.Presence = "absent"
		return
	}
	if err != nil {
		src.Presence = "unknown"
		c.degrade(src, c.reason(err, root))
		return
	}
	budget -= len(ids)
	complete := !more
	scope := c.cacheScope[c.key(root)]
	for _, id := range ids {
		if !id.IsDir() || strings.HasPrefix(id.Name(), ".") {
			continue
		}
		if _, ok := nugetID(id.Name()); !ok {
			continue
		}
		if c.stopped(src) {
			complete = false
			break
		}
		idDir := filepath.Join(root, id.Name())
		versions, more, err := files.ReadDirLimit(idDir, budget)
		if err != nil {
			c.degrade(src, c.reason(err, idDir))
			complete = false
			continue
		}
		budget -= len(versions)
		complete = complete && !more
		for _, version := range versions {
			if !version.IsDir() || c.stopped(src) {
				continue
			}
			c.cachedPackage(src, files, root, id.Name(), version.Name(), scope)
		}
	}
	if !complete {
		c.degrade(src, "entry_limit")
	}
	c.cacheDone[c.key(root)] = complete && src.Status == "complete"
}

// nugetPackageDir is the identity one extracted package directory proves,
// plus the completion markers found beside it.
type nugetPackageDir struct{ id, version, marker, sha string }

// packageDir reads a package directory's nuspec identity from the loose
// nuspec or the bounded archive; contents stay packed. A missing directory is
// silently absent; anything else that blocks identity is charged to src.
func (c *nugetScan) packageDir(src *model.NuGetSource, files executor.Executor, dir string) (nugetPackageDir, bool) {
	var d nugetPackageDir
	entries, _, err := files.ReadDirLimit(dir, 64)
	if errors.Is(err, fs.ErrNotExist) {
		return d, false
	}
	if err != nil {
		c.degrade(src, c.reason(err, dir))
		return d, false
	}
	var nuspec, nupkg string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		switch name := strings.ToLower(e.Name()); {
		case strings.HasSuffix(name, ".nuspec"):
			nuspec = p
		case strings.HasSuffix(name, ".nupkg"):
			nupkg = p
		case name == ".nupkg.metadata":
			d.marker = p
		case strings.HasSuffix(name, ".nupkg.sha512"):
			d.sha = p
		}
	}
	var data []byte
	switch {
	case nuspec != "":
		if data, err = files.ReadFile(nuspec); err != nil {
			c.degrade(src, c.reason(err, nuspec))
			return d, false
		}
	case nupkg != "":
		var reason string
		if data, reason = c.archiveNuspec(files, nupkg); reason != "" {
			c.degrade(src, reason)
			return d, false
		}
	default:
		c.degrade(src, "extraction_incomplete")
		return d, false
	}
	if d.id, d.version, err = parseNuGetNuspec(data); err != nil {
		c.degrade(src, "parse_error")
		return d, false
	}
	return d, true
}

// archiveNuspec reads the root nuspec member of one .nupkg.
func (c *nugetScan) archiveNuspec(files executor.Executor, nupkg string) ([]byte, string) {
	raw, err := files.ReadFile(nupkg)
	if err != nil {
		return nil, c.reason(err, nupkg)
	}
	return nugetArchiveNuspec(raw)
}

// nugetIdentityMatches reports whether a nuspec identity is the package the
// directory or receipt claims to hold, filling the exact version on success.
func nugetIdentityMatches(p *model.NuGetPackage, d nugetPackageDir, id, version string) bool {
	want, _ := nugetNormalizeVersion(version)
	return strings.EqualFold(d.id, id) && nugetExact(p, d.version) && p.VersionNormalized == want && want != ""
}

func (c *nugetScan) cachedPackage(src *model.NuGetSource, files executor.Executor, root, id, version, scope string) {
	dir := filepath.Join(root, id, version)
	d, ok := c.packageDir(src, files, dir)
	if !ok {
		return
	}
	p := newNuGetPackage(d.id)
	if !nugetIdentityMatches(&p, d, id, version) {
		c.degrade(src, "identity_mismatch")
		return
	}
	p.DependencyRelation = "unknown"
	p.Installation = &model.NuGetInstallation{Path: dir, PathStatus: "resolved", Presence: "present"}
	entry := nugetCached{}
	marker, sha := d.marker, d.sha
	if marker != "" {
		md, err := files.ReadFile(marker)
		if err != nil {
			p.Reasons = append(p.Reasons, c.reason(err, marker))
		} else if hash, source, err := parseNuGetMarker(md); err != nil {
			p.Reasons = append(p.Reasons, "parse_error")
		} else {
			nugetContentHash(&p, "content", hash)
			entry = nugetCached{contentHash: hash, source: source}
			p.Origin = c.markerOrigin(source)
		}
	}
	if sha != "" {
		if sd, err := files.ReadFile(sha); err != nil {
			p.Reasons = append(p.Reasons, c.reason(err, sha))
		} else {
			nugetContentHash(&p, "archive", strings.TrimSpace(string(sd)))
		}
	}
	if marker == "" && sha == "" {
		p.Reasons = append(p.Reasons, "extraction_incomplete")
	}
	c.index[c.key(root)+"\x00"+strings.ToLower(id)+"/"+p.VersionNormalized] = entry
	c.add(src, p, "cached_package", "", scope)
}

// markerOrigin is the download source a .nupkg.metadata v2 file recorded.
func (c *nugetScan) markerOrigin(source string) model.NuGetOrigin {
	if source == "" {
		return model.NuGetOrigin{Kind: "unknown"}
	}
	if path, local := composerLocalURL(source, ""); local && !strings.Contains(source, "://") {
		return model.NuGetOrigin{Kind: "local", Path: filepath.Clean(path)}
	}
	// A stripped credential still leaves a usable feed identity.
	url, _ := configaudit.SanitizeComposerURL(source)
	if url == "[redacted]" {
		return model.NuGetOrigin{Kind: "unknown"}
	}
	return model.NuGetOrigin{Kind: "feed", URL: url}
}

func (c *nugetScan) emitProjects() {
	for _, key := range slices.Sorted(maps.Keys(c.projects)) {
		st := c.projects[key]
		if c.stopped(st.src) {
			// An unvisited consumer leaves every shared declaration unproven.
			c.degradeImports(slices.Collect(maps.Values(c.imports)), []string{c.stopReason()})
			continue
		}
		dir := st.project.ProjectPath
		var central *nugetImportState
		var imports []*nugetImportState
		var layers []nugetLayer // import order: props, project, targets
		for _, name := range nugetImports {
			imp := c.nearestImport(dir, name, st.src.ParentSourceID)
			switch {
			case imp == nil:
			case name == "directory.packages.props":
				central = imp
				imports = append(imports, imp)
			default:
				layers = append(layers, nugetLayer{filepath.Dir(imp.src.Path), imp.file})
				imports = append(imports, imp)
				if imp.deferred {
					// A reference moved into the shared file is unparsed, so
					// this project's manifest no longer proves its absence.
					st.project.SelectionStatus = "partial"
					c.degrade(st.src, "unsupported_format")
				}
			}
			if name == "directory.build.props" {
				layers = append(layers, nugetLayer{dir, st.file})
			}
		}
		effective := nugetEffective(layers...)
		if effective.imports {
			c.degrade(st.src, "unsupported_format")
		}
		// Central versions apply only when the literal settings enable them.
		managed := effective.properties["ManagePackageVersionsCentrally"]
		uncertain := effective.conditional["ManagePackageVersionsCentrally"] || effective.imports
		if central != nil && central.file != nil {
			if managed == "" {
				managed = central.file.properties["ManagePackageVersionsCentrally"]
				uncertain = uncertain || central.file.conditional["ManagePackageVersionsCentrally"]
			}
			uncertain = uncertain || central.file.imports
		}
		uncertain = uncertain || nugetUnresolved(managed)
		if uncertain && central != nil {
			c.degrade(st.src, "unsupported_format")
			c.degrade(central.src, "unsupported_format")
			st.project.SelectionStatus = "partial"
		}
		if !strings.EqualFold(managed, "true") || uncertain {
			central = nil
		}
		props := map[string]string{}
		if st.file != nil {
			props = maps.Clone(st.file.properties)
			for _, key := range nugetPathProperties {
				if v := effective.properties[key]; v != "" {
					props[key] = v
				}
			}
		}
		leading := []*model.NuGetConfigFile{c.config.ProjectFile(st.project.ManifestPath, st.status, st.src.Reasons, props, dir)}
		for _, imp := range imports {
			leading = append(leading, imp.record)
		}
		c.config.Ambient(dir, leading...)
		if st.file == nil {
			st.project.SelectionStatus = "unresolved"
			c.degradeImports(imports, st.src.Reasons)
		} else {
			c.frameworks(st, effective)
		}
		c.lock(st, effective.properties["NuGetLockFilePath"])
		if !c.charge(st.src, st.project) {
			c.degradeImports(imports, []string{c.stopReason()})
			continue
		}
		c.inv.Projects = append(c.inv.Projects, st.project)
		if st.file == nil {
			continue
		}
		for _, item := range st.file.items {
			if item.kind == "PackageVersion" {
				continue // central declarations surface through consumers
			}
			c.declared(st.src, dir, item, central)
		}
		for _, item := range st.file.sdks {
			c.declared(st.src, dir, item, nil)
		}
		if central != nil && central.file != nil {
			for _, item := range central.file.items {
				if item.kind == "GlobalPackageReference" {
					c.declared(central.src, dir, item, nil)
				}
			}
		}
	}
}

// frameworks keeps the literal target framework list; anything needing
// evaluation leaves the selection partial.
func (c *nugetScan) frameworks(st *nugetProjectState, f *nugetProjectFile) {
	value := f.properties["TargetFrameworks"]
	if value == "" {
		value = f.properties["TargetFramework"]
	}
	if f.imports || f.conditional["TargetFramework"] || f.conditional["TargetFrameworks"] || nugetUnresolved(value) {
		st.project.SelectionStatus = "partial"
		if nugetUnresolved(value) {
			return
		}
	}
	for tf := range strings.SplitSeq(value, ";") {
		if tf = strings.TrimSpace(tf); tf != "" && nugetText(tf, 64) {
			st.project.TargetFrameworks = append(st.project.TargetFrameworks, tf)
		}
	}
}

// nugetEffective layers literal properties in MSBuild import order; a later
// file wins, and any conditional or imported value keeps its uncertainty.
// $(MSBuildThisFileDirectory) is the one anchor that belongs to the declaring
// file, so it is substituted here in each list entry; every other path stays
// consumer-relative.
func nugetEffective(layers ...nugetLayer) *nugetProjectFile {
	out := &nugetProjectFile{properties: map[string]string{}, conditional: map[string]bool{}}
	for _, l := range layers {
		if l.file == nil {
			continue
		}
		for key, value := range l.file.properties {
			entries := strings.Split(value, ";")
			for i, e := range entries {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(e), "$(MSBuildThisFileDirectory)"); ok {
					entries[i] = l.dir + string(filepath.Separator) + strings.TrimLeft(rest, `/\`)
				}
			}
			out.properties[key] = strings.Join(entries, ";")
		}
		maps.Copy(out.conditional, l.file.conditional)
		out.imports = out.imports || l.file.imports
	}
	return out
}

// lock attaches the project's lock file: the literal NuGetLockFilePath, else
// the project-specific or shared default name when it exists.
func (c *nugetScan) lock(st *nugetProjectState, configured string) {
	dir := st.project.ProjectPath
	candidates := []string{filepath.Join(dir, "packages."+strings.TrimSuffix(filepath.Base(st.project.ManifestPath), filepath.Ext(st.project.ManifestPath))+".lock.json"), filepath.Join(dir, "packages.lock.json")}
	if configured != "" {
		if nugetUnresolved(configured) || !nugetText(configured, 4096) {
			st.project.SelectionStatus = "partial"
			c.degrade(st.src, "path_unresolved")
			return
		}
		if !filepath.IsAbs(configured) {
			configured = filepath.Join(dir, filepath.FromSlash(configured))
		}
		candidates = []string{filepath.Clean(configured)}
	}
	for _, p := range candidates {
		info, err := c.fs(p, 0).Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			c.degrade(st.src, c.reason(err, p))
			return
		}
		if !info.Mode().IsRegular() {
			continue
		}
		st.project.LockfilePath = p
		src := c.source("lockfile", p, st.src.SourceID)
		if src == nil {
			return
		}
		c.locked(src, dir)
		return
	}
}
func (c *nugetScan) locked(src *model.NuGetSource, dir string) {
	data, ok := c.read(src, true)
	if !ok {
		return
	}
	entries, partial, err := parseNuGetLock(data)
	if err != nil {
		c.parseFailure(src, err)
		return
	}
	if partial {
		c.degrade(src, "parse_error")
	}
	for _, e := range entries {
		if c.stopped(src) {
			return
		}
		p := newNuGetPackage(e.id)
		if !nugetExact(&p, e.resolved) {
			p.Reasons = append(p.Reasons, "parse_error")
		}
		p.RequestedVersion, p.LockDependencyType, p.FrameworkAlias, p.TargetFramework = e.requested, e.typ, e.alias, e.framework
		p.DependencyRelation = "transitive"
		if e.typ == "Direct" {
			p.DependencyRelation = "direct"
		}
		nugetContentHash(&p, "content", e.contentHash)
		c.add(src, p, "locked_package", dir, "project")
	}
}

// declared emits one project-file item. Only literal versions are kept; a
// reference that depends on evaluation stays a requirement without a version.
func (c *nugetScan) declared(src *model.NuGetSource, dir string, item nugetItem, central *nugetImportState) {
	p := newNuGetPackage(item.id)
	if p.PackageName == "" {
		c.degrade(src, "parse_error")
		return
	}
	p.DependencyRelation, p.Conditional = "direct", item.conditional
	p.PrivateAssets, p.IncludeAssets, p.ExcludeAssets = item.privateAssets, item.includeAssets, item.excludeAssets
	version := item.version
	switch item.kind {
	case "PackageReference":
		p.DeclarationKind = "package_reference"
		if version == "" {
			version = item.versionOverride
		}
		if version == "" && central != nil {
			version = central.versions[p.PackageName]
		}
	case "GlobalPackageReference":
		p.DeclarationKind = "global_package_reference"
	// Even an exact bracketed PackageDownload or SDK version is a request;
	// only legacy and tool manifests record known declared versions.
	case "PackageDownload":
		p.DeclarationKind = "package_download"
	case "msbuild_sdk":
		p.DeclarationKind = "msbuild_sdk"
	}
	switch {
	case nugetUnresolved(version) || !nugetText(version, 256):
		p.Reasons = append(p.Reasons, "context_unresolved")
	case version == "" && p.Version == "":
		p.Reasons = append(p.Reasons, "context_unresolved")
	default:
		p.RequestedVersion = version
	}
	c.add(src, p, "declared_requirement", dir, "project")
}

func (c *nugetScan) emitLegacy(f nugetFound) {
	src := c.source("legacy_manifest", f.path, f.root)
	if src == nil {
		return
	}
	dir := filepath.Dir(f.path)
	data, ok := c.read(src, false)
	if !ok {
		return
	}
	entries, partial, err := parseNuGetPackagesConfig(data)
	if err != nil {
		c.degrade(src, "parse_error")
		return
	}
	if partial {
		c.degrade(src, "parse_error")
	}
	paths := c.config.Ambient(dir)
	project := model.NuGetProject{ManifestSourceID: src.SourceID, ManifestPath: f.path, ProjectPath: dir, ProjectKind: "legacy", TargetFrameworks: []string{}, SelectionStatus: "resolved", PackagesPath: paths.Repository}
	if project.PackagesPath == "" {
		// Without repositoryPath, NuGet uses the solution's packages folder.
		for p, i := dir, 0; i < 3 && configaudit.GoWithinRoots(c.goos, p, c.roots); p, i = filepath.Dir(p), i+1 {
			repo := filepath.Join(p, "packages")
			if info, err := c.fs(repo, 0).Stat(repo); err == nil && info.IsDir() {
				project.PackagesPath = repo
				break
			}
		}
	}
	if !c.charge(src, project) {
		return
	}
	c.inv.Projects = append(c.inv.Projects, project)
	for _, e := range entries {
		if c.stopped(src) {
			return
		}
		p := newNuGetPackage(e.id)
		if !nugetExact(&p, e.version) {
			p.RequestedVersion = e.version
		}
		p.TargetFramework, p.AllowedVersions, p.DevelopmentDependency = e.targetFramework, e.allowedVersions, e.developmentDependency
		c.add(src, p, "declared_requirement", dir, "project")
		if c.stopped(src) {
			return
		}
		if project.PackagesPath == "" || p.Version == "" {
			continue
		}
		// Only a readable nuspec proves the folder holds this package.
		installed := filepath.Join(project.PackagesPath, e.id+"."+e.version)
		d, ok := c.packageDir(src, c.fs(installed, maxNuGetArchiveBytes), installed)
		if !ok {
			continue
		}
		r := p
		r.Reasons, r.RecordedChecksums = []string{}, []model.NuGetRecordedChecksum{}
		if !nugetIdentityMatches(&r, d, e.id, e.version) {
			c.degrade(src, "identity_mismatch")
			continue
		}
		r.Installation = &model.NuGetInstallation{Path: installed, PathStatus: "resolved", Presence: "present"}
		c.add(src, r, "restored_package", dir, "project")
	}
}

func (c *nugetScan) emitAssets(st *nugetAssetsState) {
	a, src := st.assets, st.src
	project, scope := "", "unknown"
	switch {
	case st.project != nil:
		project, scope = st.project.project.ProjectPath, "project"
	case a.restore.projectPath != "":
		project = filepath.Dir(a.restore.projectPath)
	}
	if a.hasProject && len(a.restore.configFilePaths) > 0 {
		c.config.Restore(src.Path, cmp.Or(project, filepath.Dir(filepath.Dir(src.Path))), a.restore.configFilePaths)
	}
	seen := map[string]bool{}
	for _, t := range a.targets {
		for _, pk := range t.packages {
			if c.stopped(src) {
				return
			}
			p := newNuGetPackage(pk.id)
			if !nugetExact(&p, pk.version) {
				p.Reasons = append(p.Reasons, "parse_error")
			}
			p.FrameworkAlias, p.TargetFramework, p.RuntimeIdentifier = t.alias, t.framework, t.rid
			lib := a.libraries[strings.ToLower(pk.id+"/"+pk.version)]
			nugetContentHash(&p, "content", lib.sha512)
			// Only a target tied to a project framework decides the relation;
			// an unmatched target leaves it unknown.
			if direct, ok := a.direct[t.alias]; ok && a.hasProject {
				p.DependencyRelation = "transitive"
				if direct[p.PackageName] {
					p.DependencyRelation = "direct"
				}
			}
			c.locate(&p, a.folders, lib.sha512)
			key := nugetPackageKey(p)
			if seen[key] {
				continue
			}
			seen[key] = true
			c.add(src, p, "restored_package", project, scope)
		}
	}
}

// locate joins a restored package to the cache scan: the first package folder
// holding it is its installation, and a matching content hash lets the
// cache's recorded download source stand as the origin.
func (c *nugetScan) locate(p *model.NuGetPackage, folders []string, hash string) {
	if p.VersionNormalized == "" || len(folders) == 0 {
		return
	}
	for _, folder := range folders {
		e, ok := c.index[c.key(folder)+"\x00"+p.PackageName+"/"+p.VersionNormalized]
		if !ok {
			continue
		}
		p.Installation = &model.NuGetInstallation{Path: filepath.Join(folder, p.PackageName, p.VersionNormalized), PathStatus: "resolved", Presence: "present"}
		if hash != "" && e.contentHash == hash {
			p.Origin = c.markerOrigin(e.source)
		}
		return
	}
	p.Installation = &model.NuGetInstallation{Path: filepath.Join(folders[0], p.PackageName, p.VersionNormalized), PathStatus: "resolved", Presence: "unknown"}
	for _, folder := range folders {
		if !c.cacheDone[c.key(folder)] {
			return
		}
	}
	p.Installation.Presence = "absent"
}

// toolStore reads a global tool store: each tool keeps its own restore graph
// beside the extracted packages, and its commands beside its shims.
func (c *nugetScan) toolStore(store, scope string) {
	src := c.source("tool_store", store, "")
	if src == nil {
		return
	}
	if c.stopped(src) {
		src.Presence = "unknown"
		return
	}
	files := c.fs(store, maxNuGetMetadataBytes)
	budget := maxNuGetWalkEntries
	ids, more, err := files.ReadDirLimit(store, budget)
	if errors.Is(err, fs.ErrNotExist) {
		src.Presence = "absent"
		return
	}
	if err != nil {
		src.Presence = "unknown"
		c.degrade(src, c.reason(err, store))
		return
	}
	if more {
		c.degrade(src, "entry_limit")
	}
	budget -= len(ids)
	shims := filepath.Dir(store)
	for _, id := range ids {
		if !id.IsDir() || strings.HasPrefix(id.Name(), ".") {
			continue
		}
		if c.stopped(src) {
			return
		}
		idDir := filepath.Join(store, id.Name())
		versions, more, err := files.ReadDirLimit(idDir, budget)
		if err != nil {
			c.degrade(src, c.reason(err, idDir))
			continue
		}
		if more {
			c.degrade(src, "entry_limit")
		}
		budget -= len(versions)
		for _, version := range versions {
			if !version.IsDir() || c.stopped(src) {
				continue
			}
			c.installedTool(src, files, idDir, id.Name(), version.Name(), shims, scope)
		}
	}
}
func (c *nugetScan) installedTool(src *model.NuGetSource, files executor.Executor, idDir, id, version, shims, scope string) {
	verDir := filepath.Join(idDir, version)
	graphs := []*nugetAssets{}
	for _, name := range []string{"project.assets.json", "project.assets.ridpackage.json"} {
		data, err := files.ReadFile(filepath.Join(verDir, name))
		if errors.Is(err, fs.ErrNotExist) {
			if len(graphs) == 0 {
				return // staged or torn-down tool
			}
			continue // a framework-dependent tool has no RID payload graph
		}
		if err != nil {
			c.degrade(src, c.reason(err, verDir))
			return
		}
		a, err := parseNuGetAssets(data)
		if err != nil {
			c.parseFailure(src, err)
			return
		}
		if a.partial {
			c.degrade(src, "parse_error")
		}
		graphs = append(graphs, a)
	}
	// A RID-specific tool keeps its commands in the payload package, which the
	// companion graph names; the pointer package stays the requested identity.
	settings := map[string][]string{}
	commandsOf := func(pk nugetTargetPackage) []string {
		dir := filepath.Join(verDir, pk.id, pk.version, "tools")
		if _, seen := settings[dir]; !seen {
			settings[dir] = c.toolCommands(files, dir)
		}
		return settings[dir]
	}
	commands := commandsOf(nugetTargetPackage{id: id, version: version})
	if commands == nil && len(graphs) > 1 {
		for _, t := range graphs[1].targets {
			for _, pk := range t.packages {
				if commands = commandsOf(pk); commands != nil {
					break
				}
			}
		}
	}
	if len(commands) == 0 {
		c.degrade(src, "extraction_incomplete")
		return
	}
	want, _ := nugetNormalizeVersion(version)
	for gi, a := range graphs {
		for _, t := range a.targets {
			for _, pk := range t.packages {
				if c.stopped(src) {
					return
				}
				p := newNuGetPackage(pk.id)
				if !nugetExact(&p, pk.version) {
					p.Reasons = append(p.Reasons, "parse_error")
				}
				p.FrameworkAlias, p.TargetFramework, p.RuntimeIdentifier = t.alias, t.framework, t.rid
				nugetContentHash(&p, "content", a.libraries[strings.ToLower(pk.id+"/"+pk.version)].sha512)
				p.DependencyRelation = "transitive"
				pointer := p.PackageName == strings.ToLower(id) && p.VersionNormalized == want
				if pointer || gi > 0 {
					p.DependencyRelation, p.ToolCommands = "direct", commandsOf(pk)
					if pointer {
						p.ToolCommands = commands
					}
					if len(p.ToolCommands) > 0 {
						shim := filepath.Join(shims, p.ToolCommands[0])
						if c.goos == model.PlatformWindows {
							shim += ".exe"
						}
						p.Installation = c.presence(&p, shim)
					}
				}
				c.add(src, p, "installed_tool", "", scope)
			}
		}
	}
}

// toolCommands reads DotnetToolSettings.xml from the single framework and
// runtime folder a tool package ships.
func (c *nugetScan) toolCommands(files executor.Executor, tools string) []string {
	dir := tools
	for range 2 {
		entries, _, err := files.ReadDirLimit(dir, 16)
		if err != nil {
			return nil
		}
		i := slices.IndexFunc(entries, func(e fs.DirEntry) bool { return e.IsDir() })
		if i < 0 {
			return nil
		}
		dir = filepath.Join(dir, entries[i].Name())
	}
	data, err := files.ReadFile(filepath.Join(dir, "DotnetToolSettings.xml"))
	if err != nil {
		return nil
	}
	commands, err := parseNuGetToolSettings(data)
	if err != nil {
		return nil
	}
	return commands
}

// presence records whether a path exists, charging read failures to the package.
func (c *nugetScan) presence(p *model.NuGetPackage, path string) *model.NuGetInstallation {
	out := &model.NuGetInstallation{Path: path, PathStatus: "resolved", Presence: "unknown"}
	_, err := c.fs(path, 0).Stat(path)
	switch {
	case err == nil:
		out.Presence = "present"
	case errors.Is(err, fs.ErrNotExist):
		out.Presence = "absent"
	default:
		out.Presence = "unreadable"
		p.Reasons = append(p.Reasons, c.reason(err, path))
	}
	return out
}

func (c *nugetScan) emitToolManifest(f nugetFound) {
	src := c.source("tool_manifest", f.path, f.root)
	if src == nil {
		return
	}
	data, ok := c.read(src, false)
	if !ok {
		return
	}
	entries, partial, err := parseNuGetToolManifest(data)
	if err != nil {
		c.parseFailure(src, err)
		return
	}
	if partial {
		c.degrade(src, "parse_error")
	}
	dir := filepath.Dir(f.path)
	if filepath.Base(dir) == ".config" {
		dir = filepath.Dir(dir)
	}
	project := model.NuGetProject{ManifestSourceID: src.SourceID, ManifestPath: f.path, ProjectPath: dir, ProjectKind: "tool_manifest", TargetFrameworks: []string{}, SelectionStatus: "resolved"}
	if !c.charge(src, project) {
		return
	}
	c.inv.Projects = append(c.inv.Projects, project)
	c.config.Ambient(dir)
	for _, e := range entries {
		if c.stopped(src) {
			return
		}
		p := newNuGetPackage(e.id)
		if !nugetExact(&p, e.version) {
			p.RequestedVersion = e.version
		}
		p.DependencyRelation, p.ToolCommands = "direct", e.commands
		evidence := "declared_requirement"
		if r := c.resolvedTool(e, src.SourceID); r != nil {
			evidence = "installed_tool"
			p.TargetFramework, p.RuntimeIdentifier = r.framework, r.rid
			p.Installation = c.presence(&p, r.executable)
		}
		c.add(src, p, evidence, dir, "project")
	}
}

// resolvedTool matches a manifest entry against the SDK's resolver cache,
// which records the executable a local tool last resolved to.
func (c *nugetScan) resolvedTool(e nugetToolEntry, parent string) *nugetResolverEntry {
	path := filepath.Join(c.config.CLIHome, ".dotnet", "toolResolverCache", "1", strings.ToLower(e.id))
	key := c.key(path)
	entries, ok := c.resolver[key]
	if !ok {
		c.resolver[key] = nil
		if _, err := c.fs(path, 0).Stat(path); err != nil {
			return nil
		}
		src := c.source("tool_resolver_cache", path, parent)
		if src == nil {
			return nil
		}
		data, ok := c.read(src, true)
		if !ok {
			return nil
		}
		var partial bool
		var err error
		if entries, partial, err = parseNuGetResolverCache(data); err != nil {
			c.parseFailure(src, err)
			return nil
		}
		if partial {
			c.degrade(src, "parse_error")
		}
		c.resolver[key] = entries
	}
	want, _ := nugetNormalizeVersion(e.version)
	for i := range entries {
		r := &entries[i]
		if got, _ := nugetNormalizeVersion(r.version); got == want && want != "" && slices.Contains(e.commands, r.name) && filepath.IsAbs(r.executable) {
			return r
		}
	}
	return nil
}

func (c *nugetScan) templates() {
	src := c.source("template_receipt", filepath.Join(c.config.CLIHome, ".templateengine", "packages.json"), "")
	if src == nil {
		return
	}
	data, ok := c.read(src, true)
	if !ok {
		return
	}
	entries, partial, err := parseNuGetTemplates(data)
	if err != nil {
		c.parseFailure(src, err)
		return
	}
	if partial {
		c.degrade(src, "parse_error")
	}
	for _, e := range entries {
		if c.stopped(src) {
			return
		}
		p := newNuGetPackage(e.id)
		if !nugetExact(&p, e.version) {
			p.RequestedVersion = e.version
		}
		p.DependencyRelation = "direct"
		if e.source != "" {
			p.Origin = c.markerOrigin(e.source)
		}
		if mount := strings.TrimPrefix(e.mount, "file://"); filepath.IsAbs(mount) {
			p.Installation = c.presence(&p, filepath.Clean(mount))
			// The receipt is a claim; the archive's nuspec is the evidence.
			// Without it nothing is proven installed, and prior evidence
			// must stay stale rather than retire.
			var reason string
			switch p.Installation.Presence {
			case "absent":
				continue
			case "unreadable":
				reason = p.Reasons[len(p.Reasons)-1]
			case "present":
				var d nugetPackageDir
				var data []byte
				data, reason = c.archiveNuspec(c.fs(mount, maxNuGetArchiveBytes), mount)
				if reason == "" {
					if d.id, d.version, err = parseNuGetNuspec(data); err != nil {
						reason = "parse_error"
					}
				}
				if reason == "" && !nugetIdentityMatches(&p, d, e.id, e.version) {
					reason = "identity_mismatch"
				}
			}
			if reason != "" {
				c.degrade(src, reason)
				continue
			}
		} else {
			c.degrade(src, "path_unresolved")
			continue
		}
		c.add(src, p, "installed_template", "", "user")
	}
}

func (c *nugetScan) emitDeps(f nugetFound) {
	src := c.source("binary_metadata", f.path, f.root)
	if src == nil {
		return
	}
	data, ok := c.read(src, false)
	if !ok {
		return
	}
	entries, partial, err := parseNuGetDeps(data)
	if err != nil {
		c.parseFailure(src, err)
		return
	}
	if partial {
		c.degrade(src, "parse_error")
	}
	project, scope := c.owner(filepath.Dir(f.path))
	for _, e := range entries {
		if c.stopped(src) {
			return
		}
		p := newNuGetPackage(e.id)
		if !nugetExact(&p, e.version) {
			p.Reasons = append(p.Reasons, "parse_error")
		}
		p.TargetFramework, p.RuntimeIdentifier = e.framework, e.rid
		nugetContentHash(&p, "content", e.sha512)
		c.add(src, p, "binary_dependency", project, scope)
	}
}

// emitScript records a source file only once a package directive proves it
// is a file-based app or script; ordinary source files leave no trace.
func (c *nugetScan) emitScript(f nugetFound) {
	// Failed probes must mark discovery partial even before a directive is known.
	probe := &model.NuGetSource{Path: f.path, ParentSourceID: f.root}
	data, ok := c.read(probe, false)
	if !ok {
		return
	}
	kind, directives := "file_based", parseNuGetCSharpDirectives(data)
	if strings.EqualFold(filepath.Ext(f.path), ".fsx") {
		kind, directives = "fsharp_script", parseNuGetFSharpDirectives(data)
	}
	if len(directives) == 0 {
		return
	}
	src := c.source("script_manifest", f.path, f.root)
	if src == nil {
		return
	}
	dir := filepath.Dir(f.path)
	project := model.NuGetProject{ManifestSourceID: src.SourceID, ManifestPath: f.path, ProjectPath: dir, ProjectKind: kind, TargetFrameworks: []string{}, SelectionStatus: "resolved"}
	if !c.charge(src, project) {
		return
	}
	c.inv.Projects = append(c.inv.Projects, project)
	c.config.Ambient(dir)
	for _, d := range directives {
		item := nugetItem{kind: "PackageReference", id: d.id, version: d.version}
		if d.kind == "sdk" {
			item.kind = "msbuild_sdk"
		}
		c.declared(src, dir, item, nil)
	}
}

func nugetPackageKey(p model.NuGetPackage) string { b, _ := json.Marshal(p); return string(b) }
func (c *nugetScan) add(src *model.NuGetSource, p model.NuGetPackage, evidence, project, scope string) {
	p.SourceID, p.SourcePath, p.Evidence, p.ProjectPath, p.Scope = src.SourceID, src.Path, evidence, project, scope
	for i := range p.RecordedChecksums {
		h := &p.RecordedChecksums[i]
		h.SourceID, h.SourcePath, h.SourceKind = src.SourceID, src.Path, src.Kind
	}
	slices.Sort(p.Reasons)
	p.Reasons = slices.Compact(p.Reasons)
	if c.charge(src, p) {
		c.inv.Packages = append(c.inv.Packages, p)
	}
}
func (c *nugetScan) finish() {
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
	slices.SortFunc(c.inv.Sources, func(a, b model.NuGetSource) int {
		return strings.Compare(a.Path+"\x00"+a.Kind, b.Path+"\x00"+b.Kind)
	})
	slices.SortFunc(c.inv.Projects, func(a, b model.NuGetProject) int { return strings.Compare(a.ManifestPath, b.ManifestPath) })
	slices.SortStableFunc(c.inv.Packages, func(a, b model.NuGetPackage) int {
		return cmp.Or(strings.Compare(a.SourcePath, b.SourcePath), strings.Compare(a.Evidence, b.Evidence), strings.Compare(a.PackageName, b.PackageName),
			strings.Compare(a.VersionNormalized, b.VersionNormalized), strings.Compare(a.RequestedVersion, b.RequestedVersion), strings.Compare(a.FrameworkAlias, b.FrameworkAlias),
			strings.Compare(a.TargetFramework, b.TargetFramework), strings.Compare(a.RuntimeIdentifier, b.RuntimeIdentifier), strings.Compare(a.DeclarationKind, b.DeclarationKind))
	})
	slices.Sort(c.inv.Reasons)
}
