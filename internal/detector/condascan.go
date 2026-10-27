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
	maxCondaWalkEntries = 100_000
	maxCondaWalkDepth   = 128
	maxCondaRecords     = 50_000
	maxCondaOutputBytes = 16 << 20
	maxCondaListEntries = 10_000
)

// maxCondaCacheDepth reaches Micromamba's nested cache layout,
// pkgs/https/<host>/<channel>/<subdir>/<dist>, with room to spare.
const maxCondaCacheDepth = 8

var (
	condaManifestNames = []string{"environment.yml", "environment.yaml", "env.yml", "env.yaml", "environment.json"}
	condaLockNames     = []string{"conda-lock.yml", "conda-lock.yaml", "pixi.lock", "explicit.txt"}
)

// CondaScanner reads metadata only: no conda, mamba, micromamba, pixi,
// python or shell runs, no activation scripts and no dependency solving.
type CondaScanner struct {
	exec       executor.Executor
	log        *progress.Logger
	protection func(string, *bool) (func(string) string, func(string) bool)
}

func NewCondaScanner(exec executor.Executor, log *progress.Logger) *CondaScanner {
	if log == nil {
		log = progress.NewNoop()
	}
	return &CondaScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

type condaProjectState struct {
	project model.CondaProject
	kept    bool
}

type condaDiskLock struct{ path, parent string }

type condaScan struct {
	ctx                  context.Context
	exec                 executor.Executor
	home, identity, goos string
	roots                []string
	guard                func(string) string
	volume               func(string) bool
	files                executor.Executor
	config               *configaudit.CondaConfigSnapshot
	inv                  model.CondaInventory
	sources              []*model.CondaSource
	byID                 map[string]*model.CondaSource
	projects             map[string]*condaProjectState
	projectDirs          map[string]string
	locks                map[string]bool
	diskLocks            map[string]condaDiskLock
	envs, envRoots       map[string]bool
	envsDirs, caches     map[string]bool
	pruned               map[string]bool
	seen                 map[string]bool
	remaining            int
	bytes                int
	limited              bool
}

func emptyCondaInventory() model.CondaInventory {
	return model.CondaInventory{SchemaVersion: model.CondaInventorySchemaVersion, Status: "complete", Reasons: []string{}, Sources: []model.CondaSource{}, Projects: []model.CondaProject{}, Packages: []model.CondaPackage{}}
}

func (s *CondaScanner) Scan(ctx context.Context, target *user.User, searchDirs []string, includeNetworkVolumes *bool) (*model.CondaInventory, *model.CondaConfigAudit) {
	start := time.Now()
	inv := emptyCondaInventory()
	configDetector := configaudit.NewCondaConfigDetector(s.exec)
	if target == nil || target.Username == "" || target.HomeDir == "" || !filepath.IsAbs(target.HomeDir) || isGoServiceIdentity(s.exec.GOOS(), target) {
		inv.Status, inv.Reasons = "partial", []string{"user_unresolved"}
		audit := configDetector.Detect(ctx, configaudit.CondaConfigScope{}).Finish()
		return &inv, &audit
	}
	guard, volume := s.protection(target.HomeDir, includeNetworkVolumes)
	// Reserve the audit's separate 256 KiB allowance before collecting inventory.
	c := &condaScan{ctx: ctx, exec: s.exec, home: filepath.Clean(target.HomeDir), identity: target.Username, goos: s.exec.GOOS(), guard: guard, volume: volume, inv: inv,
		byID: map[string]*model.CondaSource{}, projects: map[string]*condaProjectState{}, projectDirs: map[string]string{}, locks: map[string]bool{}, diskLocks: map[string]condaDiskLock{},
		envs: map[string]bool{}, envRoots: map[string]bool{}, envsDirs: map[string]bool{}, caches: map[string]bool{}, pruned: map[string]bool{}, seen: map[string]bool{}, remaining: maxCondaRecords, bytes: goJSONSize(&inv) + (256 << 10)}
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
	current, err := s.exec.CurrentUser()
	verified := err == nil && current != nil && target.Uid != "" && current.Uid == target.Uid
	c.config = configDetector.Detect(ctx, configaudit.CondaConfigScope{Username: target.Username, Home: c.home, Protected: guard, Volume: volume, ProcessVerified: verified})
	c.guard = c.config.ContentGuard
	c.files = s.exec.GuardedFiles(c.roots, c.guard, maxCondaMetadataBytes)
	c.standardRoots()
	c.leads()
	c.registry()
	c.walkRoots(dirs)
	// Files read during the walk can add envs_dirs/pkgs_dirs leads.
	c.leads()
	c.independentLocks()
	if reason := c.stopReason(); reason != "" {
		c.degrade(nil, reason)
	}
	audit := c.config.Finish()
	c.finish()
	if goJSONSize(&c.inv)+goJSONSize(&audit) > maxCondaOutputBytes {
		c.inv = emptyCondaInventory()
		c.degrade(nil, "output_size_limit")
	}
	s.log.Debug("conda scan: inventory=%s (%d sources, %d projects, %d packages) audit=%s (%d files, %d findings) in %dms",
		c.inv.Status, len(c.inv.Sources), len(c.inv.Projects), len(c.inv.Packages), audit.Status, len(audit.Files), len(audit.Findings), time.Since(start).Milliseconds())
	return &c.inv, &audit
}
func (c *condaScan) key(p string) string { return configaudit.GoPathKey(c.goos, p) }
func (c *condaScan) reason(err error, p string) string {
	return configaudit.CargoReadReason(err, p, c.volume)
}
func (c *condaScan) degrade(src *model.CondaSource, reason string) {
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
func (c *condaScan) charge(src *model.CondaSource, record any) bool {
	if c.remaining <= 0 {
		c.degrade(src, "record_limit")
		return false
	}
	// Reserve later coverage reasons, child IDs and separators per record.
	size := goJSONSize(record) + 128
	if c.limited || c.bytes+size > maxCondaOutputBytes {
		c.limited = true
		c.degrade(src, "output_size_limit")
		return false
	}
	c.remaining--
	c.bytes += size
	return true
}
func (c *condaScan) stopReason() string {
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
func (c *condaScan) stopped(src *model.CondaSource) bool {
	if reason := c.stopReason(); reason != "" {
		c.degrade(src, reason)
		return true
	}
	return false
}
func (c *condaScan) source(kind, path, parent string) *model.CondaSource {
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
	src := &model.CondaSource{SourceID: id, Kind: kind, Path: path, ParentSourceID: parent, Status: "complete", Presence: "present", Reasons: []string{}, DiscoveredSources: []string{}}
	if !c.charge(owner, src) {
		return nil
	}
	c.byID[id] = src
	c.sources = append(c.sources, src)
	return src
}
func (c *condaScan) fs(path string, limit int64) executor.Executor {
	if configaudit.GoWithinRoots(c.goos, path, c.roots) {
		return c.exec.GuardedFiles(c.roots, c.guard, limit)
	}
	// Exact metadata and shared roots permit only targeted access, never a new walk.
	return c.exec.GuardedFiles([]string{path}, c.guard, limit)
}

// read loads one file for its owner. A cached_metadata source owns an info
// directory, so the file is explicit rather than the source path.
func (c *condaScan) read(src *model.CondaSource, path string, targeted bool) ([]byte, bool) {
	if c.stopped(src) {
		src.Presence = "unknown"
		return nil, false
	}
	files := c.fs(path, maxCondaMetadataBytes)
	info, err := files.Stat(path)
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
		c.degrade(src, c.reason(err, path))
		return nil, false
	case !info.Mode().IsRegular():
		c.degrade(src, "unsupported_entry")
		return nil, false
	case info.Size() > maxCondaMetadataBytes:
		c.degrade(src, "size_limit")
		return nil, false
	}
	data, err := files.ReadFile(path)
	if err != nil {
		src.Presence = "unknown"
		reason := c.reason(err, path)
		if errors.Is(err, fs.ErrNotExist) {
			reason = "changed_during_scan"
		}
		c.degrade(src, reason)
		return nil, false
	}
	return data, true
}

// list enumerates one directory for its owner. A missing directory has no
// children; any other failure or truncation leaves the owner partial.
func (c *condaScan) list(owner *model.CondaSource, dir string, limit int) ([]fs.DirEntry, bool) {
	if c.stopped(owner) {
		return nil, false
	}
	entries, more, err := c.fs(dir, 0).ReadDirLimit(dir, limit)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		c.degrade(owner, c.reason(err, dir))
		return nil, false
	}
	if more {
		c.degrade(owner, "entry_limit")
	}
	return entries, true
}

func (c *condaScan) scopeOf(path string) string {
	if configaudit.GoWithinRoots(c.goos, path, []string{c.home}) {
		return "user"
	}
	return "system"
}

// standardRoots probes the fixed installer locations. Each is one stat; a
// missing one is silent. Rattler's own cache layout is not read.
func (c *condaScan) standardRoots() {
	candidates := []string{}
	for _, name := range []string{"miniconda3", "anaconda3", "miniforge3", "mambaforge", "micromamba", ".conda"} {
		candidates = append(candidates, filepath.Join(c.home, name))
	}
	switch c.goos {
	case model.PlatformDarwin:
		candidates = append(candidates, "/opt/anaconda3", "/opt/miniconda3", "/opt/homebrew/Caskroom/miniforge/base", "/opt/homebrew/Caskroom/miniconda/base", "/usr/local/Caskroom/miniforge/base", "/usr/local/Caskroom/miniconda/base")
	case model.PlatformLinux:
		candidates = append(candidates, "/opt/conda", "/opt/anaconda3", "/opt/miniconda3", "/opt/miniforge3")
	case model.PlatformWindows:
		local := cmpOr(c.config.Env("LOCALAPPDATA"), filepath.Join(c.home, "AppData", "Local"))
		candidates = append(candidates, filepath.Join(local, "conda", "conda"), `C:\ProgramData\miniconda3`, `C:\ProgramData\anaconda3`, `C:\ProgramData\miniforge3`)
	}
	for _, p := range candidates {
		if !c.environmentRoot(p, c.scopeOf(p), "", "") {
			c.environment(p, c.scopeOf(p), "", "")
		}
	}
}

// leads follows verified process variables and present configuration files.
// Each target dedups itself, so later calls only add what a walk uncovered.
func (c *condaScan) leads() {
	for _, d := range c.config.EnvsDirs {
		c.envsDir(d, c.scopeOf(d), nil)
	}
	for _, d := range c.config.PkgsDirs {
		c.cacheRoot(d, c.scopeOf(d), "", "")
	}
	for _, p := range c.config.Prefixes {
		if !c.environmentRoot(p, c.scopeOf(p), "", "") {
			c.environment(p, c.scopeOf(p), "", "")
		}
	}
}

// environmentRoot recognizes an installation root or an envs/pkgs
// container, then enumerates its base prefix, envs and package cache. It
// reports whether path is one, including a root enumerated under another
// spelling; an unreadable candidate is reported, never assumed absent.
func (c *condaScan) environmentRoot(path, scope, parent, project string) bool {
	owner := c.byID[parent]
	if !filepath.IsAbs(path) || !composerText(path, 4096) {
		c.degrade(owner, "path_unresolved")
		return false
	}
	path = filepath.Clean(path)
	if c.envRoots[c.key(path)] {
		c.adopt(path, owner)
		return true
	}
	if c.stopped(owner) {
		return false
	}
	files := c.fs(path, 0)
	entries, more, err := files.ReadDirLimit(path, maxCondaListEntries)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		c.envRoots[c.key(path)] = true
		if src := c.source("environment_root", path, parent); src != nil {
			src.Presence = "unknown"
			c.degrade(src, c.reason(err, path))
		}
		c.config.Root(path, true)
		return true
	}
	has := func(name string) bool {
		return slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name && (e.IsDir() || e.Type()&fs.ModeSymlink != 0) })
	}
	// An activated or registered prefix with only conda-meta is an
	// environment, not an installation whose .condarc the loader consults.
	meta, envs, pkgs := has("conda-meta"), has("envs"), has("pkgs")
	if !envs && !pkgs && !more {
		return false
	}
	phys := path
	if resolved, err := files.EvalSymlinks(path); err == nil {
		phys = resolved
	}
	duplicate := c.envRoots[c.key(phys)]
	c.envRoots[c.key(path)], c.envRoots[c.key(phys)] = true, true
	c.pruned[c.key(path)], c.pruned[c.key(phys)] = true, true
	if duplicate {
		c.adopt(phys, owner)
		return true
	}
	src := c.source("environment_root", path, parent)
	if src == nil {
		return true
	}
	if more {
		c.degrade(src, "entry_limit")
	}
	c.config.Root(path, more)
	if meta {
		c.environment(path, scope, src.SourceID, project)
	}
	if envs {
		c.envsDir(filepath.Join(path, "envs"), scope, src)
	}
	if pkgs {
		c.cacheRoot(filepath.Join(path, "pkgs"), scope, src.SourceID, project)
	}
	return true
}

// envsDir enumerates one environments directory; each child is a candidate
// prefix. It is a discovery step, not a source of its own.
func (c *condaScan) envsDir(dir, scope string, owner *model.CondaSource) {
	// A newly supplied owner needs the listing's coverage as well as its children.
	if !filepath.IsAbs(dir) || c.envsDirs[c.key(dir)] && owner == nil {
		return
	}
	c.envsDirs[c.key(dir)] = true
	parent := ""
	if owner != nil {
		parent = owner.SourceID
	}
	entries, ok := c.list(owner, dir, maxCondaListEntries)
	if !ok {
		return
	}
	for _, e := range entries {
		if e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			c.environment(filepath.Join(dir, e.Name()), scope, parent, "")
		}
	}
}

// environment enumerates one prefix's conda-meta receipts. It reports
// whether the prefix holds one, including a prefix already enumerated under
// another spelling. A missing history marker means creation never finished,
// so the receipts are kept but the source stays partial.
func (c *condaScan) environment(prefix, scope, parent, project string) bool {
	owner := c.byID[parent]
	if !filepath.IsAbs(prefix) || !composerText(prefix, 4096) {
		c.degrade(owner, "path_unresolved")
		return false
	}
	prefix = filepath.Clean(prefix)
	if c.envs[c.key(prefix)] {
		c.adopt(prefix, owner)
		return true
	}
	if c.stopped(owner) {
		return false
	}
	files := c.fs(prefix, 0)
	meta := filepath.Join(prefix, "conda-meta")
	info, err := files.Stat(meta)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	phys := prefix
	if resolved, err := files.EvalSymlinks(prefix); err == nil {
		phys = resolved
	}
	duplicate := c.envs[c.key(phys)]
	c.envs[c.key(prefix)], c.envs[c.key(phys)] = true, true
	c.pruned[c.key(prefix)], c.pruned[c.key(phys)] = true, true
	if duplicate {
		c.adopt(phys, owner)
		return true
	}
	src := c.source("environment", prefix, parent)
	if src == nil {
		return true
	}
	switch {
	case err != nil:
		src.Presence = "unknown"
		c.degrade(src, c.reason(err, meta))
	case !info.IsDir():
		c.degrade(src, "unsupported_entry")
	default:
		entries, ok := c.list(src, meta, maxCondaListEntries)
		finished := false
		for _, e := range entries {
			name := e.Name()
			switch {
			case name == "history" || name == "pixi":
				finished = finished || !e.IsDir()
			case e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, "._"):
			case c.stopped(src):
			default:
				c.receipt(filepath.Join(meta, name), src, scope, project, prefix)
			}
		}
		if ok && !finished {
			c.degrade(src, "extraction_incomplete")
		}
	}
	c.config.Environment(prefix, src.Status != "complete")
	return true
}

// receipt reads one conda-meta record. Its filename must agree with the
// identity inside, as Conda itself requires; a mismatch yields no row and the
// filename never fills in identity.
func (c *condaScan) receipt(path string, owner *model.CondaSource, scope, project, prefix string) {
	src := c.source("installed_metadata", path, owner.SourceID)
	if src == nil {
		return
	}
	data, ok := c.read(src, path, false)
	if !ok {
		return
	}
	r, err := parseCondaRecord(data)
	if err != nil {
		c.degrade(src, condaParseReason(err))
		return
	}
	name, version, build, ok := condaDist(strings.TrimSuffix(filepath.Base(path), ".json"))
	if !ok || name != r.name || version != r.version || build != r.build {
		c.degrade(src, "identity_mismatch")
		return
	}
	p := condaFact(r)
	p.EnvironmentPath = prefix
	p.Installation = &model.CondaInstallation{Path: prefix, PathStatus: "resolved", Presence: "present"}
	c.recordReasons(src, r)
	c.add(src, p, "installed_package", project, scope)
}

func (c *condaScan) recordReasons(src *model.CondaSource, r *condaRecord) {
	if r.checksumInvalid {
		c.degrade(src, "checksum_invalid")
	}
	for _, reason := range r.reasons {
		c.degrade(src, reason)
	}
}

// registry reads ~/.conda/environments.txt, Conda's own list of prefixes it
// created anywhere on disk. A stale entry is simply not an environment.
func (c *condaScan) registry() {
	path := filepath.Join(c.home, ".conda", "environments.txt")
	if c.stopped(nil) {
		return
	}
	files := c.fs(path, maxCondaMetadataBytes)
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		c.degrade(nil, c.reason(err, path))
		return
	case !info.Mode().IsRegular():
		c.degrade(nil, "unsupported_entry")
		return
	case info.Size() > maxCondaMetadataBytes:
		c.degrade(nil, "size_limit")
		return
	}
	data, err := files.ReadFile(path)
	if err != nil {
		c.degrade(nil, c.reason(err, path))
		return
	}
	for _, line := range condaLines(data) {
		if line == "" {
			continue
		}
		if !composerText(line, 4096) || !filepath.IsAbs(line) {
			c.degrade(nil, "path_unresolved")
			continue
		}
		if c.stopped(nil) {
			return
		}
		c.environment(line, c.scopeOf(line), "", c.enclosing(line))
	}
}

// cacheRoot enumerates an extracted package cache. Archives are never
// opened: one that has no extracted directory beside it is reported as
// unsupported coverage, and no identity is guessed from its name.
func (c *condaScan) cacheRoot(path, scope, parent, project string) {
	owner := c.byID[parent]
	if path == "" || c.stopped(owner) {
		return
	}
	if c.caches[c.key(path)] {
		c.adopt(path, owner)
		return
	}
	info, err := c.fs(path, 0).Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	c.caches[c.key(path)], c.pruned[c.key(path)] = true, true
	src := c.source("cache_root", path, parent)
	if src == nil {
		return
	}
	if err != nil {
		src.Presence = "unknown"
		c.degrade(src, c.reason(err, path))
		return
	}
	if !info.IsDir() {
		c.degrade(src, "unsupported_entry")
		return
	}
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{path, 0}}
	stems, extracted := map[string]bool{}, map[string]bool{}
	budget := maxCondaWalkEntries
	for len(queue) > 0 {
		if budget <= 0 {
			c.degrade(src, "entry_limit")
			return
		}
		if c.stopped(src) {
			return
		}
		d := queue[0]
		queue = queue[1:]
		entries, ok := c.list(src, d.path, min(budget, maxCondaListEntries))
		budget -= len(entries)
		if !ok {
			continue
		}
		for _, e := range entries {
			if c.stopped(src) {
				return
			}
			name := e.Name()
			p := filepath.Join(d.path, name)
			switch {
			case e.Type()&fs.ModeSymlink != 0:
			case e.IsDir():
				// Index caches, lock files and trash hold no package metadata.
				if name == "cache" || name == "locks" || strings.HasPrefix(name, ".") {
					continue
				}
				if c.cached(p, src, scope, project) {
					extracted[name] = true
					continue
				}
				if d.depth+1 > maxCondaCacheDepth {
					c.degrade(src, "depth_limit")
					continue
				}
				queue = append(queue, dir{p, d.depth + 1})
			case strings.HasSuffix(name, ".conda") || strings.HasSuffix(name, ".tar.bz2"):
				stems[strings.TrimSuffix(strings.TrimSuffix(name, ".conda"), ".tar.bz2")] = true
			}
		}
	}
	for stem := range stems {
		if !extracted[stem] {
			c.degrade(src, "unsupported_format")
			break
		}
	}
}

// cached reads one extracted package's info directory: the download record
// when present, else the archive's own index. It reports whether dir is a
// package, so the caller never descends into one.
func (c *condaScan) cached(dir string, owner *model.CondaSource, scope, project string) bool {
	info := filepath.Join(dir, "info")
	index := filepath.Join(info, "index.json")
	st, err := c.fs(index, 0).Stat(index)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false
	case err != nil:
		if src := c.source("cached_metadata", info, owner.SourceID); src != nil {
			src.Presence = "unknown"
			c.degrade(src, c.reason(err, index))
		}
		return true
	case !st.Mode().IsRegular():
		return false
	}
	src := c.source("cached_metadata", info, owner.SourceID)
	if src == nil {
		return true
	}
	var r *condaRecord
	if data, ok := c.read(src, filepath.Join(info, "repodata_record.json"), true); ok {
		if rr, err := parseCondaRecord(data); err == nil {
			r = rr
		} else {
			c.degrade(src, condaParseReason(err))
		}
	}
	if r == nil {
		data, ok := c.read(src, index, true)
		if !ok {
			return true
		}
		rr, err := parseCondaRecord(data)
		if err != nil {
			c.degrade(src, condaParseReason(err))
			return true
		}
		r, src.Presence = rr, "present"
	}
	c.recordReasons(src, r)
	c.add(src, condaFact(r), "cached_package", project, scope)
	return true
}

func condaPackageKey(p model.CondaPackage) string { b, _ := json.Marshal(p); return string(b) }
func (c *condaScan) add(src *model.CondaSource, p model.CondaPackage, evidence, project, scope string) {
	p.SourceID, p.SourcePath, p.Evidence, p.ProjectPath, p.Scope = src.SourceID, src.Path, evidence, project, scope
	for i := range p.RecordedChecksums {
		h := &p.RecordedChecksums[i]
		h.SourceID, h.SourcePath, h.SourceKind = src.SourceID, src.Path, src.Kind
	}
	slices.Sort(p.Reasons)
	p.Reasons = slices.Compact(p.Reasons)
	// The same file reached twice for one project is one observation.
	key := condaPackageKey(p)
	if c.seen[key] {
		return
	}
	if c.charge(src, p) {
		c.seen[key] = true
		c.inv.Packages = append(c.inv.Packages, p)
	}
}

// project reads one environment manifest. Its declared channels become a
// project-scope configuration source; `prefix:` is ignored because a
// declaration never claims installation.
func (c *condaScan) project(path, parent string) {
	key := c.key(path)
	if c.projects[key] != nil {
		return
	}
	src := c.source("manifest", path, parent)
	if src == nil {
		return
	}
	dir := filepath.Dir(path)
	st := &condaProjectState{project: model.CondaProject{ManifestSourceID: src.SourceID, ManifestPath: path, ProjectPath: dir, SelectionStatus: "observed", LockfilePaths: []string{}}}
	c.projects[key] = st
	c.projectDirs[c.key(dir)] = dir
	status := "present"
	var m *condaManifest
	if data, ok := c.read(src, path, false); !ok {
		status = "unreadable"
		switch {
		case src.Presence == "absent":
			status = "absent"
		case slices.Contains(src.Reasons, "skipped_protected") || slices.Contains(src.Reasons, "refused_network_volume"):
			status = "skipped_protected"
		}
	} else {
		var err error
		switch m, err = parseCondaEnvironment(data); {
		case errors.Is(err, errCondaUnsupportedFormat):
			status = "unsupported"
			c.degrade(src, "unsupported_format")
		case err != nil:
			status = "invalid"
			c.degrade(src, "parse_error")
		default:
			if m.unsupported {
				c.degrade(src, "unsupported_format")
			}
			if m.invalid {
				c.degrade(src, "parse_error")
			}
		}
	}
	channels := []string{}
	if m != nil {
		channels = m.channels
	}
	partial := c.config.Manifest(path, channels, status, src.Reasons) || status != "present" || m != nil && m.unsupported
	if m != nil {
		for _, d := range m.declarations {
			if c.stopped(src) {
				break
			}
			c.declared(src, d, dir)
		}
	}
	if partial {
		st.project.SelectionStatus = "partial"
	}
	st.kept = c.charge(src, st.project)
}

// declared emits one requirement. Only a URL or local channel qualifier
// establishes origin; a bare label is not a global identity.
func (c *condaScan) declared(src *model.CondaSource, d condaDeclaration, project string) {
	p := model.CondaPackage{PackageName: d.name, Reasons: []string{}, VersionStatus: "unknown", RequestedSpecs: []string{d.spec}, DependencyRelation: "direct",
		Origin: model.CondaOrigin{Kind: "unknown"}, ChecksumStatus: "absent", RecordedChecksums: []model.CondaRecordedChecksum{}}
	switch {
	case d.channel == "":
	case d.channelRedacted:
		p.Reasons = append(p.Reasons, "origin_unresolved")
	default:
		if origin, _ := condaOrigin(d.channel, "", ""); origin.Kind != "unknown" {
			p.Origin = origin
		}
	}
	c.add(src, p, "declared_requirement", project, "project")
}

// explicitHeader decides whether a conda-*.lock file is an @EXPLICIT list
// before any source is recorded for it. A file that cannot be read stays a
// candidate so the lock source reports the failure instead of vanishing.
func (c *condaScan) explicitHeader(path string, owner *model.CondaSource) bool {
	if c.stopped(owner) {
		return false
	}
	files := c.fs(path, maxCondaMetadataBytes)
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false
	case err != nil, info.Mode().IsRegular() && info.Size() > maxCondaMetadataBytes:
		return true
	case !info.Mode().IsRegular():
		return false
	}
	data, err := files.ReadFile(path)
	return err != nil || condaIsExplicit(data)
}

func (c *condaScan) lock(path, parent, project string) *model.CondaSource {
	c.locks[c.key(path)] = true
	src := c.source("lockfile", path, parent)
	if src == nil {
		return nil
	}
	data, ok := c.read(src, path, false)
	if !ok {
		return src
	}
	base := filepath.Base(path)
	parse := parseCondaLockYAML
	if base == "explicit.txt" || strings.HasPrefix(base, "conda-") && strings.HasSuffix(base, ".lock") && !strings.HasPrefix(base, "conda-lock.") {
		parse = parseCondaExplicit
	}
	entries, reasons, err := parse(data)
	if err != nil {
		c.degrade(src, condaParseReason(err))
		return src
	}
	for _, r := range reasons {
		c.degrade(src, r)
	}
	for _, e := range entries {
		if c.stopped(src) {
			break
		}
		c.add(src, e.pkg, "locked_package", project, "project")
	}
	return src
}

// independentLocks reads every lock found on disk. Conda has no manifest-to-
// lock linkage, so each lock beside a manifest is listed on that project.
func (c *condaScan) independentLocks() {
	for _, key := range slices.Sorted(maps.Keys(c.diskLocks)) {
		l := c.diskLocks[key]
		if c.locks[key] {
			continue
		}
		dir := filepath.Dir(l.path)
		if c.stopped(c.byID[l.parent]) {
			continue
		}
		if src := c.lock(l.path, l.parent, dir); src != nil && src.Presence != "absent" {
			for _, st := range c.projects {
				if c.key(st.project.ProjectPath) == c.key(dir) {
					st.project.LockfilePaths = append(st.project.LockfilePaths, l.path)
				}
			}
		}
	}
}

func (c *condaScan) skip(path string) bool {
	path = c.key(path)
	for root := range c.pruned {
		if path == root || goPathWithin(path, root) {
			return true
		}
	}
	return false
}

// enclosing returns the deepest known project directory containing path.
func (c *condaScan) enclosing(path string) string {
	best, key := "", c.key(path)
	for k, dir := range c.projectDirs {
		if (key == k || goPathWithin(key, k)) && len(dir) > len(best) {
			best = dir
		}
	}
	return best
}

func (c *condaScan) walkRoots(dirs []string) {
	// Outermost logical/physical roots own discovery. Identical physical roots
	// retain the first spelling and never get walked twice.
	type root struct {
		path, phys string
		src        *model.CondaSource
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

func (c *condaScan) walk(root string, src *model.CondaSource) {
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{root, 0}}
	budget := maxCondaWalkEntries
	for len(queue) > 0 {
		if c.stopped(src) {
			return
		}
		d := queue[0]
		queue = queue[1:]
		if c.skip(d.path) {
			c.adopt(d.path, src)
			continue
		}
		entries, more, err := c.files.ReadDirLimit(d.path, budget)
		if err != nil {
			c.degrade(src, c.reason(err, d.path))
			continue
		}
		budget -= len(entries)
		if more {
			c.degrade(src, "entry_limit")
		}
		has := func(name string, isDir bool) bool {
			return slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name && e.IsDir() == isDir })
		}
		project, scope := c.enclosing(d.path), "unknown"
		switch {
		case project != "":
			scope = "project"
		case configaudit.GoWithinRoots(c.goos, d.path, []string{c.home}):
			scope = "user"
		}
		// A prefix with envs or pkgs beside its receipts is an installation
		// root; a bare conda-meta is an environment, wherever it lives.
		meta, envs, pkgs := has("conda-meta", true), has("envs", true), has("pkgs", true)
		switch {
		case envs && pkgs || meta && (envs || pkgs):
			c.environmentRoot(d.path, scope, src.SourceID, project)
			continue
		case meta:
			c.environment(d.path, scope, src.SourceID, project)
			continue
		}
		for _, name := range condaManifestNames {
			if has(name, false) {
				c.project(filepath.Join(d.path, name), src.SourceID)
			}
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() {
				continue
			}
			p := filepath.Join(d.path, name)
			named := slices.Contains(condaLockNames, name)
			// Any other conda-*.lock is read only once its header proves it explicit.
			if named || strings.HasPrefix(name, "conda-") && strings.HasSuffix(name, ".lock") && !strings.HasPrefix(name, "conda-lock.") && c.explicitHeader(p, src) {
				c.diskLocks[c.key(p)] = condaDiskLock{p, src.SourceID}
				c.projectDirs[c.key(d.path)] = d.path
			}
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(d.path, e.Name())
			switch e.Name() {
			case ".git", ".hg", ".svn", "node_modules", "target", ".rustup", ".cache", "__pycache__", ".bundle":
				continue
			}
			if c.skip(p) {
				c.adopt(p, src)
				continue
			}
			if c.guard(p) != "" {
				c.degrade(src, c.reasonForGuard(p))
				continue
			}
			if d.depth+1 > maxCondaWalkDepth {
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

// adopt gives a root, cache or prefix found earlier by the standard list, a
// lead or the registry the walk source that now covers it, so a later scan
// of that root can prove its removal. Existing parents are kept; adopted
// reasons propagate like any other child's.
func (c *condaScan) adopt(path string, owner *model.CondaSource) {
	if owner == nil {
		return
	}
	for _, kind := range []string{"environment_root", "cache_root", "environment"} {
		child := c.byID[configaudit.GoSourceID(c.identity, kind, filepath.Clean(path))]
		if child == nil || child.ParentSourceID != "" || child == owner {
			continue
		}
		child.ParentSourceID = owner.SourceID
		for _, r := range child.Reasons {
			c.degrade(owner, r)
		}
	}
}
func (c *condaScan) reasonForGuard(path string) string {
	if c.volume != nil && c.volume(path) {
		return "refused_network_volume"
	}
	return "skipped_protected"
}
func (c *condaScan) finish() {
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
	for _, st := range c.projects {
		if st.kept {
			slices.Sort(st.project.LockfilePaths)
			c.inv.Projects = append(c.inv.Projects, st.project)
		}
	}
	// A prefix inside a project discovered later still belongs to it;
	// discovery order never changes scope.
	for i := range c.inv.Packages {
		p := &c.inv.Packages[i]
		if p.EnvironmentPath != "" && p.ProjectPath == "" {
			if dir := c.enclosing(p.EnvironmentPath); dir != "" {
				p.ProjectPath, p.Scope = dir, "project"
			}
		}
	}
	slices.SortFunc(c.inv.Sources, func(a, b model.CondaSource) int {
		return strings.Compare(a.Path+"\x00"+a.Kind, b.Path+"\x00"+b.Kind)
	})
	slices.SortFunc(c.inv.Projects, func(a, b model.CondaProject) int { return strings.Compare(a.ManifestPath, b.ManifestPath) })
	slices.SortStableFunc(c.inv.Packages, func(a, b model.CondaPackage) int {
		return cmp.Or(strings.Compare(a.SourcePath, b.SourcePath), strings.Compare(a.Evidence, b.Evidence), strings.Compare(a.ProjectPath, b.ProjectPath),
			strings.Compare(a.EnvironmentPath, b.EnvironmentPath), strings.Compare(a.PackageName, b.PackageName), strings.Compare(a.Version, b.Version),
			strings.Compare(a.Build, b.Build), strings.Compare(a.Subdir, b.Subdir), strings.Compare(a.LockEnvironment, b.LockEnvironment), strings.Compare(a.TargetPlatform, b.TargetPlatform))
	})
	slices.Sort(c.inv.Reasons)
}
