package detector

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

var (
	maxMavenWalkEntries = 100_000
	maxMavenWalkDepth   = 128
	maxMavenRecords     = 50_000
	maxMavenOutputBytes = 16 << 20
	maxMavenListEntries = 10_000
)

var (
	mavenModernLocks = []string{"gradle.lockfile", "buildscript-gradle.lockfile", "settings-gradle.lockfile"}
	mavenBuildFiles  = []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}
)

// MavenScanner reads Maven and Gradle metadata only: no mvn, gradle,
// wrapper, build script, plugin or Java runs, and no dependency resolution.
type MavenScanner struct {
	exec       executor.Executor
	log        *progress.Logger
	protection func(string, *bool) (func(string) string, func(string) bool)
}

func NewMavenScanner(exec executor.Executor, log *progress.Logger) *MavenScanner {
	if log == nil {
		log = progress.NewNoop()
	}
	return &MavenScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

// mavenRoot is one Maven repository or Gradle module cache to enumerate.
// origin is default, settings or project, which decides where an observed
// repository split applies.
type mavenRoot struct{ path, kind, scope, origin string }

type mavenScan struct {
	ctx                  context.Context
	exec                 executor.Executor
	home, identity, goos string
	roots                []string
	guard                func(string) string
	volume               func(string) bool
	files                executor.Executor
	config               *configaudit.MavenConfigSnapshot
	inv                  model.MavenInventory
	sources              []*model.MavenSource
	byID                 map[string]*model.MavenSource
	cacheRoots           []mavenRoot
	rootKeys             map[string]bool
	split                map[string]bool // project-named roots a project asked to split
	splitSettings        bool            // a project asked to split without naming its root
	pruned               map[string]bool
	owners               map[string]string // pruned path → walk source that reached it
	seen                 map[string]bool
	remaining            int
	bytes                int
	limited              bool
}

func emptyMavenInventory() model.MavenInventory {
	return model.MavenInventory{SchemaVersion: model.MavenInventorySchemaVersion, Status: "complete", Reasons: []string{}, Sources: []model.MavenSource{}, Projects: []model.MavenProject{}, Packages: []model.MavenPackage{}}
}

func (s *MavenScanner) Scan(ctx context.Context, target *user.User, searchDirs []string, includeNetworkVolumes *bool) (*model.MavenInventory, *model.MavenConfigAudit, *model.GradleConfigAudit) {
	start := time.Now()
	inv := emptyMavenInventory()
	configDetector := configaudit.NewMavenConfigDetector(s.exec)
	if target == nil || target.Username == "" || target.HomeDir == "" || !filepath.IsAbs(target.HomeDir) || isGoServiceIdentity(s.exec.GOOS(), target) {
		inv.Status, inv.Reasons = "partial", []string{"user_unresolved"}
		maven, gradle := configDetector.Detect(ctx, configaudit.MavenConfigScope{}).Finish()
		return &inv, &maven, &gradle
	}
	guard, volume := s.protection(target.HomeDir, includeNetworkVolumes)
	// Reserve each audit's separate 256 KiB allowance before collecting inventory.
	c := &mavenScan{ctx: ctx, exec: s.exec, home: filepath.Clean(target.HomeDir), identity: target.Username, goos: s.exec.GOOS(), guard: guard, volume: volume, inv: inv,
		byID: map[string]*model.MavenSource{}, rootKeys: map[string]bool{}, split: map[string]bool{}, pruned: map[string]bool{}, owners: map[string]string{}, seen: map[string]bool{},
		remaining: maxMavenRecords, bytes: goJSONSize(&inv) + (512 << 10)}
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
	c.config = configDetector.Detect(ctx, configaudit.MavenConfigScope{Username: target.Username, Home: c.home, Protected: guard, Volume: volume, ProcessVerified: verified})
	c.guard = c.config.ContentGuard
	c.files = s.exec.GuardedFiles(c.roots, c.guard, maxMavenMetadataBytes)
	// Register every known cache before the walk so it is pruned, not walked.
	c.pruned[c.key(filepath.Join(c.home, ".m2"))] = true
	c.cacheRoot(filepath.Join(c.home, ".m2", "repository"), "maven_repository", "user", "default")
	for _, p := range c.config.RepositoryLeads {
		c.cacheRoot(p, "maven_repository", "custom", "settings")
	}
	c.gradleHome(filepath.Join(c.home, ".gradle"), "user")
	for _, p := range c.config.GradleHomes {
		c.gradleHome(p, "custom")
	}
	c.walkRoots(dirs)
	for _, r := range c.cacheRoots {
		if r.kind == "maven_repository" {
			c.mavenRepository(r)
		}
	}
	for _, r := range c.cacheRoots {
		if r.kind == "gradle_cache" {
			c.gradleCache(r)
		}
	}
	if reason := c.stopReason(); reason != "" {
		c.degrade(nil, reason)
	}
	maven, gradle := c.config.Finish()
	c.finish()
	s.log.Debug("maven scan: inventory=%s (%d sources, %d projects, %d packages) maven audit=%s (%d files) gradle audit=%s (%d files) in %dms",
		c.inv.Status, len(c.inv.Sources), len(c.inv.Projects), len(c.inv.Packages), maven.Status, len(maven.Files), gradle.Status, len(gradle.Files), time.Since(start).Milliseconds())
	return &c.inv, &maven, &gradle
}

func (c *mavenScan) key(p string) string { return configaudit.GoPathKey(c.goos, p) }
func (c *mavenScan) reason(err error, p string) string {
	return configaudit.CargoReadReason(err, p, c.volume)
}
func (c *mavenScan) degrade(src *model.MavenSource, reason string) {
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

// discovery records a cut-short project walk, which also leaves the
// configuration audits without every project they could have observed.
func (c *mavenScan) discovery(src *model.MavenSource, reason string) {
	c.degrade(src, reason)
	c.config.Partial(reason)
}
func (c *mavenScan) charge(src *model.MavenSource, record any) bool {
	if c.remaining <= 0 {
		c.degrade(src, "record_limit")
		return false
	}
	// Reserve later coverage reasons, child IDs and separators per record.
	size := goJSONSize(record) + 128
	if c.limited || c.bytes+size > maxMavenOutputBytes {
		c.limited = true
		c.degrade(src, "output_size_limit")
		return false
	}
	c.remaining--
	c.bytes += size
	return true
}
func (c *mavenScan) stopReason() string {
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
func (c *mavenScan) stopped(src *model.MavenSource) bool {
	if reason := c.stopReason(); reason != "" {
		c.degrade(src, reason)
		return true
	}
	return false
}
func (c *mavenScan) source(kind, path, parent string) *model.MavenSource {
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
	src := &model.MavenSource{SourceID: id, Kind: kind, Path: path, ParentSourceID: parent, Status: "complete", Presence: "present", Reasons: []string{}, DiscoveredSources: []string{}}
	if !c.charge(owner, src) {
		return nil
	}
	c.byID[id] = src
	c.sources = append(c.sources, src)
	return src
}
func (c *mavenScan) fs(path string, limit int64) executor.Executor {
	if configaudit.GoWithinRoots(c.goos, path, c.roots) {
		return c.exec.GuardedFiles(c.roots, c.guard, limit)
	}
	// Cache roots outside the search roots permit access below themselves only.
	return c.exec.GuardedFiles([]string{path}, c.guard, limit)
}

// read loads one file for its source. A file the listing just named but
// that is now missing changed during the scan.
func (c *mavenScan) read(src *model.MavenSource, path string) ([]byte, bool) {
	if c.stopped(src) {
		src.Presence = "unknown"
		return nil, false
	}
	files := c.fs(path, maxMavenMetadataBytes)
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		src.Presence = "unknown"
		c.degrade(src, "changed_during_scan")
		return nil, false
	case err != nil:
		src.Presence = "unknown"
		c.degrade(src, c.reason(err, path))
		return nil, false
	case !info.Mode().IsRegular():
		c.degrade(src, "unsupported_entry")
		return nil, false
	case info.Size() > maxMavenMetadataBytes:
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

// list enumerates one directory for its owner and returns the coverage
// reason when the listing is incomplete. A missing directory is complete with
// no children; any other failure or truncation leaves the owner partial.
func (c *mavenScan) list(owner *model.MavenSource, files executor.Executor, dir string, budget *int) ([]fs.DirEntry, string) {
	if c.stopped(owner) {
		return nil, c.stopReason()
	}
	if *budget <= 0 {
		c.degrade(owner, "entry_limit")
		return nil, "entry_limit"
	}
	entries, more, err := files.ReadDirLimit(dir, min(*budget, maxMavenListEntries))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ""
	}
	if err != nil {
		reason := c.reason(err, dir)
		c.degrade(owner, reason)
		return nil, reason
	}
	*budget -= len(entries)
	if more {
		c.degrade(owner, "entry_limit")
		return entries, "entry_limit"
	}
	return entries, ""
}

// mavenConfigStatus maps a failed read of a source the audit shares onto the
// audit's file status.
func mavenConfigStatus(src *model.MavenSource) (string, []string) {
	for _, r := range src.Reasons {
		switch r {
		case "skipped_protected", "refused_network_volume":
			return "skipped_protected", []string{r}
		case "unsupported_entry":
			return "unsupported", []string{r}
		}
	}
	return "unreadable", slices.Clone(src.Reasons)
}

// cacheRoot registers one repository or module cache once, by physical
// path, so an alias never duplicates its evidence.
func (c *mavenScan) cacheRoot(path, kind, scope, origin string) {
	if !filepath.IsAbs(path) || !composerText(path, 4096) {
		c.degrade(nil, "path_unresolved")
		return
	}
	path = filepath.Clean(path)
	phys := path
	// A stopped scan registers the root unresolved, so it is still reported.
	if c.guard(path) == "" && c.stopReason() == "" {
		if resolved, err := c.fs(path, 0).EvalSymlinks(path); err == nil {
			phys = resolved
		}
	}
	c.pruned[c.key(path)], c.pruned[c.key(phys)] = true, true
	if c.rootKeys[c.key(path)] || c.rootKeys[c.key(phys)] {
		return
	}
	c.rootKeys[c.key(path)], c.rootKeys[c.key(phys)] = true, true
	c.cacheRoots = append(c.cacheRoots, mavenRoot{path, kind, scope, origin})
}

// gradleHome registers a Gradle user home's module cache. The whole home is
// tool state, so the walk never enters it.
func (c *mavenScan) gradleHome(home, scope string) {
	c.pruned[c.key(home)] = true
	c.cacheRoot(filepath.Join(home, "caches", "modules-2", "files-2.1"), "gradle_cache", scope, "default")
}

func (c *mavenScan) skip(path string) bool {
	path = c.key(path)
	for root := range c.pruned {
		if path == root || goPathWithin(path, root) {
			return true
		}
	}
	return false
}

// adopt remembers the walk source that physically reached a pruned cache
// location, so the cache source can be placed under it once it exists.
func (c *mavenScan) adopt(path string, owner *model.MavenSource) {
	if owner != nil {
		if _, ok := c.owners[c.key(path)]; !ok {
			c.owners[c.key(path)] = owner.SourceID
		}
	}
}

// ownerOf returns the walk source covering a cache root, or "" when no walk
// reached it.
func (c *mavenScan) ownerOf(path string) string {
	best, key := "", ""
	for k, id := range c.owners {
		if (c.key(path) == k || goPathWithin(c.key(path), k)) && len(k) > len(key) {
			best, key = id, k
		}
	}
	return best
}
func (c *mavenScan) reasonForGuard(path string) string {
	if c.volume != nil && c.volume(path) {
		return "refused_network_volume"
	}
	return "skipped_protected"
}

func (c *mavenScan) walkRoots(dirs []string) {
	// Outermost logical/physical roots own discovery. Identical physical roots
	// retain the first spelling and never get walked twice.
	type root struct {
		path, phys string
		src        *model.MavenSource
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

func (c *mavenScan) walk(root string, src *model.MavenSource) {
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{root, 0}}
	budget := maxMavenWalkEntries
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
		entries, more, err := c.files.ReadDirLimit(d.path, budget)
		if err != nil {
			c.discovery(src, c.reason(err, d.path))
			continue
		}
		budget -= len(entries)
		if more {
			c.discovery(src, "entry_limit")
		}
		project := c.project(d.path, entries, src)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(d.path, e.Name())
			if c.skip(p) {
				c.adopt(p, src)
				continue
			}
			switch e.Name() {
			case ".git", ".hg", ".svn", "node_modules", "target", ".rustup", ".cache", "__pycache__", ".bundle", ".m2", ".gradle":
				continue
			case "build", ".mvn", "gradle":
				// In a project, build holds generated output and the .mvn and
				// gradle folders were already read with the project.
				if project {
					continue
				}
			}
			if c.guard(p) != "" {
				c.discovery(src, c.reasonForGuard(p))
				continue
			}
			if d.depth+1 > maxMavenWalkDepth {
				c.discovery(src, "depth_limit")
				continue
			}
			queue = append(queue, dir{p, d.depth + 1})
		}
		if more {
			return
		}
	}
}

// project recognizes a Maven or Gradle project from one directory listing
// and its .mvn and gradle folders, reads its supported files, and reports
// whether dir is a project. Build and settings scripts are markers only and
// are never evaluated.
func (c *mavenScan) project(dir string, entries []fs.DirEntry, walk *model.MavenSource) bool {
	has := func(entries []fs.DirEntry, name string, isDir bool) bool {
		return slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name && e.IsDir() == isDir })
	}
	budget := maxMavenListEntries
	// unlisted keeps the first reason a manager's configuration folder was not
	// fully listed, so the audit never reports its unread files as absent.
	unlisted := map[string]string{}
	sub := func(manager string, rel ...string) []fs.DirEntry {
		p := filepath.Join(append([]string{dir}, rel...)...)
		var list []fs.DirEntry
		reason := c.guard(p)
		if reason != "" {
			reason = c.reasonForGuard(p)
			c.degrade(walk, reason)
		} else {
			list, reason = c.list(walk, c.files, p, &budget)
		}
		if reason != "" && manager != "" && unlisted[manager] == "" {
			unlisted[manager] = reason
		}
		return list
	}
	var mvn, gradle, mvnWrapper, gradleWrapper, legacy []fs.DirEntry
	if has(entries, ".mvn", true) {
		mvn = sub("maven", ".mvn")
	}
	if has(entries, "gradle", true) {
		gradle = sub("gradle", "gradle")
	}
	if has(mvn, "wrapper", true) {
		mvnWrapper = sub("maven", ".mvn", "wrapper")
	}
	if has(gradle, "wrapper", true) {
		gradleWrapper = sub("gradle", "gradle", "wrapper")
	}
	// Legacy locks are inventory only; the audit reads no file there.
	if has(gradle, "dependency-locks", true) {
		legacy = sub("", "gradle", "dependency-locks")
	}
	configs := []string{}
	for _, rel := range configaudit.MavenProjectFiles {
		folder, name := filepath.Split(filepath.FromSlash(rel))
		list := entries
		switch filepath.ToSlash(folder) {
		case ".mvn/":
			list = mvn
		case ".mvn/wrapper/":
			list = mvnWrapper
		case "gradle/wrapper/":
			list = gradleWrapper
		}
		if has(list, name, false) {
			configs = append(configs, filepath.Join(dir, folder, name))
		}
	}
	legacyLocks := []string{}
	for _, e := range legacy {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".lockfile") {
			legacyLocks = append(legacyLocks, e.Name())
		}
	}
	pom := has(entries, "pom.xml", false)
	catalog, verification := has(gradle, "libs.versions.toml", false), has(gradle, "verification-metadata.xml", false)
	mavenTool := pom || has(mvn, "maven.config", false) || has(mvn, "jvm.config", false) || has(mvnWrapper, "maven-wrapper.properties", false)
	gradleTool := catalog || verification || len(legacyLocks) > 0 || has(entries, "gradle.properties", false) || has(gradleWrapper, "gradle-wrapper.properties", false) ||
		slices.ContainsFunc(mavenBuildFiles, func(n string) bool { return has(entries, n, false) }) || slices.ContainsFunc(mavenModernLocks, func(n string) bool { return has(entries, n, false) })
	if !mavenTool && !gradleTool {
		// An unlisted folder may have hidden a project, so no context is complete.
		for _, manager := range []string{"maven", "gradle"} {
			if reason := unlisted[manager]; reason != "" {
				c.config.Partial(reason)
			}
		}
		return false
	}
	tool := "unknown"
	switch {
	case !gradleTool:
		tool = "maven"
	case !mavenTool:
		tool = "gradle"
	}
	src := c.source("project", dir, walk.SourceID)
	if src == nil {
		c.config.Partial("output_size_limit")
		return true
	}
	project := model.MavenProject{ProjectPath: dir, SourceID: src.SourceID, Tool: tool}
	if c.charge(src, project) {
		c.inv.Projects = append(c.inv.Projects, project)
	}
	leads := c.config.Project(dir, tool, configs)
	for _, manager := range []string{"maven", "gradle"} {
		if reason := unlisted[manager]; reason != "" {
			c.config.Unlisted(dir, manager, reason)
		}
	}
	for _, p := range leads.Repositories {
		c.cacheRoot(p, "maven_repository", "custom", "project")
		if leads.Split {
			c.split[c.key(p)] = true
		}
	}
	c.splitSettings = c.splitSettings || leads.Split && len(leads.Repositories) == 0
	if pom {
		c.pom(src, dir, filepath.Join(dir, "pom.xml"))
	}
	if catalog {
		c.catalog(src, dir, filepath.Join(dir, "gradle", "libs.versions.toml"))
	}
	named := map[string][]string{}
	for _, name := range mavenModernLocks {
		if has(entries, name, false) {
			if lock := c.lock(src, dir, filepath.Join(dir, name), ""); lock != nil {
				named[name] = lock.named
			}
		}
	}
	for _, name := range legacyLocks {
		modern, conf := mavenLockPair(name)
		p := filepath.Join(dir, "gradle", "dependency-locks", name)
		if confs, ok := named[modern]; ok && slices.Contains(confs, conf) {
			// The modern lock owns this configuration; the legacy file is
			// observed but selects nothing.
			c.source("lockfile", p, src.SourceID)
			continue
		}
		c.lock(src, dir, p, conf)
	}
	if verification {
		c.verification(src, dir, filepath.Join(dir, "gradle", "verification-metadata.xml"))
	}
	return true
}

func (c *mavenScan) pom(project *model.MavenSource, dir, path string) {
	src := c.source("manifest", path, project.SourceID)
	if src == nil {
		return
	}
	data, ok := c.read(src, path)
	if !ok {
		status, reasons := mavenConfigStatus(src)
		c.config.Manifest(dir, path, nil, status, reasons)
		return
	}
	m, err := parseMavenPOM(data)
	if err != nil {
		c.degrade(src, "parse_error")
		c.config.Manifest(dir, path, nil, "invalid", []string{"parse_error"})
		return
	}
	c.config.Manifest(dir, path, m.repositories, "present", nil)
	for _, r := range m.reasons {
		c.degrade(src, r)
	}
	c.declare(src, dir, "maven", m.declarations)
}

func (c *mavenScan) catalog(project *model.MavenSource, dir, path string) {
	src := c.source("version_catalog", path, project.SourceID)
	if src == nil {
		return
	}
	data, ok := c.read(src, path)
	if !ok {
		return
	}
	m, err := parseGradleCatalog(data)
	if err != nil {
		c.degrade(src, "parse_error")
		return
	}
	for _, r := range m.reasons {
		c.degrade(src, r)
	}
	c.declare(src, dir, "gradle", m.declarations)
}

func (c *mavenScan) verification(project *model.MavenSource, dir, path string) {
	src := c.source("verification_metadata", path, project.SourceID)
	if src == nil {
		return
	}
	data, ok := c.read(src, path)
	if !ok {
		status, reasons := mavenConfigStatus(src)
		c.config.Verification(dir, path, configaudit.GradleVerification{}, status, reasons)
		return
	}
	refs, policy, reasons, err := parseGradleVerification(data)
	if err != nil {
		c.degrade(src, "parse_error")
		c.config.Verification(dir, path, policy, "invalid", []string{"parse_error"})
		return
	}
	c.config.Verification(dir, path, policy, "present", nil)
	for _, r := range reasons {
		c.degrade(src, r)
	}
	for _, r := range refs {
		if c.stopped(src) {
			return
		}
		p := c.pkg(r.group, r.artifact, "verification_reference", "gradle", "project", dir)
		p.VersionStatus, p.Version = "known", r.version
		p.Artifact = &model.MavenArtifact{Filename: r.filename}
		for _, h := range r.checksums {
			p.RecordedChecksums = append(p.RecordedChecksums, model.MavenRecordedChecksum{Algorithm: h.algorithm, Value: h.value, Verification: "not_verified"})
		}
		if r.invalid {
			p.Reasons = append(p.Reasons, "checksum_invalid")
			c.degrade(src, "checksum_invalid")
		}
		if r.limited {
			p.Reasons = append(p.Reasons, "record_limit")
			c.degrade(src, "record_limit")
		}
		c.add(src, p, strings.Join([]string{r.group, r.artifact, r.version, r.filename}, ":"))
	}
}

// lock reads one modern or legacy Gradle lockfile and emits its packages. It
// returns nil when the file is unread or holds an invalid line, so that file
// never supersedes legacy lock state.
func (c *mavenScan) lock(project *model.MavenSource, dir, path, legacyConfiguration string) *mavenLock {
	src := c.source("lockfile", path, project.SourceID)
	if src == nil {
		return nil
	}
	data, ok := c.read(src, path)
	if !ok {
		return nil
	}
	lock, err := parseGradleLock(data, legacyConfiguration)
	if err != nil {
		c.degrade(src, "parse_error")
		return nil
	}
	if lock.invalid {
		c.degrade(src, "parse_error")
	}
	for _, e := range lock.entries {
		if c.stopped(src) {
			break
		}
		p := c.pkg(e.group, e.artifact, "locked_package", "gradle", "project", dir)
		p.VersionStatus, p.Version = "known", e.version
		p.Configurations = c.capped(src, &p, e.configurations)
		c.add(src, p, strings.Join([]string{e.group, e.artifact, e.version}, ":"))
	}
	if lock.invalid {
		return nil
	}
	return lock
}

// capped sorts and dedups values and keeps at most maxMavenRequestedSpecs,
// marking p and src record_limit when it drops any.
func (c *mavenScan) capped(src *model.MavenSource, p *model.MavenPackage, values []string) []string {
	values = slices.Clone(values)
	slices.Sort(values)
	values = slices.Compact(values)
	if len(values) > maxMavenRequestedSpecs {
		values = values[:maxMavenRequestedSpecs]
		p.Reasons = append(p.Reasons, "record_limit")
		c.degrade(src, "record_limit")
	}
	return values
}

func (c *mavenScan) pkg(group, artifact, evidence, tool, scope, project string) model.MavenPackage {
	return model.MavenPackage{PackageName: group + ":" + artifact, GroupID: group, ArtifactID: artifact, Evidence: evidence, Tool: tool, Scope: scope, ProjectPath: project,
		VersionStatus: "unknown", RequestedSpecs: []string{}, Configurations: []string{}, RepositoryFormat: "unknown", Origin: model.MavenOrigin{Kind: "unknown"},
		RecordedChecksums: []model.MavenRecordedChecksum{}, Reasons: []string{}}
}

// declare consolidates one file's declarations by occurrence identity,
// unioning their requirements, then charges each once.
func (c *mavenScan) declare(src *model.MavenSource, project, tool string, decls []mavenDeclaration) {
	byKey := map[string]*model.MavenPackage{}
	order := []string{}
	for _, d := range decls {
		// \x01 keeps an absent classifier apart from an empty one.
		cls := "\x01"
		if d.classifier != nil {
			cls = "=" + *d.classifier
		}
		opt := ""
		if d.optional != nil {
			opt = strconv.FormatBool(*d.optional)
		}
		key := strings.Join([]string{d.role, d.profile, d.context, d.group, d.artifact, d.scope, d.declaredType, cls, opt}, "\x00")
		p := byKey[key]
		if p == nil {
			pkg := c.pkg(d.group, d.artifact, "declared_dependency", tool, "project", project)
			pkg.DeclarationRole, pkg.DeclarationContext, pkg.ProfileID = d.role, d.context, d.profile
			pkg.MavenScope, pkg.DeclaredType, pkg.DeclaredClassifier, pkg.Optional = d.scope, d.declaredType, d.classifier, d.optional
			p = &pkg
			byKey[key] = p
			order = append(order, key)
		}
		for _, spec := range d.specs {
			spec, redacted := mavenRequirement(spec)
			if redacted {
				p.Reasons = append(p.Reasons, "redacted_requirement")
				c.degrade(src, "redacted_requirement")
			}
			p.RequestedSpecs = append(p.RequestedSpecs, spec)
		}
	}
	for _, key := range order {
		if c.stopped(src) {
			return
		}
		p := byKey[key]
		p.RequestedSpecs = c.capped(src, p, p.RequestedSpecs)
		c.add(src, *p, key)
	}
}

func (c *mavenScan) add(src *model.MavenSource, p model.MavenPackage, identity string) {
	p.SourceID, p.SourcePath = src.SourceID, src.Path
	for i := range p.RecordedChecksums {
		h := &p.RecordedChecksums[i]
		h.SourceID, h.SourcePath, h.SourceKind = src.SourceID, src.Path, src.Kind
	}
	slices.Sort(p.Reasons)
	p.Reasons = slices.Compact(p.Reasons)
	key := src.SourceID + "\x00" + p.Evidence + "\x00" + identity
	if c.seen[key] {
		return
	}
	if c.charge(src, p) {
		c.seen[key] = true
		c.inv.Packages = append(c.inv.Packages, p)
	}
}

// rootSource creates a cache root's source under the walk source that
// reached it. A missing root is recorded absent so its former facts retire.
func (c *mavenScan) rootSource(r mavenRoot, budget *int) (*model.MavenSource, executor.Executor, []fs.DirEntry) {
	src := c.source(r.kind, r.path, c.ownerOf(r.path))
	if src == nil {
		return nil, nil, nil
	}
	if c.stopped(src) {
		src.Presence = "unknown"
		return nil, nil, nil
	}
	files := c.fs(r.path, maxMavenMetadataBytes)
	entries, more, err := files.ReadDirLimit(r.path, min(*budget, maxMavenListEntries))
	if errors.Is(err, fs.ErrNotExist) {
		src.Presence = "absent"
		return nil, nil, nil
	}
	if err != nil {
		src.Presence = "unknown"
		c.degrade(src, c.reason(err, r.path))
		return nil, nil, nil
	}
	*budget -= len(entries)
	if more {
		c.degrade(src, "entry_limit")
	}
	return src, files, entries
}

// mavenRepository enumerates a Maven local repository's
// group/artifact/baseVersion directories.
func (c *mavenScan) mavenRepository(r mavenRoot) {
	budget := maxMavenWalkEntries
	src, files, entries := c.rootSource(r, &budget)
	if src == nil {
		return
	}
	// A split repository's prefixes cannot be told apart from group segments.
	if c.config.Split || c.split[c.key(r.path)] || c.splitSettings && r.origin != "project" {
		c.degrade(src, "unsupported_layout")
		return
	}
	type dir struct {
		path     string
		segments []string
		entries  []fs.DirEntry
	}
	queue := []dir{{r.path, nil, entries}}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if n := len(d.segments); n >= 3 && c.versionDir(src, files, r, d.path, d.segments, d.entries) {
			continue
		}
		for _, e := range d.entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if len(d.segments)+1 > maxMavenWalkDepth {
				c.degrade(src, "depth_limit")
				continue
			}
			p := filepath.Join(d.path, e.Name())
			if list, reason := c.list(src, files, p, &budget); list != nil || reason == "" {
				queue = append(queue, dir{p, append(slices.Clone(d.segments), e.Name()), list})
			}
		}
	}
}

// versionDir treats dir as group.../artifact/version when its listing holds
// a file named for those coordinates, and reports whether it did so the walk
// stops descending. Unusable coordinates and unconfirmed split-prefix
// branches degrade the repository instead of emitting identities.
func (c *mavenScan) versionDir(repo *model.MavenSource, files executor.Executor, r mavenRoot, dir string, segments []string, entries []fs.DirEntry) bool {
	n := len(segments)
	artifact, version := segments[n-2], segments[n-1]
	group := strings.Join(segments[:n-2], ".")
	type candidate struct {
		entry fs.DirEntry
		file  mavenFile
	}
	candidates := []candidate{}
	for _, e := range entries {
		if e.Type().IsRegular() {
			if f, ok := mavenFilename(e.Name(), artifact, version); ok {
				candidates = append(candidates, candidate{e, f})
			}
		}
	}
	if len(candidates) == 0 {
		return false
	}
	for _, s := range append(slices.Clone(segments[:n-2]), artifact) {
		if reason := mavenCoordinate(s); reason != "" {
			c.degrade(repo, reason)
			return true
		}
	}
	if !mavenVersion(version) {
		c.degrade(repo, "parse_error")
		return true
	}
	// The version's POM, when readable and literal, must name the path's
	// coordinates. A default split prefix is part of the group only when that
	// POM says so; elsewhere the path identity stands without a usable POM.
	prefixed := segments[0] == "cached" || segments[0] == "installed"
	pom := artifact + "-" + version + ".pom"
	if slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == pom }) {
		data, reason := c.descriptor(files, filepath.Join(dir, pom))
		g, a, v, err := mavenPOMIdentity(data)
		literal := reason == "" && err == nil && mavenCoordinate(g) == "" && mavenCoordinate(a) == ""
		switch {
		case reason != "":
			c.degrade(repo, reason)
			if prefixed {
				return true
			}
		case literal && (g != group || a != artifact || v != "" && v != version && !strings.Contains(v, "${")):
			c.degrade(repo, "identity_mismatch")
			return true
		case !literal && prefixed:
			c.degrade(repo, "unsupported_layout")
			return true
		}
	} else if prefixed {
		c.degrade(repo, "unsupported_layout")
		return true
	}
	artifacts := []*model.MavenArtifact{}
	for _, cand := range candidates {
		if a := c.artifact(repo, dir, cand.entry, cand.file); a != nil {
			artifacts = append(artifacts, a)
		}
	}
	if len(artifacts) == 0 {
		return true
	}
	src := c.source("artifact_directory", dir, repo.SourceID)
	if src == nil {
		return true
	}
	local := map[string]bool{}
	if slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == "_remote.repositories" }) {
		// Only the empty-repository marker is kept; other keys stay opaque.
		if data, reason := c.descriptor(files, filepath.Join(dir, "_remote.repositories")); reason != "" {
			c.degrade(src, reason)
		} else {
			props, _ := configaudit.ParseJavaProperties(data)
			for _, p := range props {
				if name, ok := strings.CutSuffix(p.Key, ">"); ok {
					local[name] = true
				}
			}
		}
	}
	for _, a := range artifacts {
		if c.stopped(src) {
			return true
		}
		a.LocalInstallMarkerPresent = local[a.Filename]
		c.cached(src, a, group, artifact, version, "maven", "maven", r.scope)
	}
	return true
}

// artifact describes one non-empty regular cache file; nil skips it.
func (c *mavenScan) artifact(owner *model.MavenSource, dir string, e fs.DirEntry, f mavenFile) *model.MavenArtifact {
	info, err := e.Info()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		c.degrade(owner, c.reason(err, filepath.Join(dir, e.Name())))
		return nil
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil
	}
	role := "payload"
	if f.extension != "jar" && f.extension != "aar" {
		role = "metadata"
	}
	return &model.MavenArtifact{Filename: e.Name(), Path: filepath.Join(dir, e.Name()), ArtifactRole: role, SizeBytes: info.Size(), Extension: f.extension, Classifier: f.classifier, FileVersion: f.fileVersion}
}

// cached records one physical cache file as its own source and package.
func (c *mavenScan) cached(owner *model.MavenSource, a *model.MavenArtifact, group, artifact, version, tool, format, scope string) *model.MavenSource {
	src := c.source("cached_artifact", a.Path, owner.SourceID)
	if src == nil {
		return nil
	}
	if strings.HasSuffix(version, "SNAPSHOT") {
		a.BaseVersion = version
	}
	p := c.pkg(group, artifact, "cached_artifact", tool, scope, "")
	p.VersionStatus, p.Version, p.RepositoryFormat, p.Artifact = "known", version, format, a
	c.add(src, p, a.Path)
	return src
}

// gradleCache enumerates files-2.1/<group>/<module>/<version>/<key>/<file>.
func (c *mavenScan) gradleCache(r mavenRoot) {
	budget := maxMavenWalkEntries
	src, files, groups := c.rootSource(r, &budget)
	if src == nil {
		return
	}
	for _, g := range groups {
		if !g.IsDir() || mavenCoordinate(g.Name()) != "" {
			continue
		}
		modules, _ := c.list(src, files, filepath.Join(r.path, g.Name()), &budget)
		for _, m := range modules {
			if !m.IsDir() || mavenCoordinate(m.Name()) != "" {
				continue
			}
			versions, _ := c.list(src, files, filepath.Join(r.path, g.Name(), m.Name()), &budget)
			for _, v := range versions {
				if v.IsDir() && mavenVersion(v.Name()) {
					c.gradleVersion(src, files, r, g.Name(), m.Name(), v.Name(), &budget)
				}
			}
		}
	}
}

func (c *mavenScan) gradleVersion(cache *model.MavenSource, files executor.Executor, r mavenRoot, group, module, version string, budget *int) {
	dir := filepath.Join(r.path, group, module, version)
	keys, _ := c.list(cache, files, dir, budget)
	type candidate struct {
		key   string
		entry fs.DirEntry
	}
	candidates := []candidate{}
	for _, k := range keys {
		if !k.IsDir() || !mavenContentKey.MatchString(k.Name()) {
			continue
		}
		list, _ := c.list(cache, files, filepath.Join(dir, k.Name()), budget)
		for _, e := range list {
			if e.Type().IsRegular() {
				candidates = append(candidates, candidate{k.Name(), e})
			}
		}
	}
	var src *model.MavenSource
	for _, cand := range candidates {
		name := cand.entry.Name()
		ivy := name == "ivy-"+version+".xml"
		f, conventional := mavenFilename(name, module, version)
		if !ivy && !conventional {
			ext := strings.TrimPrefix(filepath.Ext(name), ".")
			if ext != "jar" && ext != "aar" {
				continue
			}
			// An unconventional payload name keeps no classifier guess.
			f = mavenFile{extension: ext}
		}
		if ivy {
			f = mavenFile{extension: "xml"}
		}
		if c.stopped(cache) {
			return
		}
		path := filepath.Join(dir, cand.key)
		a := c.artifact(cache, path, cand.entry, f)
		if a == nil {
			continue
		}
		a.ContentKey = cand.key
		if ivy {
			a.ArtifactRole = "metadata"
		}
		format, reason := "unknown", ""
		if ivy || f.extension == "pom" {
			var data []byte
			data, reason = c.descriptor(files, a.Path)
			switch {
			case reason != "":
				// The file is observed even though its format is not established.
			case ivy && !mavenIvyMatches(data, group, module, version):
				// Not a recognized descriptor, so not a supported file.
				continue
			case ivy:
				format = "ivy"
			default:
				if g, m, v, err := mavenPOMIdentity(data); err == nil && g == group && m == module && v == version {
					format = "maven"
				}
			}
		}
		if src == nil {
			if src = c.source("artifact_directory", dir, cache.SourceID); src == nil {
				return
			}
		}
		if file := c.cached(src, a, group, module, version, "gradle", format, r.scope); file != nil && reason != "" {
			c.degrade(file, reason)
		}
	}
}

// descriptor reads one bounded cache descriptor before its file becomes a
// source, returning the coverage reason when it cannot be read.
func (c *mavenScan) descriptor(files executor.Executor, path string) ([]byte, string) {
	if reason := c.stopReason(); reason != "" {
		return nil, reason
	}
	// The guarded reader refuses an oversized file, so size is checked first.
	if info, err := files.Stat(path); err == nil && info.Size() > maxMavenMetadataBytes {
		return nil, "size_limit"
	}
	data, err := files.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "changed_during_scan"
	case err != nil:
		return nil, c.reason(err, path)
	}
	return data, ""
}

func (c *mavenScan) finish() {
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
	slices.SortFunc(c.inv.Sources, func(a, b model.MavenSource) int {
		return strings.Compare(a.Path+"\x00"+a.Kind, b.Path+"\x00"+b.Kind)
	})
	slices.SortFunc(c.inv.Projects, func(a, b model.MavenProject) int { return strings.Compare(a.ProjectPath, b.ProjectPath) })
	artifact := func(p model.MavenPackage) string {
		if p.Artifact == nil {
			return ""
		}
		return p.Artifact.Filename + "\x00" + p.Artifact.ContentKey
	}
	slices.SortStableFunc(c.inv.Packages, func(a, b model.MavenPackage) int {
		return cmp.Or(strings.Compare(a.SourcePath, b.SourcePath), strings.Compare(a.Evidence, b.Evidence), strings.Compare(a.PackageName, b.PackageName), strings.Compare(a.Version, b.Version),
			strings.Compare(a.DeclarationRole, b.DeclarationRole), strings.Compare(a.ProfileID, b.ProfileID), strings.Compare(a.DeclarationContext, b.DeclarationContext), strings.Compare(artifact(a), artifact(b)))
	})
	slices.Sort(c.inv.Reasons)
}
