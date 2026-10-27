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
	maxRubyWalkEntries = 100_000
	maxRubyWalkDepth   = 128
	maxRubyRecords     = 50_000
	maxRubyOutputBytes = 16 << 20
	maxRubyListEntries = 10_000
)

// maxRubyEvalDepth keeps eval_gemfile chains within the eight-ancestor
// source bound: search root, manifest, evaluated manifests, then a gemspec.
const maxRubyEvalDepth = 4

// RubyScanner reads metadata only. The raw executor is required because a
// UserAwareExecutor may source a login shell when reading environment values.
type RubyScanner struct {
	exec       executor.Executor
	log        *progress.Logger
	protection func(string, *bool) (func(string) string, func(string) bool)
}

func NewRubyScanner(exec executor.Executor, log *progress.Logger) *RubyScanner {
	if log == nil {
		log = progress.NewNoop()
	}
	return &RubyScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

// rubyFile is a Gemfile, evaluated Gemfile or gemspec read once. Referenced
// files can be shared by several projects.
type rubyFile struct {
	src      *model.RubySource
	manifest *rubyManifest
	status   string // configuration file status vocabulary
	ref      bool
}

type rubyProjectState struct {
	project       model.RubyProject
	gemspec, kept bool
}

type rubyDiskLock struct{ path, parent string }

// rubyInstall builds a receipt's installation from its validated identity.
type rubyInstall func(name, version, platform string, p *model.RubyPackage) *model.RubyInstallation

const (
	rubyCacheArchives = iota // gem home cache: *.gem
	rubyCacheSlugs           // Bundler user cache: <source slug>/*.gem
	rubyCacheVendor          // project cache: *.gem and serialized checkout stubs
)

type rubyScan struct {
	ctx                  context.Context
	exec                 executor.Executor
	home, identity, goos string
	roots                []string
	guard                func(string) string
	volume               func(string) bool
	files                executor.Executor
	config               *configaudit.RubyConfigSnapshot
	inv                  model.RubyInventory
	sources              []*model.RubySource
	byID                 map[string]*model.RubySource
	projects             map[string]*rubyProjectState
	projectDirs          map[string]string
	reads                map[string]*rubyFile
	locks                map[string]bool
	diskLocks            map[string]rubyDiskLock
	homes                map[string]bool
	caches               map[string]bool
	pruned               map[string]bool
	seen                 map[string]bool
	remaining            int
	bytes                int
	limited              bool
	unproven             []string // coverage lost by a consumer of shared manifests
}

func emptyRubyInventory() model.RubyInventory {
	return model.RubyInventory{SchemaVersion: model.RubyInventorySchemaVersion, Status: "complete", Reasons: []string{}, Sources: []model.RubySource{}, Projects: []model.RubyProject{}, Packages: []model.RubyPackage{}}
}

func (s *RubyScanner) Scan(ctx context.Context, target *user.User, searchDirs []string, includeNetworkVolumes *bool) (*model.RubyInventory, *model.RubyConfigAudit) {
	start := time.Now()
	inv := emptyRubyInventory()
	configDetector := configaudit.NewRubyConfigDetector(s.exec)
	if target == nil || target.Username == "" || target.HomeDir == "" || !filepath.IsAbs(target.HomeDir) || isGoServiceIdentity(s.exec.GOOS(), target) {
		inv.Status, inv.Reasons = "partial", []string{"user_unresolved"}
		audit := configDetector.Detect(ctx, configaudit.RubyConfigScope{}).Finish()
		return &inv, &audit
	}
	guard, volume := s.protection(target.HomeDir, includeNetworkVolumes)
	// Reserve the audit's separate 256 KiB allowance before collecting inventory.
	c := &rubyScan{ctx: ctx, exec: s.exec, home: filepath.Clean(target.HomeDir), identity: target.Username, goos: s.exec.GOOS(), guard: guard, volume: volume, inv: inv,
		byID: map[string]*model.RubySource{}, projects: map[string]*rubyProjectState{}, projectDirs: map[string]string{}, reads: map[string]*rubyFile{}, locks: map[string]bool{}, diskLocks: map[string]rubyDiskLock{},
		homes: map[string]bool{}, caches: map[string]bool{}, pruned: map[string]bool{}, seen: map[string]bool{}, remaining: maxRubyRecords, bytes: goJSONSize(&inv) + (256 << 10)}
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
	c.config = configDetector.Detect(ctx, configaudit.RubyConfigScope{Username: target.Username, Home: c.home, Protected: guard, Volume: volume, ProcessVerified: verified})
	c.guard = c.config.ContentGuard
	c.files = s.exec.GuardedFiles(c.roots, c.guard, maxRubyMetadataBytes)
	c.config.Prefixes(c.knownRoots())
	// Configured leads follow standard roots, so a shared root keeps its scope.
	for _, home := range c.config.GemHomes {
		c.gemHome(home, "user", "", "")
	}
	if c.config.UserPlugin != "" {
		c.gemHome(c.config.UserPlugin, "user", "", "")
	}
	if c.config.UserCache != "" {
		c.cacheRoot(filepath.Join(c.config.UserCache, "gems"), "user", "", "", rubyCacheSlugs)
	}
	if c.config.Gemfile != "" {
		c.project(c.config.Gemfile, "", true)
	}
	c.walkRoots(dirs)
	c.independentLocks()
	if reason := c.stopReason(); reason != "" {
		c.unprove(reason)
	}
	// An unread or undiscovered consumer may use any shared file, so no
	// shared declaration's absence is proven.
	for _, f := range c.reads {
		if f.ref {
			for _, reason := range c.unproven {
				c.degrade(f.src, reason)
			}
		}
	}
	audit := c.config.Finish()
	c.finish()
	if goJSONSize(&c.inv)+goJSONSize(&audit) > maxRubyOutputBytes {
		c.inv = emptyRubyInventory()
		c.degrade(nil, "output_size_limit")
	}
	s.log.Debug("ruby scan: inventory=%s (%d sources, %d projects, %d packages) audit=%s (%d files, %d findings) in %dms",
		c.inv.Status, len(c.inv.Sources), len(c.inv.Projects), len(c.inv.Packages), audit.Status, len(audit.Files), len(audit.Findings), time.Since(start).Milliseconds())
	return &c.inv, &audit
}
func (c *rubyScan) key(p string) string { return configaudit.GoPathKey(c.goos, p) }
func (c *rubyScan) reason(err error, p string) string {
	return configaudit.CargoReadReason(err, p, c.volume)
}
func (c *rubyScan) degrade(src *model.RubySource, reason string) {
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
func (c *rubyScan) charge(src *model.RubySource, record any) bool {
	if c.remaining <= 0 {
		c.degrade(src, "record_limit")
		return false
	}
	// Reserve later coverage reasons, child IDs and separators per record.
	size := goJSONSize(record) + 128
	if c.limited || c.bytes+size > maxRubyOutputBytes {
		c.limited = true
		c.degrade(src, "output_size_limit")
		return false
	}
	c.remaining--
	c.bytes += size
	return true
}

// unprove records coverage a consumer of shared manifests lost.
func (c *rubyScan) unprove(reason string) {
	if !slices.Contains(c.unproven, reason) {
		c.unproven = append(c.unproven, reason)
	}
}

// unvisited degrades a walk that may have missed a consumer.
func (c *rubyScan) unvisited(src *model.RubySource, reason string) {
	c.degrade(src, reason)
	c.unprove(reason)
}
func (c *rubyScan) stopReason() string {
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
func (c *rubyScan) stopped(src *model.RubySource) bool {
	if reason := c.stopReason(); reason != "" {
		c.degrade(src, reason)
		return true
	}
	return false
}
func (c *rubyScan) source(kind, path, parent string) *model.RubySource {
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
	src := &model.RubySource{SourceID: id, Kind: kind, Path: path, ParentSourceID: parent, Status: "complete", Presence: "present", Reasons: []string{}, DiscoveredSources: []string{}}
	if !c.charge(owner, src) {
		return nil
	}
	c.byID[id] = src
	c.sources = append(c.sources, src)
	return src
}
func (c *rubyScan) fs(path string, limit int64) executor.Executor {
	if configaudit.GoWithinRoots(c.goos, path, c.roots) {
		return c.exec.GuardedFiles(c.roots, c.guard, limit)
	}
	// Exact metadata and shared roots permit only targeted access, never a new walk.
	return c.exec.GuardedFiles([]string{path}, c.guard, limit)
}
func (c *rubyScan) read(src *model.RubySource, targeted bool, limit int64) ([]byte, bool) {
	if c.stopped(src) {
		src.Presence = "unknown"
		return nil, false
	}
	files := c.fs(src.Path, limit)
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
	case info.Size() > limit:
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

// list enumerates one directory for its owner. A missing directory has no
// children; any other failure or truncation leaves the owner partial.
func (c *rubyScan) list(owner *model.RubySource, dir string) []fs.DirEntry {
	if c.stopped(owner) {
		return nil
	}
	entries, more, err := c.fs(dir, 0).ReadDirLimit(dir, maxRubyListEntries)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		c.degrade(owner, c.reason(err, dir))
		return nil
	}
	if more {
		c.degrade(owner, "entry_limit")
	}
	return entries
}

// expand matches `*` segments against guarded directory listings, never Glob.
// It also returns why any listing left the match set incomplete.
func (c *rubyScan) expand(base string, parts ...string) ([]string, []string) {
	paths := []string{base}
	var reasons []string
	for _, part := range parts {
		var next []string
		for _, p := range paths {
			if !strings.Contains(part, "*") {
				next = append(next, filepath.Join(p, part))
				continue
			}
			if c.stopped(nil) {
				return nil, append(reasons, c.stopReason())
			}
			entries, more, err := c.fs(p, 0).ReadDirLimit(p, maxRubyListEntries)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					reason := c.reason(err, p)
					c.degrade(nil, reason)
					reasons = append(reasons, reason)
				}
				continue
			}
			if more {
				c.degrade(nil, "entry_limit")
				reasons = append(reasons, "entry_limit")
			}
			pattern := part
			if c.goos == model.PlatformWindows {
				pattern = strings.ToLower(part)
			}
			for _, e := range entries {
				name := e.Name()
				if c.goos == model.PlatformWindows {
					name = strings.ToLower(name)
				}
				if ok, _ := filepath.Match(pattern, name); ok && (e.IsDir() || e.Type()&fs.ModeSymlink != 0) {
					next = append(next, filepath.Join(p, e.Name()))
				}
			}
		}
		paths = next
	}
	return paths, reasons
}

func (c *rubyScan) scopeOf(path string) string {
	if configaudit.GoWithinRoots(c.goos, path, []string{c.home}) {
		return "user"
	}
	return "system"
}

// knownRoots enumerates runtime-manager and shared gem homes and returns the
// interpreter prefixes that held one, for their compiled-sysconfdir gemrc,
// with the reasons prefix discovery was incomplete.
func (c *rubyScan) knownRoots() ([]string, []string) {
	type root struct {
		base  string
		parts []string
	}
	home, env := c.home, c.config.Env
	prefixes := []root{
		{cmp.Or(env("RBENV_ROOT"), filepath.Join(home, ".rbenv")), []string{"versions", "*"}},
		{filepath.Join(home, ".rvm"), []string{"rubies", "*"}},
		{cmp.Or(env("ASDF_DATA_DIR"), filepath.Join(home, ".asdf")), []string{"installs", "ruby", "*"}},
		{cmp.Or(env("MISE_DATA_DIR"), filepath.Join(home, ".local", "share", "mise")), []string{"installs", "ruby", "*"}},
		{filepath.Join(home, ".rubies"), []string{"*"}},
	}
	homes := []root{
		{filepath.Join(home, ".gem"), []string{"*", "*"}},
		{filepath.Join(cmp.Or(env("XDG_DATA_HOME"), filepath.Join(home, ".local", "share")), "gem"), []string{"*", "*"}},
		{filepath.Join(home, ".rvm", "gems"), []string{"*"}},
	}
	// Homebrew: the prefix's shared gems, the opt link, and bounded Cellar kegs
	// whose default-gem receipts can outlive a moved opt link.
	brew := func(prefix string) {
		prefixes = append(prefixes, root{prefix, nil}, root{prefix, []string{"opt", "ruby*"}}, root{prefix, []string{"Cellar", "ruby*", "*"}})
	}
	switch c.goos {
	case model.PlatformDarwin:
		prefixes = append(prefixes, root{"/System/Library/Frameworks/Ruby.framework/Versions", []string{"*", "usr"}}, root{"/opt/rubies", []string{"*"}})
		homes = append(homes, root{"/Library/Ruby/Gems", []string{"*"}})
		brew("/opt/homebrew")
		brew("/usr/local")
	case model.PlatformLinux:
		prefixes = append(prefixes, root{"/usr", nil}, root{"/usr/local", nil}, root{"/opt/rubies", []string{"*"}})
		homes = append(homes, root{"/var/lib/gems", []string{"*"}}, root{"/usr/share/rubygems-integration", []string{"*"}}, root{"/usr/lib", []string{"*-linux-gnu*", "rubygems-integration", "*"}})
		brew("/home/linuxbrew/.linuxbrew")
	case model.PlatformWindows:
		prefixes = append(prefixes, root{filepath.Join(home, "AppData", "Local", "Programs"), []string{"Ruby*"}},
			root{`C:\Program Files`, []string{"Ruby*"}}, root{`C:\`, []string{"Ruby*"}}, root{`C:\tools`, []string{"ruby*"}})
	}
	out := []string{}
	seen := map[string]bool{}
	var incomplete []string
	for _, r := range prefixes {
		candidates, reasons := c.expand(r.base, r.parts...)
		incomplete = append(incomplete, reasons...)
		for _, p := range candidates {
			if c.stopped(nil) {
				return out, append(incomplete, c.stopReason())
			}
			phys := p
			if resolved, err := c.fs(p, 0).EvalSymlinks(p); err == nil {
				phys = resolved
			}
			if seen[c.key(phys)] {
				continue
			}
			seen[c.key(phys)] = true
			scope := c.scopeOf(p)
			found := false
			gemHomes, reasons := c.expand(phys, "lib", "ruby", "gems", "*")
			incomplete = append(incomplete, reasons...)
			for _, h := range gemHomes {
				found = c.gemHome(h, scope, "", "") || found
			}
			// TruffleRuby keeps its gem home directly under lib.
			found = c.gemHome(filepath.Join(phys, "lib", "gems"), scope, "", "") || found
			if !found {
				continue
			}
			out = append(out, phys)
			if scope == "user" {
				// A manager-installed interpreter is never a project tree;
				// shared system prefixes like /usr can still contain projects.
				c.pruned[c.key(p)], c.pruned[c.key(phys)] = true, true
			}
		}
	}
	// A stopped gem-home probe can hide a prefix without a listing failure.
	if reason := c.stopReason(); reason != "" {
		incomplete = append(incomplete, reason)
	}
	for _, r := range homes {
		paths, _ := c.expand(r.base, r.parts...)
		for _, p := range paths {
			c.gemHome(p, c.scopeOf(p), "", "")
		}
	}
	return out, incomplete
}

// gemHome enumerates one RubyGems directory: ordinary and default receipts,
// its archive cache and Bundler's Git checkouts. It reports whether path is
// a gem home, including one already enumerated under another spelling.
func (c *rubyScan) gemHome(path, scope, parent, project string) bool {
	owner := c.byID[parent]
	if !filepath.IsAbs(path) || !composerText(path, 4096) {
		c.degrade(owner, "path_unresolved")
		return false
	}
	path = filepath.Clean(path)
	if c.homes[c.key(path)] {
		return true
	}
	if c.stopped(owner) {
		return false
	}
	files := c.fs(path, 0)
	specs := filepath.Join(path, "specifications")
	info, err := files.Stat(specs)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	phys := path
	if resolved, err := files.EvalSymlinks(path); err == nil {
		phys = resolved
	}
	// Opt/Cellar and other aliases keep the first safe spelling.
	duplicate := c.homes[c.key(phys)]
	c.homes[c.key(path)], c.homes[c.key(phys)] = true, true
	c.pruned[c.key(path)], c.pruned[c.key(phys)] = true, true
	if duplicate {
		return true
	}
	src := c.source("gem_home", path, parent)
	if src == nil {
		return true
	}
	if err != nil {
		src.Presence = "unknown"
		c.degrade(src, c.reason(err, specs))
		return true
	}
	if !info.IsDir() {
		c.degrade(src, "unsupported_entry")
		return true
	}
	ordinary := func(name, version, platform string, p *model.RubyPackage) *model.RubyInstallation {
		dir := name + "-" + version
		if platform != "ruby" {
			dir += "-" + platform
		}
		return c.presence(filepath.Join(path, "gems", dir), p)
	}
	builtin := func(string, string, string, *model.RubyPackage) *model.RubyInstallation {
		// Default gems can live in Ruby's own library, with no package directory.
		return &model.RubyInstallation{PathStatus: "not_applicable", Presence: "not_applicable", DefaultGem: true}
	}
	for _, e := range c.list(src, specs) {
		p := filepath.Join(specs, e.Name())
		switch {
		case e.IsDir() && e.Name() == "default":
			for _, d := range c.list(src, p) {
				if !d.IsDir() && strings.HasSuffix(d.Name(), ".gemspec") {
					c.stub(filepath.Join(p, d.Name()), "installed_metadata", src, "installed_package", scope, project, builtin)
				}
			}
		case !e.IsDir() && strings.HasSuffix(e.Name(), ".gemspec"):
			c.stub(p, "installed_metadata", src, "installed_package", scope, project, ordinary)
		}
	}
	c.cacheRoot(filepath.Join(path, "cache"), scope, src.SourceID, project, rubyCacheArchives)
	checkouts := filepath.Join(path, "bundler", "gems")
	for _, e := range c.list(src, checkouts) {
		if !e.IsDir() || c.stopped(src) {
			continue
		}
		co := c.source("bundler_checkout", filepath.Join(checkouts, e.Name()), src.SourceID)
		if co == nil {
			continue
		}
		for _, gs := range c.checkoutGemspecs(co, co.Path) {
			// Each monorepo gemspec is installed in its own directory.
			dir := filepath.Dir(gs)
			c.stub(gs, "installed_metadata", co, "installed_package", scope, project, func(string, string, string, *model.RubyPackage) *model.RubyInstallation {
				return &model.RubyInstallation{Path: dir, PathStatus: "resolved", Presence: "present"}
			})
		}
	}
	return true
}

// presence stats a receipt's package directory. A missing directory changes
// presence only, never the receipt source's completeness.
func (c *rubyScan) presence(path string, p *model.RubyPackage) *model.RubyInstallation {
	out := &model.RubyInstallation{Path: path, PathStatus: "resolved", Presence: "present"}
	if !composerText(path, 4096) {
		out.Path, out.PathStatus, out.Presence = "", "unresolved", "unknown"
		p.Reasons = append(p.Reasons, "path_unresolved")
		return out
	}
	info, err := c.fs(path, 0).Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		out.Presence = "absent"
	case err != nil:
		out.Presence = "unknown"
		p.Reasons = append(p.Reasons, c.reason(err, path))
	case !info.IsDir():
		out.Presence = "unknown"
		p.Reasons = append(p.Reasons, "unsupported_entry")
	}
	return out
}

// checkoutGemspecs follows Bundler's `{,*,*/*}.gemspec` default glob.
func (c *rubyScan) checkoutGemspecs(owner *model.RubySource, dir string) []string {
	var out []string
	for _, e := range c.list(owner, dir) {
		p := filepath.Join(dir, e.Name())
		if !e.IsDir() {
			if strings.HasSuffix(e.Name(), ".gemspec") {
				out = append(out, p)
			}
			continue
		}
		if e.Name() == ".git" {
			continue
		}
		for _, child := range c.list(owner, p) {
			if !child.IsDir() && strings.HasSuffix(child.Name(), ".gemspec") {
				out = append(out, filepath.Join(p, child.Name()))
			}
		}
	}
	return out
}

func (c *rubyScan) cacheRoot(path, scope, parent, project string, mode int) {
	owner := c.byID[parent]
	if path == "" || c.caches[c.key(path)] || c.stopped(owner) {
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
	for _, e := range c.list(src, path) {
		if c.stopped(src) {
			return
		}
		p := filepath.Join(path, e.Name())
		switch {
		case !e.IsDir() && strings.HasSuffix(e.Name(), ".gem") && mode != rubyCacheSlugs:
			c.archive(p, src, scope, project)
		case e.IsDir() && mode == rubyCacheSlugs:
			// Only archive payloads; compact-index and bare Git caches are never packages.
			for _, a := range c.list(src, p) {
				if !a.IsDir() && strings.HasSuffix(a.Name(), ".gem") {
					c.archive(filepath.Join(p, a.Name()), src, scope, project)
				}
			}
		case e.IsDir() && mode == rubyCacheVendor:
			// A vendored checkout is cached, never installed, even when complete.
			for _, gs := range c.checkoutGemspecs(src, p) {
				c.stub(gs, "cached_metadata", src, "cached_package", scope, project, nil)
			}
		}
	}
}

func rubyParseReason(err error) string {
	if errors.Is(err, errRubyUnsupportedFormat) {
		return "unsupported_format"
	}
	return "parse_error"
}

// rubyFact is identity-only evidence: receipts and caches never assert origin
// or dependency relation.
func rubyFact(name, version, platform string) model.RubyPackage {
	return model.RubyPackage{PackageName: name, Reasons: []string{}, VersionStatus: "known", Version: version, Platform: platform, DependencyRelation: "unknown",
		DependencyKind: "unknown", Origin: model.RubyOrigin{Kind: "unknown"}, ChecksumStatus: "absent", RecordedChecksums: []model.RubyRecordedChecksum{}}
}

func (c *rubyScan) stub(path, kind string, owner *model.RubySource, evidence, scope, project string, install rubyInstall) {
	src := c.source(kind, path, owner.SourceID)
	if src == nil {
		return
	}
	data, ok := c.read(src, false, maxRubyMetadataBytes)
	if !ok {
		return
	}
	name, version, platform, err := parseRubyStub(data)
	if err != nil {
		c.degrade(src, rubyParseReason(err))
		return
	}
	p := rubyFact(name, version, platform)
	if install != nil {
		p.Installation = install(name, version, platform, &p)
	}
	c.add(src, p, evidence, project, scope)
}

func (c *rubyScan) archive(path string, owner *model.RubySource, scope, project string) {
	src := c.source("cache_archive", path, owner.SourceID)
	if src == nil {
		return
	}
	data, ok := c.read(src, false, maxRubyArchiveBytes)
	if !ok {
		return
	}
	name, version, platform, reason := parseRubyArchive(data)
	if reason != "" {
		c.degrade(src, reason)
		return
	}
	c.add(src, rubyFact(name, version, platform), "cached_package", project, scope)
}

func rubyPackageKey(p model.RubyPackage) string { b, _ := json.Marshal(p); return string(b) }
func (c *rubyScan) add(src *model.RubySource, p model.RubyPackage, evidence, project, scope string) {
	p.SourceID, p.SourcePath, p.Evidence, p.ProjectPath, p.Scope = src.SourceID, src.Path, evidence, project, scope
	for i := range p.RecordedChecksums {
		h := &p.RecordedChecksums[i]
		h.SourceID, h.SourcePath, h.SourceKind = src.SourceID, src.Path, src.Kind
	}
	slices.Sort(p.Reasons)
	p.Reasons = slices.Compact(p.Reasons)
	// The same file reached twice for one project is one observation.
	key := rubyPackageKey(p)
	if c.seen[key] {
		return
	}
	if c.charge(src, p) {
		c.seen[key] = true
		c.inv.Packages = append(c.inv.Packages, p)
	}
}

// resolve applies Ruby's expand_path against a file's directory.
func (c *rubyScan) resolve(p, base string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		p = filepath.Join(c.home, p[1:])
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	if p = filepath.Clean(p); !composerText(p, 4096) {
		return ""
	}
	return p
}

// localOrigin is a device-scoped path resolved only against known project
// context, like Composer's local repositories.
func (c *rubyScan) localOrigin(raw, base string, p *model.RubyPackage) model.RubyOrigin {
	path := raw
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		path = c.home + string(filepath.Separator) + filepath.FromSlash(path[min(2, len(path)):])
	}
	if !filepath.IsAbs(path) {
		if base == "" {
			p.Reasons = append(p.Reasons, "path_unresolved")
			return model.RubyOrigin{Kind: "unknown"}
		}
		path = base + string(filepath.Separator) + filepath.FromSlash(path)
	}
	// A stopped scan keeps already-parsed declarations but resolves nothing.
	if !composerText(path, 4096) || c.stopped(nil) {
		p.Reasons = append(p.Reasons, "path_unresolved")
		return model.RubyOrigin{Kind: "unknown"}
	}
	resolved, err := c.fs(path, 0).EvalSymlinks(path)
	if err != nil {
		p.Reasons = append(p.Reasons, "path_unresolved")
		return model.RubyOrigin{Kind: "unknown"}
	}
	return model.RubyOrigin{Kind: "path", Path: resolved}
}

func (c *rubyScan) manifestFile(src *model.RubySource, targeted, gemspec bool) *rubyFile {
	if f := c.reads[c.key(src.Path)]; f != nil {
		return f
	}
	f := &rubyFile{src: src, status: "present"}
	c.reads[c.key(src.Path)] = f
	data, ok := c.read(src, targeted, maxRubyMetadataBytes)
	if !ok {
		f.status = "unreadable"
		switch {
		case src.Presence == "absent":
			f.status = "absent"
		case slices.Contains(src.Reasons, "skipped_protected") || slices.Contains(src.Reasons, "refused_network_volume"):
			f.status = "skipped_protected"
		}
		return f
	}
	parse := parseRubyGemfile
	if gemspec {
		parse = parseRubyGemspec
	}
	m, err := parse(data)
	switch {
	case errors.Is(err, errRubyUnsupportedFormat):
		f.status = "unsupported"
		c.degrade(src, "unsupported_format")
	case err != nil:
		f.status = "invalid"
		c.degrade(src, "parse_error")
	default:
		f.manifest = m
		if m.partial {
			c.degrade(src, "parse_error")
		}
	}
	return f
}

// referenced reads an eval_gemfile or gemspec target once; later consumers
// reuse it and its first referencing file stays the owner.
func (c *rubyScan) referenced(path, kind string, parent *model.RubySource) *rubyFile {
	if f := c.reads[c.key(path)]; f != nil {
		f.ref = true
		return f
	}
	src := c.source(kind, path, parent.SourceID)
	if src == nil {
		return nil
	}
	f := c.manifestFile(src, true, kind == "gemspec")
	f.ref = true
	return f
}

func (c *rubyScan) evals(f *rubyFile, visited map[string]bool, depth int, tree *[]*rubyFile) bool {
	complete := true
	for _, rel := range f.manifest.evals {
		path := c.resolve(rel, filepath.Dir(f.src.Path))
		switch {
		case path == "":
			c.degrade(f.src, "path_unresolved")
			complete = false
			continue
		case visited[c.key(path)]:
			continue
		case depth >= maxRubyEvalDepth:
			c.degrade(f.src, "depth_limit")
			complete = false
			continue
		}
		visited[c.key(path)] = true
		ref := c.referenced(path, "manifest", f.src)
		if ref == nil {
			complete = false
			continue
		}
		*tree = append(*tree, ref)
		if ref.manifest == nil || !c.evals(ref, visited, depth+1, tree) {
			complete = false
		}
	}
	return complete
}

// gemspecRefs resolves each `gemspec` directive like Bundler: one
// `{,*}.gemspec` in the directory, or the one whose name matches.
func (c *rubyScan) gemspecRefs(f *rubyFile) ([]*rubyFile, bool) {
	var out []*rubyFile
	complete := true
	for _, ref := range f.manifest.gemspecs {
		if c.stopped(f.src) {
			return out, false
		}
		dir := c.resolve(ref.path, filepath.Dir(f.src.Path))
		if dir == "" {
			c.degrade(f.src, "path_unresolved")
			complete = false
			continue
		}
		entries, more, err := c.fs(dir, 0).ReadDirLimit(dir, maxRubyListEntries)
		if err != nil {
			reason := c.reason(err, dir)
			if errors.Is(err, fs.ErrNotExist) {
				reason = "path_unresolved"
			}
			c.degrade(f.src, reason)
			complete = false
			continue
		}
		if more {
			c.degrade(f.src, "entry_limit")
			complete = false
		}
		var candidates []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".gemspec") {
				candidates = append(candidates, filepath.Join(dir, e.Name()))
			}
		}
		if ref.name == "" && len(candidates) > 1 {
			// Bundler rejects an unnamed directive with several gemspecs.
			c.degrade(f.src, "unsupported_format")
			complete = false
			continue
		}
		var matched []*rubyFile
		for _, p := range candidates {
			g := c.referenced(p, "gemspec", f.src)
			switch {
			case g == nil || g.manifest == nil:
				complete = false
			case ref.name == "" || g.manifest.name == ref.name:
				matched = append(matched, g)
			}
		}
		if len(matched) != 1 {
			if len(matched) == 0 && len(candidates) == 0 {
				c.degrade(f.src, "path_unresolved")
			} else if len(matched) > 1 {
				c.degrade(f.src, "unsupported_format")
			}
			complete = false
			continue
		}
		out = append(out, matched[0])
	}
	return out, complete
}

func rubyLockPath(manifest string) string {
	if filepath.Base(manifest) == "gems.rb" {
		return strings.TrimSuffix(manifest, ".rb") + ".locked"
	}
	return manifest + ".lock"
}

// project reads one Bundler project: its manifest tree, Bundler config leads,
// selected lock, project-local gem homes and caches, then declarations.
func (c *rubyScan) project(path, parent string, targeted bool) {
	key := c.key(path)
	if c.projects[key] != nil {
		return
	}
	src := c.source("manifest", path, parent)
	if src == nil {
		return
	}
	dir := filepath.Dir(path)
	st := &rubyProjectState{project: model.RubyProject{ManifestSourceID: src.SourceID, ManifestPath: path, ProjectPath: dir, SelectionStatus: "observed", LockfilePaths: []string{}}}
	c.projects[key] = st
	c.projectDirs[c.key(dir)] = dir
	root := c.manifestFile(src, targeted, false)
	tree := []*rubyFile{root}
	complete := root.manifest != nil && c.evals(root, map[string]bool{key: true}, 0, &tree)
	var specs []*rubyFile
	for _, f := range tree {
		if f.manifest == nil {
			continue
		}
		matched, ok := c.gemspecRefs(f)
		specs = append(specs, matched...)
		complete = complete && ok
	}
	manifests := []configaudit.RubyManifest{}
	globals := []string{}
	var directive *rubyManifest
	directives := 0
	for _, f := range tree {
		// Inventory reasons propagated from referenced files are not this
		// manifest's configuration coverage.
		m := configaudit.RubyManifest{Path: f.src.Path, Status: f.status}
		if f.status != "present" {
			m.Reasons = f.src.Reasons
		}
		if f.manifest != nil {
			m.Sources, m.Lockfile, m.NoLockfile = f.manifest.sources, f.manifest.lockfile, f.manifest.noLockfile
			for _, g := range f.manifest.globals {
				if !slices.Contains(globals, g) {
					globals = append(globals, g)
				}
			}
			if f.manifest.lockfileSet {
				directive = f.manifest
				directives++
			}
		}
		manifests = append(manifests, m)
	}
	if !complete {
		for _, f := range tree {
			for _, reason := range f.src.Reasons {
				c.unprove(reason)
			}
		}
	}
	leads := c.config.Project(configaudit.RubyProject{Dir: dir, Manifests: manifests})
	if leads.Partial && src.Status == "complete" && src.Presence == "present" {
		// Config may hide installed roots that this source previously owned.
		c.degrade(src, "path_unresolved")
	}
	// Several lockfile directives depend on evaluation order this reader
	// does not model; the default lock is then only a candidate.
	partial := !complete || leads.Partial || directives > 1
	lock := rubyLockPath(path)
	switch {
	case directives == 1 && directive.noLockfile:
		lock = ""
	case directives == 1:
		if lock = c.resolve(directive.lockfile, dir); lock == "" {
			c.degrade(src, "path_unresolved")
			partial = true
		}
	case leads.Lockfile != "":
		lock = leads.Lockfile
	}
	if lock != "" {
		if l := c.lock(lock, src.SourceID, dir, true); l != nil && l.Presence != "absent" {
			st.project.LockfilePaths = []string{lock}
		}
	}
	if leads.Path != "" {
		// A configured path appends engine/ABI; discover rather than guess them.
		homes, reasons := c.expand(leads.Path, "*", "*")
		for _, reason := range reasons {
			c.degrade(src, reason)
			partial = true
		}
		for _, h := range homes {
			c.gemHome(h, "project", src.SourceID, dir)
		}
	}
	c.cacheRoot(leads.CachePath, "project", src.SourceID, dir, rubyCacheVendor)
	if leads.AppConfig != "" {
		c.gemHome(filepath.Join(leads.AppConfig, "plugin"), "project", src.SourceID, dir)
		c.pruned[c.key(leads.AppConfig)] = true
	}
	// Undecorated declarations use the tree's global sources only when they
	// name exactly one endpoint and every manifest in the tree was read.
	def, defReason := model.RubyOrigin{Kind: "unknown"}, ""
	switch {
	case !complete || len(globals) > 1:
		defReason = "origin_unresolved"
	case len(globals) == 1:
		url, _ := configaudit.SanitizeRubyURL(globals[0])
		def = model.RubyOrigin{Kind: "registry", URL: url}
		if url == "[redacted]" {
			defReason = "origin_unresolved"
		}
	}
	for _, f := range append(tree, specs...) {
		if f.manifest == nil {
			continue
		}
		for _, d := range f.manifest.declarations {
			if c.stopped(f.src) {
				break
			}
			c.declared(f.src, d, dir, def, defReason)
		}
	}
	if len(specs) == 1 {
		st.project.PackageName, st.project.PackageVersion = specs[0].manifest.name, specs[0].manifest.version
	}
	if partial {
		st.project.SelectionStatus = "partial"
	}
	st.kept = c.charge(src, st.project)
}

// standalone records a gemspec with no Bundler manifest beside it; its
// literal dependencies have no observed source.
func (c *rubyScan) standalone(path, parent string) {
	key := c.key(path)
	if c.projects[key] != nil || c.reads[key] != nil {
		return
	}
	src := c.source("gemspec", path, parent)
	if src == nil {
		return
	}
	dir := filepath.Dir(path)
	st := &rubyProjectState{gemspec: true, project: model.RubyProject{ManifestSourceID: src.SourceID, ManifestPath: path, ProjectPath: dir, SelectionStatus: "partial", LockfilePaths: []string{}}}
	c.projects[key] = st
	c.projectDirs[c.key(dir)] = dir
	if f := c.manifestFile(src, false, true); f.manifest != nil {
		st.project.SelectionStatus = "observed"
		st.project.PackageName, st.project.PackageVersion = f.manifest.name, f.manifest.version
		for _, d := range f.manifest.declarations {
			if c.stopped(src) {
				break
			}
			c.declared(src, d, dir, model.RubyOrigin{Kind: "unknown"}, "")
		}
	}
	st.kept = c.charge(src, st.project)
}

func (c *rubyScan) declared(src *model.RubySource, d rubyDeclaration, project string, def model.RubyOrigin, defReason string) {
	requested := slices.Clone(d.requirements)
	if requested == nil {
		requested = []string{}
	}
	p := model.RubyPackage{PackageName: d.name, Reasons: []string{}, VersionStatus: "unknown", RequestedVersions: &requested, Groups: d.groups, DeclaredPlatforms: d.platforms,
		DependencyRelation: "direct", DependencyKind: d.kind, Origin: def, ChecksumStatus: "absent", RecordedChecksums: []model.RubyRecordedChecksum{}}
	base := filepath.Dir(src.Path)
	switch d.origin {
	case "":
		if defReason != "" {
			p.Reasons = append(p.Reasons, defReason)
		}
	case "path":
		p.Origin = c.localOrigin(d.path, base, &p)
	default:
		if local, ok := composerLocalURL(d.url, ""); ok && d.origin == "git" {
			p.Origin = c.localOrigin(local, base, &p)
			break
		}
		url, _ := configaudit.SanitizeRubyURL(d.url)
		p.Origin = model.RubyOrigin{Kind: d.origin, URL: url}
		if url == "[redacted]" {
			p.Reasons = append(p.Reasons, "origin_unresolved")
		}
	}
	c.add(src, p, "declared_requirement", project, "project")
}

func (c *rubyScan) lock(path, parent, project string, targeted bool) *model.RubySource {
	c.locks[c.key(path)] = true
	src := c.source("lockfile", path, parent)
	if src == nil {
		return nil
	}
	data, ok := c.read(src, targeted, maxRubyMetadataBytes)
	if !ok {
		return src
	}
	entries, reasons, err := parseRubyLock(data)
	if err != nil {
		c.degrade(src, "parse_error")
		return src
	}
	for _, r := range reasons {
		c.degrade(src, r)
	}
	for _, e := range entries {
		if c.stopped(src) {
			break
		}
		p := e.pkg
		if e.local != "" {
			p.Origin = c.localOrigin(e.local, project, &p)
		}
		c.add(src, p, "locked_package", project, "project")
	}
	return src
}

// independentLocks emits on-disk locks no project selected. A lock beside a
// project that selected another (or none) still makes its selection partial.
func (c *rubyScan) independentLocks() {
	for _, key := range slices.Sorted(maps.Keys(c.diskLocks)) {
		l := c.diskLocks[key]
		if c.locks[key] {
			continue
		}
		dir := filepath.Dir(l.path)
		for _, st := range c.projects {
			if !st.gemspec && c.key(st.project.ProjectPath) == c.key(dir) {
				st.project.SelectionStatus = "partial"
			}
		}
		if c.stopped(c.byID[l.parent]) {
			return
		}
		c.lock(l.path, l.parent, dir, false)
	}
}

func (c *rubyScan) skip(path string) bool {
	path = c.key(path)
	for root := range c.pruned {
		if path == root || goPathWithin(path, root) {
			return true
		}
	}
	return false
}

// enclosing returns the deepest known project directory containing path.
func (c *rubyScan) enclosing(path string) string {
	best, key := "", c.key(path)
	for k, dir := range c.projectDirs {
		if (key == k || goPathWithin(key, k)) && len(dir) > len(best) {
			best = dir
		}
	}
	return best
}

func (c *rubyScan) walkRoots(dirs []string) {
	// Outermost logical/physical roots own discovery. Identical physical roots
	// retain the first spelling, like Cargo, and never get walked twice.
	type root struct {
		path, phys string
		src        *model.RubySource
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
			c.unvisited(src, c.reason(err, dir))
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

// isGemHome recognizes a RubyGems directory without trusting a lone
// `specifications` folder. A denied probe is partial, never "not a gem home".
func (c *rubyScan) isGemHome(dir string, entries []fs.DirEntry, src *model.RubySource) bool {
	has := func(name string) bool {
		return slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name && e.IsDir() })
	}
	if !has("specifications") {
		return false
	}
	if has("gems") || has("cache") {
		return true
	}
	specs := filepath.Join(dir, "specifications")
	children, _, err := c.files.ReadDirLimit(specs, 256)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.degrade(src, c.reason(err, specs))
		}
		return false
	}
	return slices.ContainsFunc(children, func(e fs.DirEntry) bool {
		return e.IsDir() && e.Name() == "default" || !e.IsDir() && strings.HasSuffix(e.Name(), ".gemspec")
	})
}

func (c *rubyScan) walk(root string, src *model.RubySource) {
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{root, 0}}
	budget := maxRubyWalkEntries
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
			c.unvisited(src, c.reason(err, d.path))
			continue
		}
		budget -= len(entries)
		file := func(name string) bool {
			return slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Name() == name && !e.IsDir() })
		}
		if c.isGemHome(d.path, entries, src) {
			project, scope := c.enclosing(d.path), "unknown"
			switch {
			case project != "":
				scope = "project"
			case configaudit.GoWithinRoots(c.goos, d.path, []string{c.home}):
				scope = "user"
			}
			c.gemHome(d.path, scope, src.SourceID, project)
			continue
		}
		// gems.rb precedes Gemfile; the other is never read as a manifest. An
		// existing BUNDLE_GEMFILE selection replaces both for its directory.
		selected := false
		if g := c.config.Gemfile; g != "" && c.key(filepath.Dir(g)) == c.key(d.path) {
			src := c.byID[configaudit.GoSourceID(c.identity, "manifest", g)]
			selected = src == nil || src.Presence != "absent"
		}
		switch {
		case selected:
		case file("gems.rb"):
			c.project(filepath.Join(d.path, "gems.rb"), src.SourceID, false)
		case file("Gemfile"):
			c.project(filepath.Join(d.path, "Gemfile"), src.SourceID, false)
		default:
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".gemspec") {
					c.standalone(filepath.Join(d.path, e.Name()), src.SourceID)
				}
			}
		}
		for _, name := range []string{"Gemfile.lock", "gems.locked"} {
			if p := filepath.Join(d.path, name); file(name) {
				c.diskLocks[c.key(p)] = rubyDiskLock{p, src.SourceID}
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
				continue
			}
			if c.guard(p) != "" {
				c.unvisited(src, c.reasonForGuard(p))
				continue
			}
			if d.depth+1 > maxRubyWalkDepth {
				c.unvisited(src, "depth_limit")
				continue
			}
			queue = append(queue, dir{p, d.depth + 1})
		}
		if more {
			c.unvisited(src, "entry_limit")
			return
		}
	}
}
func (c *rubyScan) reasonForGuard(path string) string {
	if c.volume != nil && c.volume(path) {
		return "refused_network_volume"
	}
	return "skipped_protected"
}
func (c *rubyScan) finish() {
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
			c.inv.Projects = append(c.inv.Projects, st.project)
		}
	}
	slices.SortFunc(c.inv.Sources, func(a, b model.RubySource) int {
		return strings.Compare(a.Path+"\x00"+a.Kind, b.Path+"\x00"+b.Kind)
	})
	slices.SortFunc(c.inv.Projects, func(a, b model.RubyProject) int { return strings.Compare(a.ManifestPath, b.ManifestPath) })
	slices.SortStableFunc(c.inv.Packages, func(a, b model.RubyPackage) int {
		return cmp.Or(strings.Compare(a.SourcePath, b.SourcePath), strings.Compare(a.Evidence, b.Evidence), strings.Compare(a.ProjectPath, b.ProjectPath),
			strings.Compare(a.PackageName, b.PackageName), strings.Compare(a.Version, b.Version), strings.Compare(a.Platform, b.Platform), strings.Compare(a.DependencyKind, b.DependencyKind))
	})
	slices.Sort(c.inv.Reasons)
}
