package detector

import (
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

// Nix inventory bounds. Real hosts have a handful of profiles; the bounds stop
// a hostile tree from growing the scan or the upload.
const (
	maxNixSources       = 1024
	maxNixProfileListed = 10_000
	maxNixOutputBytes   = 16 << 20
	maxNixRefs          = 10_000
)

// Fixed status texts. Nothing read from disk is ever placed in a status.
const (
	nixProfileUnresolved = "profile unresolved"
	nixUnsupportedStore  = "unsupported store location"
	nixUnsupportedLayout = "unsupported profile layout"
	nixManifestUnread    = "manifest unreadable"
	nixIncomplete        = "incomplete manifest"
	nixChanged           = "profile changed during scan"
	nixDBUnavailable     = "store database unavailable"
	nixNotRegistered     = "store path not registered"
	nixRefLimit          = "reference limit reached"
)

const (
	nixDefaultProfile = "/nix/var/nix/profiles/default"
	nixPerUserRoot    = "/nix/var/nix/profiles/per-user"
	nixSystemSW       = "/run/current-system/sw"
	nixEtcPerUser     = "/etc/profiles/per-user"
	nixDBPath         = "/nix/var/nix/db/db.sqlite"
)

// nixScanner reads installed Nix profiles from disk without running Nix: it
// never starts a process, sources a shell or evaluates an expression.
type nixScanner struct {
	exec executor.Executor
	log  *progress.Logger
	// refs returns the direct references of each store path from the Nix
	// store database. Tests replace it.
	refs func(ctx context.Context, files executor.Executor, roots []string) (map[string][]string, error)
}

func newNixScanner(exec executor.Executor, log *progress.Logger) *nixScanner {
	if log == nil {
		log = progress.NewNoop()
	}
	return &nixScanner{exec: exec, log: log, refs: nixDirectRefs}
}

// nixSource is one source to read: a profile with a manifest, or a store
// environment whose members are its direct references.
// The id is the path resolved at the start and the end of the read.
type nixSource struct {
	id, root, scope string
	db              bool
	home            bool   // a Home Manager home-path member
	hasHome         bool   // a profile whose generation holds home-path
	failed          string // a status decided during discovery
	target          string // resolved store path
}

type nixScan struct {
	*nixScanner
	ctx       context.Context
	files     executor.Executor
	run       *sysPkgRun
	sources   []*nixSource
	roots     []model.SystemPackageDiscoveryRoot // in emission order
	rootOK    map[string]bool                    // false once a root cannot prove its source set
	truncated bool                               // more sources than maxNixSources
	dbFailed  string                             // a custom store makes every database source fail
	bytes     int                                // serialized size emitted so far
}

// scan adds one source per Nix profile on Linux and macOS to the run. env
// leads (XDG_STATE_HOME, NIX_PROFILES) are read only when the agent runs as
// target, never through a shell.
func (s *nixScanner) scan(ctx context.Context, r *sysPkgRun, target *user.User, includeNetworkVolumes *bool) {
	platform := s.exec.GOOS()
	if r.cut || platform != model.PlatformLinux && platform != model.PlatformDarwin {
		return
	}
	n := &nixScan{nixScanner: s, ctx: ctx, run: r, rootOK: map[string]bool{}}

	hasUser := target != nil && !isGoServiceIdentity(platform, target) && filepath.IsAbs(target.HomeDir)
	home, stateHome, verified := "", "", false
	if hasUser {
		home = filepath.Clean(target.HomeDir)
		current, err := s.exec.CurrentUser()
		verified = err == nil && target.Uid != "" && current.Uid == target.Uid
		stateHome = filepath.Join(home, ".local", "state")
		if v := n.envPath(verified, "XDG_STATE_HOME"); v != "" {
			stateHome = v
		}
	}
	for key, def := range map[string]string{"NIX_STATE_DIR": "/nix/var/nix", "NIX_STORE_DIR": "/nix/store"} {
		if v := n.envPath(verified, key); v != "" && v != def {
			n.dbFailed = nixUnsupportedStore
		}
	}
	var leads []string
	if verified {
		for _, l := range strings.Fields(s.exec.Getenv("NIX_PROFILES")) {
			if filepath.IsAbs(l) {
				leads = append(leads, filepath.Clean(l))
			}
		}
	}

	var guard func(string) string
	if hasUser {
		guard, _ = configaudit.GoProtection(home, includeNetworkVolumes)
	}
	fsRoots := []string{"/nix"}
	if platform == model.PlatformLinux {
		fsRoots = append(fsRoots, "/run/current-system", "/etc/profiles")
	}
	if hasUser {
		fsRoots = append(fsRoots, home, stateHome)
	}
	n.files = s.exec.GuardedFiles(append(fsRoots, leads...), guard, maxNixManifestBytes)

	// Directory roots, then single roots, then the home link and leads.
	var dirRoots []string
	if hasUser {
		dirRoots = []string{filepath.Join(stateHome, "nix", "profiles"), filepath.Join(nixPerUserRoot, target.Username)}
		for _, dir := range dirRoots {
			n.listProfiles(dir)
		}
	}
	n.single(nixDefaultProfile, sysPkgScopeMachine, false)
	if platform == model.PlatformLinux {
		n.single(nixSystemSW, sysPkgScopeMachine, true)
		if hasUser {
			n.single(filepath.Join(nixEtcPerUser, target.Username), sysPkgScopeUser, true)
		}
	}
	if hasUser {
		n.homeProfile(filepath.Join(home, ".nix-profile"), dirRoots)
	}
	n.leads(leads)

	n.read()
	n.listRoots()
}

// envPath returns an absolute, cleaned value of key from a verified process.
func (n *nixScan) envPath(verified bool, key string) string {
	if !verified {
		return ""
	}
	v := n.exec.Getenv(key)
	if v == "" {
		return ""
	}
	if !filepath.IsAbs(v) {
		n.log.Debug("nix: %s is not absolute, ignored", key)
		return ""
	}
	return filepath.Clean(v)
}

func (n *nixScan) addRoot(root, scope string) {
	n.roots = append(n.roots, model.SystemPackageDiscoveryRoot{ScanType: "nix", Scope: scope, Path: root})
	n.rootOK[root] = true
}

// add keeps a source within maxNixSources. The sources past the bound have
// unknown roots, so none is listed.
func (n *nixScan) add(src *nixSource) {
	if len(n.sources) >= maxNixSources {
		n.truncated = true
		return
	}
	n.sources = append(n.sources, src)
}

// listProfiles lists a profiles directory. Generation links (name-N-link) are
// only hops; every other symlink is a profile.
func (n *nixScan) listProfiles(dir string) {
	n.addRoot(dir, sysPkgScopeUser)
	entries, more, err := n.files.ReadDirLimit(dir, maxNixProfileListed)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		n.log.Debug("nix: profiles directory unreadable: %v", err)
		n.rootOK[dir] = false
		return
	case more:
		n.rootOK[dir] = false
	}
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink == 0 || isNixGenerationLink(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		n.addProfile(&nixSource{id: p, root: dir, scope: sysPkgScopeUser})
	}
}

func isNixGenerationLink(name string) bool {
	rest, ok := strings.CutSuffix(name, "-link")
	i := strings.LastIndexByte(rest, '-')
	if !ok || i <= 0 || i == len(rest)-1 {
		return false
	}
	for _, c := range rest[i+1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// single handles a root that is itself one source. A path proven absent
// lists the root with no source; a dangling link becomes a failed source.
func (n *nixScan) single(path, scope string, db bool) {
	n.addRoot(path, scope)
	if _, err := n.files.EvalSymlinks(path); nixAbsent(path, err) {
		return
	}
	src := &nixSource{id: path, root: path, scope: scope, db: db}
	if db {
		n.add(src)
		return
	}
	n.addProfile(src)
}

// nixAbsent reports that a guarded resolution error proves path missing. The
// reader returns the failed Lstat of the missing component, and only the walk
// of path's own components can name path or one of its ancestors. A component
// missing under a link target, or an error without a path, proves nothing.
func nixAbsent(path string, err error) bool {
	var pe *fs.PathError
	return errors.As(err, &pe) && errors.Is(err, fs.ErrNotExist) &&
		(pe.Path == path || strings.HasPrefix(path, pe.Path+string(filepath.Separator)))
}

// addProfile adds a manifest profile and, when its generation holds a
// home-path store path, the Home Manager member source P/home-path. Only a
// profile that holds home-path itself can own it, so a wrapper element in
// another profile never does; profiles sharing one home-path are resolved in
// read.
func (n *nixScan) addProfile(src *nixSource) {
	n.add(src)
	link := src.id + "/home-path"
	resolved, err := n.files.EvalSymlinks(link)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		n.rootOK[src.root] = false
	case nixStoreBase(resolved) != "":
		src.hasHome = true
		n.add(&nixSource{id: link, root: src.root, scope: src.scope, db: true, home: true})
	}
}

// homeProfile handles ~/.nix-profile: a link to a profile in a profiles
// directory or to the default profile is an alias with no source of its own.
func (n *nixScan) homeProfile(path string, dirRoots []string) {
	n.addRoot(path, sysPkgScopeUser)
	target, err := n.exec.Readlink(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err == nil:
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		target = filepath.Clean(target)
		if target == nixDefaultProfile || slices.Contains(dirRoots, filepath.Dir(target)) {
			return
		}
	}
	n.addProfile(&nixSource{id: path, root: path, scope: sysPkgScopeUser})
}

// leads adds NIX_PROFILES entries not covered by a root. They have no
// discovery root, so their absence never retires anything.
func (n *nixScan) leads(leads []string) {
	for _, l := range leads {
		if slices.ContainsFunc(n.sources, func(s *nixSource) bool { return s.id == l }) ||
			slices.ContainsFunc(n.roots, func(r model.SystemPackageDiscoveryRoot) bool { return r.Path == l }) {
			continue
		}
		resolved, err := n.files.EvalSymlinks(l)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			n.add(&nixSource{id: l, scope: sysPkgScopeUser, failed: nixProfileUnresolved})
		case nixStoreBase(resolved) != "":
			n.add(&nixSource{id: l, scope: sysPkgScopeUser})
		default:
			n.log.Debug("nix: NIX_PROFILES entry is not a profile, ignored")
		}
	}
}

// read resolves every source, then emits manifest sources and finally all
// database sources from one database read.
func (n *nixScan) read() {
	for _, src := range n.sources {
		if n.ctx.Err() != nil {
			n.run.cut = true
			return
		}
		if src.failed == "" {
			src.target, src.failed = n.resolve(src.id)
			// An unresolved profile hides whether it holds home-path, so its
			// root cannot prove its source set.
			if src.failed == nixProfileUnresolved && !src.db && src.root != "" {
				n.rootOK[src.root] = false
			}
		}
	}
	n.dedupHomePaths()
	var dbSources []*nixSource
	for _, src := range n.sources {
		if n.ctx.Err() != nil {
			n.run.cut = true
		}
		if n.run.cut {
			return
		}
		switch {
		case src.failed != "":
			n.emit(src, nil, model.SystemPackageStatusFailed, src.failed)
		case src.db:
			dbSources = append(dbSources, src)
		default:
			n.readManifest(src)
		}
	}
	n.readDB(dbSources)
}

// dedupHomePaths keeps one owner per Home Manager store path within a scope:
// the lexicographically first profile. Every user-scope source belongs to the
// one scanned user, so a machine profile never merges with a user profile.
func (n *nixScan) dedupHomePaths() {
	type key struct{ scope, target string }
	owner := map[key]string{}
	for _, src := range n.sources {
		if src.home && src.target != "" {
			k := key{src.scope, src.target}
			if o, ok := owner[k]; !ok || src.id < o {
				owner[k] = src.id
			}
		}
	}
	n.sources = slices.DeleteFunc(n.sources, func(src *nixSource) bool {
		return src.home && src.target != "" && owner[key{src.scope, src.target}] != src.id
	})
}

// resolve follows link through the guard to a top-level store path.
func (n *nixScan) resolve(link string) (string, string) {
	t, err := n.files.EvalSymlinks(link)
	if err != nil {
		return "", nixProfileUnresolved
	}
	if nixStoreBase(t) == "" {
		return "", nixUnsupportedStore
	}
	return t, ""
}

// readManifest reads manifest.json, else manifest.nix, of one profile. A Home
// Manager profile has neither: its home-path member is its only source.
func (n *nixScan) readManifest(src *nixSource) {
	parse := parseNixManifestJSON
	data, err := n.files.ReadFile(src.target + "/manifest.json")
	if errors.Is(err, fs.ErrNotExist) {
		parse = parseNixManifestLegacy
		data, err = n.files.ReadFile(src.target + "/manifest.nix")
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !src.hasHome {
			n.emit(src, nil, model.SystemPackageStatusFailed, nixUnsupportedLayout)
		}
		return
	case err != nil:
		n.emit(src, nil, model.SystemPackageStatusFailed, nixManifestUnread)
		return
	}
	pkgs, incomplete, err := parse(data)
	if err != nil {
		n.emit(src, nil, model.SystemPackageStatusFailed, err.Error())
		return
	}
	status, errText := model.SystemPackageStatusComplete, ""
	if incomplete {
		status, errText = model.SystemPackageStatusPartial, nixIncomplete
	}
	n.emit(src, pkgs, status, errText)
}

// readDB reads the direct references of every database source in one read.
func (n *nixScan) readDB(sources []*nixSource) {
	if len(sources) == 0 {
		return
	}
	failAll := n.dbFailed
	var refs map[string][]string
	if failAll == "" {
		roots := make([]string, len(sources))
		for i, src := range sources {
			roots[i] = src.target
		}
		var err error
		if refs, err = n.refs(n.ctx, n.files, roots); err != nil {
			n.log.Debug("nix: store database read failed: %v", err)
			failAll = nixDBUnavailable
		}
	}
	for _, src := range sources {
		members, ok := refs[src.target]
		switch {
		case failAll != "":
			n.emit(src, nil, model.SystemPackageStatusFailed, failAll)
		case !ok:
			n.emit(src, nil, model.SystemPackageStatusFailed, nixNotRegistered)
		default:
			pkgs, status, errText := nixMembers(src.target, members)
			n.emit(src, pkgs, status, errText)
		}
	}
}

// nixMembers turns direct references into records. The environment's own
// manifest is not a member.
func nixMembers(self string, refs []string) ([]model.SystemPackage, string, string) {
	status, errText := model.SystemPackageStatusComplete, ""
	if len(refs) > maxNixRefs {
		refs = refs[:maxNixRefs]
		status, errText = model.SystemPackageStatusPartial, nixRefLimit
	}
	var pkgs []model.SystemPackage
	for _, r := range refs {
		base := nixStoreBase(r)
		if r == self || base == "env-manifest.nix" {
			continue
		}
		if base == "" {
			status, errText = model.SystemPackageStatusPartial, nixIncomplete
			continue
		}
		name, version := splitNixName(base)
		pkgs = append(pkgs, model.SystemPackage{
			Name: name, Version: version, InstallPath: r,
			Outputs: []model.SystemPackageOutput{{Path: r}},
		})
	}
	return pkgs, status, errText
}

// emit records a source. A profile that moved to another generation while it
// was read keeps its records but is partial; the next scan converges.
func (n *nixScan) emit(src *nixSource, pkgs []model.SystemPackage, status, errText string) {
	if status != model.SystemPackageStatusFailed {
		if t, _ := n.files.EvalSymlinks(src.id); t != src.target {
			status, errText = model.SystemPackageStatusPartial, nixChanged
		}
	}
	res := sysPkgResult("nix", nil, pkgs, time.Now(), src.id, src.root, src.scope, status, errText)
	if n.bytes += goJSONSize(res); n.bytes > maxNixOutputBytes {
		n.run.cut = true
	}
	if !n.run.emit(res) && src.root != "" {
		n.rootOK[src.root] = false
	}
}

// listRoots lists every root whose source set is known and fully emitted.
func (n *nixScan) listRoots() {
	if n.truncated {
		return
	}
	for _, root := range n.roots {
		if n.rootOK[root.Path] {
			n.run.addRoot(root.ScanType, root.Scope, root.Path)
		}
	}
}
