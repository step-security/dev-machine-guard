package detector

import (
	"cmp"
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

// Nix inventory bounds. Real hosts have a handful of profiles and a few
// thousand environment links; the bounds stop a hostile tree from growing
// the scan or the upload.
const (
	maxNixSources       = 1024
	maxNixProfileListed = 10_000
	maxNixPackages      = 10_000
	maxNixEnvEntries    = 200_000
)

const (
	nixDefaultProfile = "/nix/var/nix/profiles/default"
	nixPerUserRoot    = "/nix/var/nix/profiles/per-user"
)

// nixInventory is what one passive read of the Nix sources found.
type nixInventory struct {
	packages []model.SystemPackage
	// present reports that /nix is not proven missing. When false, Nix is
	// definitively absent: no profile or environment can resolve without it.
	present bool
	// incomplete reports a source that was neither read in full nor proven
	// absent, so a missing package is not evidence of removal.
	incomplete bool
}

// nixIncompleteError is the error of a Nix scan that is not complete. It is
// fixed text: nothing read from disk is sent.
const nixIncompleteError = "incomplete nix inventory"

// NixScanner reads Nix profiles and environments from disk without running
// Nix: it never starts a process, sources a shell or evaluates an expression.
// It must be built with the raw executor: UserAwareExecutor.Getenv sources a
// login shell.
type NixScanner struct {
	exec executor.Executor
	log  *progress.Logger
	// protection builds the path guards; a seam so tests can place protected
	// paths.
	protection func(home string, includeNetworkVolumes *bool) (protected func(string) string, volume func(string) bool)
}

func NewNixScanner(exec executor.Executor, log *progress.Logger) *NixScanner {
	if log == nil {
		log = progress.NewNoop()
	}
	return &NixScanner{exec: exec, log: log, protection: configaudit.GoProtection}
}

// Scan returns the "nix" system package scan, or nil when it is omitted.
// A host where Nix is absent sends no scan, so its payload is unchanged,
// unless reported says an earlier acknowledged upload carried Nix: then one
// complete empty scan confirms the removal. present reports that Nix is
// installed; the caller records it once the upload is acknowledged.
//
// Each name is sent once, the first by (version, install path), and a name
// in existing (the names another package source reported in this run) is
// not sent: the existing inventory owns it.
func (s *NixScanner) Scan(ctx context.Context, target *user.User, includeNetworkVolumes *bool,
	existing map[string]bool, reported bool) (scan *model.SystemPackageScanResult, present bool) {
	start := time.Now()
	inv := s.scan(ctx, target, includeNetworkVolumes)
	if !inv.present && !reported {
		return nil, false
	}
	pkgs := selectNixPackages(inv.packages, existing)
	res := &model.SystemPackageScanResult{ScanType: "nix", Packages: pkgs, PackagesCount: len(pkgs),
		ScanDurationMs: time.Since(start).Milliseconds()}
	if inv.incomplete {
		res.Error = nixIncompleteError
	}
	return res, inv.present
}

// selectNixPackages keeps one record per name, the first by (name, version,
// install path) in byte order, and drops the names in existing. It sorts pkgs
// in place.
func selectNixPackages(pkgs []model.SystemPackage, existing map[string]bool) []model.SystemPackage {
	slices.SortFunc(pkgs, func(a, b model.SystemPackage) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version), strings.Compare(a.InstallPath, b.InstallPath))
	})
	out := []model.SystemPackage{}
	for _, p := range pkgs {
		if existing[p.Name] || len(out) > 0 && out[len(out)-1].Name == p.Name {
			continue
		}
		out = append(out, p)
	}
	return out
}

// nixSource is a profile, read from its manifest, or an environment, read
// from its symlink forest.
type nixSource struct {
	path string
	env  bool
}

type nixScan struct {
	log     *progress.Logger
	ctx     context.Context
	files   executor.Executor
	sources []nixSource
	walked  map[string]bool // environments already read, by store path
	inv     nixInventory
}

// nixSystemPaths returns the current system environment, the per-user
// environment directory and the reader roots. macOS paths are the canonical
// /private ones, so a missing path is never reported through the /etc or
// /var link. NixOS links /etc/profiles/per-user/<user> through /etc/static.
func nixSystemPaths(platform string) (system, perUser string, roots []string) {
	switch platform {
	case model.PlatformLinux:
		return "/run/current-system/sw", "/etc/profiles/per-user",
			[]string{"/nix", "/run/current-system", "/etc/profiles", "/etc/static"}
	case model.PlatformDarwin:
		return "/private/var/run/current-system/sw", "/private/etc/profiles/per-user",
			[]string{"/nix", "/private/var/run/current-system", "/private/etc/profiles", "/private/etc/static"}
	}
	return "", "", nil
}

// scan reads the machine sources and, for a real user, that user's sources.
// A service identity or a nil target reads the machine sources only; on
// macOS a nil target is a failed console lookup, so that read is incomplete.
func (s *NixScanner) scan(ctx context.Context, target *user.User, includeNetworkVolumes *bool) nixInventory {
	platform := s.exec.GOOS()
	system, perUser, roots := nixSystemPaths(platform)
	if system == "" {
		return nixInventory{}
	}
	n := &nixScan{log: s.log, ctx: ctx, walked: map[string]bool{}}

	hasUser := target != nil && !isGoServiceIdentity(platform, target) && filepath.IsAbs(target.HomeDir)
	home := ""
	if hasUser {
		home = filepath.Clean(target.HomeDir)
		roots = append(roots, home)
	}
	guard, _ := s.protection(home, includeNetworkVolumes)
	n.files = s.exec.GuardedFiles(roots, guard, maxNixManifestBytes)

	// Only a missing /nix is a definitive absence; leftover links such as
	// ~/.nix-profile cannot resolve without it. Nix is installed otherwise,
	// even when no source exists for this user.
	_, err := n.files.EvalSymlinks("/nix")
	if nixAbsent("/nix", err) {
		return nixInventory{}
	}
	n.inv.present = true
	if err != nil {
		n.fail("nix root unresolved")
	}
	// A macOS root daemon at the login window has no console user. The run
	// still uploads, so the user's profiles were not read, not proven gone.
	if target == nil && platform == model.PlatformDarwin {
		n.fail("no console user")
	}

	var dirs []string
	if hasUser {
		dirs = []string{filepath.Join(home, ".local", "state", "nix", "profiles"), filepath.Join(nixPerUserRoot, target.Username)}
		for _, dir := range dirs {
			n.listProfiles(dir)
		}
	}
	n.single(nixDefaultProfile, false)
	n.single(system, true)
	if hasUser {
		n.single(filepath.Join(perUser, target.Username), true)
		n.homeProfile(filepath.Join(home, ".nix-profile"), dirs)
	}
	n.read()
	return n.inv
}

// fail marks the read incomplete. The reason is fixed text: nothing read
// from disk is logged.
func (n *nixScan) fail(reason string) {
	n.inv.incomplete = true
	n.log.Debug("nix: %s", reason)
}

func (n *nixScan) add(src nixSource) {
	if len(n.sources) >= maxNixSources {
		n.fail("source limit reached")
		return
	}
	n.sources = append(n.sources, src)
}

// listProfiles lists a profiles directory. Generation links (name-N-link) are
// only hops; every other symlink is a profile.
func (n *nixScan) listProfiles(dir string) {
	entries, more, err := n.files.ReadDirLimit(dir, maxNixProfileListed)
	if nixAbsent(dir, err) {
		return
	}
	if err != nil {
		n.fail("profiles directory unreadable")
		return
	}
	if more {
		n.fail("profile listing limit reached")
	}
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink != 0 && !isNixGenerationLink(e.Name()) {
			n.add(nixSource{path: filepath.Join(dir, e.Name())})
		}
	}
}

func isNixGenerationLink(name string) bool {
	rest, ok := strings.CutSuffix(name, "-link")
	i := strings.LastIndexByte(rest, '-')
	return ok && i > 0 && isNumeric(rest[i+1:])
}

// single adds a path that is itself one source unless it is proven absent.
// A dangling or refused path is a source that will fail to resolve.
func (n *nixScan) single(path string, env bool) {
	if _, err := n.files.EvalSymlinks(path); !nixAbsent(path, err) {
		n.add(nixSource{path: path, env: env})
	}
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

// homeProfile handles ~/.nix-profile: a link to a profile in a profiles
// directory or to the default profile is an alias with no source of its own.
// Any other link, such as one into a custom XDG_STATE_HOME or to a pinned
// generation, is a profile. The parent is resolved through the guard first,
// because Readlink is not guarded; a refused parent is a source that fails.
func (n *nixScan) homeProfile(path string, dirs []string) {
	link := path
	dir, err := n.files.EvalSymlinks(filepath.Dir(path))
	var target string
	if err == nil {
		link = filepath.Join(dir, filepath.Base(path))
		target, err = n.files.Readlink(link)
	}
	if nixAbsent(link, err) {
		return
	}
	if err == nil {
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		target = filepath.Clean(target)
		alias := target == nixDefaultProfile || slices.Contains(dirs, filepath.Dir(target))
		if alias && !isNixGenerationLink(filepath.Base(target)) {
			return
		}
	}
	n.add(nixSource{path: path})
}

// read resolves each source to a store path and reads it. A source that
// moved to another generation while it was read keeps its records but makes
// the read incomplete; the next scan converges.
func (n *nixScan) read() {
	for _, src := range n.sources {
		if n.ctx.Err() != nil {
			n.fail("scan cancelled")
			return
		}
		target, err := n.files.EvalSymlinks(src.path)
		if err != nil {
			n.fail("source unresolved")
			continue
		}
		if nixStoreBase(target) == "" {
			n.fail("source outside the store")
			continue
		}
		if src.env {
			n.walkEnv(target)
		} else {
			n.readProfile(target)
		}
		if t, _ := n.files.EvalSymlinks(src.path); t != target {
			n.fail("source changed during scan")
		}
	}
}

// readProfile reads manifest.json, else manifest.nix, of one profile
// generation, and the Home Manager environment it holds as home-path. A Home
// Manager generation has no manifest: home-path is its only content.
func (n *nixScan) readProfile(gen string) {
	home := gen + "/home-path"
	hasHome := false
	switch t, err := n.files.EvalSymlinks(home); {
	case nixAbsent(home, err):
	case err != nil || nixStoreBase(t) == "":
		n.fail("home-path unresolved")
	default:
		hasHome = true
		n.walkEnv(t)
	}

	parse := parseNixManifestJSON
	data, err := n.files.ReadFile(gen + "/manifest.json")
	if errors.Is(err, fs.ErrNotExist) {
		parse = parseNixManifestLegacy
		data, err = n.files.ReadFile(gen + "/manifest.nix")
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !hasHome {
			n.fail("unsupported profile layout")
		}
		return
	case err != nil:
		n.fail("manifest unreadable")
		return
	}
	pkgs, incomplete, err := parse(data)
	if err != nil {
		n.fail("manifest unparsed")
		return
	}
	if incomplete {
		n.fail("manifest incomplete")
	}
	n.keep(pkgs)
}

// walkEnv records the direct members of a buildEnv environment: the distinct
// top-level store paths its symlinks point into. A symlinked directory is one
// member and is not entered; files the environment generated itself are not
// members.
func (n *nixScan) walkEnv(env string) {
	if n.walked[env] {
		return
	}
	n.walked[env] = true
	seen := map[string]bool{}
	dirs, entries := []string{env}, 0
	for len(dirs) > 0 {
		if n.ctx.Err() != nil {
			n.fail("scan cancelled")
			break
		}
		dir := dirs[len(dirs)-1]
		dirs = dirs[:len(dirs)-1]
		list, more, err := n.files.ReadDirLimit(dir, maxNixEnvEntries-entries)
		if err != nil {
			n.fail("environment unreadable")
			break
		}
		entries += len(list)
		for _, e := range list {
			p := filepath.Join(dir, e.Name())
			switch {
			case e.Type()&fs.ModeSymlink != 0:
				t, ok := linkTarget(n.files, p)
				if !ok {
					n.fail("environment link unreadable")
					continue
				}
				if m := nixStoreTop(t); m != "" && m != env {
					seen[m] = true
				}
			case e.IsDir():
				dirs = append(dirs, p)
			}
		}
		if more {
			n.fail("environment entry limit reached")
			break
		}
	}
	pkgs := make([]model.SystemPackage, 0, len(seen))
	for _, m := range slices.Sorted(maps.Keys(seen)) {
		name, version := splitNixName(nixStoreBase(m))
		pkgs = append(pkgs, model.SystemPackage{Name: name, Version: version, InstallPath: m})
	}
	n.keep(pkgs)
}

// nixStoreTop returns the top-level store path p lies in, or "".
func nixStoreTop(p string) string {
	rest, ok := strings.CutPrefix(filepath.Clean(p), nixStorePrefix)
	if !ok {
		return ""
	}
	top, _, _ := strings.Cut(rest, "/")
	if nixStoreBase(nixStorePrefix+top) == "" {
		return ""
	}
	return nixStorePrefix + top
}

func (n *nixScan) keep(pkgs []model.SystemPackage) {
	if room := maxNixPackages - len(n.inv.packages); len(pkgs) > room {
		pkgs = pkgs[:room]
		n.fail("package limit reached")
	}
	n.inv.packages = append(n.inv.packages, pkgs...)
}
