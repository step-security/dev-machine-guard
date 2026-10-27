package runtimeinv

import (
	"context"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

const (
	// maxEntries bounds the total directory entries visited per scan so a
	// pathological tree cannot stall the phase; the result is marked truncated.
	maxEntries = 2_500_000
	// defaultRootBudget bounds the entries one root may consume, so a huge
	// home directory cannot starve the roots after it.
	defaultRootBudget = 150_000
	// maxDirEntries bounds a single directory listing.
	maxDirEntries = 20_000
)

// walkRoot is a directory to walk to a depth. skip lists top-level child
// names (lowercased) the walk does not descend into from this root — used to
// keep the generic home walk out of ~/Library and AppData, whose runtime
// locations are walked as their own known roots instead.
type walkRoot struct {
	path   string
	depth  int
	skip   []string
	budget int // entries this root may visit; 0 = defaultRootBudget
}

// skipDirs are never descended at any depth: dependency stores (runtimes
// vendored there are package-scan territory), VCS internals, trash and OS
// internals.
var skipDirs = map[string]bool{
	"node_modules": true, "site-packages": true, "dist-packages": true, "__pycache__": true,
	".git": true, ".hg": true, ".svn": true,
	".npm": true, ".pnpm-store": true, ".m2": true, ".gradle": true, ".cargo": true, ".rustup": true,
	".trash": true, "$recycle.bin": true, "system volume information": true,
	"windowsapps": true, "winsxs": true,
}

// Scanner discovers runtime installs for the logged-in user and the machine.
type Scanner struct {
	exec executor.Executor
	goos string
	home string

	rootsOverride []walkRoot // tests
	skipper       *tcc.Skipper

	entries     int
	rootEntries int
	rootBudget  int
	curRoot     string
	// whole is set when the scan stopped for a reason that affects every
	// root (deadline, global cap); truncRoots lists roots that only ran out
	// of their own budget.
	whole      bool
	truncRoots []string
	walked     map[string]int // dir -> remaining depth it was walked with
	seenExe    map[string]bool
	seenRoot   map[string]bool
	out        []model.RuntimeInstall
}

// NewScanner returns a scanner for the given user home ("" = resolve from the
// logged-in user).
func NewScanner(exec executor.Executor, home string) *Scanner {
	if home == "" {
		if u, err := exec.LoggedInUser(); err == nil {
			home = u.HomeDir
		}
	}
	return &Scanner{exec: exec, goos: exec.GOOS(), home: home}
}

// WithSkipper applies the run's TCC-protected / network-volume exclusions,
// so the walk never reads a directory (or resolves into one) the scan
// settings exclude. A nil skipper skips nothing.
func (s *Scanner) WithSkipper(sk *tcc.Skipper) *Scanner {
	s.skipper = sk
	return s
}

// Scan walks all roots and returns the inventory, sorted by runtime then path.
// truncated reports an incomplete walk. truncatedRoots is non-empty only when
// every truncation was a per-root budget hit, so installs outside those roots
// are known to be complete; on a deadline or the global cap it is nil.
func (s *Scanner) Scan(ctx context.Context) (runtimes []model.RuntimeInstall, truncated bool, truncatedRoots []string) {
	s.entries, s.whole, s.truncRoots = 0, false, nil
	s.walked = map[string]int{}
	s.seenExe = map[string]bool{}
	s.seenRoot = map[string]bool{}
	s.out = nil

	roots := s.rootsOverride
	if roots == nil {
		roots = s.roots()
	}
	for _, r := range roots {
		if ctx.Err() != nil || s.entries >= maxEntries {
			s.whole = true
			break
		}
		s.rootEntries, s.rootBudget, s.curRoot = 0, r.budget, r.path
		if s.rootBudget <= 0 {
			s.rootBudget = defaultRootBudget
		}
		s.walk(ctx, r.path, r.depth, r.skip)
	}
	sort.Slice(s.out, func(i, j int) bool {
		if s.out[i].Runtime != s.out[j].Runtime {
			return s.out[i].Runtime < s.out[j].Runtime
		}
		if s.out[i].ExecutablePath != s.out[j].ExecutablePath {
			return s.out[i].ExecutablePath < s.out[j].ExecutablePath
		}
		return s.out[i].Version < s.out[j].Version
	})
	if s.whole {
		return s.out, true, nil
	}
	return s.out, len(s.truncRoots) > 0, s.truncRoots
}

// walk visits a root breadth-first, so when the entry budget runs out it is
// the deepest levels that go unvisited rather than whichever subtrees sort
// last.
func (s *Scanner) walk(ctx context.Context, root string, depth int, skipTop []string) {
	type item struct {
		dir   string
		depth int
		top   bool
	}
	queue := []item{{root, depth, true}}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if it.dir == "" || it.depth < 0 {
			continue
		}
		key := s.pathKey(it.dir)
		if prev, ok := s.walked[key]; ok && prev >= it.depth {
			continue
		}
		s.walked[key] = it.depth

		// Consult the skipper before ReadDir: reading the protected dir or
		// mountpoint is what fires the TCC / network-volume prompt.
		if s.skipper.ShouldSkip(it.dir, root) || (it.top && s.skipper.WithinProtected(it.dir)) {
			continue
		}
		ents, more, err := s.exec.ReadDirLimit(it.dir, maxDirEntries)
		if err != nil {
			continue
		}
		// A capped listing may hide runtimes: report this root as truncated so
		// the backend merges under it instead of deleting what it can't see.
		if more && !contains(s.truncRoots, s.curRoot) {
			s.truncRoots = append(s.truncRoots, s.curRoot)
		}
		// A directory holding pyvenv.cfg is a virtualenv; its interpreter is
		// a copy/link of a base install the python package scan covers.
		if hasEntry(ents, "pyvenv.cfg") {
			continue
		}
		for _, e := range ents {
			if ctx.Err() != nil || s.entries >= maxEntries {
				s.whole = true
				return
			}
			s.entries++
			s.rootEntries++
			if s.rootEntries >= s.rootBudget {
				if !contains(s.truncRoots, s.curRoot) {
					s.truncRoots = append(s.truncRoots, s.curRoot)
				}
				return
			}
			name := e.Name()
			path := filepath.Join(it.dir, name)
			// IsDir is false for symlinks and Windows junctions, so links are
			// never followed: nvm/scoop "current" links and NVM_SYMLINK
			// resolve to directories the walk reaches directly.
			if e.IsDir() {
				lower := strings.ToLower(name)
				if skipDirs[lower] || (it.top && contains(skipTop, lower)) || isGoModCache(it.dir, lower) || s.isCondaPkgCache(it.dir, lower) || isVenvTemplates(it.dir, lower) {
					continue
				}
				if it.depth > 0 {
					queue = append(queue, item{path, it.depth - 1, false})
				}
				continue
			}
			if e.Type()&^fs.ModeSymlink != 0 { // devices, sockets, pipes, junctions
				continue
			}
			if sig := matchSignature(name, s.goos); sig != nil {
				s.consider(ctx, sig, path)
			}
		}
	}
}

func hasEntry(ents []fs.DirEntry, name string) bool {
	for _, e := range ents {
		if e.Name() == name {
			return true
		}
	}
	return false
}

// consider resolves a candidate executable and records it.
func (s *Scanner) consider(ctx context.Context, sig *signature, path string) {
	// Don't resolve into excluded trees: following a link into ~/Documents
	// or a network mount would touch it.
	if target, err := s.exec.Readlink(path); err == nil && target != "" {
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		if s.skipper.WithinProtected(target) {
			return
		}
	}
	real, err := s.exec.EvalSymlinks(path)
	if err != nil || real == "" || s.skipper.WithinProtected(real) {
		return
	}
	info, err := s.exec.Stat(real)
	// Only regular files go on to the content probes: opening a FIFO or
	// device (isScript, the embedded-version scan) would block.
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if s.goos != "windows" && info.Mode().Perm()&0o111 == 0 {
		return
	}
	if s.isShim(real) || inLauncherDir(real) || s.isLauncher(sig, real) {
		return
	}
	exeKey := sig.runtime + "|" + s.pathKey(real)
	if s.seenExe[exeKey] {
		return
	}
	s.seenExe[exeKey] = true

	root := installRoot(real)
	// JDK 8 ships jre/bin/java next to bin/java; report the JDK once.
	if sig.runtime == "java" && strings.EqualFold(filepath.Base(root), "jre") {
		if s.exec.FileExists(filepath.Join(filepath.Dir(root), "bin", filepath.Base(real))) {
			return
		}
	}

	base := model.RuntimeInstall{
		Runtime:        sig.runtime,
		ExecutablePath: real,
		InstallRoot:    root,
		Source:         attributeSource(real, s.exec.Getenv("NVM_HOME")),
		Scope:          s.scope(real),
		BundledBy:      bundledBy(real),
		Arch:           binaryArch(real),
	}
	if base.BundledBy == "" {
		base.BundledBy = snapBundler(sig.runtime, real)
	}
	if base.BundledBy != "" {
		base.Source = "bundled"
	}
	if !info.ModTime().IsZero() {
		base.InstallTimeUnix = info.ModTime().Unix()
	}

	if sig.runtime == "dotnet" {
		for _, v := range dotnetRuntimeVersions(s.exec, filepath.Dir(real)) {
			r := base
			r.InstallRoot = filepath.Dir(real)
			r.Version, r.VersionSource = v, versionFromPath
			s.add(r)
		}
		return
	}

	vr := detectVersion(ctx, s.exec, sig, real, root)
	base.Version, base.VersionSource = vr.version, vr.source
	if vr.vendor != "" {
		base.Vendor = vr.vendor
	}
	s.add(base)
}

// add records a runtime unless the same (runtime, root, version) is already
// present — e.g. python, python3 and python3.12 copies in one bin/.
func (s *Scanner) add(r model.RuntimeInstall) {
	k := r.Runtime + "|" + s.pathKey(r.InstallRoot) + "|" + r.Version
	if s.seenRoot[k] {
		return
	}
	s.seenRoot[k] = true
	s.out = append(s.out, r)
}

// isLauncher reports version-manager shims and wrappers, which select a
// runtime rather than being one:
//   - a link whose target is not itself a runtime binary (volta's
//     node -> volta-shim);
//   - a script (pyenv/rbenv/asdf shims are shell scripts; runtimes are
//     compiled binaries);
//   - a Scoop shim, marked by a sibling <name>.shim file.
func (s *Scanner) isLauncher(sig *signature, real string) bool {
	if t := matchSignature(filepath.Base(real), s.goos); t == nil || t.runtime != sig.runtime {
		return true
	}
	if s.goos == "windows" {
		return s.exec.FileExists(strings.TrimSuffix(real, filepath.Ext(real)) + ".shim")
	}
	return isScript(real)
}

// isShim reports binaries that are launchers rather than runtimes: the macOS
// /usr/bin stubs that prompt for the Command Line Tools / a JDK.
func (s *Scanner) isShim(real string) bool {
	if s.goos != "darwin" {
		return false
	}
	switch real {
	case "/usr/bin/python3", "/usr/bin/java":
		return true
	}
	return false
}

func (s *Scanner) scope(real string) string {
	if s.home != "" && strings.HasPrefix(normPath(real), normPath(s.home)) {
		return "user"
	}
	return "machine"
}

// pathKey folds case on Windows, where paths are case-insensitive.
func (s *Scanner) pathKey(p string) string {
	if s.goos == "windows" {
		return strings.ToLower(p)
	}
	return p
}

// installRoot is the runtime home: the parent of bin/, else the exe's dir
// (Windows layouts put node.exe / python.exe / php.exe at the root).
func installRoot(exe string) string {
	d := filepath.Dir(exe)
	if strings.EqualFold(filepath.Base(d), "bin") {
		return filepath.Dir(d)
	}
	return d
}

// isVenvTemplates reports the stdlib venv package's scripts dir
// (Lib\venv\scripts\nt\python.exe on Windows): launcher templates copied
// into new virtualenvs, not an install.
func isVenvTemplates(parent, lowerName string) bool {
	return lowerName == "scripts" && strings.EqualFold(filepath.Base(parent), "venv") &&
		strings.EqualFold(filepath.Base(filepath.Dir(parent)), "lib")
}

// isCondaPkgCache reports a conda install's pkgs/ dir: extracted package
// tarballs (a dependency store), not environments.
func (s *Scanner) isCondaPkgCache(parent, lowerName string) bool {
	return lowerName == "pkgs" && s.exec.DirExists(filepath.Join(parent, "conda-meta"))
}

// isGoModCache reports $GOPATH/pkg/mod: a dependency store of hundreds of
// thousands of files. Go toolchains downloaded into it are walked as their
// own known root (pkg/mod/golang.org).
func isGoModCache(parent, lowerName string) bool {
	return lowerName == "mod" && strings.EqualFold(filepath.Base(parent), "pkg")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ScanResult runs a scan for the logged-in user and packages it for telemetry.
func ScanResult(ctx context.Context, exec executor.Executor, skipper *tcc.Skipper) *model.RuntimeScanResult {
	start := time.Now()
	runtimes, truncated, truncatedRoots := NewScanner(exec, "").WithSkipper(skipper).Scan(ctx)
	if runtimes == nil {
		runtimes = []model.RuntimeInstall{}
	}
	return &model.RuntimeScanResult{
		Runtimes:       runtimes,
		RuntimesCount:  len(runtimes),
		Truncated:      truncated,
		TruncatedRoots: truncatedRoots,
		ScanDurationMs: time.Since(start).Milliseconds(),
	}
}
