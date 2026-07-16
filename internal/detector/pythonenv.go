// Filesystem walk-and-recognize discovery of installed Python packages.
//
// Rather than enumerating exact site-packages paths (a location allow-list that
// silently misses any interpreter installed somewhere we didn't list), we hand
// the existing dist-info recognizer (PythonDistDetector.ScanRoots) a bounded set
// of Python *install-tree* roots and let it recognize *.dist-info / *.egg-info
// metadata ANYWHERE beneath them. A package is then found regardless of the
// interpreter's internal layout or version — the only thing that must be known
// is the install tree, not the exact site-packages directory.
//
// No interpreter is executed: running python (even a tiny `python -c`) risks the
// macOS install-prompt / TCC behavior the disk-based scan exists to avoid. The
// walk itself is kept out of TCC-protected trees by the tcc.Skipper that
// ScanRoots already applies.
//
// All filesystem access and the home directory go through the executor so the
// discovery is user-aware (a root-run launchd scan resolves the console user's
// home, not /var/root) and mockable in tests.
package detector

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// pythonInstallTreeGlobs returns glob patterns for Python install trees to
// walk-and-recognize. Each pattern is scoped to a python version/framework tree
// (not a bare home or a whole Homebrew/Frameworks dir) so the walk stays
// bounded while still recognizing dist-info wherever it sits inside the tree.
//
// The home directory is resolved via executor.ResolveHome so a root-run scan
// (enterprise launchd) anchors on the logged-in user's home rather than
// /var/root, which is where the user's version-manager installs actually live.
func pythonInstallTreeGlobs(exec executor.Executor) []string {
	var pats []string

	if home := executor.ResolveHome(exec); home != "" {
		j := func(p ...string) string { return filepath.Join(append([]string{home}, p...)...) }
		pats = append(pats,
			// Version managers / user installs (one tree per version/env).
			j(".pyenv", "versions", "*"),
			j(".asdf", "installs", "python", "*"),
			j(".rye", "py", "*"),
			j(".local", "lib", "python*"),
			j(".local", "share", "uv", "python", "*"),
			j(".local", "share", "pipx", "venvs", "*"),
			// conda / mamba base + named envs.
			j("miniconda3"), j("miniconda3", "envs", "*"),
			j("anaconda3"), j("anaconda3", "envs", "*"),
			j("miniforge3"), j("miniforge3", "envs", "*"),
			j(".conda", "envs", "*"),
			// User-site under ~/Library (macOS). The whole-home skipper skips
			// ~/Library wholesale, so this specific tree is passed as its own
			// explicit root (ShouldSkip treats an explicit walk root as opt-in).
			j("Library", "Python", "*"),
		)
	}

	switch exec.GOOS() {
	case "darwin":
		pats = append(pats,
			// Framework pythons. The wrapper /usr/bin/python3 does not resolve
			// into the CLT/Xcode frameworks, so these are found structurally.
			"/Library/Frameworks/Python*.framework/Versions/*",
			"/Library/Developer/CommandLineTools/Library/Frameworks/Python*.framework/Versions/*",
			"/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python*.framework/Versions/*",
			// Homebrew (scoped to python cellars / lib version dirs).
			"/opt/homebrew/lib/python*",
			"/opt/homebrew/Cellar/python*",
			"/usr/local/lib/python*",
		)
	case "linux":
		pats = append(pats,
			"/usr/lib/python*",
			"/usr/lib64/python*",
			"/usr/local/lib/python*",
		)
	}
	return pats
}

// DiscoverPythonInstallRoots expands pythonInstallTreeGlobs and returns the
// existing directories to walk, symlink-resolved, deduplicated, and with any
// root nested under another dropped. No interpreter is executed.
func DiscoverPythonInstallRoots(exec executor.Executor, log *progress.Logger) []string {
	if log == nil {
		log = progress.NewNoop()
	}
	out := existingDirs(exec, expandGlobs(exec, pythonInstallTreeGlobs(exec)))
	log.Debug("python discovery: %d install tree(s) to walk", len(out))
	return out
}

// expandGlobs expands each glob pattern into its matches (patterns that match
// nothing contribute nothing).
func expandGlobs(exec executor.Executor, patterns []string) []string {
	var out []string
	for _, pat := range patterns {
		if m, err := exec.Glob(pat); err == nil {
			out = append(out, m...)
		}
	}
	return out
}

// existingDirs keeps only paths that exist and are directories, resolving
// symlinks (so framework "Versions/Current" collapses onto the concrete
// version), deduplicating, and dropping subsumed (nested) roots.
func existingDirs(exec executor.Executor, paths []string) []string {
	seen := make(map[string]struct{})
	var dirs []string
	for _, p := range paths {
		resolved, err := exec.EvalSymlinks(p)
		if err != nil {
			continue // absent
		}
		if fi, serr := exec.Stat(resolved); serr != nil || !fi.IsDir() {
			continue
		}
		if _, dup := seen[resolved]; dup {
			continue
		}
		seen[resolved] = struct{}{}
		dirs = append(dirs, resolved)
	}
	return dropSubsumedRoots(dirs)
}

// dropSubsumedRoots removes any directory nested under another directory in the
// set so ScanRoots does not walk the same subtree twice (e.g. a static
// ".../lib/pythonX.Y/site-packages" glob subsumed by the broader install tree).
func dropSubsumedRoots(dirs []string) []string {
	sort.Strings(dirs) // ancestors sort before their descendants
	var out []string
	for _, d := range dirs {
		subsumed := false
		for _, kept := range out {
			if d == kept || strings.HasPrefix(d, kept+string(filepath.Separator)) {
				subsumed = true
				break
			}
		}
		if !subsumed {
			out = append(out, d)
		}
	}
	return out
}

// GlobalPythonRoots returns the roots ScanRoots should walk-and-recognize for
// global/system Python packages: the filesystem-discovered install trees unioned
// with the static PythonGlobalRoots list (belt-and-suspenders, so coverage never
// regresses below the previous behavior), deduped by resolved path with nested
// roots dropped.
func GlobalPythonRoots(exec executor.Executor, log *progress.Logger) []string {
	if log == nil {
		log = progress.NewNoop()
	}
	var all []string
	all = append(all, PythonGlobalRoots(exec)...)
	all = append(all, DiscoverPythonInstallRoots(exec, log)...)
	roots := existingDirs(exec, all)

	// Coverage diagnostic: one concise info line per scan (a count, so it is
	// not noisy across a fleet), and the full list of scanned roots at debug.
	// This makes "which locations did we actually look in" visible in field
	// logs — so a reported miss can be traced to a package living outside the
	// scanned trees (add it via search_dirs) rather than guessed at.
	log.Progress("  Python: scanning %d global install root(s) for packages", len(roots))
	if len(roots) > 0 {
		log.Debug("python global install roots: %s", strings.Join(roots, ", "))
	}
	return roots
}
