package detector

import (
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// nodeGlobalRoot is a global node_modules directory paired with the package
// manager that owns it.
type nodeGlobalRoot struct {
	pm  string
	dir string
}

// NodeGlobalRoots enumerates global node_modules directories on the host,
// grouped by package manager, with no PM invocation (replaces `npm config get
// prefix` / `yarn global dir` / `pnpm root -g`). Only directories that exist
// are returned.
//
// Globals are scattered across version managers and install prefixes, so this
// is a best-effort sweep of the well-known locations rather than an exhaustive
// resolution of the user's active prefix — the same trade-off as the Python
// global-roots scan. Where a manager (nvm/fnm/volta) keeps per-version trees,
// every installed version's global dir is included.
func NodeGlobalRoots(exec executor.Executor) []nodeGlobalRoot {
	var roots []nodeGlobalRoot
	add := func(pm, dir string) {
		if dir != "" && exec.DirExists(dir) {
			roots = append(roots, nodeGlobalRoot{pm: pm, dir: dir})
		}
	}
	addGlob := func(pm, pattern string) {
		if matches, err := exec.Glob(pattern); err == nil {
			for _, m := range matches {
				add(pm, m)
			}
		}
	}
	home := nodeHomeDir(exec)

	// --- npm: <prefix>/lib/node_modules (POSIX) or <prefix>/node_modules (Windows). ---
	switch exec.GOOS() {
	case model.PlatformDarwin, model.PlatformLinux:
		add("npm", "/usr/local/lib/node_modules")
		add("npm", "/usr/lib/node_modules")
		add("npm", "/opt/homebrew/lib/node_modules")
		if home != "" {
			add("npm", filepath.Join(home, ".npm-global", "lib", "node_modules"))
			addGlob("npm", filepath.Join(home, ".nvm", "versions", "node", "*", "lib", "node_modules"))
			addGlob("npm", filepath.Join(home, ".volta", "tools", "image", "node", "*", "lib", "node_modules"))
			addGlob("npm", filepath.Join(home, ".local", "share", "fnm", "node-versions", "*", "installation", "lib", "node_modules"))
		}
	case model.PlatformWindows:
		if appData := exec.Getenv("APPDATA"); appData != "" {
			add("npm", filepath.Join(appData, "npm", "node_modules"))
		}
	}
	// Honor an explicit prefix override regardless of OS.
	for _, env := range []string{"npm_config_prefix", "PREFIX"} {
		if p := exec.Getenv(env); p != "" {
			add("npm", filepath.Join(p, "lib", "node_modules")) // POSIX layout
			add("npm", filepath.Join(p, "node_modules"))        // Windows layout
		}
	}

	// --- pnpm globals. Layout varies by pnpm major:
	//   - pnpm <=9: <pnpm-home>/global/<n>/node_modules       (<n> is a store-format id)
	//   - pnpm v10+: <pnpm-home>/global/v<major>/<hash>/node_modules
	//     (each `pnpm add -g` gets its own hashed install dir under global/v<major>)
	// Match both so a modern pnpm's globals aren't silently missed.
	for _, pnpmHome := range pnpmGlobalHomes(exec, home) {
		addGlob("pnpm", filepath.Join(pnpmHome, "global", "*", "node_modules"))
		addGlob("pnpm", filepath.Join(pnpmHome, "global", "*", "*", "node_modules"))
	}

	// --- yarn classic globals. Location differs by OS:
	//   - POSIX:   ~/.config/yarn/global/node_modules
	//   - Windows: %LOCALAPPDATA%\Yarn\Data\global\node_modules (yarn 1.x
	//     `yarn global dir`); older builds used %LOCALAPPDATA%\Yarn\global.
	// The POSIX path uses HOME/USERPROFILE, which never resolves the Windows
	// yarn prefix, so yarn globals were invisible on Windows.
	switch exec.GOOS() {
	case model.PlatformWindows:
		if localAppData := exec.Getenv("LOCALAPPDATA"); localAppData != "" {
			add("yarn", filepath.Join(localAppData, "Yarn", "Data", "global", "node_modules"))
			add("yarn", filepath.Join(localAppData, "Yarn", "global", "node_modules"))
		}
	default:
		if home != "" {
			add("yarn", filepath.Join(home, ".config", "yarn", "global", "node_modules"))
		}
	}

	return roots
}

// pnpmGlobalHomes returns candidate pnpm home directories (PNPM_HOME plus the
// OS default), under which global installs live at global/<n>/node_modules.
func pnpmGlobalHomes(exec executor.Executor, home string) []string {
	var homes []string
	if h := exec.Getenv("PNPM_HOME"); h != "" {
		homes = append(homes, h)
	}
	switch exec.GOOS() {
	case model.PlatformDarwin:
		if home != "" {
			homes = append(homes, filepath.Join(home, "Library", "pnpm"))
		}
	case model.PlatformLinux:
		if home != "" {
			homes = append(homes, filepath.Join(home, ".local", "share", "pnpm"))
		}
	case model.PlatformWindows:
		if localAppData := exec.Getenv("LOCALAPPDATA"); localAppData != "" {
			homes = append(homes, filepath.Join(localAppData, "pnpm"))
		}
	}
	return homes
}

// nodeHomeDir returns the user's home directory via the platform-appropriate
// environment variable. Uses the env rather than user.Current so that, under a
// root daemon delegating to a logged-in user, callers that pre-set HOME resolve
// the user's tree.
func nodeHomeDir(exec executor.Executor) string {
	if exec.GOOS() == model.PlatformWindows {
		return exec.Getenv("USERPROFILE")
	}
	return exec.Getenv("HOME")
}
