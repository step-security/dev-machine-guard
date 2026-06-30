package detector

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// pmBinaryCandidateDirs returns an ordered list of directories where Node.js
// package managers (npm/yarn/pnpm/bun) are commonly installed on the current
// OS. It is the source list for a deterministic fallback used when a package
// manager can't be resolved on PATH.
//
// Why this exists: under launchd the agent inherits a stripped PATH
// (/usr/bin:/bin:/usr/sbin:/sbin), so a bare LookPath / "<pm> --version" can't
// see managers installed via Homebrew/nvm/Volta/bun/etc. The login-shell
// sourcing in executor.RunAsUser fixes most machines, but probing these
// well-known absolute locations is the deterministic backstop for the rest —
// generalizing the pnpm-only defaultPnpmBinDir (nodescan.go) to every manager.
//
// Dirs are anchored on the logged-in user's home (getHomeDir), NOT $HOME, which
// under a LaunchDaemon is /var/root. System dirs come first, then per-user
// package-manager dirs, then nvm's node bin dirs (newest version first).
func pmBinaryCandidateDirs(exec executor.Executor) []string {
	home := getHomeDir(exec)
	var dirs []string

	switch exec.GOOS() {
	case model.PlatformDarwin:
		dirs = append(dirs,
			"/opt/homebrew/bin", // Apple Silicon Homebrew
			"/usr/local/bin",    // Intel Homebrew, n, manual installs
		)
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, ".bun", "bin"),            // bun
				filepath.Join(home, "Library", "pnpm"),        // pnpm (PNPM_HOME)
				filepath.Join(home, "Library", "pnpm", "bin"), // pnpm global shims
				filepath.Join(home, ".npm-global", "bin"),     // npm prefix override
				filepath.Join(home, ".volta", "bin"),          // Volta shims
				filepath.Join(home, ".asdf", "shims"),         // asdf shims
			)
			dirs = append(dirs, nvmNodeBinDirs(exec, home)...)
		}
	case model.PlatformLinux:
		dirs = append(dirs,
			"/usr/bin",
			"/usr/local/bin",
			"/home/linuxbrew/.linuxbrew/bin", // Linuxbrew (shared install)
		)
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, ".linuxbrew", "bin"),       // Linuxbrew (per-user)
				filepath.Join(home, ".bun", "bin"),             // bun
				filepath.Join(home, ".local", "share", "pnpm"), // pnpm (PNPM_HOME)
				filepath.Join(home, ".npm-global", "bin"),      // npm prefix override
				filepath.Join(home, ".volta", "bin"),           // Volta shims
				filepath.Join(home, ".asdf", "shims"),          // asdf shims
			)
			dirs = append(dirs, nvmNodeBinDirs(exec, home)...)
		}
	case model.PlatformWindows:
		// Windows has no launchd/stripped-PATH problem; these are for symmetry.
		if appData := exec.Getenv("APPDATA"); appData != "" {
			dirs = append(dirs, filepath.Join(appData, "npm")) // npm global
		}
		if localAppData := exec.Getenv("LOCALAPPDATA"); localAppData != "" {
			dirs = append(dirs,
				filepath.Join(localAppData, "pnpm"),         // pnpm
				filepath.Join(localAppData, "Volta", "bin"), // Volta
			)
		}
		if home != "" {
			dirs = append(dirs, filepath.Join(home, ".bun", "bin")) // bun
		}
		if pf := exec.Getenv("ProgramFiles"); pf != "" {
			dirs = append(dirs, filepath.Join(pf, "nodejs")) // node installer
		}
		// TODO: nvm-windows (%APPDATA%\nvm) and fnm multishell dirs.
	}

	return dirs
}

// nvmNodeBinDirs returns the bin directories of every nvm-managed node release
// under home, newest version first. nvm installs each release at
// ~/.nvm/versions/node/<version>/bin. The newest is the most likely to hold a
// working npm/npx, so it is probed first; a lexical descending sort is good
// enough for the common vMAJOR.MINOR.PATCH layout (we only need a working
// binary, not strict semver ordering).
func nvmNodeBinDirs(exec executor.Executor, home string) []string {
	pattern := filepath.Join(home, ".nvm", "versions", "node", "*", "bin")
	matches, err := exec.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	return matches
}

// pmBinaryFilenames returns the on-disk filenames to probe for a package
// manager binary inside a candidate dir. On Unix the binary name is used as-is.
// On Windows npm/yarn/pnpm ship as .cmd shims (with .exe/.bat variants), while
// bun ships as bun.exe.
func pmBinaryFilenames(exec executor.Executor, binary string) []string {
	if exec.GOOS() != model.PlatformWindows {
		return []string{binary}
	}
	if binary == "bun" {
		return []string{binary + ".exe"}
	}
	return []string{binary + ".cmd", binary + ".exe", binary + ".bat"}
}

// resolveNodePMFromDefaults probes the OS-specific default install dirs
// (pmBinaryCandidateDirs) for the given package-manager binary. On the first
// existing file it runs that absolute path with versionCmd to read the version.
//
// Returns the resolved absolute path and the version. The version is the first
// non-empty "--version" output found; the path is the binary that produced that
// version, or — when no probed binary yields a version — the first one that
// merely exists (so the caller can still report a path with version "unknown").
// Both are "" when the binary is found in no candidate dir.
func resolveNodePMFromDefaults(ctx context.Context, exec executor.Executor, binary, versionCmd string) (path, version string) {
	dirs := pmBinaryCandidateDirs(exec)
	filenames := pmBinaryFilenames(exec, binary)
	for _, dir := range dirs {
		for _, name := range filenames {
			candidate := filepath.Join(dir, name)
			if !exec.FileExists(candidate) {
				continue
			}
			if path == "" {
				path = candidate
			}
			if v := runPMVersion(ctx, exec, dirs, candidate, versionCmd); v != "" {
				return candidate, v
			}
		}
	}
	return path, version
}

// runPMVersion runs binPath's version command and returns the trimmed output,
// or "" on failure.
//
// npm/yarn/pnpm are Node scripts (#!/usr/bin/env node), so invoking them by
// absolute path is not enough — they still need `node` resolvable on PATH, and
// node lives in one of the candidate dirs (e.g. /opt/homebrew/bin), often a
// DIFFERENT dir than the manager itself (yarn under ~/.npm-global/bin while
// node is under Homebrew). So on Unix the call is wrapped in `sh -c` with every
// candidate dir prepended to PATH; without it the fallback recovers only bun (a
// native binary) and still reports "unknown" for the Node-script managers. The
// wrapper behaves the same whether exec is the plain Real executor (bare PATH)
// or the UserAwareExecutor (login shell): the inner sh prepends to whatever
// $PATH it inherits, then runs the manager.
//
// On Windows the .cmd shims locate node relative to themselves and there is no
// launchd stripped-PATH problem, so the binary is invoked directly.
func runPMVersion(ctx context.Context, exec executor.Executor, dirs []string, binPath, versionCmd string) string {
	if exec.GOOS() == model.PlatformWindows {
		stdout, _, _, err := exec.RunWithTimeout(ctx, 10*time.Second, binPath, versionCmd)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(stdout)
	}
	cmd := pmVersionShellCommand(exec, dirs, binPath, versionCmd)
	stdout, _, _, err := exec.RunWithTimeout(ctx, 10*time.Second, "/bin/sh", "-c", cmd)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(stdout)
}

// pmVersionShellCommand builds the POSIX shell command that runs binPath's
// version flag with every candidate dir prepended to PATH (so the Node-script
// managers' "env node" shebang resolves — see runPMVersion). $PATH is left for
// the inner shell to expand, so the candidate dirs are added on top of whatever
// PATH that shell already has.
func pmVersionShellCommand(exec executor.Executor, dirs []string, binPath, versionCmd string) string {
	var b strings.Builder
	b.WriteString("PATH=")
	for _, d := range dirs {
		b.WriteString(platformShellQuote(exec, d))
		b.WriteString(":")
	}
	b.WriteString(`"$PATH" `)
	b.WriteString(platformShellQuote(exec, binPath))
	b.WriteString(" ")
	b.WriteString(platformShellQuote(exec, versionCmd))
	return b.String()
}
