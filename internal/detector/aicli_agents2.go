package detector

import (
	"context"
	"regexp"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"github.com/step-security/dev-machine-guard/internal/versionmeta"
)

// ---------------------------------------------------------------------------
// Identity ladders for Grok Build, Kimi Code, Muse Code, Hermes Agent and Oh My
// Pi. Same contract as resolvePi/resolveFactory/resolveAmp: first match wins,
// nothing is ever executed, every reject is Debug-logged with path and reason,
// and a state directory (~/.grok, ~/.kimi-code, ~/.hermes, ~/.omp,
// ~/.config/muse) never accepts a candidate by itself.
//
// `grok`, `kimi`, `muse` and `hermes` are all shared binary names — a Homebrew
// core regex tool, a MIDI sequencer in every Debian archive, unrelated npm and
// crates.io packages — so a PATH hit proves nothing. Identity comes from an npm
// manifest, an installer anchor plus a corroborator, a Homebrew root, a winget
// package directory or a pacman ownership record. The only file reads below
// are package.json (npmIdentity), .bunx (bunxTarget), pacman `files`
// manifests (pacmanPackageOwns) and Muse's 14-byte .muse-version sidecar.
// ---------------------------------------------------------------------------

const (
	grokPackageName = "@xai-official/grok"
	kimiPackageName = "@moonshot-ai/kimi-code"
	ompPackageName  = "@oh-my-pi/pi-coding-agent"

	// kimiMinBinaryBytes is the floor for the Kimi Code installer binary at
	// ~/.kimi-code/bin/kimi, measured at 151–181 MB across platforms. 64 MiB
	// leaves 2× headroom below and is what stops a stray script dropped at
	// that path from counting.
	kimiMinBinaryBytes int64 = 64 << 20

	// ompMinBinaryBytes is the floor for the Oh My Pi standalone binary,
	// measured at 135–161 MB. Required on the Homebrew channel too, because a
	// third-party tap token is attacker-choosable.
	ompMinBinaryBytes int64 = 64 << 20

	// museVersionMaxBytes caps the .muse-version read. The real sidecar is a
	// 14-byte version string.
	museVersionMaxBytes int64 = 64
)

// museVersionRE is Muse Code's release format: semver plus an -R<build>[.n]
// suffix, e.g. 1.0.3-R2198.1.
var museVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-R[0-9]+(\.[0-9]+)?$`)

// kimiLegacyVenvs are the uv-tool and pipx virtualenvs the Python-era Kimi CLI
// installs into; ~/.local/bin/kimi is a symlink into one of them.
var kimiLegacyVenvs = []string{
	"~/.local/share/uv/tools/kimi-cli",
	"~/.local/share/pipx/venvs/kimi-cli",
	"~/AppData/Local/uv/tools/kimi-cli",
	"~/AppData/Local/pipx/venvs/kimi-cli",
}

// hermesLayouts pairs each installer launcher location with the venv the same
// installer writes. The launcher is a tiny bash script (not a symlink, so
// resolved == found) and is never read: the launcher-plus-venv pair is the
// installer's own signature, and an unrelated ~/.local/bin/hermes with no venv
// beside it is rejected.
var hermesLayouts = []struct{ launcher, venv string }{
	{"~/.local/bin/hermes", "~/.hermes/hermes-agent/venv"},
	{"/usr/local/bin/hermes", "/usr/local/lib/hermes-agent/venv"},
	{"~/AppData/Local/hermes/bin", "~/AppData/Local/hermes/hermes-agent/venv"},
}

// ompMiseRoot is mise's install root for the github:can1357/oh-my-pi backend;
// each release lives in its own version directory under it. Windows never
// reaches the mise rule: aiCLIBinaryCandidateDirs globs the tree only on
// darwin/linux, and the Windows PATH shim resolves to mise.exe.
const ompMiseRoot = "~/.local/share/mise/installs/github-can1357-oh-my-pi"

// versionFromFilename returns the version token that follows prefix in a
// versioned binary name — grok-1.0.13, grok-1.0.13-linux-aarch64,
// grok-1.0.13.exe, muse-bin-1.0.3-R2198.1 — stopping at the first platform
// token, and "" unless the result is version-shaped (grok-macos-aarch64 is the
// unversioned bootstrap and yields "").
func versionFromFilename(base, prefix string) string {
	if n := len(base) - len(".exe"); n > 0 && strings.EqualFold(base[n:], ".exe") {
		base = base[:n]
	}
	rest, ok := strings.CutPrefix(base, prefix)
	if !ok {
		return ""
	}
	tokens := strings.Split(rest, "-")
	end := 0
	for end < len(tokens) && !isOSToken(tokens[end]) {
		end++
	}
	v := strings.Join(tokens[:end], "-")
	if !versionmeta.IsVersionLike(v) {
		return ""
	}
	return v
}

func isOSToken(s string) bool {
	switch strings.ToLower(s) {
	case "macos", "darwin", "linux", "windows":
		return true
	}
	return false
}

// distInfoVersion returns the version of the Python distribution dist installed
// in venv, read from the NAME of its single <dist>-<v>.dist-info directory —
// one Glob, nothing opened. "" when the glob finds zero or several matches.
func distInfoVersion(exec executor.Executor, log *progress.Logger, venv, dist string) string {
	sitePackages := joinPath(venv, "lib", "python*", "site-packages")
	if exec.GOOS() == model.PlatformWindows {
		sitePackages = joinPath(venv, "Lib", "site-packages")
	}
	matches, err := exec.Glob(joinPath(sitePackages, dist+"-*.dist-info"))
	if err != nil || len(matches) != 1 {
		log.Debug("%s: %d dist-info directories under %s, need exactly one; no dist-info version", dist, len(matches), sitePackages)
		return ""
	}
	v := strings.TrimSuffix(strings.TrimPrefix(pathBase(matches[0]), dist+"-"), ".dist-info")
	if !versionmeta.IsVersionLike(v) {
		return ""
	}
	return v
}

// brewKeg returns the Cellar/<formula>/<version> directory enclosing resolved,
// "" when resolved is not under a Cellar. Homebrew paths are always absolute
// POSIX paths.
func brewKeg(resolved string) string {
	segments := splitPathAny(resolved)
	for i := 0; i < len(segments)-2; i++ {
		if segments[i] == "Cellar" {
			return "/" + strings.Join(segments[:i+3], "/")
		}
	}
	return ""
}

// grokCopyVersion recovers the version of the Windows ~\.grok\bin\grok.exe,
// which the installer writes as a COPY of grok-<v>.exe rather than a link. When
// exactly one versioned sibling exists and is the same size, it is the source
// of the copy. This is the one place a size equality is correct: it compares a
// file with its own copy, not with a published artifact.
func grokCopyVersion(exec executor.Executor, log *progress.Logger, resolved string) string {
	dir := pathDir(resolved)
	matches, err := exec.Glob(joinPath(dir, "grok-*.exe"))
	if err != nil || len(matches) != 1 {
		log.Debug("grok-build: %d versioned grok-*.exe siblings beside %s, need exactly one; version unknown", len(matches), resolved)
		return ""
	}
	copyInfo, err := exec.Stat(resolved)
	if err != nil {
		return ""
	}
	srcInfo, err := exec.Stat(matches[0])
	if err != nil || srcInfo.Size() != copyInfo.Size() {
		log.Debug("grok-build: %s is not the same size as %s; version unknown", resolved, matches[0])
		return ""
	}
	return versionFromFilename(pathBase(matches[0]), "grok-")
}

// resolveGrok proves an xAI Grok Build install. The colliders are the unrelated
// `grok` regex log parser (Homebrew core, Debian, Arch) and cargo crates of the
// same name; none of them lives under ~/.grok or ships the @xai-official/grok
// manifest. ~/.grok/config.toml names the installer channel but is never read:
// the filename rule below already distinguishes the channels that matter.
func resolveGrok(_ context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool) {
	return resolveVerified(exec, log, skipper, spec, homeDir, func(found, resolved string) (string, bool) {
		// Rule 1 — npm: the Unix trampoline symlink, the Windows grok.cmd
		// shim and every npm/pnpm/yarn/volta prefix candidatePaths probes.
		name, version, ok := npmIdentity(exec, found, resolved, grokPackageName)
		if ok {
			return version, true
		}

		// Rule 2 — Grok's own home. ~/.grok/bin/grok links to grok-<v> after
		// an npm postinstall, to ../downloads/grok-<v>-<os>-<arch> after a
		// self-update, and to the unversioned grok-<os>-<arch> bootstrap on a
		// fresh script install (reported unknown). On Windows the .exe is a
		// copy, so its version comes from the same-size versioned sibling.
		if underHomeDir(exec, homeDir, resolved, "~/.grok/bin") || underHomeDir(exec, homeDir, resolved, "~/.grok/downloads") {
			if v := versionFromFilename(pathBase(resolved), "grok-"); v != "" {
				return v, true
			}
			if exec.GOOS() == model.PlatformWindows {
				return grokCopyVersion(exec, log, resolved), true
			}
			return "", true
		}

		// Rule 3 — winget portable.
		if exec.GOOS() == model.PlatformWindows && wingetPackage(resolved, "xAI.GrokBuild") {
			return "", true
		}

		// Rule 4 — pacman. /usr/bin/grok is the log parser on every distro
		// unless an AUR grok-build package owns it.
		if cleanPath(resolved) == "/usr/bin/grok" {
			if pacmanPackageOwns(exec, []string{"grok-build", "grok-build-bin", "grok-build-git"}, "usr/bin/grok") {
				return "", true
			}
			log.Debug("grok-build: rejecting %s — no installed grok-build package owns usr/bin/grok; the distro `grok` is the unrelated regex log parser", found)
			return "", false
		}

		// Rule 5 — reject.
		if root, pkg := brewRoot(resolved); root == "Cellar" && pkg == "grok" {
			log.Debug("grok-build: rejecting %s — Homebrew Cellar/grok is the regex log-parser formula, not Grok Build", found)
			return "", false
		}
		if underHomeDir(exec, homeDir, resolved, "~/.cargo") {
			log.Debug("grok-build: rejecting %s — under ~/.cargo, a cargo-installed grok crate", found)
			return "", false
		}
		if name != "" {
			log.Debug("grok-build: rejecting %s — npm package is %q, not %s", found, name, grokPackageName)
		} else {
			log.Debug("grok-build: rejecting %s — no Grok Build channel claims it (resolved %s)", found, resolved)
		}
		return "", false
	})
}

// resolveKimi proves a Moonshot Kimi Code install, including the Python-era
// Kimi CLI it replaced: same vendor, same product line, and the new installer
// migrates the old one, so both report as kimi-code (the 1.x versus 0.x
// version tells them apart). The Homebrew cask `kimi` is a desktop app and
// never produces a `kimi` binary.
func resolveKimi(_ context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool) {
	return resolveVerified(exec, log, skipper, spec, homeDir, func(found, resolved string) (string, bool) {
		// Rule 1 — npm and the Homebrew formula, whose binary resolves into
		// Cellar/kimi-code/<v>/libexec/lib/node_modules/@moonshot-ai/kimi-code
		// and so carries the same manifest.
		name, version, ok := npmIdentity(exec, found, resolved, kimiPackageName)
		if ok {
			return version, true
		}

		// Rule 2 — the installer anchor, corroborated by the size floor. No
		// on-disk version source: reported unknown.
		if underHomeDir(exec, homeDir, resolved, "~/.kimi-code/bin") {
			if fileAtLeast(exec, found, kimiMinBinaryBytes) {
				return "", true
			}
			log.Debug("kimi-code: rejecting %s — at the installer target but under %d bytes", found, kimiMinBinaryBytes)
			return "", false
		}

		// Rule 3 — the legacy Python CLI's uv-tool or pipx venv, which
		// ~/.local/bin/kimi symlinks into. Version from the dist-info name.
		for _, venv := range kimiLegacyVenvs {
			if underHomeDir(exec, homeDir, resolved, venv) {
				return distInfoVersion(exec, log, expandTildePath(venv, homeDir), "kimi_cli"), true
			}
		}

		// Rule 4 — winget portable, both identifiers.
		if exec.GOOS() == model.PlatformWindows &&
			(wingetPackage(resolved, "MoonshotAI.KimiCodeCLI") || wingetPackage(resolved, "MoonshotAI.KimiCLI")) {
			return "", true
		}

		// Rule 5 — reject.
		if underHomeDir(exec, homeDir, resolved, "~/.cargo") {
			log.Debug("kimi-code: rejecting %s — under ~/.cargo, a cargo-installed kimi crate", found)
			return "", false
		}
		if root, pkg := brewRoot(resolved); root == "Cellar" && pkg == "kimi" {
			log.Debug("kimi-code: rejecting %s — Homebrew Cellar/kimi is not the kimi-code formula", found)
			return "", false
		}
		if name != "" {
			log.Debug("kimi-code: rejecting %s — npm package is %q, not %s", found, name, kimiPackageName)
		} else {
			log.Debug("kimi-code: rejecting %s — no Kimi Code channel claims it (resolved %s)", found, resolved)
		}
		return "", false
	})
}

// resolveMuse proves a Meta Muse Code install. The launcher is a 33 KB script
// beside a .muse-version sidecar and the muse-bin-<v> payload it names; the
// colliders — Debian's MusE MIDI sequencer at /usr/bin/muse, the crates.io
// `muse` commit-message CLI and the unrelated npm `muse` — have neither.
func resolveMuse(_ context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool) {
	return resolveVerified(exec, log, skipper, spec, homeDir, func(found, resolved string) (string, bool) {
		// The npm and cargo colliders first: rule 1 probes for siblings in
		// the resolved directory, and a collider's directory is never probed.
		if versionmeta.NodeModulesPackageRoot(resolved) != "" {
			log.Debug("muse-code: rejecting %s — under node_modules; npm `muse` is unrelated and Muse Code has no npm package", found)
			return "", false
		}
		if underHomeDir(exec, homeDir, resolved, "~/.cargo") {
			log.Debug("muse-code: rejecting %s — under ~/.cargo, the cargo-installed muse commit-message CLI", found)
			return "", false
		}

		// Rule 1 — launcher plus sidecar, directory-relative so a relocated
		// MUSE_INSTALL_DIR on PATH still resolves. The sidecar is read only
		// under the size cap, and it accepts only when the muse-bin-<v> it
		// names is actually there. Without a sidecar, a single muse-bin-*
		// sibling still identifies the install.
		dir := pathDir(resolved)
		sidecar := joinPath(dir, ".muse-version")
		if info, err := exec.Stat(sidecar); err == nil {
			if info.Size() > museVersionMaxBytes {
				log.Debug("muse-code: rejecting %s — %s is %d bytes, over the %d-byte cap", found, sidecar, info.Size(), museVersionMaxBytes)
				return "", false
			}
			data, err := exec.ReadFile(sidecar)
			v := strings.TrimSpace(string(data))
			if err != nil || int64(len(data)) > museVersionMaxBytes || !museVersionRE.MatchString(v) {
				log.Debug("muse-code: rejecting %s — %s does not carry a Muse release version", found, sidecar)
				return "", false
			}
			if !exec.FileExists(joinPath(dir, "muse-bin-"+v)) {
				log.Debug("muse-code: rejecting %s — %s names %s but no muse-bin-%s sits beside it", found, sidecar, v, v)
				return "", false
			}
			return v, true
		}
		if bins, err := exec.Glob(joinPath(dir, "muse-bin-*")); err == nil && len(bins) > 0 {
			if len(bins) == 1 {
				return versionFromFilename(pathBase(bins[0]), "muse-bin-"), true
			}
			log.Debug("muse-code: %d muse-bin-* siblings beside %s and no .muse-version; version unknown", len(bins), found)
			return "", true
		}

		// Rule 2 — homebrew/cask muse-code. No version here: getVersion
		// recovers it from the Caskroom segment, statically.
		if root, pkg := brewRoot(resolved); root == "Caskroom" && pkg == "muse-code" {
			return "", true
		}
		if root, pkg := brewRoot(resolved); root == "Cellar" && pkg == "muse" {
			log.Debug("muse-code: rejecting %s — Homebrew Cellar/muse is not the muse-code cask", found)
			return "", false
		}

		// Rule 3 — pacman. Ubuntu's and Arch's `muse` package is the MusE
		// sequencer; only the AUR muse-code packages make /usr/bin/muse ours.
		if cleanPath(resolved) == "/usr/bin/muse" {
			if pacmanPackageOwns(exec, []string{"muse-code-bin", "muse-code"}, "usr/bin/muse") {
				return "", true
			}
			log.Debug("muse-code: rejecting %s — no installed muse-code package owns usr/bin/muse; the distro `muse` is the MusE sequencer", found)
			return "", false
		}

		// Rule 4 — reject.
		log.Debug("muse-code: rejecting %s — no Muse Code channel claims it (resolved %s)", found, resolved)
		return "", false
	})
}

// resolveHermes proves a Nous Research Hermes Agent install. The colliders are
// npm `hermes` and PyPI `hermes`, plus an unofficial npm `hermes-agent`
// bridge; none of them writes the installer's venv.
func resolveHermes(_ context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool) {
	return resolveVerified(exec, log, skipper, spec, homeDir, func(found, resolved string) (string, bool) {
		// Rules 1 and 2 — the installer's launcher-plus-venv pairs (user,
		// root and Windows layouts). The launcher is never read; the venv
		// directory beside it is the corroborator, and its dist-info name is
		// the version.
		for _, layout := range hermesLayouts {
			if !underHomeDir(exec, homeDir, resolved, layout.launcher) {
				continue
			}
			venv := expandTildePath(layout.venv, homeDir)
			if exec.DirExists(venv) {
				return distInfoVersion(exec, log, venv, "hermes_agent"), true
			}
			log.Debug("hermes-agent: rejecting %s — the installer launcher is there but %s is not", found, venv)
			return "", false
		}

		// Rule 3 — Homebrew formula. The keg's own venv carries the upstream
		// version (0.21.0, consistent with the other channels); when it is
		// missing, getVersion falls back to the Cellar segment (2026.8.31).
		if root, pkg := brewRoot(resolved); root == "Cellar" && pkg == "hermes-agent" {
			return distInfoVersion(exec, log, joinPath(brewKeg(resolved), "libexec"), "hermes_agent"), true
		}

		// Rule 4 — reject.
		if versionmeta.NodeModulesPackageRoot(resolved) != "" {
			log.Debug("hermes-agent: rejecting %s — under node_modules; npm `hermes` and the unofficial hermes-agent bridge are not the installer", found)
			return "", false
		}
		if underHomeDir(exec, homeDir, resolved, "~/.cargo") {
			log.Debug("hermes-agent: rejecting %s — under ~/.cargo, a cargo-installed hermes crate", found)
			return "", false
		}
		log.Debug("hermes-agent: rejecting %s — no Hermes Agent channel claims it (resolved %s)", found, resolved)
		return "", false
	})
}

// resolveOMP proves a Stencil Oh My Pi install. `omp` has no popular collider,
// but the Homebrew tap and the standalone anchors are attacker-choosable
// paths, so both carry the size floor.
func resolveOMP(_ context.Context, exec executor.Executor, log *progress.Logger, skipper *tcc.Skipper, spec cliToolSpec, homeDir string) (cliResolution, bool) {
	return resolveVerified(exec, log, skipper, spec, homeDir, func(found, resolved string) (string, bool) {
		// Rule 1 — npm, pnpm, yarn, Bun and the Windows .cmd shim (which
		// names bun.exe as its runner; NPMShimPackageRoot only needs the
		// node_modules path).
		name, version, ok := npmIdentity(exec, found, resolved, ompPackageName)
		if ok {
			return version, true
		}

		// Rule 2 — the Windows Bun shim, exactly as resolvePi rule 2b.
		if exec.GOOS() == model.PlatformWindows {
			if target := bunxTarget(exec, found, homeDir); target != "" {
				if _, bunVersion, bunOK := npmIdentity(exec, target, target, ompPackageName); bunOK {
					return bunVersion, true
				}
			}
		}

		// Rule 3 — Homebrew formula, corroborated by the floor. getVersion
		// recovers the Cellar segment.
		if root, pkg := brewRoot(resolved); root == "Cellar" && pkg == "omp" {
			if fileAtLeast(exec, found, ompMinBinaryBytes) {
				return "", true
			}
			log.Debug("oh-my-pi: rejecting %s — Homebrew Cellar/omp but under %d bytes", found, ompMinBinaryBytes)
			return "", false
		}

		// Rule 4 — mise. resolveVerified already followed the shim-free
		// candidate from aiCLIBinaryCandidateDirs through EvalSymlinks, so an
		// alias dir (18, 18.1, latest) arrives as its real version dir.
		if underHomeDir(exec, homeDir, resolved, ompMiseRoot) {
			return miseVersionSegment(resolved), true
		}

		// Rule 5 — standalone anchors with the floor; no version on disk.
		if underHomeDir(exec, homeDir, resolved, "~/.local/bin/omp") || underHomeDir(exec, homeDir, resolved, "~/AppData/Local/omp/omp.exe") {
			if fileAtLeast(exec, found, ompMinBinaryBytes) {
				return "", true
			}
			log.Debug("oh-my-pi: rejecting %s — at the standalone anchor but under %d bytes", found, ompMinBinaryBytes)
			return "", false
		}

		// Rule 6 — winget portable.
		if exec.GOOS() == model.PlatformWindows && wingetPackage(resolved, "can1357.oh-my-pi") {
			return "", true
		}

		// Rule 7 — reject.
		if name != "" {
			log.Debug("oh-my-pi: rejecting %s — npm package is %q, not %s", found, name, ompPackageName)
		} else {
			log.Debug("oh-my-pi: rejecting %s — no Oh My Pi channel claims it (resolved %s)", found, resolved)
		}
		return "", false
	})
}

// miseVersionSegment returns the version directory segment that follows the
// mise install root in resolved, "" when that segment is not version-shaped.
func miseVersionSegment(resolved string) string {
	segments := splitPathAny(resolved)
	for i := 0; i < len(segments)-1; i++ {
		if segments[i] == "github-can1357-oh-my-pi" && versionmeta.IsVersionLike(segments[i+1]) {
			return segments[i+1]
		}
	}
	return ""
}
