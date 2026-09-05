package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Cases for the five wave-2 ladders (grok-build, kimi-code, muse-code,
// hermes-agent, oh-my-pi), on the harness aicli_agents_test.go owns. Every case
// traps exec: all five specs are StaticVersionOnly, so no channel — accept or
// reject — may launch anything.

const (
	kimiRealBytes int64 = 151 << 20 // measured installer binary, low end
	ompRealBytes  int64 = 135 << 20 // measured standalone binary, low end
	museVersion         = "1.0.3-R2198.1"
	hermesVersion       = "0.21.0"
	ompVersion          = "18.1.10"
)

// distInfoGlob is the pattern distInfoVersion issues for venv, in the goos
// spelling — what a case must SetGlob and allow.
func distInfoGlob(goos, venv, dist string) string {
	if goos == model.PlatformWindows {
		return joinPath(venv, "Lib", "site-packages", dist+"-*.dist-info")
	}
	return joinPath(venv, "lib", "python*", "site-packages", dist+"-*.dist-info")
}

// addDistInfo registers exactly one <dist>-<v>.dist-info under venv and returns
// the pattern the case must allow.
func addDistInfo(m *executor.Mock, goos, venv, dist, version string) string {
	pattern := distInfoGlob(goos, venv, dist)
	m.SetGlob(pattern, []string{joinPath(pathDir(pattern), dist+"-"+version+".dist-info")})
	return pattern
}

// addMuseInstall lays down the installer's directory: the launcher script, the
// .muse-version sidecar and the muse-bin-<v> payload.
func addMuseInstall(m *executor.Mock, dir, version string) {
	addFile(m, joinPath(dir, "muse"), []byte("#!/usr/bin/env bash\n"))
	addFile(m, joinPath(dir, ".muse-version"), []byte(version+"\n"))
	addBinary(m, joinPath(dir, "muse-bin-"+version), 90<<20)
}

func TestVersionFromFilename(t *testing.T) {
	tests := []struct{ base, prefix, want string }{
		{"grok-1.0.13", "grok-", "1.0.13"},
		{"grok-1.0.13-linux-aarch64", "grok-", "1.0.13"},
		{"grok-1.0.13-macos-aarch64", "grok-", "1.0.13"},
		{"grok-1.0.13.exe", "grok-", "1.0.13"},
		{"grok-1.0.13-windows-x64.EXE", "grok-", "1.0.13"},
		{"grok-macos-aarch64", "grok-", ""}, // unversioned bootstrap
		{"grok", "grok-", ""},
		{"grok.exe", "grok-", ""},
		{"muse-bin-1.0.3-R2198.1", "muse-bin-", "1.0.3-R2198.1"},
		{"muse-bin-", "muse-bin-", ""},
		{"kimi-1.0.13", "grok-", ""},
	}
	for _, tc := range tests {
		if got := versionFromFilename(tc.base, tc.prefix); got != tc.want {
			t.Errorf("versionFromFilename(%q, %q) = %q, want %q", tc.base, tc.prefix, got, tc.want)
		}
	}
}

func TestDistInfoVersion(t *testing.T) {
	venv := "/home/u/.local/share/uv/tools/kimi-cli"
	pattern := distInfoGlob(model.PlatformLinux, venv, "kimi_cli")
	sp := pathDir(pattern)

	t.Run("one match yields its version", func(t *testing.T) {
		m, _ := newAICLIMock(model.PlatformLinux)
		m.SetGlob(pattern, []string{sp + "/kimi_cli-1.49.0.dist-info"})
		if got := distInfoVersion(m, progress.NewNoop(), venv, "kimi_cli"); got != "1.49.0" {
			t.Errorf("got %q, want 1.49.0", got)
		}
	})
	t.Run("two matches yield nothing", func(t *testing.T) {
		m, _ := newAICLIMock(model.PlatformLinux)
		m.SetGlob(pattern, []string{sp + "/kimi_cli-1.49.0.dist-info", sp + "/kimi_cli-1.50.0.dist-info"})
		if got := distInfoVersion(m, progress.NewNoop(), venv, "kimi_cli"); got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
	})
	t.Run("no match yields nothing and nothing else is touched", func(t *testing.T) {
		m, _ := newAICLIMock(model.PlatformLinux)
		rec := &recExec{Mock: m, t: t, trapExec: true}
		if got := distInfoVersion(rec, progress.NewNoop(), venv, "kimi_cli"); got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
		if len(rec.reads) != 0 || len(rec.globs) != 1 {
			t.Errorf("reads=%v globs=%v; want no reads and one glob", rec.reads, rec.globs)
		}
	})
	t.Run("windows uses Lib/site-packages", func(t *testing.T) {
		m, _ := newAICLIMock(model.PlatformWindows)
		wv := `C:\Users\u\AppData\Local\hermes\hermes-agent\venv`
		wp := distInfoGlob(model.PlatformWindows, wv, "hermes_agent")
		m.SetGlob(wp, []string{wv + `\Lib\site-packages\hermes_agent-0.21.0.dist-info`})
		if got := distInfoVersion(m, progress.NewNoop(), wv, "hermes_agent"); got != "0.21.0" {
			t.Errorf("got %q, want 0.21.0", got)
		}
	})
}

// ---------------------------------------------------------------------------
// grok-build
// ---------------------------------------------------------------------------

func TestAICLIAgents_Grok(t *testing.T) {
	runAICLICases(t, []aicliCase{
		{
			name: "(g1) script install: the bootstrap link carries no version and reports unknown",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				link := joinPath(home, ".grok", "bin", "grok")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(home, ".grok", "bin", "grok-macos-aarch64"))
				setConfigDir(m, home, "~/.grok")
			},
			want: []aicliWant{{tool: "grok-build", binary: "/Users/u/.grok/bin/grok", version: "unknown", configRel: "~/.grok"}},
		},
		{
			name: "(g2) after npm postinstall the link names its version",
			setup: func(m *executor.Mock, home string) {
				link := joinPath(home, ".grok", "bin", "grok")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(home, ".grok", "bin", "grok-1.0.13"))
			},
			want: []aicliWant{{tool: "grok-build", binary: "/home/u/.grok/bin/grok", version: "1.0.13"}},
		},
		{
			name: "(g3) after a self-update the link points into downloads with a platform suffix",
			setup: func(m *executor.Mock, home string) {
				link := joinPath(home, ".grok", "bin", "grok")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(home, ".grok", "downloads", "grok-1.0.13-linux-aarch64"))
			},
			want: []aicliWant{{tool: "grok-build", binary: "/home/u/.grok/bin/grok", version: "1.0.13"}},
		},
		{
			name: "(g4) the npm prefix trampoline accepts from its manifest",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("grok", "/usr/local/bin/grok")
				addNPMGlobal(m, "/usr/local/bin/grok", "/usr/local/lib/node_modules/@xai-official/grok", grokPackageName, "1.0.13")
			},
			want: []aicliWant{{tool: "grok-build", binary: "/usr/local/bin/grok", version: "1.0.13"}},
		},
		{
			name: "(g4a) the anchor wins over a PATH hit that resolves to the same file",
			setup: func(m *executor.Mock, home string) {
				link := joinPath(home, ".grok", "bin", "grok")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(home, ".grok", "bin", "grok-1.0.13"))
				local := joinPath(home, ".local", "bin", "grok")
				m.SetPath("grok", local)
				addFile(m, local, []byte{})
				m.SetSymlink(local, joinPath(home, ".grok", "bin", "grok-1.0.13"))
			},
			want: []aicliWant{{tool: "grok-build", binary: "/home/u/.grok/bin/grok", version: "1.0.13"}},
		},
		{
			name: "(g5) /usr/bin/grok owned by an AUR grok-build package accepts",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("grok", "/usr/bin/grok")
				addFile(m, "/usr/bin/grok", []byte{})
				m.SetGlob("/var/lib/pacman/local/*-*", []string{"/var/lib/pacman/local/grok-build-bin-1.0.13-1"})
				addFile(m, "/var/lib/pacman/local/grok-build-bin-1.0.13-1/files", pacmanFiles("usr/bin/grok"))
			},
			want: []aicliWant{{tool: "grok-build", binary: "/usr/bin/grok", version: "unknown"}},
		},
		{
			name: "(g5r) /usr/bin/grok owned by the distro grok is the unrelated log parser",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("grok", "/usr/bin/grok")
				addFile(m, "/usr/bin/grok", []byte{})
				m.SetGlob("/var/lib/pacman/local/*-*", []string{"/var/lib/pacman/local/grok-1.20.2-1"})
				addFile(m, "/var/lib/pacman/local/grok-1.20.2-1/files", pacmanFiles("usr/bin/grok"))
			},
			wantDebug: []string{"no installed grok-build package owns usr/bin/grok"},
		},
		{
			name: "(g6r) Homebrew Cellar/grok is the regex formula",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("grok", "/opt/homebrew/bin/grok")
				addFile(m, "/opt/homebrew/bin/grok", []byte{})
				m.SetSymlink("/opt/homebrew/bin/grok", "/opt/homebrew/Cellar/grok/1.20.2/bin/grok")
			},
			wantDebug: []string{"Homebrew Cellar/grok is the regex log-parser formula"},
		},
		{
			name: "(g7r) the cargo grok is rejected",
			setup: func(m *executor.Mock, home string) {
				cargo := joinPath(home, ".cargo", "bin", "grok")
				m.SetPath("grok", cargo)
				addFile(m, cargo, []byte{})
			},
			wantDebug: []string{"under ~/.cargo"},
		},
		{
			name: "(g8r) an npm package of another name is rejected by name",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("grok", "/usr/local/bin/grok")
				addNPMGlobal(m, "/usr/local/bin/grok", "/usr/local/lib/node_modules/grok", "grok", "0.1.0")
			},
			wantDebug: []string{`npm package is "grok", not ` + grokPackageName},
		},
		{
			name: "(g9r) a plain ~/.local/bin/grok script with no corroborator is rejected",
			setup: func(m *executor.Mock, home string) {
				addFile(m, joinPath(home, ".local", "bin", "grok"), []byte("#!/bin/sh\n"))
			},
			wantDebug: []string{"no Grok Build channel claims it"},
		},
		{
			name: "(g10) ~/.grok and its generic `agent` launcher alone are not an install",
			setup: func(m *executor.Mock, home string) {
				setConfigDir(m, home, "~/.grok")
				addFile(m, joinPath(home, ".grok", "bin", "agent"), []byte{})
			},
		},
	})
}

// ---------------------------------------------------------------------------
// kimi-code
// ---------------------------------------------------------------------------

func TestAICLIAgents_Kimi(t *testing.T) {
	runAICLICases(t, []aicliCase{
		{
			name: "(k1) the installer binary at or above the floor accepts with version unknown",
			setup: func(m *executor.Mock, home string) {
				addBinary(m, joinPath(home, ".kimi-code", "bin", "kimi"), kimiRealBytes)
				setConfigDir(m, home, "~/.kimi-code")
			},
			want: []aicliWant{{tool: "kimi-code", binary: "/home/u/.kimi-code/bin/kimi", version: "unknown", configRel: "~/.kimi-code"}},
		},
		{
			name: "(k1r) a script at the installer target is under the floor and rejected",
			setup: func(m *executor.Mock, home string) {
				addBinary(m, joinPath(home, ".kimi-code", "bin", "kimi"), 40<<10)
			},
			wantDebug: []string{"at the installer target but under"},
		},
		{
			name: "(k2) the npm prefix accepts from its manifest",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("kimi", "/usr/local/bin/kimi")
				addNPMGlobal(m, "/usr/local/bin/kimi", "/usr/local/lib/node_modules/@moonshot-ai/kimi-code", kimiPackageName, "0.12.0")
			},
			want: []aicliWant{{tool: "kimi-code", binary: "/usr/local/bin/kimi", version: "0.12.0"}},
		},
		{
			name: "(k3) the Homebrew formula resolves into its libexec node_modules and needs no brew rule",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("kimi", "/opt/homebrew/bin/kimi")
				addNPMGlobal(m, "/opt/homebrew/bin/kimi",
					"/opt/homebrew/Cellar/kimi-code/0.12.0/libexec/lib/node_modules/@moonshot-ai/kimi-code", kimiPackageName, "0.12.0")
			},
			want: []aicliWant{{tool: "kimi-code", binary: "/opt/homebrew/bin/kimi", version: "0.12.0"}},
		},
		{
			name: "(k3b) an unlinked brew install is reached through the opt anchor",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				addNPMGlobal(m, "/opt/homebrew/opt/kimi-code/bin/kimi",
					"/opt/homebrew/Cellar/kimi-code/0.12.0/libexec/lib/node_modules/@moonshot-ai/kimi-code", kimiPackageName, "0.12.0")
			},
			want: []aicliWant{{tool: "kimi-code", binary: "/opt/homebrew/opt/kimi-code/bin/kimi", version: "0.12.0"}},
		},
		{
			name: "(k4) the legacy uv-tool venv accepts with its dist-info version",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				venv := joinPath(home, ".local", "share", "uv", "tools", "kimi-cli")
				link := joinPath(home, ".local", "bin", "kimi")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(venv, "bin", "kimi"))
				addDistInfo(m, model.PlatformDarwin, venv, "kimi_cli", "1.49.0")
			},
			allowGlobs: []string{distInfoGlob(model.PlatformDarwin, "/Users/u/.local/share/uv/tools/kimi-cli", "kimi_cli")},
			want:       []aicliWant{{tool: "kimi-code", binary: "/Users/u/.local/bin/kimi", version: "1.49.0"}},
		},
		{
			name: "(k4b) the pipx venv accepts too; two dist-info dirs degrade to unknown",
			setup: func(m *executor.Mock, home string) {
				venv := joinPath(home, ".local", "share", "pipx", "venvs", "kimi-cli")
				link := joinPath(home, ".local", "bin", "kimi")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(venv, "bin", "kimi"))
				pattern := distInfoGlob(model.PlatformLinux, venv, "kimi_cli")
				m.SetGlob(pattern, []string{pathDir(pattern) + "/kimi_cli-1.48.0.dist-info", pathDir(pattern) + "/kimi_cli-1.49.0.dist-info"})
			},
			allowGlobs: []string{distInfoGlob(model.PlatformLinux, "/home/u/.local/share/pipx/venvs/kimi-cli", "kimi_cli")},
			want:       []aicliWant{{tool: "kimi-code", binary: "/home/u/.local/bin/kimi", version: "unknown"}},
			wantDebug:  []string{"2 dist-info directories"},
		},
		{
			name: "(k5r) the cargo kimi is rejected",
			setup: func(m *executor.Mock, home string) {
				cargo := joinPath(home, ".cargo", "bin", "kimi")
				m.SetPath("kimi", cargo)
				addFile(m, cargo, []byte{})
			},
			wantDebug: []string{"under ~/.cargo"},
		},
		{
			name: "(k6r) Homebrew Cellar/kimi is not the kimi-code formula",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("kimi", "/opt/homebrew/bin/kimi")
				addFile(m, "/opt/homebrew/bin/kimi", []byte{})
				m.SetSymlink("/opt/homebrew/bin/kimi", "/opt/homebrew/Cellar/kimi/2.0.0/bin/kimi")
			},
			wantDebug: []string{"Homebrew Cellar/kimi is not the kimi-code formula"},
		},
		{
			name: "(k7r) a plain ~/.local/bin/kimi script is rejected; ~/.kimi-code alone is not an install",
			setup: func(m *executor.Mock, home string) {
				addFile(m, joinPath(home, ".local", "bin", "kimi"), []byte("#!/bin/sh\n"))
				setConfigDir(m, home, "~/.kimi-code")
			},
			wantDebug: []string{"no Kimi Code channel claims it"},
		},
	})
}

// ---------------------------------------------------------------------------
// muse-code
// ---------------------------------------------------------------------------

func TestAICLIAgents_Muse(t *testing.T) {
	runAICLICases(t, []aicliCase{
		{
			name: "(m1) launcher with sidecar and matching muse-bin accepts with the sidecar version",
			setup: func(m *executor.Mock, home string) {
				addMuseInstall(m, joinPath(home, ".local", "bin"), museVersion)
				setConfigDir(m, home, "~/.config/muse")
			},
			want: []aicliWant{{tool: "muse-code", binary: "/home/u/.local/bin/muse", version: museVersion, configRel: "~/.config/muse"}},
		},
		{
			name: "(m1b) a relocated MUSE_INSTALL_DIR on PATH is directory-relative and still accepts",
			setup: func(m *executor.Mock, _ string) {
				addMuseInstall(m, "/opt/muse", museVersion)
				m.SetPath("muse", "/opt/muse/muse")
			},
			want: []aicliWant{{tool: "muse-code", binary: "/opt/muse/muse", version: museVersion}},
		},
		{
			name: "(m2r) sidecar without its muse-bin payload is rejected",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				addFile(m, joinPath(bin, ".muse-version"), []byte(museVersion+"\n"))
			},
			wantDebug: []string{"no muse-bin-" + museVersion + " sits beside it"},
		},
		{
			name: "(m2b) a sidecar that is not a Muse release string is rejected",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				addFile(m, joinPath(bin, ".muse-version"), []byte("1.0.3\n"))
				addBinary(m, joinPath(bin, "muse-bin-1.0.3"), 90<<20)
			},
			wantDebug: []string{"does not carry a Muse release version"},
		},
		{
			name: "(m2c) an oversized sidecar is refused before it is read",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				addBinary(m, joinPath(bin, ".muse-version"), museVersionMaxBytes+1)
			},
			wantDebug: []string{"over the 64-byte cap"},
		},
		{
			name: "(m3) launcher with a single muse-bin and no sidecar accepts from the filename",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				addBinary(m, joinPath(bin, "muse-bin-"+museVersion), 90<<20)
				m.SetGlob(joinPath(bin, "muse-bin-*"), []string{joinPath(bin, "muse-bin-"+museVersion)})
			},
			allowGlobs: []string{"/home/u/.local/bin/muse-bin-*"},
			want:       []aicliWant{{tool: "muse-code", binary: "/home/u/.local/bin/muse", version: museVersion}},
		},
		{
			name: "(m3b) two muse-bin payloads and no sidecar accept with version unknown",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				m.SetGlob(joinPath(bin, "muse-bin-*"), []string{joinPath(bin, "muse-bin-1.0.2-R2040.1"), joinPath(bin, "muse-bin-"+museVersion)})
			},
			allowGlobs: []string{"/home/u/.local/bin/muse-bin-*"},
			want:       []aicliWant{{tool: "muse-code", binary: "/home/u/.local/bin/muse", version: "unknown"}},
		},
		{
			name: "(m4) the homebrew cask accepts and its version comes from the Caskroom segment",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("muse", "/opt/homebrew/bin/muse")
				addFile(m, "/opt/homebrew/bin/muse", []byte{})
				m.SetSymlink("/opt/homebrew/bin/muse", "/opt/homebrew/Caskroom/muse-code/1.0.2-R2040.1/muse")
			},
			allowGlobs: []string{"/opt/homebrew/Caskroom/muse-code/1.0.2-R2040.1/muse-bin-*"},
			want:       []aicliWant{{tool: "muse-code", binary: "/opt/homebrew/bin/muse", version: "1.0.2-R2040.1"}},
		},
		{
			name: "(m5) /usr/bin/muse owned by the AUR muse-code-bin accepts",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("muse", "/usr/bin/muse")
				addFile(m, "/usr/bin/muse", []byte{})
				m.SetGlob("/var/lib/pacman/local/*-*", []string{"/var/lib/pacman/local/muse-code-bin-1.0.3-1"})
				addFile(m, "/var/lib/pacman/local/muse-code-bin-1.0.3-1/files", pacmanFiles("usr/bin/muse"))
			},
			allowGlobs: []string{"/usr/bin/muse-bin-*"},
			want:       []aicliWant{{tool: "muse-code", binary: "/usr/bin/muse", version: "unknown"}},
		},
		{
			name: "(m5r) /usr/bin/muse owned by the distro muse is the MusE sequencer",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("muse", "/usr/bin/muse")
				addFile(m, "/usr/bin/muse", []byte{})
				m.SetGlob("/var/lib/pacman/local/*-*", []string{"/var/lib/pacman/local/muse-4.2.1-1"})
				addFile(m, "/var/lib/pacman/local/muse-4.2.1-1/files", pacmanFiles("usr/bin/muse"))
			},
			allowGlobs: []string{"/usr/bin/muse-bin-*"},
			wantDebug:  []string{"the distro `muse` is the MusE sequencer"},
		},
		{
			name: "(m6r) the npm muse is rejected before its directory is probed",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("muse", "/usr/local/bin/muse")
				addNPMGlobal(m, "/usr/local/bin/muse", "/usr/local/lib/node_modules/muse", "muse", "3.1.0")
			},
			noReadPrefix: []string{"/usr/local/lib/node_modules/muse/dist"},
			wantDebug:    []string{"under node_modules; npm `muse` is unrelated"},
		},
		{
			name: "(m7r) the cargo muse is rejected",
			setup: func(m *executor.Mock, home string) {
				cargo := joinPath(home, ".cargo", "bin", "muse")
				m.SetPath("muse", cargo)
				addFile(m, cargo, []byte{})
			},
			wantDebug: []string{"under ~/.cargo"},
		},
		{
			name: "(m8r) a bare ~/.local/bin/muse with neither sidecar nor payload is rejected",
			setup: func(m *executor.Mock, home string) {
				addFile(m, joinPath(home, ".local", "bin", "muse"), []byte("#!/bin/sh\n"))
				setConfigDir(m, home, "~/.config/muse")
			},
			allowGlobs: []string{"/home/u/.local/bin/muse-bin-*"},
			wantDebug:  []string{"no Muse Code channel claims it"},
		},
	})
}

// ---------------------------------------------------------------------------
// hermes-agent
// ---------------------------------------------------------------------------

func TestAICLIAgents_Hermes(t *testing.T) {
	const keg = "/opt/homebrew/Cellar/hermes-agent/2026.8.31"
	runAICLICases(t, []aicliCase{
		{
			name: "(h1) the user launcher with its venv accepts with the dist-info version; the launcher is never read",
			setup: func(m *executor.Mock, home string) {
				addFile(m, joinPath(home, ".local", "bin", "hermes"), []byte("#!/bin/bash\nexec ~/.hermes/hermes-agent/venv/bin/hermes \"$@\"\n"))
				venv := joinPath(home, ".hermes", "hermes-agent", "venv")
				m.SetDir(venv)
				addDistInfo(m, model.PlatformLinux, venv, "hermes_agent", hermesVersion)
				setConfigDir(m, home, "~/.hermes")
			},
			allowGlobs: []string{distInfoGlob(model.PlatformLinux, "/home/u/.hermes/hermes-agent/venv", "hermes_agent")},
			want:       []aicliWant{{tool: "hermes-agent", binary: "/home/u/.local/bin/hermes", version: hermesVersion, configRel: "~/.hermes"}},
		},
		{
			name: "(h1r) the same launcher without the venv is rejected",
			setup: func(m *executor.Mock, home string) {
				addFile(m, joinPath(home, ".local", "bin", "hermes"), []byte("#!/bin/bash\n"))
				setConfigDir(m, home, "~/.hermes")
			},
			wantDebug: []string{"the installer launcher is there but /home/u/.hermes/hermes-agent/venv is not"},
		},
		{
			name: "(h1v) the venv alone, with no launcher, is not an install",
			setup: func(m *executor.Mock, home string) {
				m.SetDir(joinPath(home, ".hermes", "hermes-agent", "venv"))
				setConfigDir(m, home, "~/.hermes")
			},
		},
		{
			name: "(h2) the root layout pairs /usr/local/bin/hermes with /usr/local/lib/hermes-agent/venv",
			setup: func(m *executor.Mock, _ string) {
				addFile(m, "/usr/local/bin/hermes", []byte("#!/bin/bash\n"))
				m.SetDir("/usr/local/lib/hermes-agent/venv")
				addDistInfo(m, model.PlatformLinux, "/usr/local/lib/hermes-agent/venv", "hermes_agent", hermesVersion)
			},
			allowGlobs: []string{distInfoGlob(model.PlatformLinux, "/usr/local/lib/hermes-agent/venv", "hermes_agent")},
			want:       []aicliWant{{tool: "hermes-agent", binary: "/usr/local/bin/hermes", version: hermesVersion}},
		},
		{
			name: "(h3) the Homebrew keg accepts with the venv's upstream version when its dist-info exists",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("hermes", "/opt/homebrew/bin/hermes")
				addFile(m, "/opt/homebrew/bin/hermes", []byte{})
				m.SetSymlink("/opt/homebrew/bin/hermes", keg+"/bin/hermes")
				addDistInfo(m, model.PlatformDarwin, keg+"/libexec", "hermes_agent", hermesVersion)
			},
			allowGlobs: []string{distInfoGlob(model.PlatformDarwin, keg+"/libexec", "hermes_agent")},
			want:       []aicliWant{{tool: "hermes-agent", binary: "/opt/homebrew/bin/hermes", version: hermesVersion}},
		},
		{
			name: "(h3b) without a dist-info the keg falls back to its Cellar version segment",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("hermes", "/opt/homebrew/bin/hermes")
				addFile(m, "/opt/homebrew/bin/hermes", []byte{})
				m.SetSymlink("/opt/homebrew/bin/hermes", keg+"/bin/hermes")
			},
			allowGlobs: []string{distInfoGlob(model.PlatformDarwin, keg+"/libexec", "hermes_agent")},
			want:       []aicliWant{{tool: "hermes-agent", binary: "/opt/homebrew/bin/hermes", version: "2026.8.31"}},
		},
		{
			name: "(h4r) the npm hermes is rejected",
			setup: func(m *executor.Mock, home string) {
				addNPMGlobal(m, joinPath(home, ".local", "bin", "hermes"), joinPath(home, ".local", "lib", "node_modules", "hermes"), "hermes", "0.3.0")
			},
			wantDebug: []string{"under node_modules; npm `hermes`"},
		},
		{
			name: "(h5r) the cargo hermes is rejected",
			setup: func(m *executor.Mock, home string) {
				cargo := joinPath(home, ".cargo", "bin", "hermes")
				m.SetPath("hermes", cargo)
				addFile(m, cargo, []byte{})
			},
			wantDebug: []string{"under ~/.cargo"},
		},
		{
			name: "(h6r) a hermes on PATH somewhere else is rejected",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("hermes", "/opt/hermes/hermes")
				addFile(m, "/opt/hermes/hermes", []byte("#!/bin/sh\n"))
			},
			wantDebug: []string{"no Hermes Agent channel claims it"},
		},
	})
}

// ---------------------------------------------------------------------------
// oh-my-pi
// ---------------------------------------------------------------------------

func TestAICLIAgents_OMP(t *testing.T) {
	runAICLICases(t, []aicliCase{
		{
			name: "(o1) the npm prefix accepts from its manifest",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("omp", "/usr/local/bin/omp")
				addNPMGlobal(m, "/usr/local/bin/omp", "/usr/local/lib/node_modules/@oh-my-pi/pi-coding-agent", ompPackageName, ompVersion)
				setConfigDir(m, home, "~/.omp/agent")
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: "/usr/local/bin/omp", version: ompVersion, configRel: "~/.omp/agent"}},
		},
		{
			name: "(o1b) the ~/.local/bin npm symlink is an npm channel, not the standalone anchor",
			setup: func(m *executor.Mock, home string) {
				addNPMGlobal(m, joinPath(home, ".local", "bin", "omp"), joinPath(home, ".local", "lib", "node_modules", "@oh-my-pi", "pi-coding-agent"), ompPackageName, ompVersion)
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: "/home/u/.local/bin/omp", version: ompVersion}},
		},
		{
			name: "(o2) the Bun global symlink accepts",
			setup: func(m *executor.Mock, home string) {
				addNPMGlobal(m, joinPath(home, ".bun", "bin", "omp"), joinPath(home, ".bun", "install", "global", "node_modules", "@oh-my-pi", "pi-coding-agent"), ompPackageName, ompVersion)
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: "/home/u/.bun/bin/omp", version: ompVersion}},
		},
		{
			name: "(o3) the Homebrew formula at or above the floor accepts with the Cellar version",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("omp", "/opt/homebrew/bin/omp")
				addBinary(m, "/opt/homebrew/bin/omp", ompRealBytes)
				m.SetSymlink("/opt/homebrew/bin/omp", "/opt/homebrew/Cellar/omp/18.1.10/bin/omp")
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: "/opt/homebrew/bin/omp", version: ompVersion}},
		},
		{
			name: "(o3r) a tap token is attacker-choosable, so a small Cellar/omp is rejected",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("omp", "/opt/homebrew/bin/omp")
				addBinary(m, "/opt/homebrew/bin/omp", 2<<20)
				m.SetSymlink("/opt/homebrew/bin/omp", "/opt/homebrew/Cellar/omp/18.1.10/bin/omp")
			},
			wantDebug: []string{"Homebrew Cellar/omp but under"},
		},
		{
			name: "(o4) the mise install tree is globbed; the alias dir resolves to the real version dir",
			setup: func(m *executor.Mock, home string) {
				root := joinPath(home, ".local", "share", "mise", "installs", "github-can1357-oh-my-pi")
				real := joinPath(root, ompVersion)
				alias := joinPath(root, "latest")
				m.SetGlob(joinPath(root, "*"), []string{real, alias})
				addBinary(m, joinPath(real, "omp"), ompRealBytes)
				addFile(m, joinPath(alias, "omp"), []byte{})
				m.SetSymlink(joinPath(alias, "omp"), joinPath(real, "omp"))
				// The shim on PATH resolves to mise itself and proves nothing.
				shim := joinPath(home, ".local", "share", "mise", "shims", "omp")
				m.SetPath("omp", shim)
				addFile(m, shim, []byte{})
				m.SetSymlink(shim, joinPath(home, ".local", "share", "mise", "bin", "mise"))
			},
			// globDirs sorts descending, so "latest" is probed before "18.1.10";
			// its resolved form is the real dir, and the real dir then dedups.
			want:      []aicliWant{{tool: "oh-my-pi", binary: "/home/u/.local/share/mise/installs/github-can1357-oh-my-pi/latest/omp", version: ompVersion}},
			wantDebug: []string{"no Oh My Pi channel claims it (resolved /home/u/.local/share/mise/bin/mise)"},
		},
		{
			name: "(o4b) a mise version dir alone accepts with that version",
			setup: func(m *executor.Mock, home string) {
				root := joinPath(home, ".local", "share", "mise", "installs", "github-can1357-oh-my-pi")
				real := joinPath(root, ompVersion)
				m.SetGlob(joinPath(root, "*"), []string{real})
				addBinary(m, joinPath(real, "omp"), ompRealBytes)
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: "/home/u/.local/share/mise/installs/github-can1357-oh-my-pi/18.1.10/omp", version: ompVersion}},
		},
		{
			name: "(o5) the standalone ~/.local/bin/omp at or above the floor accepts with version unknown",
			setup: func(m *executor.Mock, home string) {
				addBinary(m, joinPath(home, ".local", "bin", "omp"), ompRealBytes)
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: "/home/u/.local/bin/omp", version: "unknown"}},
		},
		{
			name: "(o5r) a script at the standalone anchor is under the floor and rejected",
			setup: func(m *executor.Mock, home string) {
				addBinary(m, joinPath(home, ".local", "bin", "omp"), 4<<10)
				setConfigDir(m, home, "~/.omp/agent")
			},
			wantDebug: []string{"at the standalone anchor but under"},
		},
		{
			name: "(o6r) an npm package of another name is rejected by name",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("omp", "/usr/local/bin/omp")
				addNPMGlobal(m, "/usr/local/bin/omp", "/usr/local/lib/node_modules/omp", "omp", "1.0.0")
			},
			wantDebug: []string{`npm package is "omp", not ` + ompPackageName},
		},
	})
}

// ---------------------------------------------------------------------------
// Windows-shaped cases
// ---------------------------------------------------------------------------

func TestAICLIAgents2_Windows(t *testing.T) {
	npmDir := `C:\Users\u\AppData\Roaming\npm`
	linksDir := `C:\Users\u\AppData\Local\Microsoft\WinGet\Links`
	pkgsDir := `C:\Users\u\AppData\Local\Microsoft\WinGet\Packages`
	grokBin := `C:\Users\u\.grok\bin`
	hermesVenv := `C:\Users\u\AppData\Local\hermes\hermes-agent\venv`

	runAICLICases(t, []aicliCase{
		{
			name: "(w1) the grok.cmd npm shim accepts",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, npmDir+`\grok.cmd`, winNPMShim(`node_modules\@xai-official\grok\dist\cli.js`))
				addManifest(m, npmDir+`\node_modules\@xai-official\grok`, grokPackageName, "1.0.13")
			},
			want: []aicliWant{{tool: "grok-build", binary: npmDir + `\grok.cmd`, version: "1.0.13"}},
		},
		{
			name: "(w2) the home copy takes its version from the single same-size versioned sibling",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				addBinary(m, grokBin+`\grok.exe`, 95_000_000)
				addBinary(m, grokBin+`\grok-1.0.13.exe`, 95_000_000)
				m.SetGlob(grokBin+`\grok-*.exe`, []string{grokBin + `\grok-1.0.13.exe`})
				setConfigDir(m, home, "~/.grok")
			},
			allowGlobs: []string{grokBin + `\grok-*.exe`},
			want:       []aicliWant{{tool: "grok-build", binary: grokBin + `\grok.exe`, version: "1.0.13", configRel: "~/.grok"}},
		},
		{
			name: "(w2b) two versioned siblings leave the copy's version unknown",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addBinary(m, grokBin+`\grok.exe`, 95_000_000)
				addBinary(m, grokBin+`\grok-1.0.12.exe`, 94_000_000)
				addBinary(m, grokBin+`\grok-1.0.13.exe`, 95_000_000)
				m.SetGlob(grokBin+`\grok-*.exe`, []string{grokBin + `\grok-1.0.12.exe`, grokBin + `\grok-1.0.13.exe`})
			},
			allowGlobs: []string{grokBin + `\grok-*.exe`},
			want:       []aicliWant{{tool: "grok-build", binary: grokBin + `\grok.exe`, version: "unknown"}},
			wantDebug:  []string{"2 versioned grok-*.exe siblings"},
		},
		{
			name: "(w2c) a single sibling of a different size is not the copy's source",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addBinary(m, grokBin+`\grok.exe`, 95_000_000)
				addBinary(m, grokBin+`\grok-1.0.13.exe`, 94_000_000)
				m.SetGlob(grokBin+`\grok-*.exe`, []string{grokBin + `\grok-1.0.13.exe`})
			},
			allowGlobs: []string{grokBin + `\grok-*.exe`},
			want:       []aicliWant{{tool: "grok-build", binary: grokBin + `\grok.exe`, version: "unknown"}},
			wantDebug:  []string{"is not the same size as"},
		},
		{
			name: "(w3) winget Grok Build accepts through the Links shim",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, linksDir+`\grok.exe`, []byte{})
				m.SetSymlink(linksDir+`\grok.exe`, pkgsDir+`\xAI.GrokBuild_Microsoft.Winget.Source_8wekyb3d8bbwe\grok.exe`)
			},
			want: []aicliWant{{tool: "grok-build", binary: linksDir + `\grok.exe`, version: "unknown"}},
		},
		{
			name: "(w4) the Kimi installer .exe at or above the floor accepts",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				addBinary(m, `C:\Users\u\.kimi-code\bin\kimi.exe`, kimiRealBytes)
				setConfigDir(m, home, "~/.kimi-code")
			},
			want: []aicliWant{{tool: "kimi-code", binary: `C:\Users\u\.kimi-code\bin\kimi.exe`, version: "unknown", configRel: "~/.kimi-code"}},
		},
		{
			name: "(w5) winget Kimi accepts under either identifier",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, linksDir+`\kimi.exe`, []byte{})
				m.SetSymlink(linksDir+`\kimi.exe`, pkgsDir+`\MoonshotAI.KimiCLI_Microsoft.Winget.Source_8wekyb3d8bbwe\kimi.exe`)
			},
			want: []aicliWant{{tool: "kimi-code", binary: linksDir + `\kimi.exe`, version: "unknown"}},
		},
		{
			name: "(w5b) the newer winget identifier too",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, linksDir+`\kimi.exe`, []byte{})
				m.SetSymlink(linksDir+`\kimi.exe`, pkgsDir+`\MoonshotAI.KimiCodeCLI_Microsoft.Winget.Source_8wekyb3d8bbwe\kimi.exe`)
			},
			want: []aicliWant{{tool: "kimi-code", binary: linksDir + `\kimi.exe`, version: "unknown"}},
		},
		{
			name: "(w5r) another publisher's kimi in WinGet is rejected",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, linksDir+`\kimi.exe`, []byte{})
				m.SetSymlink(linksDir+`\kimi.exe`, pkgsDir+`\SomeoneElse.Kimi_Microsoft.Winget.Source_8wekyb3d8bbwe\kimi.exe`)
			},
			wantDebug: []string{"no Kimi Code channel claims it"},
		},
		{
			name: "(w6) the legacy Kimi CLI's uv venv under %LOCALAPPDATA% reads Lib\\site-packages",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				venv := joinPath(home, "AppData", "Local", "uv", "tools", "kimi-cli")
				addFile(m, npmDir+`\kimi.cmd`, []byte("@echo off\r\n"))
				m.SetSymlink(npmDir+`\kimi.cmd`, venv+`\Scripts\kimi.exe`)
				addDistInfo(m, model.PlatformWindows, venv, "kimi_cli", "1.49.0")
			},
			allowGlobs: []string{distInfoGlob(model.PlatformWindows, `C:\Users\u\AppData\Local\uv\tools\kimi-cli`, "kimi_cli")},
			want:       []aicliWant{{tool: "kimi-code", binary: npmDir + `\kimi.cmd`, version: "1.49.0"}},
		},
		{
			name: "(w7) hermes.exe with the %LOCALAPPDATA% venv accepts",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				addFile(m, `C:\Users\u\AppData\Local\hermes\bin\hermes.exe`, []byte{})
				m.SetDir(hermesVenv)
				addDistInfo(m, model.PlatformWindows, hermesVenv, "hermes_agent", hermesVersion)
				setConfigDir(m, home, "~/AppData/Local/hermes")
			},
			allowGlobs: []string{distInfoGlob(model.PlatformWindows, hermesVenv, "hermes_agent")},
			want: []aicliWant{{
				tool: "hermes-agent", binary: `C:\Users\u\AppData\Local\hermes\bin\hermes.exe`,
				version: hermesVersion, configRel: "~/AppData/Local/hermes",
			}},
		},
		{
			name: "(w7b) the hermes.cmd variant accepts too",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, `C:\Users\u\AppData\Local\hermes\bin\hermes.cmd`, []byte("@echo off\r\n"))
				m.SetDir(hermesVenv)
				addDistInfo(m, model.PlatformWindows, hermesVenv, "hermes_agent", hermesVersion)
			},
			allowGlobs: []string{distInfoGlob(model.PlatformWindows, hermesVenv, "hermes_agent")},
			want:       []aicliWant{{tool: "hermes-agent", binary: `C:\Users\u\AppData\Local\hermes\bin\hermes.cmd`, version: hermesVersion}},
		},
		{
			name: "(w7r) hermes.exe without the venv is rejected",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, `C:\Users\u\AppData\Local\hermes\bin\hermes.exe`, []byte{})
			},
			wantDebug: []string{"the installer launcher is there but " + hermesVenv + " is not"},
		},
		{
			name: "(w8) the omp.cmd npm shim accepts even though its runner is bun.exe",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, npmDir+`\omp.cmd`, []byte("@ECHO off\r\n\"%dp0%\\bun.exe\" \"%dp0%\\node_modules\\@oh-my-pi\\pi-coding-agent\\dist\\cli.js\" %*\r\n"))
				addManifest(m, npmDir+`\node_modules\@oh-my-pi\pi-coding-agent`, ompPackageName, ompVersion)
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: npmDir + `\omp.cmd`, version: ompVersion}},
		},
		{
			name: "(w9) the Bun .exe is identified through its .bunx pointer",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				bunBin := joinPath(home, ".bun", "bin")
				pkgRoot := joinPath(home, ".bun", "install", "global", "node_modules", "@oh-my-pi", "pi-coding-agent")
				addFile(m, bunBin+`\omp.exe`, []byte{})
				addFile(m, bunBin+`\omp.bunx`, utf16LE(pkgRoot+`\dist\cli.js`))
				addManifest(m, pkgRoot, ompPackageName, ompVersion)
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: `C:\Users\u\.bun\bin\omp.exe`, version: ompVersion}},
		},
		{
			name: "(w10) the standalone %LOCALAPPDATA%\\omp\\omp.exe at or above the floor accepts",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				addBinary(m, `C:\Users\u\AppData\Local\omp\omp.exe`, ompRealBytes)
				setConfigDir(m, home, "~/.omp/agent")
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: `C:\Users\u\AppData\Local\omp\omp.exe`, version: "unknown", configRel: "~/.omp/agent"}},
		},
		{
			name: "(w11) winget Oh My Pi accepts",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, linksDir+`\omp.exe`, []byte{})
				m.SetSymlink(linksDir+`\omp.exe`, pkgsDir+`\can1357.oh-my-pi_Microsoft.Winget.Source_8wekyb3d8bbwe\omp.exe`)
			},
			want: []aicliWant{{tool: "oh-my-pi", binary: linksDir + `\omp.exe`, version: "unknown"}},
		},
	})
}

// ---------------------------------------------------------------------------
// TCC guard: one decoy per new binary name under ~/Documents, and a symlink from
// an accepted anchor into ~/Downloads. Each decoy satisfies an accept rule, so a
// green reject is the guard firing and not a ladder miss.
// ---------------------------------------------------------------------------

func TestAICLIAgents2_TCCGuard(t *testing.T) {
	requireDarwinHost(t)
	docs := "/Users/u/Documents"

	decoys := []struct {
		bin   string
		setup func(m *executor.Mock, home, dir string)
	}{
		{"grok", func(m *executor.Mock, _, dir string) {
			addNPMGlobal(m, dir+"/grok", dir+"/node_modules/@xai-official/grok", grokPackageName, "1.0.13")
		}},
		{"kimi", func(m *executor.Mock, _, dir string) {
			addNPMGlobal(m, dir+"/kimi", dir+"/node_modules/@moonshot-ai/kimi-code", kimiPackageName, "0.12.0")
		}},
		{"muse", func(m *executor.Mock, _, dir string) {
			addMuseInstall(m, dir, museVersion)
		}},
		{"hermes", func(m *executor.Mock, _, dir string) {
			addFile(m, dir+"/hermes", []byte("#!/bin/bash\n"))
		}},
		{"omp", func(m *executor.Mock, _, dir string) {
			addNPMGlobal(m, dir+"/omp", dir+"/node_modules/@oh-my-pi/pi-coding-agent", ompPackageName, ompVersion)
		}},
	}
	for _, d := range decoys {
		t.Run("~/Documents/bin/"+d.bin+" on PATH is never touched", func(t *testing.T) {
			runAICLICase(t, aicliCase{
				name:    d.bin,
				goos:    model.PlatformDarwin,
				skipper: true,
				setup: func(m *executor.Mock, home string) {
					dir := joinPath(home, "Documents", "bin")
					m.SetPath(d.bin, dir+"/"+d.bin)
					d.setup(m, home, dir)
				},
				noReadPrefix: []string{docs},
				wantDebug:    []string{"under a macOS TCC-protected path"},
			})
		})
	}

	t.Run("~/.local/bin/muse -> ~/Downloads/muse is rejected before its sidecar is read", func(t *testing.T) {
		runAICLICase(t, aicliCase{
			name:    "symlink into Downloads",
			goos:    model.PlatformDarwin,
			skipper: true,
			setup: func(m *executor.Mock, home string) {
				addMuseInstall(m, joinPath(home, "Downloads"), museVersion)
				link := joinPath(home, ".local", "bin", "muse")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(home, "Downloads", "muse"))
			},
			noReadPrefix: []string{"/Users/u/Downloads"},
			wantDebug:    []string{"under a macOS TCC-protected path"},
		})
	})

	t.Run("~/.local/bin/grok -> ~/Downloads/grok-1.0.13 is rejected; the same link into ~/.grok accepts", func(t *testing.T) {
		runAICLICase(t, aicliCase{
			name:    "grok symlink into Downloads",
			goos:    model.PlatformDarwin,
			skipper: true,
			setup: func(m *executor.Mock, home string) {
				link := joinPath(home, ".local", "bin", "grok")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(home, "Downloads", "grok-1.0.13"))
			},
			noReadPrefix: []string{"/Users/u/Downloads"},
			wantDebug:    []string{"under a macOS TCC-protected path"},
		})
		runAICLICase(t, aicliCase{
			name:    "grok symlink into ~/.grok",
			goos:    model.PlatformDarwin,
			skipper: true,
			setup: func(m *executor.Mock, home string) {
				link := joinPath(home, ".local", "bin", "grok")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(home, ".grok", "bin", "grok-1.0.13"))
			},
			want: []aicliWant{{tool: "grok-build", binary: "/Users/u/.local/bin/grok", version: "1.0.13"}},
		})
	})
}

// TestAICLIAgents2_EmptyFixture: the five new specs produce nothing on the empty
// fixture on every platform, and nothing is read outside the candidate probes.
func TestAICLIAgents2_EmptyFixture(t *testing.T) {
	for _, goos := range []string{model.PlatformLinux, model.PlatformDarwin, model.PlatformWindows} {
		t.Run(goos, func(t *testing.T) {
			m, _ := newAICLIMock(goos)
			rec := &recExec{Mock: m, t: t, trapExec: true}
			var tools []model.AITool
			captureStderr(t, func() { tools = NewAICLIDetector(rec).Detect(context.Background()) })
			if len(tools) != 0 {
				t.Errorf("empty fixture: got %d rows, want 0; %+v", len(tools), tools)
			}
		})
	}
}
