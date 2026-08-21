package detector

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// ---------------------------------------------------------------------------
// Harness for the three ResolveFunc specs (pi, factory, amp).
//
// recExec embeds *executor.Mock and records — or refuses — the executor calls
// these ladders are allowed to make. Three distinct claims are asserted here,
// and each needs its own instrument:
//
//   - Pi and Amp are never launched, on any channel, accept or reject
//     (StaticVersionOnly returns before the version flag is even chosen, so
//     execguard is unreachable for them and no case has a legitimate exec).
//     trapExec turns any launch into a test failure.
//   - Factory IS launched, but only on the channels whose ladder carried no
//     version, only the accepted binary, and only once. Those cases set
//     allowExec and pin the recorded calls exactly.
//   - No ladder ever walks a directory. Executor.Glob never calls
//     Executor.ReadDir on either implementation, so "ReadDir only via the glob"
//     is not an assertable statement; what is assertable is that ReadDir is
//     never called at all, and that every Glob pattern is one of the targeted
//     install-tree patterns.
// ---------------------------------------------------------------------------

type aicliExecCall struct {
	name string
	args []string
}

type recExec struct {
	*executor.Mock
	t        *testing.T
	trapExec bool

	execs   []aicliExecCall
	globs   []string
	reads   []string // ReadFile + Stat + FileExists, i.e. every path touched
	lookups []string
}

// No mutex: Detect is single-goroutine and AGENTS.md §15.5 forbids t.Parallel.
func (e *recExec) recordExec(name string, args []string) {
	e.execs = append(e.execs, aicliExecCall{name: name, args: slices.Clone(args)})
	if e.trapExec {
		e.t.Fatalf("unexpected exec: %s %v", name, args)
	}
}

func (e *recExec) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	e.recordExec(name, args)
	return e.Mock.Run(ctx, name, args...)
}

func (e *recExec) RunWithTimeout(ctx context.Context, _ time.Duration, name string, args ...string) (string, string, int, error) {
	e.recordExec(name, args)
	return e.Mock.Run(ctx, name, args...)
}

func (e *recExec) RunInDir(ctx context.Context, _ string, _ time.Duration, name string, args ...string) (string, string, int, error) {
	e.recordExec(name, args)
	return e.Mock.Run(ctx, name, args...)
}

func (e *recExec) RunAsUser(ctx context.Context, user, command string) (string, error) {
	e.recordExec("bash", []string{"-c", command})
	return e.Mock.RunAsUser(ctx, user, command)
}

func (e *recExec) ReadDir(path string) ([]os.DirEntry, error) {
	e.t.Fatalf("unexpected ReadDir(%q): the AI-CLI ladders stat targeted paths, they never walk", path)
	return nil, nil
}

func (e *recExec) Glob(pattern string) ([]string, error) {
	e.globs = append(e.globs, pattern)
	return e.Mock.Glob(pattern)
}

func (e *recExec) ReadFile(path string) ([]byte, error) {
	e.reads = append(e.reads, path)
	return e.Mock.ReadFile(path)
}

func (e *recExec) Stat(path string) (os.FileInfo, error) {
	e.reads = append(e.reads, path)
	return e.Mock.Stat(path)
}

func (e *recExec) FileExists(path string) bool {
	e.reads = append(e.reads, path)
	return e.Mock.FileExists(path)
}

func (e *recExec) LookPath(name string) (string, error) {
	e.lookups = append(e.lookups, name)
	return e.Mock.LookPath(name)
}

// sizedInfo is a local os.FileInfo — executor's mockFileInfo is unexported and
// its zero size is exactly what the Factory floor cases must vary.
type sizedInfo struct {
	n  string
	sz int64
}

func (f sizedInfo) Name() string       { return f.n }
func (f sizedInfo) Size() int64        { return f.sz }
func (f sizedInfo) Mode() os.FileMode  { return 0o755 }
func (f sizedInfo) ModTime() time.Time { return time.Time{} }
func (f sizedInfo) IsDir() bool        { return false }
func (f sizedInfo) Sys() any           { return nil }

const (
	droidRealBytes  int64 = 117_860_304 // measured macOS build (§4.2 floor table)
	droidSmallBytes int64 = 3_024       // the --ignore-scripts JS launcher
)

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

func aicliHome(goos string) string {
	switch goos {
	case model.PlatformWindows:
		return `C:\Users\u`
	case model.PlatformDarwin:
		return "/Users/u"
	default:
		return "/home/u"
	}
}

func newAICLIMock(goos string) (*executor.Mock, string) {
	m := executor.NewMock()
	m.SetGOOS(goos)
	home := aicliHome(goos)
	m.SetHomeDir(home)
	if goos == model.PlatformWindows {
		m.SetEnv("APPDATA", joinPath(home, "AppData", "Roaming"))
		m.SetEnv("LOCALAPPDATA", joinPath(home, "AppData", "Local"))
		m.SetEnv("ProgramFiles", `C:\Program Files`)
	}
	return m, home
}

func aicliManifest(name, version string) []byte {
	if version == "" {
		return []byte(`{"name":"` + name + `"}`)
	}
	return []byte(`{"name":"` + name + `","version":"` + version + `"}`)
}

// addFile registers path as an existing, readable file.
func addFile(m *executor.Mock, path string, content []byte) {
	m.SetFile(path, content)
}

// addBinary registers path as an existing file whose Stat reports size. Both
// halves are needed: FileExists reads the mock's files map and Stat prefers its
// fileInfos map.
func addBinary(m *executor.Mock, path string, size int64) {
	m.SetFile(path, []byte{})
	m.SetFileInfo(path, sizedInfo{n: pathBase(path), sz: size})
}

// addManifest writes pkgRoot/package.json.
func addManifest(m *executor.Mock, pkgRoot, name, version string) {
	m.SetFile(joinPath(pkgRoot, "package.json"), aicliManifest(name, version))
}

// addNPMGlobal wires a Unix-shaped npm/pnpm/bun global: binPath is a symlink
// into pkgRoot, whose manifest names the package.
func addNPMGlobal(m *executor.Mock, binPath, pkgRoot, name, version string) {
	m.SetFile(binPath, []byte{})
	m.SetSymlink(binPath, joinPath(pkgRoot, "dist", "cli.js"))
	addManifest(m, pkgRoot, name, version)
}

// winNPMShim is cmd-shim's generated body, naming rel relative to %dp0%.
func winNPMShim(rel string) []byte {
	return []byte("@ECHO off\r\n\"%_prog%\" \"%dp0%\\" + rel + "\" %*\r\n")
}

// utf16LE encodes s the way Bun writes a .bunx pointer: BOM then LE units.
func utf16LE(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// setConfigDir registers a home-relative config dir under BOTH spellings: the
// ladders join with joinPath (separator-agnostic) while shipped findConfigDir
// joins with the host filepath, and the two differ when a Unix-shaped fixture
// runs on a Windows CI host.
func setConfigDir(m *executor.Mock, home, rel string) {
	m.SetDir(expandTildePath(rel, home))
	m.SetDir(expandTilde(rel, home))
}

// captureStderr redirects os.Stderr (progress.Logger writes there directly,
// with no injectable writer) for the duration of fn. The restore is deferred so
// a t.Fatalf inside fn — which is how the exec and ReadDir traps fail — still
// puts stderr back and drains the pipe. Precedent: progress/filelog's test.
func captureStderr(t *testing.T, fn func()) (out string) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() {
		os.Stderr = old
		_ = w.Close()
		out = <-done
		_ = r.Close()
	}()
	fn()
	return
}

// ---------------------------------------------------------------------------
// Case table plumbing
// ---------------------------------------------------------------------------

// aicliNewSpecs are the specs this file owns. Every case asserts one row for
// each spec it names in want and ZERO rows for the others, so a fixture built
// for one agent cannot quietly start reporting another.
var aicliNewSpecs = []string{"pi", "factory", "amp"}

type aicliWant struct {
	tool      string
	binary    string
	version   string
	install   string
	configRel string // compared after expandTilde, i.e. what findConfigDir emits
}

type aicliCase struct {
	name  string
	goos  string // "" -> linux
	setup func(m *executor.Mock, home string)

	// skipper installs a real tcc.Skipper via WithSkipper. Leaving it false is
	// the --include-tcc-protected polarity the construction sites pass.
	skipper bool
	// allowExec lifts the blanket exec trap. Only Factory's exec-channel
	// accepts may set it, and they must pin wantExecs.
	allowExec bool

	want         []aicliWant
	wantExecs    []aicliExecCall
	noReadPrefix []string // no ReadFile/Stat/FileExists path may start with these
	noLookup     []string // no LookPath name may contain these
	wantDebug    []string
	noDebug      []string
}

func findAITool(tools []model.AITool, name string) *model.AITool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	return nil
}

func countAITool(tools []model.AITool, name string) int {
	n := 0
	for i := range tools {
		if tools[i].Name == name {
			n++
		}
	}
	return n
}

// aicliAllowedGlobs is the complete set of patterns the three resolvers may
// glob. The nvm pattern is built with filepath.Join because nvmNodeBinDirs
// (shipped, untouched) builds it that way; the §4.4 supplements use joinPath
// because aiCLIBinaryCandidateDirs does.
func aicliAllowedGlobs(home, goos string) map[string]bool {
	allowed := map[string]bool{
		"/var/lib/pacman/local/*-*":                        true,
		joinPath(expandTildePath("~/.factory", home), "*"): true,
	}
	if goos == model.PlatformWindows {
		images := joinPath(home, "AppData", "Local", "Volta", "tools", "image", "packages")
		allowed[joinPath(images, "*")] = true
		allowed[joinPath(images, "*", "*")] = true
		return allowed
	}
	allowed[filepath.Join(home, ".nvm", "versions", "node", "*", "bin")] = true
	allowed[joinPath(home, ".local", "share", "fnm", "node-versions", "*", "installation", "bin")] = true
	allowed[joinPath(home, ".local", "share", "mise", "installs", "node", "*", "bin")] = true
	allowed[joinPath(home, ".volta", "tools", "image", "packages", "*", "bin")] = true
	allowed[joinPath(home, ".volta", "tools", "image", "packages", "*", "*", "bin")] = true
	allowed[joinPath(home, ".asdf", "installs", "nodejs", "*", "bin")] = true
	if goos == model.PlatformDarwin {
		allowed[joinPath(home, "Library", "Application Support", "fnm", "node-versions", "*", "installation", "bin")] = true
	}
	return allowed
}

func runAICLICase(t *testing.T, tc aicliCase) {
	t.Helper()
	goos := tc.goos
	if goos == "" {
		goos = model.PlatformLinux
	}
	m, home := newAICLIMock(goos)
	if tc.setup != nil {
		tc.setup(m, home)
	}

	rec := &recExec{Mock: m, t: t, trapExec: !tc.allowExec}
	log := progress.NewNoop()
	if len(tc.wantDebug) > 0 || len(tc.noDebug) > 0 {
		log = progress.NewLogger(progress.LevelDebug)
	}
	d := NewAICLIDetector(rec).WithLogger(log)
	if tc.skipper {
		d = d.WithSkipper(tcc.New(home))
	}

	var tools []model.AITool
	stderr := captureStderr(t, func() { tools = d.Detect(context.Background()) })

	for _, w := range tc.want {
		got := findAITool(tools, w.tool)
		if got == nil {
			t.Fatalf("%s: not detected; got %+v", w.tool, tools)
		}
		if w.binary != "" && got.BinaryPath != w.binary {
			t.Errorf("%s binary_path: got %q, want %q", w.tool, got.BinaryPath, w.binary)
		}
		if w.version != "" && got.Version != w.version {
			t.Errorf("%s version: got %q, want %q", w.tool, got.Version, w.version)
		}
		if w.install != "" && got.InstallPath != w.install {
			t.Errorf("%s install_path: got %q, want %q", w.tool, got.InstallPath, w.install)
		}
		if w.configRel != "" {
			wantDir := expandTilde(w.configRel, home)
			if got.ConfigDir != wantDir {
				t.Errorf("%s config_dir: got %q, want %q", w.tool, got.ConfigDir, wantDir)
			}
		}
	}

	for _, name := range aicliNewSpecs {
		want := 0
		if slices.ContainsFunc(tc.want, func(w aicliWant) bool { return w.tool == name }) {
			want = 1
		}
		if got := countAITool(tools, name); got != want {
			t.Errorf("%s: got %d rows, want %d; tools=%+v", name, got, want, tools)
		}
	}

	if tc.wantExecs != nil && !slices.EqualFunc(rec.execs, tc.wantExecs, func(a, b aicliExecCall) bool {
		return a.name == b.name && slices.Equal(a.args, b.args)
	}) {
		t.Errorf("execs: got %+v, want %+v", rec.execs, tc.wantExecs)
	}
	for _, prefix := range tc.noReadPrefix {
		for _, read := range rec.reads {
			if strings.HasPrefix(read, prefix) {
				t.Errorf("touched %q, which is under the forbidden prefix %q", read, prefix)
			}
		}
	}
	for _, frag := range tc.noLookup {
		for _, name := range rec.lookups {
			if strings.Contains(name, frag) {
				t.Errorf("LookPath(%q) issued; no lookup may contain %q", name, frag)
			}
		}
	}
	for _, want := range tc.wantDebug {
		if !strings.Contains(stderr, want) {
			t.Errorf("debug output missing %q; got:\n%s", want, stderr)
		}
	}
	for _, unwanted := range tc.noDebug {
		if strings.Contains(stderr, unwanted) {
			t.Errorf("debug output must not contain %q; got:\n%s", unwanted, stderr)
		}
	}

	allowed := aicliAllowedGlobs(home, goos)
	for _, pattern := range rec.globs {
		// versionmeta's dpkg source globs one <tool>:<arch>.list per candidate.
		// Matched by prefix since the tool name varies per case; it reads the
		// package database and launches nothing.
		if strings.HasPrefix(pattern, "/var/lib/dpkg/info/") {
			continue
		}
		if !allowed[pattern] {
			t.Errorf("unexpected Glob(%q); the ladders may only glob the targeted install trees", pattern)
		}
	}
}

func runAICLICases(t *testing.T, tests []aicliCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { runAICLICase(t, tc) })
	}
}

// ---------------------------------------------------------------------------
// Pi (§7 "Pi")
// ---------------------------------------------------------------------------

func TestAICLIAgents_Pi(t *testing.T) {
	const piPkg = piPackageName
	runAICLICases(t, []aicliCase{
		{
			name: "(a) npm global accept, version and config dir from the manifest read",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("pi", "/usr/local/bin/pi")
				addNPMGlobal(m, "/usr/local/bin/pi", "/usr/local/lib/node_modules/"+piPkg, piPkg, "0.83.0")
				setConfigDir(m, home, "~/.pi/agent")
			},
			want: []aicliWant{{tool: "pi", binary: "/usr/local/bin/pi", version: "0.83.0", configRel: "~/.pi/agent"}},
		},
		{
			name: "(b) the npm PI-number collider is rejected by name",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("pi", "/usr/local/bin/pi")
				addNPMGlobal(m, "/usr/local/bin/pi", "/usr/local/lib/node_modules/pi", "pi", "2.0.5")
			},
			wantDebug: []string{`npm package is "pi", not ` + piPkg},
		},
		{
			name: "(c) a bare PATH script with no manifest anywhere is rejected",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("pi", "/usr/local/bin/pi")
				addFile(m, "/usr/local/bin/pi", []byte("#!/bin/sh\n"))
			},
			wantDebug: []string{"nothing proves " + piPkg + " owns it"},
		},
		{
			name: "(e) ~/.pi/agent without a binary is not an install",
			setup: func(m *executor.Mock, home string) {
				setConfigDir(m, home, "~/.pi/agent")
			},
		},
		{
			name: "(f) the Bun global layout is accepted with its static version",
			setup: func(m *executor.Mock, home string) {
				bunRoot := joinPath(home, ".bun", "install", "global", "node_modules", piPkg)
				addNPMGlobal(m, joinPath(home, ".bun", "bin", "pi"), bunRoot, piPkg, "0.83.0")
			},
			want: []aicliWant{{tool: "pi", binary: "/home/u/.bun/bin/pi", version: "0.83.0"}},
		},
		{
			name: "(g) the standalone tarball is accepted from its sibling manifest (rule 2)",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("pi", "/opt/pi/pi")
				addFile(m, "/opt/pi/pi", []byte{})
				addManifest(m, "/opt/pi", piPkg, "0.83.0")
			},
			want: []aicliWant{{tool: "pi", binary: "/opt/pi/pi", version: "0.83.0"}},
		},
		{
			// The padding is a spare JSON field, so this manifest PARSES and
			// names the right package — (g) with a fat file. Only the cap can
			// reject it; drop the cap and this reports pi 0.83.0. Sibling
			// manifests are the one read versionmeta cannot reach, so this is
			// the one read a directory on PATH can aim at.
			name: "(g2) an oversized sibling manifest is refused rather than loaded",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("pi", "/opt/pi/pi")
				addFile(m, "/opt/pi/pi", []byte{})
				addFile(m, "/opt/pi/package.json", []byte(
					`{"name":"`+piPkg+`","version":"0.83.0","_pad":"`+
						strings.Repeat("x", int(siblingManifestMaxBytes))+`"}`))
			},
			wantDebug: []string{"nothing proves " + piPkg + " owns it"},
		},
		{
			name: "(h) a standalone layout whose sibling manifest names something else is rejected",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("pi", "/opt/pi/pi")
				addFile(m, "/opt/pi/pi", []byte{})
				addManifest(m, "/opt/pi", "pi-fun", "1.0.0")
			},
			wantDebug: []string{"nothing proves " + piPkg + " owns it"},
		},
		{
			name: "(i) a sibling manifest with a name but no version degrades to unknown, never to an exec",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("pi", "/opt/pi/pi")
				addFile(m, "/opt/pi/pi", []byte{})
				addManifest(m, "/opt/pi", piPkg, "")
			},
			want: []aicliWant{{tool: "pi", binary: "/opt/pi/pi", version: "unknown"}},
		},
	})
}

// ---------------------------------------------------------------------------
// Factory (§7 "Factory")
//
// The exec asymmetry is the assertion. Every reject and every static-version
// accept runs under the blanket trap; only the three exec-channel accepts lift
// it, and they pin the launch exactly (§4.0G G5).
// ---------------------------------------------------------------------------

func TestAICLIAgents_Factory(t *testing.T) {
	runAICLICases(t, []aicliCase{
		{
			name: "(a) npm unscoped droid accepts with a static version, nothing launched",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("droid", "/usr/local/bin/droid")
				addNPMGlobal(m, "/usr/local/bin/droid", "/usr/local/lib/node_modules/droid", "droid", "0.183.0")
			},
			want: []aicliWant{{tool: "factory", binary: "/usr/local/bin/droid", version: "0.183.0"}},
		},
		{
			name: "(b) npm @factory/cli carries its version out of the ladder's own manifest read",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("droid", "/usr/local/bin/droid")
				addNPMGlobal(m, "/usr/local/bin/droid", "/usr/local/lib/node_modules/@factory/cli", "@factory/cli", "0.183.0")
				setConfigDir(m, home, "~/.factory")
			},
			// matchesTool("cli","droid") is false, so versionmeta cannot serve
			// this one: a green version here proves the ladder carried it.
			want: []aicliWant{{tool: "factory", binary: "/usr/local/bin/droid", version: "0.183.0", configRel: "~/.factory"}},
		},
		{
			name: "(c) installer target plus non-empty ~/.factory resolves version through exactly one launch",
			setup: func(m *executor.Mock, home string) {
				droid := joinPath(home, ".local", "bin", "droid")
				addBinary(m, droid, droidSmallBytes) // corroborator carries it, not the floor
				setConfigDir(m, home, "~/.factory")
				m.SetGlob(joinPath(expandTildePath("~/.factory", home), "*"), []string{joinPath(home, ".factory", "config.json")})
				m.SetCommand("0.183.0\n", "", 0, droid, "--version")
			},
			allowExec: true,
			want:      []aicliWant{{tool: "factory", binary: "/home/u/.local/bin/droid", version: "0.183.0", configRel: "~/.factory"}},
			wantExecs: []aicliExecCall{{name: "/home/u/.local/bin/droid", args: []string{"--version"}}},
		},
		{
			name: "(d) installer target at or above the floor accepts without ~/.factory",
			setup: func(m *executor.Mock, home string) {
				droid := joinPath(home, ".local", "bin", "droid")
				addBinary(m, droid, droidRealBytes)
				m.SetCommand("0.183.0\n", "", 0, droid, "--version")
			},
			allowExec: true,
			want:      []aicliWant{{tool: "factory", binary: "/home/u/.local/bin/droid", version: "0.183.0"}},
			wantExecs: []aicliExecCall{{name: "/home/u/.local/bin/droid", args: []string{"--version"}}},
		},
		{
			name: "(e) installer target under the floor with no corroborator is rejected, never launched",
			setup: func(m *executor.Mock, home string) {
				addBinary(m, joinPath(home, ".local", "bin", "droid"), droidSmallBytes)
			},
			wantDebug: []string{"at the installer target but under"},
		},
		{
			name: "(f) Homebrew Cellar/droid is the formula collider",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("droid", "/opt/homebrew/bin/droid")
				addBinary(m, "/opt/homebrew/bin/droid", droidRealBytes)
				m.SetSymlink("/opt/homebrew/bin/droid", "/opt/homebrew/Cellar/droid/v0.1.5/bin/droid")
			},
			wantDebug: []string{"Homebrew Cellar/droid is the formula collider"},
		},
		{
			name: "(g) ~/.cargo/bin/droid is the cargo collider",
			setup: func(m *executor.Mock, home string) {
				cargo := joinPath(home, ".cargo", "bin", "droid")
				m.SetPath("droid", cargo)
				addBinary(m, cargo, droidRealBytes)
			},
			wantDebug: []string{"under ~/.cargo, the cargo-installed droid collider"},
		},
		{
			name: "(h) the Windows installer target plus ~/.factory accepts and launches once",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				droid := joinPath(home, "bin", "droid.exe")
				addBinary(m, droid, droidSmallBytes)
				setConfigDir(m, home, "~/.factory")
				m.SetGlob(joinPath(expandTildePath("~/.factory", home), "*"), []string{joinPath(home, ".factory", "config.json")})
				m.SetCommand("0.183.0\n", "", 0, droid, "--version")
			},
			allowExec: true,
			want:      []aicliWant{{tool: "factory", binary: `C:\Users\u\bin\droid.exe`, version: "0.183.0", configRel: "~/.factory"}},
			wantExecs: []aicliExecCall{{name: `C:\Users\u\bin\droid.exe`, args: []string{"--version"}}},
		},
		{
			name: "(i) /usr/bin/droid is claimed by no Factory channel",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("droid", "/usr/bin/droid")
				addBinary(m, "/usr/bin/droid", droidRealBytes)
			},
			wantDebug: []string{"no Factory channel claims it"},
		},
		{
			name: "(j) the homebrew CASK accepts and reads its version off the Caskroom segment",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("droid", "/opt/homebrew/bin/droid")
				// Stat follows the symlink on a real box, so the size lives on
				// the found path — which is what fileAtLeast stats.
				addBinary(m, "/opt/homebrew/bin/droid", droidRealBytes)
				m.SetSymlink("/opt/homebrew/bin/droid", "/opt/homebrew/Caskroom/droid/0.183.0/droid")
			},
			want: []aicliWant{{tool: "factory", binary: "/opt/homebrew/bin/droid", version: "0.183.0"}},
		},
		{
			name: "(k) the cask root alone is not sufficient — a sub-floor payload is rejected",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("droid", "/opt/homebrew/bin/droid")
				addBinary(m, "/opt/homebrew/bin/droid", droidSmallBytes)
				m.SetSymlink("/opt/homebrew/bin/droid", "/opt/homebrew/Caskroom/droid/0.183.0/droid")
			},
			wantDebug: []string{"no Factory channel claims it"},
		},
	})
}

// ---------------------------------------------------------------------------
// Amp (§7 "Amp")
// ---------------------------------------------------------------------------

const (
	ampPkg     = "@ampcode/cli"
	ampLegacy  = "@sourcegraph/amp"
	ampVersion = "0.0.1785328548"
)

// pacmanFiles is a %FILES% manifest terminated by a blank line, followed by the
// %BACKUP% section the parse must not run into.
func pacmanFiles(paths ...string) []byte {
	var b strings.Builder
	b.WriteString("%FILES%\n")
	for _, p := range paths {
		b.WriteString(p + "\n")
	}
	b.WriteString("\n%BACKUP%\nusr/bin/amp\t0000\n")
	return []byte(b.String())
}

func TestAICLIAgents_Amp(t *testing.T) {
	runAICLICases(t, []aicliCase{
		{
			name: "(a) the anchor wins over the ~/.local/bin symlink that points at it",
			setup: func(m *executor.Mock, home string) {
				anchor := joinPath(home, ".amp", "bin", "amp")
				link := joinPath(home, ".local", "bin", "amp")
				addFile(m, anchor, []byte{})
				addFile(m, link, []byte{})
				m.SetSymlink(link, anchor)
				m.SetPath("amp", link)
				setConfigDir(m, home, "~/.config/amp")
			},
			want: []aicliWant{{tool: "amp", binary: "/home/u/.amp/bin/amp", version: "unknown", configRel: "~/.config/amp"}},
		},
		{
			name: "(b) the anchor alone reports unknown rather than launching amp",
			setup: func(m *executor.Mock, home string) {
				addFile(m, joinPath(home, ".amp", "bin", "amp"), []byte{})
			},
			want: []aicliWant{{tool: "amp", binary: "/home/u/.amp/bin/amp", version: "unknown"}},
		},
		{
			name: "(c) homebrew/core Cellar/amp is the amp.rs editor",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("amp", "/opt/homebrew/bin/amp")
				m.SetSymlink("/opt/homebrew/bin/amp", "/opt/homebrew/Cellar/amp/0.7.1/bin/amp")
			},
			wantDebug: []string{"Homebrew Cellar/amp is the amp.rs text editor"},
		},
		{
			name: "(d) ~/.cargo/bin/amp is the cargo-installed amp.rs editor",
			setup: func(m *executor.Mock, home string) {
				cargo := joinPath(home, ".cargo", "bin", "amp")
				m.SetPath("amp", cargo)
				addFile(m, cargo, []byte{})
			},
			wantDebug: []string{"under ~/.cargo, the cargo-installed amp.rs editor"},
		},
		{
			name: "(e) /usr/bin/amp with no pacman entry is rejected, nothing launched",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("amp", "/usr/bin/amp")
				addFile(m, "/usr/bin/amp", []byte{})
			},
			wantDebug: []string{"no installed ampcode/ampcode-bin package owns usr/bin/amp"},
		},
		{
			name: "(f) the AUR ampcode package owning usr/bin/amp accepts",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("amp", "/usr/bin/amp")
				addFile(m, "/usr/bin/amp", []byte{})
				dir := "/var/lib/pacman/local/ampcode-0.0.1785328548_gc93a97-1"
				m.SetGlob("/var/lib/pacman/local/*-*", []string{dir})
				addFile(m, dir+"/files", pacmanFiles("usr/", "usr/bin/", "usr/bin/amp"))
			},
			want: []aicliWant{{tool: "amp", binary: "/usr/bin/amp", version: "unknown"}},
		},
		{
			name: "(f2) ampcode installed but not owning the path is presence, not ownership",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("amp", "/usr/bin/amp")
				addFile(m, "/usr/bin/amp", []byte{})
				dir := "/var/lib/pacman/local/ampcode-0.0.1785328548_gc93a97-1"
				m.SetGlob("/var/lib/pacman/local/*-*", []string{dir})
				addFile(m, dir+"/files", pacmanFiles("usr/", "usr/share/licenses/ampcode/LICENSE"))
			},
			wantDebug: []string{"no installed ampcode/ampcode-bin package owns usr/bin/amp"},
		},
		{
			name: "(f3) ampcode-bin alone is enough — the two names are alternatives",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("amp", "/usr/bin/amp")
				addFile(m, "/usr/bin/amp", []byte{})
				dir := "/var/lib/pacman/local/ampcode-bin-0.0.1785328548-1"
				m.SetGlob("/var/lib/pacman/local/*-*", []string{dir})
				addFile(m, dir+"/files", pacmanFiles("usr/bin/amp"))
			},
			want: []aicliWant{{tool: "amp", binary: "/usr/bin/amp", version: "unknown"}},
		},
		{
			name: "(f4) amp-utils must not parse as the amp.rs package",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("amp", "/usr/bin/amp")
				addFile(m, "/usr/bin/amp", []byte{})
				dir := "/var/lib/pacman/local/amp-utils-1.0-1"
				m.SetGlob("/var/lib/pacman/local/*-*", []string{dir})
				addFile(m, dir+"/files", pacmanFiles("usr/bin/amp"))
			},
			wantDebug: []string{"no installed ampcode/ampcode-bin package owns usr/bin/amp"},
			noDebug:   []string{"pacman package `amp` owns"},
		},
		{
			name: "(g) the amp.rs package owning usr/bin/amp is named in the reject line",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("amp", "/usr/bin/amp")
				addFile(m, "/usr/bin/amp", []byte{})
				dir := "/var/lib/pacman/local/amp-0.7.1-1"
				m.SetGlob("/var/lib/pacman/local/*-*", []string{dir})
				addFile(m, dir+"/files", pacmanFiles("usr/bin/amp"))
			},
			wantDebug: []string{"pacman package `amp` owns usr/bin/amp, which is the amp.rs editor"},
		},
		{
			name: "(h) npm @ampcode/cli carries its version out of the rule-2 manifest read",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("amp", "/usr/local/bin/amp")
				addNPMGlobal(m, "/usr/local/bin/amp", "/usr/local/lib/node_modules/"+ampPkg, ampPkg, ampVersion)
			},
			// matchesTool("cli","amp") is false — versionmeta cannot serve this.
			want: []aicliWant{{tool: "amp", binary: "/usr/local/bin/amp", version: ampVersion}},
		},
		{
			name: "(i) the nested @sourcegraph/amp layout reports the INNERMOST package's version",
			setup: func(m *executor.Mock, _ string) {
				outer := "/usr/local/lib/node_modules/" + ampLegacy
				inner := outer + "/node_modules/" + ampPkg
				m.SetPath("amp", "/usr/local/bin/amp")
				addFile(m, "/usr/local/bin/amp", []byte{})
				m.SetSymlink("/usr/local/bin/amp", inner+"/bin/amp.js")
				addManifest(m, outer, ampLegacy, "9.9.9")
				addManifest(m, inner, ampPkg, ampVersion)
			},
			want: []aicliWant{{tool: "amp", binary: "/usr/local/bin/amp", version: ampVersion}},
		},
	})
}

// TestNPMIdentity_AllowlistNames exercises the literal "@sourcegraph/amp"
// allowlist entry directly. It is kept as a unit test because no npm install
// produces a top-level @sourcegraph/amp bin — a fixture of that layout would be
// a guess, and the entry exists as insurance against a future republish.
func TestNPMIdentity_AllowlistNames(t *testing.T) {
	root := "/usr/local/lib/node_modules/" + ampLegacy
	resolved := root + "/bin/amp.js"

	tests := []struct {
		name        string
		allow       []string
		wantOK      bool
		wantVersion string
	}{
		{"legacy name is allowlisted", []string{ampPkg, ampLegacy}, true, "0.9.0"},
		{"a version is never returned without the identity check", []string{ampPkg}, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := executor.NewMock()
			m.SetGOOS(model.PlatformLinux)
			addManifest(m, root, ampLegacy, "0.9.0")

			name, version, ok := npmIdentity(m, resolved, resolved, tc.allow...)
			if ok != tc.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if name != ampLegacy {
				t.Errorf("observed name: got %q, want %q (a reject must still report what it saw)", name, ampLegacy)
			}
			if version != tc.wantVersion {
				t.Errorf("version: got %q, want %q", version, tc.wantVersion)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Candidate walk (§3.8) — a collider resolving from an earlier candidate must
// not hide a genuine install at a later one. All three fail without ResolveFunc.
// ---------------------------------------------------------------------------

func TestAICLIAgents_CandidateWalk(t *testing.T) {
	runAICLICases(t, []aicliCase{
		{
			name: "(a) nvm PATH hit is the PI-number package; real Pi comes from the prefix set",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				nvmBin := "/Users/u/.nvm/versions/node/v24.18.1/bin"
				m.SetGlob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin"), []string{nvmBin})
				m.SetPath("pi", nvmBin+"/pi")
				addNPMGlobal(m, nvmBin+"/pi", "/Users/u/.nvm/versions/node/v24.18.1/lib/node_modules/pi", "pi", "2.0.5")
				addNPMGlobal(m, "/opt/homebrew/bin/pi", "/opt/homebrew/lib/node_modules/"+piPackageName, piPackageName, "0.83.0")
			},
			want:      []aicliWant{{tool: "pi", binary: "/opt/homebrew/bin/pi", version: "0.83.0"}},
			wantDebug: []string{`npm package is "pi", not ` + piPackageName},
		},
		{
			name: "(b) PI-number on PATH does not hide the real Pi in ~/.local/bin",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("pi", "/usr/local/bin/pi")
				addNPMGlobal(m, "/usr/local/bin/pi", "/usr/local/lib/node_modules/pi", "pi", "2.0.5")
				addNPMGlobal(m, joinPath(home, ".local", "bin", "pi"),
					joinPath(home, ".local", "lib", "node_modules", piPackageName), piPackageName, "0.83.0")
			},
			want: []aicliWant{{tool: "pi", binary: "/home/u/.local/bin/pi", version: "0.83.0"}},
		},
		{
			name: "(c) the cargo droid on PATH does not hide the real Droid in ~/.local/bin",
			setup: func(m *executor.Mock, home string) {
				cargo := joinPath(home, ".cargo", "bin", "droid")
				m.SetPath("droid", cargo)
				addBinary(m, cargo, droidRealBytes)
				real := joinPath(home, ".local", "bin", "droid")
				addBinary(m, real, droidRealBytes)
				m.SetCommand("0.183.0\n", "", 0, real, "--version")
			},
			allowExec: true,
			want:      []aicliWant{{tool: "factory", binary: "/home/u/.local/bin/droid", version: "0.183.0"}},
			wantExecs: []aicliExecCall{{name: "/home/u/.local/bin/droid", args: []string{"--version"}}},
		},
		{
			// Not a candidate-walk case: Amp lists its anchor first, so this
			// passes under today's control flow too. It guards that ordering.
			name: "anchor precedence — amp.rs on PATH loses to the anchored install",
			setup: func(m *executor.Mock, home string) {
				cargo := joinPath(home, ".cargo", "bin", "amp")
				m.SetPath("amp", cargo)
				addFile(m, cargo, []byte{})
				addFile(m, joinPath(home, ".amp", "bin", "amp"), []byte{})
			},
			want: []aicliWant{{tool: "amp", binary: "/home/u/.amp/bin/amp", version: "unknown"}},
		},
	})
}

// ---------------------------------------------------------------------------
// No-regression (§2.1's receipt)
// ---------------------------------------------------------------------------

func TestAICLIAgents_NoRegression(t *testing.T) {
	runAICLICases(t, []aicliCase{
		{
			name: "(a) a machine with none of the three agents reports no rows at all",
		},
		{
			name: "(b) an existing VerifyFunc spec still resolves through the ResolveFunc==nil path",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("copilot", "/usr/local/bin/copilot")
				addNPMGlobal(m, "/usr/local/bin/copilot", "/usr/local/lib/node_modules/@github/copilot", "@github/copilot", "1.2.3")
				setConfigDir(m, home, "~/.config/github-copilot")
			},
			want: []aicliWant{{
				tool: "github-copilot-cli", binary: "/usr/local/bin/copilot",
				version: "1.2.3", configRel: "~/.config/github-copilot",
			}},
		},
		{
			// Nothing on PATH: the only way to this row is the gh data-directory
			// anchor, and with no manifest beside it both probes must be execs.
			name: "(c) the Copilot CLI gh downloads for itself is found off PATH",
			setup: func(m *executor.Mock, home string) {
				bin := expandTilde("~/.local/share/gh/copilot/copilot", home)
				addBinary(m, bin, 40<<20)
				m.SetCommand("GitHub Copilot CLI 2077.1.1\n", "", 0, bin, "--version")
			},
			allowExec: true,
			want: []aicliWant{{
				tool: "github-copilot-cli", binary: "/home/u/.local/share/gh/copilot/copilot",
				version: "2077.1.1",
			}},
			wantExecs: []aicliExecCall{
				{name: "/home/u/.local/share/gh/copilot/copilot", args: []string{"--version"}},
				{name: "/home/u/.local/share/gh/copilot/copilot", args: []string{"--version"}},
			},
		},
	})
}

func TestAICLIAgents_EmptyFixtureReportsNothing(t *testing.T) {
	m, _ := newAICLIMock(model.PlatformLinux)
	rec := &recExec{Mock: m, t: t, trapExec: true}
	var tools []model.AITool
	captureStderr(t, func() {
		tools = NewAICLIDetector(rec).Detect(context.Background())
	})
	if len(tools) != 0 {
		t.Errorf("empty fixture: got %d rows, want 0; %+v", len(tools), tools)
	}
}

// ---------------------------------------------------------------------------
// Windows-shaped cases (§4.0W)
// ---------------------------------------------------------------------------

func TestAICLIAgents_Windows(t *testing.T) {
	npmDir := `C:\Users\u\AppData\Roaming\npm`
	linksDir := `C:\Users\u\AppData\Local\Microsoft\WinGet\Links`
	pkgsDir := `C:\Users\u\AppData\Local\Microsoft\WinGet\Packages`
	voltaImages := `C:\Users\u\AppData\Local\Volta\tools\image\packages`

	runAICLICases(t, []aicliCase{
		{
			name: "(w1) the extension-less npm shim is not a candidate",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				// npm writes a 455 B #!/bin/sh sibling that PATHEXT never
				// resolves and NPMShimPackageRoot refuses to parse.
				addFile(m, npmDir+`\pi`, []byte("#!/bin/sh\nbasedir=$(dirname \"$0\")\n"))
				addManifest(m, npmDir+`\node_modules\`+strings.ReplaceAll(piPackageName, "/", `\`), piPackageName, "0.83.0")
			},
		},
		{
			name: "(w1b) the .cmd spelling of the same install is accepted",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				addFile(m, npmDir+`\pi.cmd`, winNPMShim(`node_modules\@earendil-works\pi-coding-agent\dist\cli.js`))
				addManifest(m, npmDir+`\node_modules\@earendil-works\pi-coding-agent`, piPackageName, "0.83.0")
				setConfigDir(m, home, "~/.pi/agent")
			},
			want: []aicliWant{{tool: "pi", binary: npmDir + `\pi.cmd`, version: "0.83.0", configRel: "~/.pi/agent"}},
		},
		{
			name: "(w2) no size floor applies on the npm branch — a 3,024 B launcher still accepts",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, npmDir+`\droid.cmd`, winNPMShim(`node_modules\droid\bin\droid.js`))
				addManifest(m, npmDir+`\node_modules\droid`, "droid", "0.183.0")
				addBinary(m, npmDir+`\node_modules\droid\bin\droid.js`, droidSmallBytes)
			},
			want: []aicliWant{{tool: "factory", binary: npmDir + `\droid.cmd`, version: "0.183.0"}},
		},
		{
			name: "(w3) the Windows shim branch reaches the manifest too",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, npmDir+`\amp.cmd`, winNPMShim(`node_modules\@ampcode\cli\dist\main.js`))
				addManifest(m, npmDir+`\node_modules\@ampcode\cli`, ampPkg, ampVersion)
			},
			want: []aicliWant{{tool: "amp", binary: npmDir + `\amp.cmd`, version: ampVersion}},
		},
		{
			name: "(w4) ~\\bin\\droid.exe at or above the floor accepts with no ~\\.factory",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				droid := joinPath(home, "bin", "droid.exe")
				addBinary(m, droid, droidRealBytes)
				m.SetCommand("0.183.0\n", "", 0, droid, "--version")
			},
			allowExec: true,
			want:      []aicliWant{{tool: "factory", binary: `C:\Users\u\bin\droid.exe`, version: "0.183.0"}},
			wantExecs: []aicliExecCall{{name: `C:\Users\u\bin\droid.exe`, args: []string{"--version"}}},
		},
		{
			name: "(w5) the winget portable Links symlink accepts, reporting the Links path as binary_path",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				target := pkgsDir + `\Sourcegraph.Amp_Microsoft.Winget.Source_8wekyb3d8bbwe\amp.exe`
				addFile(m, linksDir+`\amp.exe`, []byte{})
				m.SetSymlink(linksDir+`\amp.exe`, target)
			},
			want: []aicliWant{{
				tool:    "amp",
				binary:  linksDir + `\amp.exe`,
				install: pkgsDir + `\Sourcegraph.Amp_Microsoft.Winget.Source_8wekyb3d8bbwe\amp.exe`,
				version: "unknown",
			}},
		},
		{
			name: "(w5r) the rule is pinned to the publisher-qualified identifier, not to WinGet generally",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, linksDir+`\amp.exe`, []byte{})
				m.SetSymlink(linksDir+`\amp.exe`, pkgsDir+`\SomeoneElse.Amp_Microsoft.Winget.Source_8wekyb3d8bbwe\amp.exe`)
			},
			wantDebug: []string{"no Amp channel claims it"},
		},
		{
			name: "(w6) a .cmd shim naming node_modules\\pi is rejected and the debug line records the name",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, _ string) {
				addFile(m, npmDir+`\pi.cmd`, winNPMShim(`node_modules\pi\index.js`))
				addManifest(m, npmDir+`\node_modules\pi`, "pi", "2.0.5")
			},
			wantDebug: []string{`npm package is "pi", not ` + piPackageName},
		},
		{
			name: "(w7) three Amp channels at once collapse to one row on the anchor",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				addFile(m, joinPath(home, ".amp", "bin", "amp.exe"), []byte{})
				addFile(m, npmDir+`\amp.cmd`, winNPMShim(`node_modules\@ampcode\cli\dist\main.js`))
				addManifest(m, npmDir+`\node_modules\@ampcode\cli`, ampPkg, ampVersion)
				addFile(m, linksDir+`\amp.exe`, []byte{})
				m.SetSymlink(linksDir+`\amp.exe`, pkgsDir+`\Sourcegraph.Amp_Microsoft.Winget.Source_8wekyb3d8bbwe\amp.exe`)
			},
			want: []aicliWant{{tool: "amp", binary: `C:\Users\u\.amp\bin\amp.exe`, version: "unknown"}},
		},
		{
			name: "(w8) the Bun .exe is identified through its .bunx pointer",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				bunBin := joinPath(home, ".bun", "bin")
				pkgRoot := joinPath(home, ".bun", "install", "global", "node_modules", `@earendil-works`, "pi-coding-agent")
				addFile(m, bunBin+`\pi.exe`, []byte{})
				addFile(m, bunBin+`\pi.bunx`, utf16LE(pkgRoot+`\dist\cli.js`))
				addManifest(m, pkgRoot, piPackageName, "0.83.0")
			},
			want: []aicliWant{{tool: "pi", binary: `C:\Users\u\.bun\bin\pi.exe`, version: "0.83.0"}},
		},
		{
			name: "(w8r) the pointer is trusted only as far as the target's manifest",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				bunBin := joinPath(home, ".bun", "bin")
				pkgRoot := joinPath(home, ".bun", "install", "global", "node_modules", "pi")
				addFile(m, bunBin+`\pi.exe`, []byte{})
				addFile(m, bunBin+`\pi.bunx`, utf16LE(pkgRoot+`\dist\cli.js`))
				addManifest(m, pkgRoot, "pi", "2.0.5")
			},
			wantDebug: []string{"nothing proves " + piPackageName + " owns it"},
		},
		{
			name: "(w8b) a .bunx that is not valid UTF-16 is refused",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				bunBin := joinPath(home, ".bun", "bin")
				addFile(m, bunBin+`\pi.exe`, []byte{})
				addFile(m, bunBin+`\pi.bunx`, []byte{0x41, 0x00, 0x42})
			},
			wantDebug: []string{"nothing proves " + piPackageName + " owns it"},
		},
		{
			name: "(w8u) a UNC pointer is dropped BEFORE its target is touched",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				bunBin := joinPath(home, ".bun", "bin")
				addFile(m, bunBin+`\pi.exe`, []byte{})
				addFile(m, bunBin+`\pi.bunx`, utf16LE(`\\server\share\pi\dist\cli.js`))
				addManifest(m, `\\server\share\pi`, piPackageName, "0.83.0")
			},
			noReadPrefix: []string{`\\`},
		},
		{
			name: "(w8o) a local but out-of-root pointer is dropped before its target is touched",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				bunBin := joinPath(home, ".bun", "bin")
				addFile(m, bunBin+`\pi.exe`, []byte{})
				addFile(m, bunBin+`\pi.bunx`, utf16LE(`C:\Users\u\Documents\pi\dist\cli.js`))
				addManifest(m, `C:\Users\u\Documents\pi`, piPackageName, "0.83.0")
			},
			noReadPrefix: []string{`C:\Users\u\Documents`},
		},
		{
			// The padding is whitespace the decoder trims, so this pointer is
			// otherwise VALID and names a real manifest — only the size cap can
			// reject it. Drop the cap and this case reports pi 0.83.0.
			name: "(w8x) an oversized .bunx is refused before it is decoded",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				bunBin := joinPath(home, ".bun", "bin")
				pkgRoot := joinPath(home, ".bun", "install", "global", "node_modules", `@earendil-works`, "pi-coding-agent")
				addFile(m, bunBin+`\pi.exe`, []byte{})
				addFile(m, bunBin+`\pi.bunx`, utf16LE(pkgRoot+`\dist\cli.js`+strings.Repeat(" ", int(bunxMaxBytes))))
				addManifest(m, pkgRoot, piPackageName, "0.83.0")
			},
			noReadPrefix: []string{joinPath(aicliHome(model.PlatformWindows), ".bun", "install")},
		},
		{
			name: "(w9) the volta shim is rejected while the scoped image root accepts",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				voltaBin := joinPath(home, "AppData", "Local", "Volta", "bin")
				addFile(m, voltaBin+`\pi.exe`, []byte{})
				m.SetSymlink(voltaBin+`\pi.exe`, voltaBin+`\volta-shim.exe`)

				// Volta joins the npm name verbatim, so a scoped package nests
				// one directory deeper — and Windows keeps the binary at the
				// image ROOT, not under bin.
				scope := voltaImages + `\@earendil-works`
				image := scope + `\pi-coding-agent`
				m.SetGlob(joinPath(voltaImages, "*"), []string{scope})
				m.SetGlob(joinPath(voltaImages, "*", "*"), []string{image})
				addFile(m, image+`\pi.cmd`, winNPMShim(`node_modules\@earendil-works\pi-coding-agent\dist\cli.js`))
				addManifest(m, image+`\node_modules\@earendil-works\pi-coding-agent`, piPackageName, "0.83.0")
			},
			want:      []aicliWant{{tool: "pi", binary: voltaImages + `\@earendil-works\pi-coding-agent\pi.cmd`, version: "0.83.0"}},
			wantDebug: []string{"nothing proves " + piPackageName + " owns it"},
		},
	})
}

// TestCandidatePaths_WindowsExeRetry pins the .exe retry INSIDE candidatePaths
// (§3.8's deliberate duplicate of findBinary's). pmDirs is nil so only the
// tilde branch can produce the hit — through the bare-name branch the same file
// is reachable via pmBinaryFilenames, which would make the integration case
// green either way.
func TestCandidatePaths_WindowsExeRetry(t *testing.T) {
	m, home := newAICLIMock(model.PlatformWindows)
	addBinary(m, joinPath(home, "bin", "droid.exe"), droidRealBytes)

	got := candidatePaths(m, progress.NewNoop(), newCandidateGuard(m, home, nil), "~/bin/droid", home, nil)
	want := []string{`C:\Users\u\bin\droid.exe`}
	if !slices.Equal(got, want) {
		t.Errorf("candidatePaths: got %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Linux-shaped cases (§4.0L)
// ---------------------------------------------------------------------------

func TestAICLIAgents_Linux(t *testing.T) {
	const snapCurrent = "/snap/pi-coding-agent/current/bin/pi"
	const snapPayload = "/snap/pi-coding-agent/10/bin/pi"

	runAICLICases(t, []aicliCase{
		{
			name: "(l1) /snap/bin/pi resolves to the snapd wrapper and is rejected; the payload accepts",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("pi", "/snap/bin/pi")
				m.SetSymlink("/snap/bin/pi", "/usr/bin/snap")
				addFile(m, snapCurrent, []byte{})
				m.SetSymlink(snapCurrent, snapPayload)
				addManifest(m, "/snap/pi-coding-agent/10/bin", piPackageName, "0.83.0")
			},
			want:      []aicliWant{{tool: "pi", binary: snapCurrent, version: "0.83.0"}},
			wantDebug: []string{"nothing proves " + piPackageName + " owns it (resolved /usr/bin/snap)"},
		},
		{
			name: "(l2) the apt pi calculator answers --version with a version-shaped string; it is never asked",
			setup: func(m *executor.Mock, _ string) {
				m.SetPath("pi", "/usr/bin/pi")
				addBinary(m, "/usr/bin/pi", 67_760)
			},
			wantDebug: []string{"nothing proves " + piPackageName + " owns it"},
		},
		{
			name: "(l3) collider on PATH plus snap plus nvm yields exactly one row, from the nvm candidate",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("pi", "/usr/bin/pi")
				addBinary(m, "/usr/bin/pi", 67_760)

				nvmBin := "/home/u/.nvm/versions/node/v24.18.1/bin"
				m.SetGlob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin"), []string{nvmBin})
				addNPMGlobal(m, nvmBin+"/pi",
					"/home/u/.nvm/versions/node/v24.18.1/lib/node_modules/"+piPackageName, piPackageName, "0.83.0")

				addFile(m, snapCurrent, []byte{})
				m.SetSymlink(snapCurrent, snapPayload)
				addManifest(m, "/snap/pi-coding-agent/10/bin", piPackageName, "0.83.0")
			},
			want: []aicliWant{{tool: "pi", binary: "/home/u/.nvm/versions/node/v24.18.1/bin/pi", version: "0.83.0"}},
		},
		{
			name: "(l4) Droid at the floor and Amp behind its ~/.local/bin symlink, on the same box",
			setup: func(m *executor.Mock, home string) {
				droid := joinPath(home, ".local", "bin", "droid")
				addBinary(m, droid, droidRealBytes)
				m.SetCommand("0.183.0\n", "", 0, droid, "--version")

				anchor := joinPath(home, ".amp", "bin", "amp")
				link := joinPath(home, ".local", "bin", "amp")
				addFile(m, anchor, []byte{})
				addFile(m, link, []byte{})
				m.SetSymlink(link, anchor)
			},
			allowExec: true,
			want: []aicliWant{
				{tool: "factory", binary: "/home/u/.local/bin/droid", version: "0.183.0"},
				{tool: "amp", binary: "/home/u/.amp/bin/amp", version: "unknown"},
			},
			wantExecs: []aicliExecCall{{name: "/home/u/.local/bin/droid", args: []string{"--version"}}},
		},
		{
			name: "(l5) brewRoot is prefix-independent — the Linuxbrew Cellar rejects too",
			setup: func(m *executor.Mock, _ string) {
				brewBin := "/home/linuxbrew/.linuxbrew/bin/amp"
				m.SetPath("amp", brewBin)
				addFile(m, brewBin, []byte{})
				m.SetSymlink(brewBin, "/home/linuxbrew/.linuxbrew/Cellar/amp/0.7.1/bin/amp")
			},
			wantDebug: []string{"Homebrew Cellar/amp is the amp.rs text editor"},
		},
		{
			name: "(l7) an absolute candidate resolves by stat, never through LookPath",
			setup: func(m *executor.Mock, _ string) {
				// Registered as a file ONLY: nothing in the mock's paths map,
				// which is a different map than FileExists reads. A copy of
				// findBinary's two-mode dispatch would miss this entirely.
				addFile(m, snapCurrent, []byte{})
				addManifest(m, "/snap/pi-coding-agent/current/bin", piPackageName, "0.83.0")
			},
			want:     []aicliWant{{tool: "pi", binary: snapCurrent, version: "0.83.0"}},
			noLookup: []string{"snap"},
		},
		{
			name: "(l8) the volta shim is rejected while the SCOPED package image accepts",
			setup: func(m *executor.Mock, home string) {
				shim := joinPath(home, ".volta", "bin", "pi")
				addFile(m, shim, []byte{})
				m.SetSymlink(shim, joinPath(home, ".volta", "bin", "volta-shim"))

				image := joinPath(home, ".volta", "tools", "image", "packages", "@earendil-works", "pi-coding-agent")
				m.SetGlob(joinPath(home, ".volta", "tools", "image", "packages", "*", "*", "bin"),
					[]string{joinPath(image, "bin")})
				addNPMGlobal(m, joinPath(image, "bin", "pi"),
					joinPath(image, "lib", "node_modules", piPackageName), piPackageName, "0.83.0")
			},
			want: []aicliWant{{
				tool:    "pi",
				binary:  "/home/u/.volta/tools/image/packages/@earendil-works/pi-coding-agent/bin/pi",
				version: "0.83.0",
			}},
			wantDebug: []string{"nothing proves " + piPackageName + " owns it"},
		},
		{
			name: "(l9) the asdf shim is a script; only the installs tree proves the package",
			setup: func(m *executor.Mock, home string) {
				shim := joinPath(home, ".asdf", "shims", "pi")
				addFile(m, shim, []byte("#!/usr/bin/env bash\nexec asdf exec pi \"$@\"\n"))

				installBin := joinPath(home, ".asdf", "installs", "nodejs", "24.18.1", "bin")
				m.SetGlob(joinPath(home, ".asdf", "installs", "nodejs", "*", "bin"), []string{installBin})
				addNPMGlobal(m, joinPath(installBin, "pi"),
					joinPath(home, ".asdf", "installs", "nodejs", "24.18.1", "lib", "node_modules", piPackageName),
					piPackageName, "0.83.0")
			},
			want:      []aicliWant{{tool: "pi", binary: "/home/u/.asdf/installs/nodejs/24.18.1/bin/pi", version: "0.83.0"}},
			wantDebug: []string{"nothing proves " + piPackageName + " owns it"},
		},
	})
}

// TestAICLIAgents_LinuxPrefixDirs is (l6) and its family: LookPath fails
// outright — which §4.0L.2 makes the common case on Debian/Ubuntu, where
// RunAsUser's rc-sourcing is inert — so the §4.4 prefix set is the ONLY way
// each of these genuine installs is found.
func TestAICLIAgents_LinuxPrefixDirs(t *testing.T) {
	type prefixCase struct {
		name    string
		binRel  []string // relative to home
		globPat []string // relative to home; registered to yield the bin's dir
		pkgRel  []string // node_modules package root, relative to home
	}
	prefixes := []prefixCase{
		{
			name:   "(l6) pnpm PNPM_HOME",
			binRel: []string{".local", "share", "pnpm", "pi"},
			pkgRel: []string{".local", "share", "pnpm", "global", "5", "node_modules", piPackageName},
		},
		{
			name:   "(l6b) the custom npm prefix",
			binRel: []string{".npm-global", "bin", "pi"},
			pkgRel: []string{".npm-global", "lib", "node_modules", piPackageName},
		},
		{
			name:   "(l6c) n's default N_PREFIX",
			binRel: []string{"n", "bin", "pi"},
			pkgRel: []string{"n", "lib", "node_modules", piPackageName},
		},
		{
			name:    "(l6d) the fnm XDG install tree",
			binRel:  []string{".local", "share", "fnm", "node-versions", "v24.18.1", "installation", "bin", "pi"},
			globPat: []string{".local", "share", "fnm", "node-versions", "*", "installation", "bin"},
			pkgRel: []string{".local", "share", "fnm", "node-versions", "v24.18.1", "installation",
				"lib", "node_modules", piPackageName},
		},
		{
			name:    "(l6e) the mise install tree",
			binRel:  []string{".local", "share", "mise", "installs", "node", "24.18.1", "bin", "pi"},
			globPat: []string{".local", "share", "mise", "installs", "node", "*", "bin"},
			pkgRel: []string{".local", "share", "mise", "installs", "node", "24.18.1",
				"lib", "node_modules", piPackageName},
		},
	}

	for _, pc := range prefixes {
		runAICLICase(t, aicliCase{
			name: pc.name,
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, pc.binRel...)
				addNPMGlobal(m, bin, joinPath(home, pc.pkgRel...), piPackageName, "0.83.0")
				if len(pc.globPat) > 0 {
					m.SetGlob(joinPath(home, pc.globPat...), []string{pathDir(bin)})
				}
			},
			want: []aicliWant{{tool: "pi", binary: joinPath("/home/u", pc.binRel...), version: "0.83.0"}},
		})
	}
}

// ---------------------------------------------------------------------------
// TCC (§3.10)
// ---------------------------------------------------------------------------

// requireDarwinHost skips cases whose expected outcome depends on the skipper
// actually matching something. tcc_other.go returns nil for both
// buildProtectedPaths and protectedPrefixes, so off darwin a Skipper is inert
// and a reject-case would pass vacuously (AGENTS.md §15.4). Accept-cases carry
// no such guard — they must hold on every host.
func requireDarwinHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != model.PlatformDarwin {
		t.Skipf("tcc.Skipper matches nothing on %s; this case asserts a rejection", runtime.GOOS)
	}
}

func TestAICLIAgents_TCCGuard(t *testing.T) {
	t.Run("(t1) the macOS pnpm channel survives the wired skipper", func(t *testing.T) {
		runAICLICase(t, aicliCase{
			name:    "pnpm under ~/Library",
			goos:    model.PlatformDarwin,
			skipper: true,
			setup: func(m *executor.Mock, home string) {
				addNPMGlobal(m, joinPath(home, "Library", "pnpm", "bin", "pi"),
					joinPath(home, "Library", "pnpm", "global", "5", "node_modules", piPackageName),
					piPackageName, "0.83.0")
			},
			want: []aicliWant{{tool: "pi", binary: "/Users/u/Library/pnpm/bin/pi", version: "0.83.0"}},
		})
	})

	t.Run("(t1b) the exemption compares the CLEANED path", func(t *testing.T) {
		requireDarwinHost(t)
		runAICLICase(t, aicliCase{
			name:    "pnpm/../Mail cannot ride the exemption",
			goos:    model.PlatformDarwin,
			skipper: true,
			setup: func(m *executor.Mock, home string) {
				sneaky := joinPath(home, "Library", "pnpm", "..", "Mail", "pi")
				m.SetPath("pi", sneaky)
				m.SetSymlink(sneaky, joinPath(home, "Library", "Mail", "node_modules", piPackageName, "dist", "cli.js"))
				addManifest(m, joinPath(home, "Library", "Mail", "node_modules", piPackageName), piPackageName, "0.83.0")
			},
			noReadPrefix: []string{"/Users/u/Library/Mail", "/Users/u/Library/pnpm/../Mail"},
			wantDebug:    []string{"under a macOS TCC-protected path"},
		})
	})

	t.Run("(t1c) the darwin fnm tree is exempt too", func(t *testing.T) {
		runAICLICase(t, aicliCase{
			name:    "fnm under ~/Library/Application Support",
			goos:    model.PlatformDarwin,
			skipper: true,
			setup: func(m *executor.Mock, home string) {
				binDir := joinPath(home, "Library", "Application Support", "fnm",
					"node-versions", "v24.18.1", "installation", "bin")
				m.SetGlob(joinPath(home, "Library", "Application Support", "fnm",
					"node-versions", "*", "installation", "bin"), []string{binDir})
				addNPMGlobal(m, joinPath(binDir, "pi"),
					joinPath(home, "Library", "Application Support", "fnm", "node-versions", "v24.18.1",
						"installation", "lib", "node_modules", piPackageName),
					piPackageName, "0.83.0")
			},
			want: []aicliWant{{
				tool:    "pi",
				binary:  "/Users/u/Library/Application Support/fnm/node-versions/v24.18.1/installation/bin/pi",
				version: "0.83.0",
			}},
		})
	})

	t.Run("(t3) the guard is darwin-only, and both polarities are asserted", func(t *testing.T) {
		t.Run("darwin rejects", func(t *testing.T) {
			requireDarwinHost(t)
			runAICLICase(t, aicliCase{
				name:    "~/Documents/bin/pi",
				goos:    model.PlatformDarwin,
				skipper: true,
				setup:   tccDocumentsFixture,
				// The fixture satisfies rule 2, so a green reject here is the
				// guard firing and not a ladder miss.
				noReadPrefix: []string{"/Users/u/Documents"},
				wantDebug:    []string{"under a macOS TCC-protected path"},
			})
		})
		t.Run("linux accepts", func(t *testing.T) {
			runAICLICase(t, aicliCase{
				name:    "~/Documents/bin/pi on linux is still a real install",
				goos:    model.PlatformLinux,
				skipper: true,
				setup:   tccDocumentsFixture,
				want:    []aicliWant{{tool: "pi", binary: "/home/u/Documents/bin/pi", version: "0.83.0"}},
			})
		})
	})

	t.Run("(t4) the guard also applies to the RESOLVED form", func(t *testing.T) {
		t.Run("a symlink into ~/Downloads is rejected before its manifest is read", func(t *testing.T) {
			requireDarwinHost(t)
			runAICLICase(t, aicliCase{
				name:    "~/.local/bin/amp -> ~/Downloads/amp",
				goos:    model.PlatformDarwin,
				skipper: true,
				setup: func(m *executor.Mock, home string) {
					link := joinPath(home, ".local", "bin", "amp")
					addFile(m, link, []byte{})
					m.SetSymlink(link, joinPath(home, "Downloads", "amp"))
					addManifest(m, joinPath(home, "Downloads", "node_modules", ampPkg), ampPkg, ampVersion)
				},
				noReadPrefix: []string{"/Users/u/Downloads"},
				wantDebug:    []string{"under a macOS TCC-protected path"},
			})
		})
		t.Run("the same shape resolving to the anchor accepts", func(t *testing.T) {
			runAICLICase(t, aicliCase{
				name:    "~/.local/bin/amp -> ~/.amp/bin/amp",
				goos:    model.PlatformDarwin,
				skipper: true,
				setup: func(m *executor.Mock, home string) {
					link := joinPath(home, ".local", "bin", "amp")
					addFile(m, link, []byte{})
					m.SetSymlink(link, joinPath(home, ".amp", "bin", "amp"))
				},
				want: []aicliWant{{tool: "amp", binary: "/Users/u/.local/bin/amp", version: "unknown"}},
			})
		})
	})

	t.Run("(t5) --include-tcc-protected (nil skipper) opts the same path back in", func(t *testing.T) {
		runAICLICase(t, aicliCase{
			name:  "the exact (t3) darwin fixture with no WithSkipper call",
			goos:  model.PlatformDarwin,
			setup: tccDocumentsFixture,
			want:  []aicliWant{{tool: "pi", binary: "/Users/u/Documents/bin/pi", version: "0.83.0"}},
		})
	})
}

// tccDocumentsFixture is one Pi install under ~/Documents that satisfies rule 2
// (standalone sibling manifest). Shared by (t3) both polarities and (t5) so the
// three differ only in GOOS and whether a skipper is wired.
func tccDocumentsFixture(m *executor.Mock, home string) {
	bin := joinPath(home, "Documents", "bin", "pi")
	m.SetPath("pi", bin)
	addFile(m, bin, []byte{})
	addManifest(m, joinPath(home, "Documents", "bin"), piPackageName, "0.83.0")
}

// TestAICLIAgents_NoWalkAndGlobBudget is (t2). Executor.Glob never calls
// Executor.ReadDir on either implementation, so the two claims are asserted
// separately: recExec.ReadDir fails the test unconditionally (across this whole
// file, not just here), and the glob budget is pinned exactly — one call per
// targeted install-tree pattern per resolver, three resolvers.
func TestAICLIAgents_NoWalkAndGlobBudget(t *testing.T) {
	tests := []struct {
		goos           string
		wantDistinct   int
		wantTotalGlobs int
	}{
		{model.PlatformLinux, 6, 18},
		{model.PlatformDarwin, 7, 21},
		{model.PlatformWindows, 2, 6},
	}
	for _, tc := range tests {
		t.Run(tc.goos, func(t *testing.T) {
			m, home := newAICLIMock(tc.goos)
			rec := &recExec{Mock: m, t: t, trapExec: true}
			captureStderr(t, func() {
				NewAICLIDetector(rec).WithSkipper(tcc.New(home)).Detect(context.Background())
			})

			if len(rec.globs) != tc.wantTotalGlobs {
				t.Errorf("total Glob calls: got %d, want %d; %v", len(rec.globs), tc.wantTotalGlobs, rec.globs)
			}
			allowed := aicliAllowedGlobs(home, tc.goos)
			counts := map[string]int{}
			for _, pattern := range rec.globs {
				if !allowed[pattern] {
					t.Errorf("unexpected Glob(%q)", pattern)
				}
				counts[pattern]++
			}
			if len(counts) != tc.wantDistinct {
				t.Errorf("distinct patterns: got %d (%v), want %d", len(counts), counts, tc.wantDistinct)
			}
			for pattern, n := range counts {
				if n != 3 {
					t.Errorf("Glob(%q) called %d times, want 3 (once per resolver)", pattern, n)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Skills roots (§6.1)
// ---------------------------------------------------------------------------

func TestResolveGlobalRoots_AmpConfigAndFactoryAgentRoots(t *testing.T) {
	cases := []struct{ dir, source, agent string }{
		{testHome + "/.config/amp/skills/ampcfg", "amp_user", "amp"},
		{testHome + "/.agent/skills/facag", "factory_agent_user", "factory"},
	}
	m, fs := newSkillsMock()
	for _, c := range cases {
		fs.addSkill(c.dir, "SKILL.md", validFrontmatter(filepath.Base(c.dir), "d"), nil)
	}
	fs.commit()

	records, info := NewSkillsDetector(m).Detect(context.Background(), nil, nil)
	for _, c := range cases {
		slug := filepath.Base(c.dir)
		rec := findSkill(records, c.source, slug)
		if rec == nil {
			t.Errorf("%s skill %q not found; records=%+v", c.source, slug, records)
			continue
		}
		if rec.Agent != c.agent || rec.Scope != "global" {
			t.Errorf("%s: agent=%q scope=%q, want %s/global", c.source, rec.Agent, rec.Scope, c.agent)
		}
		root := filepath.Dir(c.dir)
		if !slices.Contains(info.RootsScanned, root) {
			t.Errorf("roots_scanned missing %q; got %v", root, info.RootsScanned)
		}
	}
}

func TestResolveGlobalRoots_NewRootsAbsentWhenDirsAbsent(t *testing.T) {
	m, fs := newSkillsMock()
	fs.addSkill(testHome+"/.claude/skills/only", "SKILL.md", validFrontmatter("only", "d"), nil)
	fs.commit()

	_, info := NewSkillsDetector(m).Detect(context.Background(), nil, nil)
	want := []string{filepath.Join(testHome, ".claude", "skills")}
	if !slices.Equal(info.RootsScanned, want) {
		t.Errorf("roots_scanned: got %v, want %v (the two new roots must not appear when absent)", info.RootsScanned, want)
	}
}
