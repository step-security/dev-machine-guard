package detector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
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

	execs []aicliExecCall
	// regReads counts the Kiro CLI registry reads. On Windows that is a native
	// registry API call; only the non-Windows test twin (registry_other.go)
	// spells it as `reg query`, so it is kept out of execs and never trips the
	// trap — but it is fatal off Windows, where the registry must not exist.
	regReads int
	globs    []string
	reads    []string // ReadFile + Stat + FileExists, i.e. every path touched
	evals    []string // EvalSymlinks, i.e. every path followed
	lookups  []string
}

// No mutex: Detect is single-goroutine and AGENTS.md §15.5 forbids t.Parallel.
func (e *recExec) recordExec(name string, args []string) {
	if name == "reg" && slices.Equal(args, []string{"query", `HKCU\SOFTWARE\Kiro\CLI`}) {
		if e.GOOS() != model.PlatformWindows {
			e.t.Fatalf("Kiro CLI registry read on %s: the registry is Windows-only", e.GOOS())
		}
		e.regReads++
		return
	}
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

// EvalSymlinks follows every component; it is recorded apart from reads so a
// case can assert a path was never followed without forbidding the failed
// resolution attempt another case is about.
func (e *recExec) EvalSymlinks(path string) (string, error) {
	e.evals = append(e.evals, path)
	return e.Mock.EvalSymlinks(path)
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
var aicliNewSpecs = []string{"pi", "factory", "amp", "amazon-q-cli", "grok-build", "kimi-code", "muse-code", "hermes-agent", "oh-my-pi"}

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

	want           []aicliWant
	wantExecs      []aicliExecCall
	noReadPrefix   []string // no ReadFile/Stat/FileExists path may start with these
	noFollowPrefix []string // no EvalSymlinks path may start with these either
	noLookup       []string // no LookPath name may contain these
	wantDebug      []string
	noDebug        []string
	// allowGlobs are the fixture-specific patterns this case may glob on top
	// of aicliAllowedGlobs: a sibling probe beside an accepted anchor
	// (grok-*.exe, muse-bin-*) or a venv's dist-info directory.
	allowGlobs []string
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
	allowed[joinPath(home, ".local", "share", "mise", "installs", "github-can1357-oh-my-pi", "*")] = true
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
	// The Kiro ladder reads its registry key once per resolve, whether or not a
	// candidate exists (the key is also how a non-default InstallPath is found).
	wantRegReads := 0
	if goos == model.PlatformWindows {
		wantRegReads = 1
	}
	if rec.regReads != wantRegReads {
		t.Errorf("Kiro registry reads: got %d, want %d", rec.regReads, wantRegReads)
	}
	for _, prefix := range tc.noReadPrefix {
		for _, read := range rec.reads {
			if strings.HasPrefix(read, prefix) {
				t.Errorf("touched %q, which is under the forbidden prefix %q", read, prefix)
			}
		}
	}
	for _, prefix := range tc.noFollowPrefix {
		for _, followed := range rec.evals {
			if strings.HasPrefix(followed, prefix) {
				t.Errorf("followed %q, which is under the forbidden prefix %q", followed, prefix)
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
	for _, pattern := range tc.allowGlobs {
		allowed[pattern] = true
	}
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

	t.Run("(t6) a corroborator derived beside an accepted candidate is guarded after it resolves", func(t *testing.T) {
		t.Run("a .muse-version symlinked into ~/Downloads is rejected before it is read", func(t *testing.T) {
			requireDarwinHost(t)
			runAICLICase(t, aicliCase{
				name:    "~/.local/bin/.muse-version -> ~/Downloads/.muse-version",
				goos:    model.PlatformDarwin,
				skipper: true,
				setup: func(m *executor.Mock, home string) {
					bin := joinPath(home, ".local", "bin")
					addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
					sidecar := joinPath(bin, ".muse-version")
					addFile(m, sidecar, []byte(museVersion+"\n"))
					m.SetSymlink(sidecar, joinPath(home, "Downloads", ".muse-version"))
					addBinary(m, joinPath(bin, "muse-bin-"+museVersion), 90<<20)
				},
				noReadPrefix: []string{"/Users/u/Downloads"},
				wantDebug:    []string{"under a macOS TCC-protected path"},
			})
		})
		t.Run("a muse-bin payload symlinked into ~/Downloads is rejected before it is stat'd", func(t *testing.T) {
			requireDarwinHost(t)
			runAICLICase(t, aicliCase{
				name:    "~/.local/bin/muse-bin-<v> -> ~/Downloads/muse-bin-<v>",
				goos:    model.PlatformDarwin,
				skipper: true,
				setup: func(m *executor.Mock, home string) {
					bin := joinPath(home, ".local", "bin")
					addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
					addFile(m, joinPath(bin, ".muse-version"), []byte(museVersion+"\n"))
					payload := joinPath(bin, "muse-bin-"+museVersion)
					addFile(m, payload, []byte{})
					m.SetSymlink(payload, joinPath(home, "Downloads", "muse-bin-"+museVersion))
				},
				noReadPrefix: []string{"/Users/u/Downloads"},
				wantDebug:    []string{"under a macOS TCC-protected path"},
			})
		})
		t.Run("a hermes venv symlinked into ~/Documents is rejected before it is globbed", func(t *testing.T) {
			requireDarwinHost(t)
			runAICLICase(t, aicliCase{
				name:    "~/.hermes/hermes-agent/venv -> ~/Documents/venv",
				goos:    model.PlatformDarwin,
				skipper: true,
				setup: func(m *executor.Mock, home string) {
					addFile(m, joinPath(home, ".local", "bin", "hermes"), []byte("#!/bin/bash\n"))
					venv := joinPath(home, ".hermes", "hermes-agent", "venv")
					m.SetDir(venv)
					m.SetSymlink(venv, joinPath(home, "Documents", "venv"))
				},
				noReadPrefix: []string{"/Users/u/Documents"},
				wantDebug:    []string{"under a macOS TCC-protected path"},
			})
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
// targeted install-tree pattern per resolver. Every spec in aicliNewSpecs
// walks on Unix; on Windows the Kiro ladder returns before any candidate walk
// when its registry key is absent, so one fewer.
func TestAICLIAgents_NoWalkAndGlobBudget(t *testing.T) {
	resolvers := len(aicliNewSpecs)
	tests := []struct {
		goos           string
		wantDistinct   int
		wantPerPattern int
		wantTotalGlobs int
	}{{model.PlatformLinux, 7, resolvers, 7 * resolvers},
		{model.PlatformDarwin, 8, resolvers, 8 * resolvers},
		{model.PlatformWindows, 2, resolvers - 1, 2 * (resolvers - 1)},
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
				if n != tc.wantPerPattern {
					t.Errorf("Glob(%q) called %d times, want %d (once per resolver)", pattern, n, tc.wantPerPattern)
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
		{testHome + "/.agent/skills/facag", "factory_agent_user", "shared"}, // read by Factory and Antigravity
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

// ---------------------------------------------------------------------------
// Kiro CLI (amazon-q-cli). Runs under the aicli harness: the exec trap is on
// unless a case says otherwise, so every accept below is proven without
// launching the candidate. Fixture values are the ones measured on real
// installs (bundle id com.amazon.codewhisperer, version 2.21.1, Windows
// ProductVersion 2.21.1.0).
// ---------------------------------------------------------------------------

const kiroCLIBundle = "/Applications/Kiro CLI.app"

// kiroPlist is a minimal XML Info.plist; short == "" omits
// CFBundleShortVersionString. CFBundleVersion is always present and never the
// answer.
func kiroPlist(bundleID, short string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
		`<plist version="1.0"><dict>`)
	b.WriteString(`<key>CFBundleIdentifier</key><string>` + bundleID + `</string>`)
	if short != "" {
		b.WriteString(`<key>CFBundleShortVersionString</key><string>` + short + `</string>`)
	}
	b.WriteString(`<key>CFBundleVersion</key><string>999</string>` +
		`<key>CFBundleExecutable</key><string>kiro_cli_desktop</string></dict></plist>`)
	return []byte(b.String())
}

// kiroDarwinBundle installs the CLI bundle with the given plist.
func kiroDarwinBundle(m *executor.Mock, plist []byte) {
	addFile(m, kiroCLIBundle+"/Contents/MacOS/kiro-cli", []byte{})
	addFile(m, kiroCLIBundle+"/Contents/Info.plist", plist)
}

// kiroLinuxTrio drops the installer's three binaries into dir.
func kiroLinuxTrio(m *executor.Mock, dir string) {
	for _, name := range []string{"kiro-cli", "kiro-cli-chat", "kiro-cli-term"} {
		addFile(m, joinPath(dir, name), []byte{})
	}
}

// kiroRegistry stubs the installer key as the non-Windows twin queries it.
func kiroRegistry(m *executor.Mock, installPath string) {
	m.SetCommand("\r\nHKEY_CURRENT_USER\\SOFTWARE\\Kiro\\CLI\r\n"+
		"    InstallPath    REG_SZ    "+installPath+"\r\n"+
		"    ProductVersion    REG_SZ    2.21.1.0\r\n"+
		"    CliVersion    REG_SZ    v2\r\n", "", 0,
		"reg", "query", `HKCU\SOFTWARE\Kiro\CLI`)
}

func TestAICLIAgents_Kiro_Darwin(t *testing.T) {
	bin := kiroCLIBundle + "/Contents/MacOS/kiro-cli"
	plistBuddy := aicliExecCall{name: "/usr/libexec/PlistBuddy", args: []string{"-c", "Print :CFBundleShortVersionString", kiroCLIBundle + "/Contents/Info.plist"}}
	runAICLICases(t, []aicliCase{
		{
			name: "PATH symlink into the bundle: identity and version from the plist",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				kiroDarwinBundle(m, kiroPlist(kiroCLIBundleID, "2.21.1"))
				link := joinPath(home, ".local", "bin", "kiro-cli")
				m.SetPath("kiro-cli", link)
				addFile(m, link, []byte{})
				m.SetSymlink(link, bin)
				setConfigDir(m, home, "~/.kiro")
			},
			want: []aicliWant{{tool: "amazon-q-cli", binary: "/Users/u/.local/bin/kiro-cli", version: "2.21.1", install: bin, configRel: "~/.kiro"}},
		},
		{
			name: "nothing on PATH: the fixed bundle path is the anchor",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				kiroDarwinBundle(m, kiroPlist(kiroCLIBundleID, "2.21.1"))
			},
			want: []aicliWant{{tool: "amazon-q-cli", binary: bin, version: "2.21.1"}},
		},
		{
			name: "PATH alias and fixed path resolve to one file: one row",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				kiroDarwinBundle(m, kiroPlist(kiroCLIBundleID, "2.21.1"))
				m.SetPath("kiro-cli", bin)
				m.SetPath("q", bin)
			},
			want: []aicliWant{{tool: "amazon-q-cli", binary: bin, version: "2.21.1"}},
		},
		{
			// The only exec is Apple's PlistBuddy, from the shared static
			// version ladder every bundle-shipped tool goes through; the CLI
			// itself is never launched (StaticVersionOnly).
			name: "plist without a short version: unknown, CLI never launched",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				kiroDarwinBundle(m, kiroPlist(kiroCLIBundleID, ""))
			},
			allowExec: true,
			wantExecs: []aicliExecCall{plistBuddy},
			want:      []aicliWant{{tool: "amazon-q-cli", binary: bin, version: "unknown"}},
			wantDebug: []string{"reporting version unknown (never launched)"},
		},
		{
			name: "a bundle with another identifier is rejected",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				other := "/Applications/Other.app/Contents/MacOS/kiro-cli"
				addFile(m, other, []byte{})
				addFile(m, "/Applications/Other.app/Contents/Info.plist", kiroPlist("com.example.other", "9.9.9"))
				m.SetPath("kiro-cli", other)
			},
			wantDebug: []string{`bundle identifier is "com.example.other", not com.amazon.codewhisperer`},
		},
		{
			name: "the Kiro IDE bundle is not the CLI",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				ide := "/Applications/Kiro.app/Contents/Resources/app/bin/code"
				addFile(m, ide, []byte{})
				addFile(m, "/Applications/Kiro.app/Contents/Info.plist", kiroPlist("dev.kiro.desktop", "1.0.437"))
				m.SetPath("kiro", ide)
			},
			wantDebug: []string{"not <bundle>.app/Contents/MacOS/kiro-cli"},
		},
		{
			// The link is seen with Readlink and never followed: neither its
			// target nor the link path itself is stat'd, resolved or read.
			name: "a plist symlinked into ~/Downloads is never followed",
			goos: model.PlatformDarwin,
			setup: func(m *executor.Mock, home string) {
				addFile(m, bin, []byte{})
				m.SetSymlink(kiroCLIBundle+"/Contents/Info.plist", joinPath(home, "Downloads", "Info.plist"))
				addFile(m, joinPath(home, "Downloads", "Info.plist"), kiroPlist(kiroCLIBundleID, "2.21.1"))
			},
			skipper:        true,
			noReadPrefix:   []string{"/Users/u/Downloads", kiroCLIBundle + "/Contents/Info.plist"},
			noFollowPrefix: []string{"/Users/u/Downloads", kiroCLIBundle + "/Contents/Info.plist"},
			wantDebug:      []string{"under a macOS TCC-protected path"},
		},
	})
}

func TestAICLIAgents_Kiro_Linux(t *testing.T) {
	const dpkgStatus = "Package: kiro-cli\nStatus: install ok installed\nVersion: 2.21.1\n\n"
	runAICLICases(t, []aicliCase{
		{
			name: "dpkg: the package owns the binary and carries the version",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("kiro-cli", "/usr/bin/kiro-cli")
				addFile(m, "/usr/bin/kiro-cli", []byte{})
				addFile(m, "/var/lib/dpkg/info/kiro-cli.list", []byte("/usr\n/usr/bin\n/usr/bin/kiro-cli\n"))
				addFile(m, "/var/lib/dpkg/status", []byte(dpkgStatus))
			},
			want: []aicliWant{{tool: "amazon-q-cli", binary: "/usr/bin/kiro-cli", version: "2.21.1"}},
		},
		{
			name: "installer trio in ~/.local/bin, archive gone: unknown version, never launched",
			setup: func(m *executor.Mock, home string) {
				dir := joinPath(home, ".local", "bin")
				kiroLinuxTrio(m, dir)
				m.SetPath("kiro-cli", joinPath(dir, "kiro-cli"))
			},
			want:      []aicliWant{{tool: "amazon-q-cli", binary: "/home/u/.local/bin/kiro-cli", version: "unknown"}},
			wantDebug: []string{"reporting version unknown (never launched)"},
		},
		{
			name: "trio symlinked from the retained kirocli/bin tree: detected, version unknown",
			setup: func(m *executor.Mock, home string) {
				archive := joinPath(home, "kirocli")
				kiroLinuxTrio(m, joinPath(archive, "bin"))
				link := joinPath(home, ".local", "bin", "kiro-cli")
				addFile(m, link, []byte{})
				m.SetSymlink(link, joinPath(archive, "bin", "kiro-cli"))
			},
			want: []aicliWant{{tool: "amazon-q-cli", binary: "/home/u/.local/bin/kiro-cli", version: "unknown", install: "/home/u/kirocli/bin/kiro-cli"}},
		},
		{
			name: "kiro-cli without its siblings is not a Kiro install",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("kiro-cli", "/usr/local/bin/kiro-cli")
				addFile(m, "/usr/local/bin/kiro-cli", []byte{})
			},
			wantDebug: []string{"no kiro-cli-chat beside it"},
		},
		{
			name: "the IDE's /usr/bin/kiro launcher and a `q` wrapper alone prove nothing",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("kiro", "/usr/bin/kiro")
				addFile(m, "/usr/bin/kiro", []byte{})
				m.SetSymlink("/usr/bin/kiro", "/usr/share/kiro/bin/kiro")
				m.SetPath("q", "/usr/local/bin/q")
				addFile(m, "/usr/local/bin/q", []byte("#!/bin/sh\nexec kiro-cli chat \"$@\"\n"))
			},
			wantDebug: []string{"resolves to /usr/share/kiro/bin/kiro, whose basename is not kiro-cli", "resolves to /usr/local/bin/q, whose basename is not kiro-cli"},
		},
		{
			// kiro-cli is listed first, so the installer trio off PATH is
			// found before either alias is examined.
			name: "the same colliders on PATH do not hide the trio in ~/.local/bin",
			setup: func(m *executor.Mock, home string) {
				m.SetPath("kiro", "/usr/bin/kiro")
				addFile(m, "/usr/bin/kiro", []byte{})
				m.SetSymlink("/usr/bin/kiro", "/usr/share/kiro/bin/kiro")
				m.SetPath("q", "/usr/local/bin/q")
				addFile(m, "/usr/local/bin/q", []byte{})
				kiroLinuxTrio(m, joinPath(home, ".local", "bin"))
			},
			want:     []aicliWant{{tool: "amazon-q-cli", binary: "/home/u/.local/bin/kiro-cli"}},
			noLookup: []string{"q"},
		},
		{
			name: "a sibling that is a symlink is not followed",
			setup: func(m *executor.Mock, home string) {
				dir := joinPath(home, ".local", "bin")
				kiroLinuxTrio(m, dir)
				m.SetSymlink(joinPath(dir, "kiro-cli-chat"), "/home/u/Documents/kiro-cli-chat")
				addFile(m, "/home/u/Documents/kiro-cli-chat", []byte{})
			},
			noReadPrefix:   []string{"/home/u/Documents", "/home/u/.local/bin/kiro-cli-chat"},
			noFollowPrefix: []string{"/home/u/Documents", "/home/u/.local/bin/kiro-cli-chat"},
			wantDebug:      []string{"no kiro-cli-chat beside it"},
		},
		{
			name: "a sibling that is a directory does not count",
			setup: func(m *executor.Mock, home string) {
				dir := joinPath(home, ".local", "bin")
				addFile(m, joinPath(dir, "kiro-cli"), []byte{})
				addFile(m, joinPath(dir, "kiro-cli-chat"), []byte{})
				m.SetFileInfo(joinPath(dir, "kiro-cli-term"), &dirInfo{n: "kiro-cli-term"})
				m.SetPath("kiro-cli", joinPath(dir, "kiro-cli"))
			},
			wantDebug: []string{"no kiro-cli-term beside it"},
		},
	})
}

func TestAICLIAgents_Kiro_Windows(t *testing.T) {
	const defaultInstall = `C:\Users\u\AppData\Local\Kiro-Cli`
	exe := defaultInstall + `\kiro-cli.exe`
	runAICLICases(t, []aicliCase{
		{
			name: "default install: the fixed path is bound to the registry InstallPath",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				kiroRegistry(m, defaultInstall)
				addFile(m, exe, []byte{})
			},
			allowExec: true,
			wantExecs: []aicliExecCall{},
			want:      []aicliWant{{tool: "amazon-q-cli", binary: exe, version: "2.21.1.0", install: exe}},
		},
		{
			name: "PATH hit inside the registered InstallPath, spelled in another case",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				kiroRegistry(m, `c:\users\u\appdata\local\kiro-cli\`)
				m.SetPath("kiro-cli", exe)
				addFile(m, exe, []byte{})
			},
			allowExec: true,
			wantExecs: []aicliExecCall{},
			want:      []aicliWant{{tool: "amazon-q-cli", binary: exe, version: "2.21.1.0"}},
		},
		{
			name: "non-default InstallPath, on no PATH: the key's path joins the candidates",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				kiroRegistry(m, `D:\Tools\KiroCli`)
				addFile(m, `D:\Tools\KiroCli\kiro-cli.exe`, []byte{})
			},
			allowExec: true,
			wantExecs: []aicliExecCall{},
			want:      []aicliWant{{tool: "amazon-q-cli", binary: `D:\Tools\KiroCli\kiro-cli.exe`, version: "2.21.1.0"}},
		},
		{
			name: "a kiro-cli.exe outside the registered InstallPath is rejected",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				kiroRegistry(m, `D:\Tools\KiroCli`)
				m.SetPath("kiro-cli", `C:\stray\kiro-cli.exe`)
				addFile(m, `C:\stray\kiro-cli.exe`, []byte{})
			},
			allowExec: true,
			wantExecs: []aicliExecCall{},
			wantDebug: []string{`not kiro-cli.exe under the registered InstallPath D:\Tools\KiroCli`},
		},
		{
			name: "registry key present but the executable is gone",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				kiroRegistry(m, defaultInstall)
			},
			allowExec: true,
			wantExecs: []aicliExecCall{},
		},
		{
			// With no key nothing can be proven, so no candidate is even looked
			// up — the PATH kiro-cli.exe stays untouched.
			name: "no registry key: no candidate is examined",
			goos: model.PlatformWindows,
			setup: func(m *executor.Mock, home string) {
				m.SetPath("kiro-cli", exe)
				addFile(m, exe, []byte{})
			},
			allowExec: true,
			wantExecs: []aicliExecCall{},
			noLookup:  []string{"kiro"},
			wantDebug: []string{`HKCU\SOFTWARE\Kiro\CLI is absent`},
		},
	})
}

// dirInfo is an os.FileInfo for a directory, for the sibling-is-a-directory case.
type dirInfo struct{ n string }

func (d *dirInfo) Name() string       { return d.n }
func (d *dirInfo) Size() int64        { return 0 }
func (d *dirInfo) Mode() os.FileMode  { return os.ModeDir | 0o755 }
func (d *dirInfo) ModTime() time.Time { return time.Time{} }
func (d *dirInfo) IsDir() bool        { return true }
func (d *dirInfo) Sys() any           { return nil }

// Cases for the grok-build, kimi-code, muse-code, hermes-agent and oh-my-pi
// ladders, on the harness above. Every case
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
			name: "(m2d) a FIFO sidecar is refused before it is read; its zero size must not pass the cap",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				m.SetFileInfo(joinPath(bin, ".muse-version"), pipeFileInfo{name: ".muse-version"})
				addBinary(m, joinPath(bin, "muse-bin-"+museVersion), 90<<20)
			},
			wantDebug: []string{"is not a regular file"},
		},
		{
			name: "(m2e) a sidecar whose resolution fails for a reason other than absence rejects instead of touching the unresolved path",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addMuseInstall(m, bin, museVersion)
				m.SetSymlinkError(joinPath(bin, ".muse-version"), errors.New("too many levels of symbolic links"))
			},
			noReadPrefix: []string{"/home/u/.local/bin/.muse-version"},
			wantDebug:    []string{"could not be safely resolved"},
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
			name: "(m3a) an absent sidecar reported by EvalSymlinks still falls through to the muse-bin-* sibling",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				addBinary(m, joinPath(bin, "muse-bin-"+museVersion), 90<<20)
				m.SetGlob(joinPath(bin, "muse-bin-*"), []string{joinPath(bin, "muse-bin-"+museVersion)})
				m.SetSymlinkError(joinPath(bin, ".muse-version"), fs.ErrNotExist)
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
			name: "(m3r) a single muse-bin-* sibling without a Muse release suffix proves nothing",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				m.SetGlob(joinPath(bin, "muse-bin-*"), []string{joinPath(bin, "muse-bin-readme")})
			},
			allowGlobs: []string{"/home/u/.local/bin/muse-bin-*"},
			wantDebug:  []string{"no Muse Code channel claims it"},
		},
		{
			name: "(m3c) one release payload beside an unversioned sibling accepts with the payload version",
			setup: func(m *executor.Mock, home string) {
				bin := joinPath(home, ".local", "bin")
				addFile(m, joinPath(bin, "muse"), []byte("#!/usr/bin/env bash\n"))
				m.SetGlob(joinPath(bin, "muse-bin-*"), []string{joinPath(bin, "muse-bin-readme"), joinPath(bin, "muse-bin-"+museVersion)})
			},
			allowGlobs: []string{"/home/u/.local/bin/muse-bin-*"},
			want:       []aicliWant{{tool: "muse-code", binary: "/home/u/.local/bin/muse", version: museVersion}},
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
			// The venv path is derived from $HOME, not from a resolved candidate,
			// so a link there is seen with Readlink and never followed.
			name: "(h1l) a venv that is itself a symlink is rejected unread",
			setup: func(m *executor.Mock, home string) {
				addFile(m, joinPath(home, ".local", "bin", "hermes"), []byte("#!/bin/bash\n"))
				venv := joinPath(home, ".hermes", "hermes-agent", "venv")
				m.SetSymlink(venv, joinPath(home, "Documents", "venv"))
				m.SetDir(joinPath(home, "Documents", "venv"))
				setConfigDir(m, home, "~/.hermes")
			},
			noReadPrefix:   []string{"/home/u/Documents", "/home/u/.hermes/hermes-agent/venv"},
			noFollowPrefix: []string{"/home/u/Documents", "/home/u/.hermes/hermes-agent/venv"},
			wantDebug:      []string{"could not be safely resolved"},
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
			name: "(o4r) a non-version directory under the mise root is rejected",
			setup: func(m *executor.Mock, home string) {
				root := joinPath(home, ".local", "share", "mise", "installs", "github-can1357-oh-my-pi")
				dev := joinPath(root, "dev")
				m.SetGlob(joinPath(root, "*"), []string{dev})
				addBinary(m, joinPath(dev, "omp"), ompRealBytes)
			},
			wantDebug: []string{"under the mise install root but not in a version directory"},
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
