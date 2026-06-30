package detector

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func newTestScanner(exec *executor.Mock) *NodeScanner {
	log := progress.NewLogger(progress.LevelInfo)
	return NewNodeScanner(exec, log, "")
}

func TestNodeScanner_ScanNPMGlobal(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("npm", "/usr/local/bin/npm")
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")
	mock.SetCommand("/usr/local\n", "", 0, "npm", "config", "get", "prefix")
	mock.SetCommand(`{"dependencies":{"express":{"version":"4.18.2"}}}`, "", 0, "npm", "list", "-g", "--json", "--depth=3")

	scanner := newTestScanner(mock)
	results := scanner.ScanGlobalPackages(context.Background())

	npmFound := false
	for _, r := range results {
		if r.PackageManager == "npm" {
			npmFound = true
			if r.ProjectPath != "/usr/local" {
				t.Errorf("expected ProjectPath /usr/local, got %s", r.ProjectPath)
			}
			if r.PMVersion != "10.2.0" {
				t.Errorf("expected PMVersion 10.2.0, got %s", r.PMVersion)
			}
			if r.ExitCode != 0 {
				t.Errorf("expected ExitCode 0, got %d", r.ExitCode)
			}
			decoded, _ := base64.StdEncoding.DecodeString(r.RawStdoutBase64)
			if len(decoded) == 0 {
				t.Error("expected non-empty RawStdoutBase64")
			}
		}
	}
	if !npmFound {
		t.Fatal("expected npm in global scan results")
	}
}

func TestNodeScanner_ScanNPMGlobal_Windows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("npm", `C:\Program Files\nodejs\npm.cmd`)
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")
	// npm config get prefix returns a Windows-style path on real Windows.
	// The code stores it directly (no filepath.* processing), so the mock
	// value flows through unchanged.
	mock.SetCommand(`C:\Users\dev\AppData\Roaming\npm`+"\n", "", 0, "npm", "config", "get", "prefix")
	mock.SetCommand(`{"dependencies":{"express":{"version":"4.18.2"}}}`, "", 0, "npm", "list", "-g", "--json", "--depth=3")

	scanner := newTestScanner(mock)
	results := scanner.ScanGlobalPackages(context.Background())

	npmFound := false
	for _, r := range results {
		if r.PackageManager == "npm" {
			npmFound = true
			if r.ProjectPath != `C:\Users\dev\AppData\Roaming\npm` {
				t.Errorf("expected Windows npm prefix, got %s", r.ProjectPath)
			}
			if r.PMVersion != "10.2.0" {
				t.Errorf("expected PMVersion 10.2.0, got %s", r.PMVersion)
			}
			if r.ExitCode != 0 {
				t.Errorf("expected ExitCode 0, got %d", r.ExitCode)
			}
		}
	}
	if !npmFound {
		t.Fatal("expected npm in global scan results on Windows")
	}
}

func TestNodeScanner_ScanYarnGlobal_Windows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("yarn", `C:\Program Files\nodejs\yarn.cmd`)
	mock.SetCommand("1.22.19\n", "", 0, "yarn", "--version")
	mock.SetCommand(`C:\Users\dev\AppData\Local\Yarn\Data\global`+"\n", "", 0, "yarn", "global", "dir")
	// RunInDir calls Run(name, args...) directly — no shell cd needed
	mock.SetCommand(`{"type":"tree","data":{"trees":[]}}`, "", 0,
		"yarn", "list", "--json", "--depth=0")

	scanner := newTestScanner(mock)
	results := scanner.ScanGlobalPackages(context.Background())

	yarnFound := false
	for _, r := range results {
		if r.PackageManager == "yarn" {
			yarnFound = true
			if r.ProjectPath != `C:\Users\dev\AppData\Local\Yarn\Data\global` {
				t.Errorf("expected Windows yarn global dir, got %s", r.ProjectPath)
			}
			if r.PMVersion != "1.22.19" {
				t.Errorf("expected PMVersion 1.22.19, got %s", r.PMVersion)
			}
		}
	}
	if !yarnFound {
		t.Fatal("expected yarn in global scan results on Windows")
	}
}

func TestNodeScanner_ScanPnpmGlobal_Windows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("pnpm", `C:\Users\dev\AppData\Local\pnpm\pnpm.cmd`)
	mock.SetCommand("9.1.0\n", "", 0, "pnpm", "--version")
	// pnpm root -g returns the global node_modules dir. The code calls
	// filepath.Dir on it. Since filepath.Dir is host-OS dependent, we use
	// forward slashes here so the test works on macOS hosts too. First
	// attempt succeeds so the PATH workaround is skipped on this path.
	mock.SetCommand("C:/Users/dev/AppData/Local/pnpm/global/5/node_modules\n", "", 0, "pnpm", "root", "-g")
	// Production tries `--depth=3` first (v10 transitive), falls back to no --depth
	// on non-zero exit (v11 path). Stub both legs so the fallback is verified.
	mock.SetCommand("", "ERR_PNPM_GLOBAL_LS_DEPTH_NOT_SUPPORTED", 1, "pnpm", "list", "-g", "--json", "--depth=3")
	mock.SetCommand(`{"dependencies":{"typescript":{"version":"5.4.0"}}}`, "", 0, "pnpm", "list", "-g", "--json")

	scanner := newTestScanner(mock)
	results := scanner.ScanGlobalPackages(context.Background())

	pnpmFound := false
	for _, r := range results {
		if r.PackageManager == "pnpm" {
			pnpmFound = true
			// filepath.Dir strips the last component (node_modules)
			expected := "C:/Users/dev/AppData/Local/pnpm/global/5"
			if r.ProjectPath != expected {
				t.Errorf("expected ProjectPath %s, got %s", expected, r.ProjectPath)
			}
			if r.PMVersion != "9.1.0" {
				t.Errorf("expected PMVersion 9.1.0, got %s", r.PMVersion)
			}
			if r.ExitCode != 0 {
				t.Errorf("expected ExitCode 0 (mock stub matched), got %d — check that production args still match the SetCommand stub", r.ExitCode)
			}
		}
	}
	if !pnpmFound {
		t.Fatal("expected pnpm in global scan results on Windows")
	}
}

// TestNodeScanner_ScanPnpmGlobal_Delegated exercises the root → user delegation
// path (macOS-as-root or Linux-as-root with a logged-in user). Verifies the
// lazy-fallback flow:
//   - `pnpm --version` runs plainly (doesn't need bin dir on PATH).
//   - First `pnpm root -g` runs plainly; on failure the scanner applies the
//     inline `PATH='…':$PATH pnpm` workaround and retries.
//   - `pnpm list -g` then uses the same prefixed pnpmCmd, so it survives sudo's
//     env policy (Linux `secure_path` or hardened macOS sudoers).
func TestNodeScanner_ScanPnpmGlobal_Delegated(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetIsRoot(true)
	mock.SetEnv("HOME", "/Users/testuser")

	// checkPath in delegation mode runs `which pnpm` through RunAsUser, which
	// the Mock dispatches as `bash -c "<cmd>"`.
	mock.SetCommand("/opt/homebrew/bin/pnpm\n", "", 0, "bash", "-c", "which pnpm")

	// `pnpm --version` is called plainly (no prefix) — it doesn't need the
	// bin dir on PATH.
	mock.SetCommand("11.1.2\n", "", 0, "bash", "-c", "pnpm --version")

	// First `pnpm root -g` attempt runs plainly; v11 errors when bin dir not on PATH.
	mock.SetCommand("", "ERR_PNPM_GLOBAL_LS_DEPTH_NOT_SUPPORTED", 1, "bash", "-c", "pnpm root -g")

	// Production then applies the workaround and retries with the inline PATH= prefix.
	prefix := `PATH='/Users/testuser/Library/pnpm/bin':$PATH pnpm`
	mock.SetCommand("/Users/testuser/Library/pnpm/global/v11/node_modules\n", "", 0, "bash", "-c", prefix+" root -g")

	// `pnpm list -g` tries with --depth=3 first; v11 path errors → fall back to no --depth.
	mock.SetCommand("", "ERR_PNPM_GLOBAL_LS_DEPTH_NOT_SUPPORTED", 1, "bash", "-c", prefix+" list -g --json --depth=3")
	mock.SetCommand(`{"dependencies":{"typescript":{"version":"5.4.0"}}}`, "", 0, "bash", "-c", prefix+" list -g --json")

	log := progress.NewLogger(progress.LevelInfo)
	scanner := NewNodeScanner(mock, log, "testuser")

	results := scanner.ScanGlobalPackages(context.Background())

	var pnpm *model.NodeScanResult
	for i, r := range results {
		if r.PackageManager == "pnpm" {
			pnpm = &results[i]
			break
		}
	}
	if pnpm == nil {
		t.Fatal("expected pnpm in delegated scan results")
	}
	if pnpm.PMVersion != "11.1.2" {
		t.Errorf("PMVersion = %q, want 11.1.2 — `pnpm --version` should run plainly without PATH prefix", pnpm.PMVersion)
	}
	if pnpm.ProjectPath != "/Users/testuser/Library/pnpm/global/v11" {
		t.Errorf("ProjectPath = %q, want /Users/testuser/Library/pnpm/global/v11 — PATH= prefix likely missing from `pnpm root -g` retry", pnpm.ProjectPath)
	}
	if pnpm.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 — PATH= prefix likely missing from `pnpm list -g` invocation", pnpm.ExitCode)
	}
}

// TestNodeScanner_ScanPnpmGlobal_RootGFallback verifies that when BOTH
// `pnpm root -g` attempts fail (plain + with PATH workaround), the scan does
// not bail out — it falls back to the platform-default bin dir
// (defaultPnpmBinDir) as ProjectPath so the result is still produced.
func TestNodeScanner_ScanPnpmGlobal_RootGFallback(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetHomeDir("/Users/foo")
	mock.SetPath("pnpm", "/opt/homebrew/bin/pnpm")
	mock.SetCommand("11.1.2\n", "", 0, "pnpm", "--version")
	// pnpm root -g errors on every attempt — both the plain first call AND
	// the retry use the same plain `pnpm root -g` command, because
	// shouldRunAsUser is false on this in-process path (IsRoot not set).
	mock.SetCommand("", "ERR_PNPM_GLOBAL_LS_DEPTH_NOT_SUPPORTED", 1, "pnpm", "root", "-g")
	mock.SetCommand("", "ERR_PNPM_GLOBAL_LS_DEPTH_NOT_SUPPORTED", 1, "pnpm", "list", "-g", "--json", "--depth=3")
	mock.SetCommand(`{"dependencies":{"jest":{"version":"30.4.2"}}}`, "", 0, "pnpm", "list", "-g", "--json")

	scanner := newTestScanner(mock)
	results := scanner.ScanGlobalPackages(context.Background())

	var pnpm *model.NodeScanResult
	for i, r := range results {
		if r.PackageManager == "pnpm" {
			pnpm = &results[i]
			break
		}
	}
	if pnpm == nil {
		t.Fatal("expected pnpm in results — fallback should have prevented an early return")
	}
	// ProjectPath falls back to defaultPnpmBinDir on darwin = $HOME/Library/pnpm/bin.
	if pnpm.ProjectPath != "/Users/foo/Library/pnpm/bin" {
		t.Errorf("ProjectPath = %q, want /Users/foo/Library/pnpm/bin (defaultPnpmBinDir fallback)", pnpm.ProjectPath)
	}
	if pnpm.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 — `pnpm list -g` should have succeeded via the no-depth fallback", pnpm.ExitCode)
	}
}

// TestDefaultPnpmBinDir pins pnpm's per-platform global bin-dir layout.
// pnpm v11 places global shims under a /bin subdirectory on macOS, Linux,
// and Windows alike. This matches pnpm's own `pnpm setup` output: the error
// it emits names "<PNPM_HOME>/bin" as the dir that must be on PATH.
func TestDefaultPnpmBinDir(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		homeDir string            // drives getHomeDir via the mock's CurrentUser
		envs    map[string]string // LOCALAPPDATA on Windows
		want    string
	}{
		{
			name:    "darwin → bin subdir under home",
			goos:    "darwin",
			homeDir: "/Users/foo",
			want:    "/Users/foo/Library/pnpm/bin",
		},
		{
			name:    "linux → bin subdir under home",
			goos:    "linux",
			homeDir: "/home/foo",
			want:    "/home/foo/.local/share/pnpm/bin",
		},
		{
			name: "windows with LOCALAPPDATA → bin subdir",
			goos: "windows",
			envs: map[string]string{"LOCALAPPDATA": `C:\Users\foo\AppData\Local`},
			want: filepath.Join(`C:\Users\foo\AppData\Local`, "pnpm", "bin"),
		},
		{
			name: "windows without LOCALAPPDATA → empty",
			goos: "windows",
			envs: map[string]string{},
			want: "",
		},
		{
			name:    "unrecognized OS → empty",
			goos:    "freebsd",
			homeDir: "/home/foo",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS(tt.goos)
			if tt.homeDir != "" {
				mock.SetHomeDir(tt.homeDir)
			}
			for k, v := range tt.envs {
				mock.SetEnv(k, v)
			}
			got := defaultPnpmBinDir(mock)
			if got != tt.want {
				t.Errorf("defaultPnpmBinDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNodeScanner_ScanProject_Windows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("npm", `C:\Program Files\nodejs\npm.cmd`)
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")
	// DetectProjectPM uses filepath.Join which is host-dependent;
	// construct the mock file path the same way the code will.
	mock.SetFile(filepath.Join(`C:\Users\dev\myapp`, "package-lock.json"), []byte{})
	// RunInDir calls Run(name, args...) directly — no shell cd needed
	mock.SetCommand(`{"dependencies":{"lodash":{"version":"4.17.21"}}}`, "", 0,
		"npm", "ls", "--json", "--depth=3")

	scanner := newTestScanner(mock)
	result, ok := scanner.scanProject(context.Background(), `C:\Users\dev\myapp`, "npm")

	if !ok {
		t.Fatal("expected scanProject to emit a result when npm is available")
	}
	if result.PackageManager != "npm" {
		t.Errorf("expected npm, got %s", result.PackageManager)
	}
	if result.ProjectPath != `C:\Users\dev\myapp` {
		t.Errorf("expected project path C:\\Users\\dev\\myapp, got %s", result.ProjectPath)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected ExitCode 0, got %d", result.ExitCode)
	}
	if result.PMVersion != "10.2.0" {
		t.Errorf("expected PMVersion 10.2.0, got %s", result.PMVersion)
	}
	decoded, _ := base64.StdEncoding.DecodeString(result.RawStdoutBase64)
	if len(decoded) == 0 {
		t.Error("expected non-empty RawStdoutBase64")
	}
}

func TestNodeScanner_ScanProject_YarnBerry_Windows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("yarn", `C:\Program Files\nodejs\yarn.cmd`)
	mock.SetCommand("4.1.0\n", "", 0, "yarn", "--version")
	// Use filepath.Join to construct mock file paths matching the code's behavior.
	projectDir := `C:\Users\dev\myapp`
	mock.SetFile(filepath.Join(projectDir, "yarn.lock"), []byte{})
	mock.SetFile(filepath.Join(projectDir, ".yarnrc.yml"), []byte{})
	// RunInDir calls Run(name, args...) directly — no shell cd needed
	mock.SetCommand(`{"name":"myapp","children":[]}`, "", 0,
		"yarn", "info", "--all", "--json")

	scanner := newTestScanner(mock)
	result, ok := scanner.scanProject(context.Background(), projectDir, "yarn-berry")

	if !ok {
		t.Fatal("expected scanProject to emit a result when yarn is available")
	}
	if result.PackageManager != "yarn-berry" {
		t.Errorf("expected yarn-berry, got %s", result.PackageManager)
	}
	if result.PMVersion != "4.1.0" {
		t.Errorf("expected PMVersion 4.1.0, got %s", result.PMVersion)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected ExitCode 0, got %d", result.ExitCode)
	}
}

// TestNodeScanner_ScanProject_PMNotInPATH covers the empty-payload
// regression: a package-lock.json project on a Windows device where
// Node.js isn't deployed (npm absent from PATH). Previously this path
// discarded the exec.CommandContext ENOENT and shipped a NodeScanResult
// with empty RawStdoutBase64 — indistinguishable on the backend from a
// successful scan of an empty project. The fix drops the record entirely:
// "PM not installed" is a normal configuration state, not an error to
// report.
func TestNodeScanner_ScanProject_PMNotInPATH(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	// Note: deliberately do NOT call mock.SetPath("npm", ...) — that's the
	// condition we're regression-testing.
	projectDir := `C:\Users\dev\myapp`
	mock.SetFile(filepath.Join(projectDir, "package-lock.json"), []byte{})

	scanner := newTestScanner(mock)
	_, ok := scanner.scanProject(context.Background(), projectDir, "npm")

	if ok {
		t.Error("expected scanProject to return ok=false when PM not on PATH (so no record is emitted)")
	}
}

// TestNodeScanner_ScanProjects_DropsRecordsForMissingPM exercises the
// loop-level contract end-to-end: a device with multiple package.json
// files but no installed PM should produce zero records, not zero-result
// records. Mirrors the field-observed scenario the empty-payload fix
// addresses.
func TestNodeScanner_ScanProjects_DropsRecordsForMissingPM(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	// Two real package.json files, no npm on PATH.
	dirA := `C:\Users\dev\a`
	dirB := `C:\Users\dev\b`
	mock.SetFile(filepath.Join(dirA, "package.json"), []byte("{}"))
	mock.SetFile(filepath.Join(dirA, "package-lock.json"), []byte{})
	mock.SetFile(filepath.Join(dirB, "package.json"), []byte("{}"))
	mock.SetFile(filepath.Join(dirB, "package-lock.json"), []byte{})

	scanner := newTestScanner(mock)
	results, _ := scanner.ScanProjects(context.Background(), []string{`C:\Users\dev`}, nil)

	if len(results) != 0 {
		t.Errorf("expected 0 telemetry records when PM not installed, got %d", len(results))
	}
}

// TestNodeScanner_ScanProject_BinaryAvailabilityCached verifies the
// pmAvailability cache: two scanProject calls for the same PM should
// trigger exactly one PATH lookup. Important on devices with hundreds
// of lockfiles — without caching we'd pay a LookPath per project.
func TestNodeScanner_ScanProject_BinaryAvailabilityCached(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	dirA := `C:\Users\dev\a`
	dirB := `C:\Users\dev\b`
	mock.SetFile(filepath.Join(dirA, "package-lock.json"), []byte{})
	mock.SetFile(filepath.Join(dirB, "package-lock.json"), []byte{})

	scanner := newTestScanner(mock)
	_, firstOK := scanner.scanProject(context.Background(), dirA, "npm")
	_, secondOK := scanner.scanProject(context.Background(), dirB, "npm")

	if firstOK || secondOK {
		t.Errorf("expected both scanProject calls to return ok=false, got firstOK=%v secondOK=%v",
			firstOK, secondOK)
	}
	if got, want := len(scanner.pmAvailability), 1; got != want {
		t.Errorf("expected exactly %d cached PM lookup after two scans of same PM, got %d", want, got)
	}
	if _, ok := scanner.pmAvailability["npm"]; !ok {
		t.Error("expected pmAvailability to contain entry for npm")
	}
}

// TestNodeScanner_ShouldRunAsUser pins the delegation decision. The fix dropped
// the old IsRoot() requirement: whenever there's a logged-in user on a non-
// Windows host, package-manager commands run through that user's login shell —
// in BOTH deployment modes. The non-root row is the LaunchAgent regression:
// launchd runs the agent as the user with a stripped PATH, and before the fix
// shouldRunAsUser was false there, so npm/yarn/pnpm fell through to a bare exec
// and weren't found (exit -1, empty output, version "unknown").
func TestNodeScanner_ShouldRunAsUser(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		isRoot       bool
		loggedInUser string
		want         bool
	}{
		{"non-root macOS with user (LaunchAgent regression)", "darwin", false, "alice", true},
		{"root macOS with user (LaunchDaemon)", "darwin", true, "alice", true},
		{"non-root linux with user", "linux", false, "alice", true},
		{"no logged-in user", "darwin", false, "", false},
		{"windows excluded", "windows", false, "alice", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS(tc.goos)
			mock.SetIsRoot(tc.isRoot)
			scanner := NewNodeScanner(mock, progress.NewLogger(progress.LevelInfo), tc.loggedInUser)
			if got := scanner.shouldRunAsUser(); got != tc.want {
				t.Errorf("shouldRunAsUser() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNodeScanner_ScanProject_Delegated_NonRoot is the core LaunchAgent
// regression: the agent runs as the console user (NOT root) under launchd's
// stripped PATH. The scanner must still route npm through the user's login
// shell — the Mock dispatches RunAsUser as `bash -c "<cmd>"` — so an
// nvm/fnm/homebrew npm is resolved. checkPath (`which npm`), getVersion
// (`npm --version`) and the scan itself (a cd + single-quoted argv built by
// platformShellQuote) all flow through that path.
func TestNodeScanner_ScanProject_Delegated_NonRoot(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	// Deliberately NOT root — this is the LaunchAgent-as-user deployment that
	// previously skipped delegation.
	projectDir := "/Users/testuser/myapp"

	mock.SetCommand("/Users/testuser/.nvm/versions/node/v20.11.0/bin/npm\n", "", 0, "bash", "-c", "which npm")
	mock.SetCommand("10.9.0\n", "", 0, "bash", "-c", "npm --version")
	scanCmd := "cd '/Users/testuser/myapp' && 'npm' 'ls' '--json' '--depth=3'"
	mock.SetCommand(`{"dependencies":{"lodash":{"version":"4.17.21"}}}`, "", 0, "bash", "-c", scanCmd)

	scanner := NewNodeScanner(mock, progress.NewLogger(progress.LevelInfo), "testuser")
	if !scanner.shouldRunAsUser() {
		t.Fatal("shouldRunAsUser must be true for a non-root macOS scan with a logged-in user")
	}

	result, ok := scanner.scanProject(context.Background(), projectDir, "npm")
	if !ok {
		t.Fatal("expected scanProject to emit a result (npm resolved via the user's login shell)")
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 — the scan should have run through `bash -c`, not a bare exec", result.ExitCode)
	}
	if result.PMVersion != "10.9.0" {
		t.Errorf("PMVersion = %q, want 10.9.0", result.PMVersion)
	}
	decoded, _ := base64.StdEncoding.DecodeString(result.RawStdoutBase64)
	if len(decoded) == 0 {
		t.Error("expected non-empty RawStdoutBase64 from the delegated scan")
	}
	if result.Error != "" {
		t.Errorf("Error = %q, want empty on a successful scan", result.Error)
	}
}

// TestNodeScanner_ScanProject_Delegated_SurfacesError verifies a delegated
// failure is captured in the telemetry Error field (and log.Warn'd) rather than
// reduced to an opaque exit code. When npm IS resolvable but the run itself
// fails, RunAsUser returns an error carrying the shell's reason; scanProject
// must fold that into result.Error so the next occurrence is self-explanatory.
func TestNodeScanner_ScanProject_Delegated_SurfacesError(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	projectDir := "/Users/testuser/broken"

	mock.SetCommand("/opt/homebrew/bin/npm\n", "", 0, "bash", "-c", "which npm")
	mock.SetCommand("10.9.0\n", "", 0, "bash", "-c", "npm --version")
	scanCmd := "cd '/Users/testuser/broken' && 'npm' 'ls' '--json' '--depth=3'"
	// SetCommandError mirrors what executor.RunAsUser returns when the user
	// shell exits non-zero — now with the stderr folded into the message.
	mock.SetCommandError(
		fmt.Errorf("command exited with code 127: zsh: command not found: npm"),
		"bash", "-c", scanCmd,
	)

	scanner := NewNodeScanner(mock, progress.NewLogger(progress.LevelInfo), "testuser")
	result, ok := scanner.scanProject(context.Background(), projectDir, "npm")
	if !ok {
		t.Fatal("expected scanProject to still emit a record when the PM is present but the run fails")
	}
	if result.Error == "" {
		t.Fatal("expected a non-empty Error capturing the failure reason (was the runErr discarded?)")
	}
	if !strings.Contains(result.Error, "command not found") {
		t.Errorf("Error = %q, want it to carry the underlying shell reason", result.Error)
	}
}

func TestNodeScanner_ScanGlobalPackages_NoneInstalled(t *testing.T) {
	mock := executor.NewMock()
	scanner := newTestScanner(mock)
	results := scanner.ScanGlobalPackages(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 results when no PMs installed, got %d", len(results))
	}
}

func TestIsInsideNodeModules(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Unix-style paths
		{"/Users/dev/node_modules/foo", true},
		{"/Users/dev/myapp", false},
		{"/Users/dev/node_modules_backup/foo", false},
		{"/node_modules/", true},
		// Windows-style paths (backslashes)
		{`C:\Users\dev\node_modules\foo`, true},
		{`C:\Users\dev\myapp`, false},
		{`C:\node_modules\pkg`, true},
		{`\node_modules\`, true},
		// Edge cases
		{"node_modules", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isInsideNodeModules(tt.path)
			if got != tt.want {
				t.Errorf("isInsideNodeModules(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
