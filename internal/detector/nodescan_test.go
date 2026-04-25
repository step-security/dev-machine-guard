package detector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func newTestScanner(exec *executor.Mock) *NodeScanner {
	log := progress.NewLogger(false)
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
	// forward slashes here so the test works on macOS hosts too.
	mock.SetCommand("C:/Users/dev/AppData/Local/pnpm/global/5/node_modules\n", "", 0, "pnpm", "root", "-g")
	mock.SetCommand(`{"dependencies":{"typescript":{"version":"5.4.0"}}}`, "", 0, "pnpm", "list", "-g", "--json", "--depth=3")

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
		}
	}
	if !pnpmFound {
		t.Fatal("expected pnpm in global scan results on Windows")
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
	result := scanner.scanProject(context.Background(), `C:\Users\dev\myapp`)

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
	result := scanner.scanProject(context.Background(), projectDir)

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

func TestNodeScanner_ScanGlobalPackages_NoneInstalled(t *testing.T) {
	mock := executor.NewMock()
	scanner := newTestScanner(mock)
	results := scanner.ScanGlobalPackages(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 results when no PMs installed, got %d", len(results))
	}
}

func TestNodeScanner_ScanProject_LockfilePath(t *testing.T) {
	// When a package-lock.json with valid content exists, the scanner should
	// parse it directly instead of spawning a subprocess.
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("npm", `C:\Program Files\nodejs\npm.cmd`)
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")

	projectDir := `C:\Users\dev\myapp`
	lockfileContent := `{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "myapp", "version": "1.0.0"},
			"node_modules/express": {"version": "4.18.2"},
			"node_modules/lodash": {"version": "4.17.21", "dev": true}
		}
	}`
	mock.SetFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockfileContent))
	// No subprocess command stubbed for "npm ls" — if it falls through, the test
	// would get empty output, proving lockfile path was used.

	scanner := newTestScanner(mock)
	result := scanner.scanProject(context.Background(), projectDir)

	if result.PackageManager != "npm" {
		t.Errorf("expected npm, got %s", result.PackageManager)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected ExitCode 0, got %d", result.ExitCode)
	}
	if result.Error != "" {
		t.Errorf("expected no error, got %q", result.Error)
	}

	// Decode and verify the lockfile result
	decoded, err := base64.StdEncoding.DecodeString(result.RawStdoutBase64)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("expected non-empty RawStdoutBase64 from lockfile parse")
	}

	var lockResult LockfileResult
	if err := json.Unmarshal(decoded, &lockResult); err != nil {
		t.Fatalf("failed to unmarshal lockfile result: %v", err)
	}
	if lockResult.Source != "lockfile" {
		t.Errorf("expected source 'lockfile', got %q", lockResult.Source)
	}
	if len(lockResult.Packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(lockResult.Packages))
	}
}

func TestNodeScanner_ScanProject_FallsBackToSubprocess(t *testing.T) {
	// When no lockfile exists, should fall back to running npm ls subprocess.
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("npm", `C:\Program Files\nodejs\npm.cmd`)
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")
	// package-lock.json exists but is empty / not set — lockfile parse fails.
	// Subprocess command is stubbed:
	mock.SetCommand(`{"dependencies":{"lodash":{"version":"4.17.21"}}}`, "", 0,
		"npm", "ls", "--json", "--depth=3")

	scanner := newTestScanner(mock)
	result := scanner.scanProject(context.Background(), `C:\Users\dev\myapp`)

	if result.PackageManager != "npm" {
		t.Errorf("expected npm, got %s", result.PackageManager)
	}
	if result.PMVersion != "10.2.0" {
		t.Errorf("expected PMVersion 10.2.0, got %s", result.PMVersion)
	}

	// Should contain the subprocess output
	decoded, _ := base64.StdEncoding.DecodeString(result.RawStdoutBase64)
	if len(decoded) == 0 {
		t.Error("expected non-empty RawStdoutBase64 from subprocess fallback")
	}
}

func TestNodeScanner_VersionCaching(t *testing.T) {
	// Verify that getVersionOrFetch caches and reuses values.
	mock := executor.NewMock()
	mock.SetPath("npm", "/usr/local/bin/npm")
	mock.SetCommand("10.2.0\n", "", 0, "npm", "--version")

	scanner := newTestScanner(mock)
	ctx := context.Background()

	v1 := scanner.getVersionOrFetch(ctx, "npm")
	if v1 != "10.2.0" {
		t.Errorf("first call: expected 10.2.0, got %s", v1)
	}

	// Change the mock to return a different version — but cache should prevent re-fetch
	mock.SetCommand("99.0.0\n", "", 0, "npm", "--version")
	v2 := scanner.getVersionOrFetch(ctx, "npm")
	if v2 != "10.2.0" {
		t.Errorf("cached call: expected 10.2.0 (cached), got %s", v2)
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
