package detector

import (
	"context"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestFrameworkDetector_FindsOllama(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("ollama", "/usr/local/bin/ollama")
	mock.SetCommand("0.5.4\n", "", 0, "/usr/local/bin/ollama", "--version")
	mock.SetCommand("12345\n", "", 0, "pgrep", "-x", "ollama")

	det := NewFrameworkDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "ollama" {
			found = true
			if r.Type != "framework" {
				t.Errorf("expected framework, got %s", r.Type)
			}
			if r.IsRunning == nil || !*r.IsRunning {
				t.Error("expected is_running=true")
			}
		}
	}
	if !found {
		t.Error("ollama not found")
	}
}

// TestFrameworkDetector_OllamaVersionWithWarnings asserts that the framework
// detector strips warning lines that ollama prints when its daemon isn't
// running and still surfaces the real version. See bug 0001 F3.
func TestFrameworkDetector_OllamaVersionWithWarnings(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("ollama", "/usr/bin/ollama")
	mock.SetCommand(
		"Warning: could not connect to a running Ollama instance\nWarning: client version is 0.0.0\n",
		"", 0,
		"/usr/bin/ollama", "--version",
	)
	mock.SetCommand("", "", 1, "pgrep", "-x", "ollama") // not running

	det := NewFrameworkDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "ollama" {
			found = true
			if r.Version != "0.0.0" {
				t.Errorf("expected version 0.0.0 (extracted from second 'Warning:' line), got %q", r.Version)
			}
		}
	}
	if !found {
		t.Error("ollama not found")
	}
}

func TestFrameworkDetector_NotRunning(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("ollama", "/usr/local/bin/ollama")
	mock.SetCommand("0.5.4\n", "", 0, "/usr/local/bin/ollama", "--version")
	mock.SetCommand("", "", 1, "pgrep", "-x", "ollama") // not running

	det := NewFrameworkDetector(mock)
	results := det.Detect(context.Background())

	for _, r := range results {
		if r.Name == "ollama" {
			if r.IsRunning == nil || *r.IsRunning {
				t.Error("expected is_running=false")
			}
		}
	}
}

func TestFrameworkDetector_LMStudioApp(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Applications/LM Studio.app")
	mock.SetFile("/Applications/LM Studio.app/Contents/Info.plist", []byte{})
	mock.SetCommand("0.3.1", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", "/Applications/LM Studio.app/Contents/Info.plist")
	mock.SetCommand("", "", 1, "pgrep", "-f", "LM Studio") // not running

	det := NewFrameworkDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "lm-studio" {
			found = true
			if r.Version != "0.3.1" {
				t.Errorf("expected 0.3.1, got %s", r.Version)
			}
		}
	}
	if !found {
		t.Error("lm-studio not found")
	}
}

func TestFrameworkDetector_Windows_FindsOllama(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetPath("ollama", `C:\Program Files\Ollama\ollama.exe`)

	mock.SetCommand("0.5.4\n", "", 0, `C:\Program Files\Ollama\ollama.exe`, "--version")

	// isProcessRunning on Windows: tasklist /FI "IMAGENAME eq ollama.exe" /NH
	mock.SetCommand(
		"ollama.exe                   12345 Console                    1    100,000 K\n",
		"", 0,
		"tasklist", "/FI", "IMAGENAME eq ollama.exe", "/NH",
	)

	// LM Studio app detection on Windows also runs; ensure it doesn't interfere.
	// detectLMStudioApp will try Getenv("LOCALAPPDATA") which is empty, so DirExists will fail.
	// isProcessRunningFuzzy on Windows calls tasklist /NH
	mock.SetCommand("", "", 1, "tasklist", "/NH")

	det := NewFrameworkDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "ollama" {
			found = true
			if r.Type != "framework" {
				t.Errorf("expected framework, got %s", r.Type)
			}
			if r.Version != "0.5.4" {
				t.Errorf("expected 0.5.4, got %s", r.Version)
			}
			if r.IsRunning == nil || !*r.IsRunning {
				t.Error("expected is_running=true")
			}
		}
	}
	if !found {
		t.Error("ollama not found")
	}
}

// noExecMock turns any subprocess into a test failure. On Linux the whole
// lm-studio path (LookPath, version, /proc liveness) is filesystem reads, so
// a single exec is the regression.
type noExecMock struct {
	*executor.Mock
	t *testing.T
}

func (m *noExecMock) Run(_ context.Context, name string, args ...string) (string, string, int, error) {
	m.t.Fatalf("unexpected exec: %s %v", name, args)
	return "", "", -1, nil
}

func (m *noExecMock) RunWithTimeout(ctx context.Context, _ time.Duration, name string, args ...string) (string, string, int, error) {
	return m.Run(ctx, name, args...) //nolint:contextcheck // trap, never reaches a real command
}

// The reported machine: the .deb's launcher on PATH, symlinked into the
// electron-builder install root.
func linuxLMStudioMock(t *testing.T) *noExecMock {
	t.Helper()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHomeDir("/home/dev")
	mock.SetPath("lm-studio", "/usr/bin/lm-studio")
	mock.SetSymlink("/usr/bin/lm-studio", "/opt/LM Studio/lm-studio")
	return &noExecMock{Mock: mock, t: t}
}

func findTool(results []model.AITool, name string) (model.AITool, bool) {
	for _, r := range results {
		if r.Name == name {
			return r, true
		}
	}
	return model.AITool{}, false
}

func TestFrameworkDetector_LMStudioLinuxIsNeverLaunched(t *testing.T) {
	mock := linuxLMStudioMock(t)

	results := NewFrameworkDetector(mock).Detect(context.Background())

	tool, ok := findTool(results, "lm-studio")
	if !ok {
		t.Fatal("suppressing the exec must not suppress the detection")
	}
	if tool.Version != "unknown" {
		t.Errorf("version = %q, want unknown", tool.Version)
	}
	if tool.BinaryPath != "/usr/bin/lm-studio" {
		t.Errorf("binary_path = %q, want /usr/bin/lm-studio", tool.BinaryPath)
	}
}

// Still recoverable without launching anything: dpkg records both the file
// list and the version of the .deb that installed the launcher.
func TestFrameworkDetector_LMStudioLinuxVersionFromDpkg(t *testing.T) {
	mock := linuxLMStudioMock(t)
	mock.SetFile("/var/lib/dpkg/info/lm-studio.list", []byte(
		"/opt\n/opt/LM Studio\n/opt/LM Studio/lm-studio\n/usr/bin/lm-studio\n"))
	mock.SetFile("/var/lib/dpkg/status", []byte(
		"Package: lm-studio\nStatus: install ok installed\nVersion: 0.3.31-1\nArchitecture: amd64\n\n"))

	results := NewFrameworkDetector(mock).Detect(context.Background())

	tool, ok := findTool(results, "lm-studio")
	if !ok {
		t.Fatal("lm-studio not found")
	}
	if tool.Version != "0.3.31" {
		t.Errorf("version = %q, want 0.3.31 (upstream part of 0.3.31-1)", tool.Version)
	}
}

// GUIApp is opt-in per entry: ollama is a real CLI and must still be exec'd.
func TestFrameworkDetector_OllamaStillExecsOnLinux(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHomeDir("/home/dev")
	mock.SetPath("ollama", "/usr/local/bin/ollama")
	mock.SetCommand("ollama version is 0.5.13\n", "", 0, "/usr/local/bin/ollama", "--version")

	results := NewFrameworkDetector(mock).Detect(context.Background())

	tool, ok := findTool(results, "ollama")
	if !ok {
		t.Fatal("ollama not found")
	}
	if tool.Version != "0.5.13" {
		t.Errorf("version = %q, want 0.5.13", tool.Version)
	}
}
