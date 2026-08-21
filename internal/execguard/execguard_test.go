package execguard

import (
	"context"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const (
	binary   = "/usr/local/bin/cursor-agent"
	resolved = "/opt/homebrew/Caskroom/cursor-cli/2026.03.11/cursor-agent"
)

// quarantineStub marks path as carrying com.apple.quarantine.
func quarantineStub(mock *executor.Mock, path string) {
	mock.SetCommand("0083;65a1b2c3;Safari;", "", 0, "/usr/bin/xattr", "-p", "com.apple.quarantine", path)
}

func TestSafeToExec(t *testing.T) {
	spctlArgs := []string{"--assess", "--type", "execute", resolved}

	t.Run("not quarantined is safe", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		// xattr unstubbed -> errors -> attribute absent.
		if !SafeToExec(context.Background(), mock, binary) {
			t.Error("unquarantined binary should be safe to exec")
		}
	})

	t.Run("quarantined and rejected is unsafe", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		quarantineStub(mock, resolved)
		mock.SetCommand("", "rejected", 3, "/usr/sbin/spctl", spctlArgs...)
		if SafeToExec(context.Background(), mock, binary) {
			t.Error("quarantined + Gatekeeper-rejected binary must not be exec'd")
		}
	})

	t.Run("quarantined but accepted is safe", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		quarantineStub(mock, resolved)
		mock.SetCommand("accepted", "", 0, "/usr/sbin/spctl", spctlArgs...)
		if !SafeToExec(context.Background(), mock, binary) {
			t.Error("quarantined but notarized (spctl-accepted) binary should be safe")
		}
	})

	t.Run("quarantined parent dir triggers assessment", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		// Binary itself clean (partially-cleared install), containing dir quarantined.
		quarantineStub(mock, "/opt/homebrew/Caskroom/cursor-cli/2026.03.11")
		mock.SetCommand("", "rejected", 3, "/usr/sbin/spctl", spctlArgs...)
		if SafeToExec(context.Background(), mock, binary) {
			t.Error("quarantined install dir must trigger assessment and reject")
		}
	})

	t.Run("spctl failure is conservatively unsafe", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetSymlink(binary, resolved)
		quarantineStub(mock, resolved)
		// spctl unstubbed -> errors -> treat as rejected.
		if SafeToExec(context.Background(), mock, binary) {
			t.Error("quarantined binary with failing spctl must not be exec'd")
		}
	})

	t.Run("non-darwin is always safe", func(t *testing.T) {
		for _, goos := range []string{"linux", "windows"} {
			mock := executor.NewMock()
			mock.SetGOOS(goos)
			quarantineStub(mock, binary)
			if !SafeToExec(context.Background(), mock, binary) {
				t.Errorf("GOOS=%s: quarantine is a macOS concept; must be safe", goos)
			}
		}
	})

	t.Run("empty path is safe", func(t *testing.T) {
		if !SafeToExec(context.Background(), executor.NewMock(), "") {
			t.Error("empty path should be a no-op (safe)")
		}
	})
}

// Linux: Electron app entry points. The distinction that matters is app-root
// vs. CLI-shim, and it is visible on disk — the shim lives one directory down,
// beside none of the bundle files.
func linuxMock(files ...string) *executor.Mock {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	for _, f := range files {
		mock.SetFile(f, []byte{})
	}
	return mock
}

func TestSafeToExec_Linux(t *testing.T) {
	tests := []struct {
		name    string
		binary  string
		symlink string // resolved target, "" for none
		files   []string
		want    bool
	}{
		{
			name:    "LM Studio's .deb launcher is refused",
			binary:  "/usr/bin/lm-studio",
			symlink: "/opt/LM Studio/lm-studio",
			files:   []string{"/opt/LM Studio/resources/app.asar", "/opt/LM Studio/libffmpeg.so"},
			want:    false,
		},
		{
			// The case the guard must not break.
			name:   "a VS Code fork's CLI shim is allowed",
			binary: "/usr/share/code/bin/code",
			files:  []string{"/usr/share/code/resources/app.asar", "/usr/share/code/libffmpeg.so"},
			want:   true,
		},
		{
			name:   "the same fork's GUI binary is refused",
			binary: "/usr/share/code/code",
			files:  []string{"/usr/share/code/resources/app.asar", "/usr/share/code/libffmpeg.so"},
			want:   false,
		},
		{
			name:   "Chromium runtime data alone is enough to identify a bundle",
			binary: "/opt/Some App/some-app",
			files:  []string{"/opt/Some App/icudtl.dat"},
			want:   false,
		},
		{
			name:   "an ordinary CLI in /usr/bin is allowed",
			binary: "/usr/bin/ollama",
			want:   true,
		},
		{
			name:   "a CLI beside other CLIs is allowed",
			binary: "/usr/local/bin/ollama",
			files:  []string{"/usr/local/bin/lm-studio", "/usr/local/bin/code"},
			want:   true,
		},
		{
			name:   "a bare binary name with no directory is allowed",
			binary: "ollama",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := linuxMock(tt.files...)
			if tt.symlink != "" {
				mock.SetSymlink(tt.binary, tt.symlink)
			}
			if got := SafeToExec(context.Background(), mock, tt.binary); got != tt.want {
				t.Errorf("SafeToExec(%q) = %v, want %v", tt.binary, got, tt.want)
			}
		})
	}
}

// The Linux arm must reach for no subprocess at all.
func TestSafeToExec_LinuxLaunchesNothing(t *testing.T) {
	mock := linuxMock("/opt/LM Studio/resources/app.asar")
	mock.SetSymlink("/usr/bin/lm-studio", "/opt/LM Studio/lm-studio")
	trap := &trapExecutor{Mock: mock, t: t}

	if SafeToExec(context.Background(), trap, "/usr/bin/lm-studio") {
		t.Error("Electron app entry point must be refused")
	}
}

type trapExecutor struct {
	*executor.Mock
	t *testing.T
}

func (e *trapExecutor) Run(_ context.Context, name string, args ...string) (string, string, int, error) {
	e.t.Fatalf("unexpected exec: %s %v", name, args)
	return "", "", -1, nil
}

func (e *trapExecutor) RunWithTimeout(ctx context.Context, _ time.Duration, name string, args ...string) (string, string, int, error) {
	return e.Run(ctx, name, args...)
}

// Windows is unchanged.
func TestSafeToExec_WindowsAlwaysSafe(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetFile(`C:\Program Files\LM Studio\resources\app.asar`, []byte{})
	if !SafeToExec(context.Background(), mock, `C:\Program Files\LM Studio\LM Studio.exe`) {
		t.Error("Windows must be unaffected")
	}
}
