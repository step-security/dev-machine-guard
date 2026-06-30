package detector

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestPMBinaryCandidateDirs(t *testing.T) {
	t.Run("darwin", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("darwin")
		mock.SetHomeDir("/Users/foo")
		got := pmBinaryCandidateDirs(mock)
		want := []string{
			"/opt/homebrew/bin",
			"/usr/local/bin",
			filepath.Join("/Users/foo", ".bun", "bin"),
			filepath.Join("/Users/foo", "Library", "pnpm"),
			filepath.Join("/Users/foo", "Library", "pnpm", "bin"),
			filepath.Join("/Users/foo", ".npm-global", "bin"),
			filepath.Join("/Users/foo", ".volta", "bin"),
			filepath.Join("/Users/foo", ".asdf", "shims"),
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("darwin dirs mismatch:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("linux", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("linux")
		mock.SetHomeDir("/home/foo")
		got := pmBinaryCandidateDirs(mock)
		want := []string{
			"/usr/bin",
			"/usr/local/bin",
			"/home/linuxbrew/.linuxbrew/bin",
			filepath.Join("/home/foo", ".linuxbrew", "bin"),
			filepath.Join("/home/foo", ".bun", "bin"),
			filepath.Join("/home/foo", ".local", "share", "pnpm"),
			filepath.Join("/home/foo", ".npm-global", "bin"),
			filepath.Join("/home/foo", ".volta", "bin"),
			filepath.Join("/home/foo", ".asdf", "shims"),
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("linux dirs mismatch:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("windows", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("windows")
		mock.SetHomeDir(`C:\Users\foo`)
		mock.SetEnv("APPDATA", `C:\Users\foo\AppData\Roaming`)
		mock.SetEnv("LOCALAPPDATA", `C:\Users\foo\AppData\Local`)
		mock.SetEnv("ProgramFiles", `C:\Program Files`)
		got := pmBinaryCandidateDirs(mock)
		want := []string{
			filepath.Join(`C:\Users\foo\AppData\Roaming`, "npm"),
			filepath.Join(`C:\Users\foo\AppData\Local`, "pnpm"),
			filepath.Join(`C:\Users\foo\AppData\Local`, "Volta", "bin"),
			filepath.Join(`C:\Users\foo`, ".bun", "bin"),
			filepath.Join(`C:\Program Files`, "nodejs"),
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("windows dirs mismatch:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("darwin appends nvm dirs newest-first", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("darwin")
		mock.SetHomeDir("/Users/foo")
		pattern := filepath.Join("/Users/foo", ".nvm", "versions", "node", "*", "bin")
		v18 := filepath.Join("/Users/foo", ".nvm", "versions", "node", "v18.20.0", "bin")
		v20 := filepath.Join("/Users/foo", ".nvm", "versions", "node", "v20.11.0", "bin")
		// Provide unsorted to prove the helper reverse-sorts.
		mock.SetGlob(pattern, []string{v18, v20})

		got := pmBinaryCandidateDirs(mock)
		if len(got) < 2 {
			t.Fatalf("expected nvm dirs appended, got %v", got)
		}
		gotLast2 := got[len(got)-2:]
		wantLast2 := []string{v20, v18} // newest (v20) first
		if !reflect.DeepEqual(gotLast2, wantLast2) {
			t.Errorf("nvm dirs not newest-first:\n got %v\nwant %v", gotLast2, wantLast2)
		}
	})
}

func TestNvmNodeBinDirs(t *testing.T) {
	t.Run("reverse sorted", func(t *testing.T) {
		mock := executor.NewMock()
		pattern := filepath.Join("/Users/foo", ".nvm", "versions", "node", "*", "bin")
		a := filepath.Join("/Users/foo", ".nvm", "versions", "node", "v16.0.0", "bin")
		b := filepath.Join("/Users/foo", ".nvm", "versions", "node", "v18.20.0", "bin")
		c := filepath.Join("/Users/foo", ".nvm", "versions", "node", "v20.11.0", "bin")
		mock.SetGlob(pattern, []string{b, a, c})

		got := nvmNodeBinDirs(mock, "/Users/foo")
		want := []string{c, b, a}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("nvmNodeBinDirs:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("no matches → nil", func(t *testing.T) {
		mock := executor.NewMock()
		if got := nvmNodeBinDirs(mock, "/Users/foo"); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestPMBinaryFilenames(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		binary string
		want   []string
	}{
		{"unix npm", "darwin", "npm", []string{"npm"}},
		{"unix pnpm", "linux", "pnpm", []string{"pnpm"}},
		{"windows npm", "windows", "npm", []string{"npm.cmd", "npm.exe", "npm.bat"}},
		{"windows yarn", "windows", "yarn", []string{"yarn.cmd", "yarn.exe", "yarn.bat"}},
		{"windows bun", "windows", "bun", []string{"bun.exe"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS(tt.goos)
			got := pmBinaryFilenames(mock, tt.binary)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pmBinaryFilenames(%q) = %v, want %v", tt.binary, got, tt.want)
			}
		})
	}
}

func TestResolveNodePMFromDefaults(t *testing.T) {
	ctx := context.Background()

	t.Run("hit with version", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("darwin")
		mock.SetHomeDir("/Users/foo")
		mock.SetFile("/opt/homebrew/bin/npm", []byte{})
		stubFallbackVersion(mock, "/opt/homebrew/bin/npm", "--version", "10.2.0\n")

		path, version := resolveNodePMFromDefaults(ctx, mock, "npm", "--version")
		if path != "/opt/homebrew/bin/npm" {
			t.Errorf("path = %q, want /opt/homebrew/bin/npm", path)
		}
		if version != "10.2.0" {
			t.Errorf("version = %q, want 10.2.0", version)
		}
	})

	t.Run("hit but --version empty → path set, version empty", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("darwin")
		mock.SetHomeDir("/Users/foo")
		// File exists but no --version stub → RunWithTimeout errors.
		mock.SetFile("/opt/homebrew/bin/pnpm", []byte{})

		path, version := resolveNodePMFromDefaults(ctx, mock, "pnpm", "--version")
		if path != "/opt/homebrew/bin/pnpm" {
			t.Errorf("path = %q, want /opt/homebrew/bin/pnpm (first existing binary)", path)
		}
		if version != "" {
			t.Errorf("version = %q, want empty", version)
		}
	})

	t.Run("miss → both empty", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("darwin")
		mock.SetHomeDir("/Users/foo")

		path, version := resolveNodePMFromDefaults(ctx, mock, "npm", "--version")
		if path != "" || version != "" {
			t.Errorf("path=%q version=%q, want both empty", path, version)
		}
	})

	t.Run("returns the binary that yields a version", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("darwin")
		mock.SetHomeDir("/Users/foo")
		// Homebrew npm exists but its --version fails; a later candidate works.
		mock.SetFile("/opt/homebrew/bin/npm", []byte{})
		npmGlobal := filepath.Join("/Users/foo", ".npm-global", "bin", "npm")
		mock.SetFile(npmGlobal, []byte{})
		stubFallbackVersion(mock, npmGlobal, "--version", "9.8.1\n")

		path, version := resolveNodePMFromDefaults(ctx, mock, "npm", "--version")
		if path != npmGlobal {
			t.Errorf("path = %q, want %q (binary that produced a version)", path, npmGlobal)
		}
		if version != "9.8.1" {
			t.Errorf("version = %q, want 9.8.1", version)
		}
	})

	t.Run("windows .cmd shim", func(t *testing.T) {
		mock := executor.NewMock()
		mock.SetGOOS("windows")
		mock.SetEnv("LOCALAPPDATA", `C:\Users\foo\AppData\Local`)
		pnpmCmd := filepath.Join(`C:\Users\foo\AppData\Local`, "pnpm", "pnpm.cmd")
		mock.SetFile(pnpmCmd, []byte{})
		mock.SetCommand("9.1.0\n", "", 0, pnpmCmd, "--version")

		path, version := resolveNodePMFromDefaults(ctx, mock, "pnpm", "--version")
		if path != pnpmCmd {
			t.Errorf("path = %q, want %q", path, pnpmCmd)
		}
		if version != "9.1.0" {
			t.Errorf("version = %q, want 9.1.0", version)
		}
	})
}

// stubFallbackVersion stubs the fallback's Unix version invocation
// (`sh -c "PATH=<candidate dirs>:$PATH <binPath> <versionCmd>"`) so a probed
// binary returns the given version. Mirrors how runPMVersion builds the
// command so the mock's exact command key matches.
func stubFallbackVersion(mock *executor.Mock, binPath, versionCmd, version string) {
	dirs := pmBinaryCandidateDirs(mock)
	cmd := pmVersionShellCommand(mock, dirs, binPath, versionCmd)
	mock.SetCommand(version, "", 0, "/bin/sh", "-c", cmd)
}

func TestPMVersionShellCommand(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	mock.SetHomeDir("/Users/foo")
	dirs := pmBinaryCandidateDirs(mock)

	// yarn lives under ~/.npm-global/bin, but node lives under /opt/homebrew/bin.
	// The command must put node's dir on PATH so the env-node shebang resolves.
	yarn := filepath.Join("/Users/foo", ".npm-global", "bin", "yarn")
	cmd := pmVersionShellCommand(mock, dirs, yarn, "--version")

	if !strings.HasPrefix(cmd, "PATH=") {
		t.Errorf("command should start with a PATH assignment: %q", cmd)
	}
	if !strings.Contains(cmd, "'/opt/homebrew/bin':") {
		t.Errorf("command must prepend node's dir (/opt/homebrew/bin) to PATH: %q", cmd)
	}
	if !strings.Contains(cmd, `:"$PATH" `) {
		t.Errorf("command must preserve the inherited $PATH: %q", cmd)
	}
	if !strings.HasSuffix(cmd, "'"+yarn+"' '--version'") {
		t.Errorf("command must end by running the probed binary: %q", cmd)
	}
}
