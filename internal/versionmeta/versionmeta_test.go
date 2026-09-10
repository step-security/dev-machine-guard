package versionmeta

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestFromBinary_NPMPackageManifest(t *testing.T) {
	mock := executor.NewMock()
	mock.SetSymlink("/opt/homebrew/bin/claude", "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js")
	mock.SetFile("/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json",
		[]byte(`{"name":"@anthropic-ai/claude-code","version":"2.1.98"}`))

	got := FromBinary(context.Background(), mock, "/opt/homebrew/bin/claude")
	if got != "2.1.98" {
		t.Errorf("FromBinary = %q, want 2.1.98", got)
	}
}

// A corepack shim resolves into node_modules/corepack/, whose manifest
// version is corepack's, not yarn's. The mismatched package name must force
// the exec fallback ("" here), and no path rule may fire either — the shim
// can live under Cellar/node/<v>/, which encodes node's version, not yarn's.
func TestFromBinary_RejectsForeignManifestAndSkipsPathRules(t *testing.T) {
	mock := executor.NewMock()
	mock.SetSymlink("/opt/homebrew/bin/yarn",
		"/opt/homebrew/Cellar/node/22.1.0/lib/node_modules/corepack/dist/yarn.js")
	mock.SetFile("/opt/homebrew/Cellar/node/22.1.0/lib/node_modules/corepack/package.json",
		[]byte(`{"name":"corepack","version":"0.29.4"}`))

	if got := FromBinary(context.Background(), mock, "/opt/homebrew/bin/yarn"); got != "" {
		t.Errorf("FromBinary = %q, want \"\" (foreign manifest must not be trusted)", got)
	}
}

func TestFromBinary_VersionsDirLayout(t *testing.T) {
	tests := []struct {
		name     string
		binary   string
		resolved string
		want     string
	}{
		{
			// The customer-reported Gatekeeper case: metadata must answer so
			// cursor-agent is never executed.
			name:     "cursor-agent curl install",
			binary:   "/Users/testuser/.local/bin/cursor-agent",
			resolved: "/Users/testuser/.local/share/cursor-agent/versions/2026.03.11-6dfa30c/cursor-agent",
			want:     "2026.03.11-6dfa30c",
		},
		{
			// pyenv owns the "versions" dir but the version is python's, not
			// the tool's — the owner-name mismatch must reject it.
			name:     "pyenv-installed tool not misattributed",
			binary:   "/Users/testuser/.pyenv/versions/3.12.1/bin/poetry",
			resolved: "/Users/testuser/.pyenv/versions/3.12.1/bin/poetry",
			want:     "",
		},
		{
			// nvm's layout is versions/node/<v> — "node" sits where the
			// version would have to be, so the rule can't fire.
			name:     "nvm node dir ignored",
			binary:   "/Users/testuser/.nvm/versions/node/v22.1.0/bin/some-tool",
			resolved: "/Users/testuser/.nvm/versions/node/v22.1.0/bin/some-tool",
			want:     "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetSymlink(tc.binary, tc.resolved)
			if got := FromBinary(context.Background(), mock, tc.binary); got != tc.want {
				t.Errorf("FromBinary(%q) = %q, want %q", tc.binary, got, tc.want)
			}
		})
	}
}

func TestFromBinary_Homebrew(t *testing.T) {
	tests := []struct {
		name     string
		binary   string
		resolved string
		want     string
	}{
		{
			name:     "cellar formula",
			binary:   "/opt/homebrew/bin/ollama",
			resolved: "/opt/homebrew/Cellar/ollama/0.5.7/bin/ollama",
			want:     "0.5.7",
		},
		{
			name:     "cellar bottle revision stripped",
			binary:   "/opt/homebrew/bin/uv",
			resolved: "/opt/homebrew/Cellar/uv/0.9.2_1/bin/uv",
			want:     "0.9.2",
		},
		{
			// Cask token (cursor-cli) differs from the binary name
			// (cursor-agent); physical containment still identifies it.
			name:     "caskroom cursor-cli",
			binary:   "/opt/homebrew/bin/cursor-agent",
			resolved: "/opt/homebrew/Caskroom/cursor-cli/2026.03.11-6dfa30c/cursor-agent",
			want:     "2026.03.11-6dfa30c",
		},
		{
			// "version,build" composites don't round-trip to what the tool
			// reports — fall back to exec.
			name:     "caskroom version-comma-build rejected",
			binary:   "/opt/homebrew/bin/sometool",
			resolved: "/opt/homebrew/Caskroom/sometool/1.2.3,4567/sometool",
			want:     "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetSymlink(tc.binary, tc.resolved)
			if got := FromBinary(context.Background(), mock, tc.binary); got != tc.want {
				t.Errorf("FromBinary(%q) = %q, want %q", tc.binary, got, tc.want)
			}
		})
	}
}

func TestFromBinary_AppBundle(t *testing.T) {
	binary := "/usr/local/bin/ollama"
	resolved := "/Applications/Ollama.app/Contents/Resources/ollama"
	plist := "/Applications/Ollama.app/Contents/Info.plist"

	mock := executor.NewMock()
	mock.SetSymlink(binary, resolved)
	mock.SetFile(plist, []byte("binary plist"))
	mock.SetCommand("0.5.7\n", "", 0, "/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", plist)

	if got := FromBinary(context.Background(), mock, binary); got != "0.5.7" {
		t.Errorf("FromBinary = %q, want 0.5.7", got)
	}

	// The PlistBuddy path is macOS-only.
	mock.SetGOOS("linux")
	if got := FromBinary(context.Background(), mock, binary); got != "" {
		t.Errorf("FromBinary on linux = %q, want \"\"", got)
	}
}

func TestFromBinary_NoMetadata(t *testing.T) {
	mock := executor.NewMock()
	// Plain binary, resolves to itself, no manifest anywhere.
	if got := FromBinary(context.Background(), mock, "/usr/local/bin/aider"); got != "" {
		t.Errorf("FromBinary = %q, want \"\"", got)
	}
	if got := FromBinary(context.Background(), mock, ""); got != "" {
		t.Errorf("FromBinary(\"\") = %q, want \"\"", got)
	}
}

func TestFromBinary_WindowsCmdShim(t *testing.T) {
	shim := `C:\Users\Administrator\AppData\Roaming\npm\copilot.cmd`
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetFile(shim, []byte(`"%_prog%"  "%dp0%\node_modules\@github\copilot\index.js" %*`))
	mock.SetFile(`C:\Users\Administrator\AppData\Roaming\npm\node_modules\@github\copilot\package.json`,
		[]byte(`{"name":"@github/copilot","version":"0.0.339"}`))

	if got := FromBinary(context.Background(), mock, shim); got != "0.0.339" {
		t.Errorf("FromBinary = %q, want 0.0.339", got)
	}
	if got := NPMPackageName(mock, shim); got != "@github/copilot" {
		t.Errorf("NPMPackageName = %q, want @github/copilot", got)
	}
}

func TestNPMPackageName_NotAPackage(t *testing.T) {
	mock := executor.NewMock()
	if got := NPMPackageName(mock, "/usr/local/bin/ollama"); got != "" {
		t.Errorf("NPMPackageName = %q, want \"\"", got)
	}
}

func TestMatchesTool(t *testing.T) {
	tests := []struct {
		name, base string
		want       bool
	}{
		{"claude-code", "claude", true},
		{"@google/gemini-cli", "gemini", true},
		{"yarn", "yarn", true},
		{"corepack", "yarn", false},
		{"python@3.12", "python3", false}, // "@" boundary must not bridge python3→python@
		{"cursor-agent", "cursor-agent", true},
		{"", "yarn", false},
	}
	for _, tc := range tests {
		if got := matchesTool(tc.name, tc.base); got != tc.want {
			t.Errorf("matchesTool(%q, %q) = %v, want %v", tc.name, tc.base, got, tc.want)
		}
	}
}

func TestIsVersionLike(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"1.2.3", true},
		{"v1.2.3", true},
		{"2026.03.11-6dfa30c", true},
		{"3.12.8_1", true},
		{"1.2.3,4567", false}, // cask version,build composite
		{"node", false},
		{"22", false}, // no dot
		{"", false},
	}
	for _, tc := range tests {
		if got := IsVersionLike(tc.in); got != tc.want {
			t.Errorf("IsVersionLike(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestNodeModulesPackageRoot exercises the npm package-root extractor
// directly. The detector resolveInstallPath wrapper depends on this for both
// the AI CLI detector and the general-agent detector.
func TestNodeModulesPackageRoot(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", "/usr/local/lib/node_modules/@anthropic-ai/claude-code"},
		{"/usr/local/lib/node_modules/@openai/codex/bin/codex.js", "/usr/local/lib/node_modules/@openai/codex"},
		{"/home/u/.npm-global/lib/node_modules/opencode/bin/opencode", "/home/u/.npm-global/lib/node_modules/opencode"},
		{"/usr/bin/ollama", ""},                   // not a node_modules path
		{"/Users/u/Library/foo/node_modules", ""}, // node_modules with no package after
		{"", ""},
	}
	for _, tt := range tests {
		got := NodeModulesPackageRoot(tt.path)
		if got != tt.want {
			t.Errorf("NodeModulesPackageRoot(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
