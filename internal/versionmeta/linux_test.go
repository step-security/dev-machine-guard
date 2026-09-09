package versionmeta

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// The Ubuntu box from the LM Studio report: the .deb's launcher on PATH,
// symlinked into the electron-builder install root.
func dpkgMock(list, status string) *executor.Mock {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetSymlink("/usr/bin/lm-studio", "/opt/LM Studio/lm-studio")
	if list != "" {
		mock.SetFile("/var/lib/dpkg/info/lm-studio.list", []byte(list))
	}
	if status != "" {
		mock.SetFile("/var/lib/dpkg/status", []byte(status))
	}
	return mock
}

const dpkgOwnedList = "/opt\n/opt/LM Studio\n/opt/LM Studio/lm-studio\n/usr/bin/lm-studio\n"

func TestFromBinary_Dpkg(t *testing.T) {
	tests := []struct {
		name   string
		list   string
		status string
		want   string
	}{
		{
			name:   "package owns the launcher",
			list:   dpkgOwnedList,
			status: "Package: lm-studio\nStatus: install ok installed\nVersion: 0.3.31-1\n\n",
			want:   "0.3.31",
		},
		{
			// Matching either the PATH entry or its target is enough.
			name:   "matches the resolved target",
			list:   "/opt/LM Studio/lm-studio\n",
			status: "Package: lm-studio\nStatus: install ok installed\nVersion: 0.3.31\n\n",
			want:   "0.3.31",
		},
		{
			// A stale deb and a hand-installed launcher coexist; lending one's
			// version to the other is a silent wrong answer.
			name:   "same-named package that owns nothing is rejected",
			list:   "/usr/share/doc/lm-studio/copyright\n",
			status: "Package: lm-studio\nStatus: install ok installed\nVersion: 0.2.9\n\n",
			want:   "",
		},
		{
			name:   "purged package is rejected",
			list:   dpkgOwnedList,
			status: "Package: lm-studio\nStatus: deinstall ok config-files\nVersion: 0.2.9\n\n",
			want:   "",
		},
		{
			name:   "epoch is stripped",
			list:   dpkgOwnedList,
			status: "Package: lm-studio\nStatus: install ok installed\nVersion: 2:0.3.31-1ubuntu2\n\n",
			want:   "0.3.31",
		},
		{
			// Neither first nor last, and no leaking across stanza boundaries.
			name: "finds the stanza among others",
			list: dpkgOwnedList,
			status: "Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.2.11.dfsg-2\n\n" +
				"Package: lm-studio\nStatus: install ok installed\nVersion: 0.3.31-1\n\n" +
				"Package: zsh\nStatus: install ok installed\nVersion: 5.8.1-1\n",
			want: "0.3.31",
		},
		{
			name:   "unparseable version falls through to the caller's fallback",
			list:   dpkgOwnedList,
			status: "Package: lm-studio\nStatus: install ok installed\nVersion: nightly\n\n",
			want:   "",
		},
		{
			name: "no dpkg database at all",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromBinary(context.Background(), dpkgMock(tt.list, tt.status), "/usr/bin/lm-studio")
			if got != tt.want {
				t.Errorf("FromBinary = %q, want %q", got, tt.want)
			}
		})
	}
}

// /var/lib/dpkg on a Mac never describes what is installed there.
func TestFromBinary_DpkgIsLinuxOnly(t *testing.T) {
	mock := dpkgMock(dpkgOwnedList, "Package: lm-studio\nStatus: install ok installed\nVersion: 0.3.31-1\n\n")
	mock.SetGOOS("darwin")

	if got := FromBinary(context.Background(), mock, "/usr/bin/lm-studio"); got != "" {
		t.Errorf("FromBinary = %q, want \"\" on darwin", got)
	}
}

// Multi-Arch: same packages record their file list under <pkg>:<arch>.list.
func TestFromBinary_DpkgMultiarchManifest(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetSymlink("/usr/bin/local-ai", "/usr/bin/local-ai")
	mock.SetGlob("/var/lib/dpkg/info/local-ai:*.list", []string{"/var/lib/dpkg/info/local-ai:amd64.list"})
	mock.SetFile("/var/lib/dpkg/info/local-ai:amd64.list", []byte("/usr/bin/local-ai\n"))
	mock.SetFile("/var/lib/dpkg/status", []byte(
		"Package: local-ai\nStatus: install ok installed\nVersion: 2.24.1-3\nArchitecture: amd64\n\n"))

	if got := FromBinary(context.Background(), mock, "/usr/bin/local-ai"); got != "2.24.1" {
		t.Errorf("FromBinary = %q, want 2.24.1", got)
	}
}

func TestFromBinary_AppImage(t *testing.T) {
	tests := []struct {
		name     string
		binary   string
		resolved string
		want     string
	}{
		{
			// The LM Studio install dpkg can't see: one file, no package entry.
			name:     "electron-builder naming",
			binary:   "/home/dev/.local/bin/lm-studio",
			resolved: "/home/dev/Applications/LM-Studio-0.3.31-x64.AppImage",
			want:     "0.3.31",
		},
		{
			name:     "debian-style revision after the version",
			binary:   "/home/dev/.local/bin/lm-studio",
			resolved: "/home/dev/Applications/LM-Studio-0.3.31-1-x64.AppImage",
			want:     "0.3.31",
		},
		{
			name:     "single-segment product name",
			binary:   "/usr/local/bin/cursor",
			resolved: "/opt/appimages/Cursor-1.5.9-x86_64.AppImage",
			want:     "1.5.9",
		},
		{
			// "linux" must not be mistaken for a version.
			name:     "no version in the filename",
			binary:   "/usr/local/bin/nvim",
			resolved: "/opt/appimages/nvim-linux-x86_64.AppImage",
			want:     "",
		},
		{
			name:     "prefix names a different tool",
			binary:   "/usr/local/bin/lm-studio",
			resolved: "/opt/appimages/Cursor-1.5.9-x86_64.AppImage",
			want:     "",
		},
		{
			name:     "not an AppImage at all",
			binary:   "/usr/local/bin/lm-studio",
			resolved: "/opt/lm-studio/LM-Studio-0.3.31-x64.bin",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS("linux")
			mock.SetSymlink(tt.binary, tt.resolved)
			if got := FromBinary(context.Background(), mock, tt.binary); got != tt.want {
				t.Errorf("FromBinary = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromBinary_Snap(t *testing.T) {
	// /snap/bin/<name> symlinks to the snap wrapper, so resolving the binary
	// walks away from the install — the manifest is the only way in.
	snapMock := func(yaml string) *executor.Mock {
		mock := executor.NewMock()
		mock.SetGOOS("linux")
		mock.SetSymlink("/snap/bin/local-ai", "/usr/bin/snap")
		if yaml != "" {
			mock.SetFile("/snap/local-ai/current/meta/snap.yaml", []byte(yaml))
		}
		return mock
	}

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "manifest names this snap",
			yaml: "name: local-ai\nversion: 2.24.1\nsummary: LocalAI\nbase: core22\n",
			want: "2.24.1",
		},
		{
			name: "quoted version",
			yaml: "name: local-ai\nversion: '2.24.1'\n",
			want: "2.24.1",
		},
		{
			name: "manifest disagrees with its own directory",
			yaml: "name: something-else\nversion: 9.9.9\n",
			want: "",
		},
		{
			// Snap versions are free-form strings.
			name: "non-version version string",
			yaml: "name: local-ai\nversion: stable\n",
			want: "",
		},
		{
			name: "no manifest",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromBinary(context.Background(), snapMock(tt.yaml), "/snap/bin/local-ai"); got != tt.want {
				t.Errorf("FromBinary = %q, want %q", got, tt.want)
			}
		})
	}
}

// `snap run <snap>.<app>` exposes apps under a name that differs from the
// snap's own, so the tool name is not part of the check.
func TestFromBinary_SnapSecondaryApp(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetSymlink("/snap/bin/local-ai.cli", "/usr/bin/snap")
	mock.SetFile("/snap/local-ai/current/meta/snap.yaml", []byte("name: local-ai\nversion: 2.24.1\n"))

	if got := FromBinary(context.Background(), mock, "/snap/bin/local-ai.cli"); got != "2.24.1" {
		t.Errorf("FromBinary = %q, want 2.24.1", got)
	}
}

// A snap alias has no directory of its own, so there is no manifest to read.
func TestFromBinary_SnapAliasHasNoManifest(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetSymlink("/snap/bin/lai", "/usr/bin/snap")
	mock.SetFile("/snap/local-ai/current/meta/snap.yaml", []byte("name: local-ai\nversion: 2.24.1\n"))

	if got := FromBinary(context.Background(), mock, "/snap/bin/lai"); got != "" {
		t.Errorf("FromBinary = %q, want \"\"", got)
	}
}
