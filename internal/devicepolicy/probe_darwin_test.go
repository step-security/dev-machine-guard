//go:build darwin

package devicepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

// TestProbeDarwinEitherKey confirms the probe yields on AllowedExtensions OR
// ExtensionGalleryServiceUrl (key names are plain ASCII runs in binary plists).
func TestProbeDarwinEitherKey(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
		detail  string
	}{
		{"allowlist only", "bplist00\x00AllowedExtensions\x00", true, allowedExtensionsName},
		{"gallery only", "bplist00\x00ExtensionGalleryServiceUrl\x00", true, galleryServiceURLName},
		{"both (allowlist preferred in detail)", "bplist00\x00AllowedExtensions\x00ExtensionGalleryServiceUrl\x00", true, allowedExtensionsName},
		{"neither", "bplist00\x00SomethingElse\x00", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, darwinVSCodePlistName)
			if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			managed, detail := probeDarwinManagedPrefs(root)
			if managed != tc.want {
				t.Fatalf("managed = %v, want %v (detail %q)", managed, tc.want, detail)
			}
			if tc.want && !strings.Contains(detail, tc.detail) {
				t.Fatalf("detail = %q, want to contain %q", detail, tc.detail)
			}
		})
	}
}

// TestProbeDarwinPerUserGalleryKey covers the per-user glob path (plist under a
// <user> subdir).
func TestProbeDarwinPerUserGalleryKey(t *testing.T) {
	root := t.TempDir()
	userDir := filepath.Join(root, "alice")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, darwinVSCodePlistName),
		[]byte("bplist00\x00ExtensionGalleryServiceUrl\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	managed, detail := probeDarwinManagedPrefs(root)
	if !managed || !strings.Contains(detail, galleryServiceURLName) {
		t.Fatalf("per-user gallery key: want managed=true with gallery detail, got (%v, %q)", managed, detail)
	}
}

// writeManagedPrefsPlist writes dict as a real binary plist at path (creating
// parent dirs), so the content probe exercises the actual plist parser rather
// than a byte scan.
func writeManagedPrefsPlist(t *testing.T, path string, dict map[string]any) {
	t.Helper()
	b, err := plist.Marshal(dict, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshal plist: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestProbeDarwinManagedContent parses real binary plists: per-user precedence
// over machine-wide, an absent tree as not-managed, a non-string/unparseable
// value as an error.
func TestProbeDarwinManagedContent(t *testing.T) {
	t.Run("machine-wide stringified allowlist + gallery", func(t *testing.T) {
		root := t.TempDir()
		writeManagedPrefsPlist(t, filepath.Join(root, darwinVSCodePlistName), map[string]any{
			allowedExtensionsName: `{"*":false,"ms-python.python":"stable"}`,
			galleryServiceURLName: "https://mkt.example/api/v1",
		})
		present, observed, err := probeDarwinManagedContent(root, "")
		if err != nil || !present {
			t.Fatalf("present=%v err=%v", present, err)
		}
		got, _ := json.Marshal(observed)
		want := `{"extensions.allowed":{"*":false,"ms-python.python":"stable"},"extensions.gallery.serviceUrl":"https://mkt.example/api/v1"}`
		if string(got) != want {
			t.Fatalf("observed = %s, want %s", got, want)
		}
	})

	t.Run("per-user overrides machine-wide", func(t *testing.T) {
		root := t.TempDir()
		writeManagedPrefsPlist(t, filepath.Join(root, darwinVSCodePlistName), map[string]any{
			allowedExtensionsName: `{"*":false}`,
		})
		writeManagedPrefsPlist(t, filepath.Join(root, "alice", darwinVSCodePlistName), map[string]any{
			allowedExtensionsName: `{"golang.go":true}`,
		})
		present, observed, err := probeDarwinManagedContent(root, "alice")
		if err != nil || !present {
			t.Fatalf("present=%v err=%v", present, err)
		}
		got, _ := json.Marshal(observed)
		if want := `{"extensions.allowed":{"golang.go":true}}`; string(got) != want {
			t.Fatalf("per-user should win: observed = %s, want %s", got, want)
		}
	})

	t.Run("no managed prefs is absent", func(t *testing.T) {
		present, observed, err := probeDarwinManagedContent(t.TempDir(), "")
		if err != nil || present || len(observed) != 0 {
			t.Fatalf("absent: present=%v observed=%v err=%v", present, observed, err)
		}
	})

	t.Run("non-string value is verification_failed", func(t *testing.T) {
		root := t.TempDir()
		writeManagedPrefsPlist(t, filepath.Join(root, darwinVSCodePlistName), map[string]any{
			allowedExtensionsName: 42,
		})
		if _, _, err := probeDarwinManagedContent(root, ""); err == nil {
			t.Fatal("non-string AllowedExtensions must be an error")
		}
	})

	t.Run("unparseable plist is verification_failed", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, darwinVSCodePlistName), []byte("not a plist"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := probeDarwinManagedContent(root, ""); err == nil {
			t.Fatal("unparseable plist must be an error")
		}
	})
}

// TestCurrentManagedPrefsUserPrefersHome locks $HOME as the lead signal (matching
// the writer's os.UserHomeDir), $USER as fallback: a root LaunchDaemon bakes
// $HOME to the console user but leaves $USER=root.
func TestCurrentManagedPrefsUserPrefersHome(t *testing.T) {
	t.Setenv("HOME", "/Users/alice")
	t.Setenv("USER", "root")
	if got := currentManagedPrefsUser(); got != "alice" {
		t.Fatalf("HOME=/Users/alice USER=root: got %q, want alice", got)
	}

	t.Setenv("HOME", "")
	t.Setenv("USER", "bob")
	if got := currentManagedPrefsUser(); got != "bob" {
		t.Fatalf("empty HOME falls back to USER: got %q, want bob", got)
	}
}
