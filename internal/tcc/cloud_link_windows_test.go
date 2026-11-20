//go:build windows

package tcc

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCloudLinkToOfflineTarget(t *testing.T) {
	home := t.TempDir()
	syncDir := filepath.Join(home, "OneDrive")
	if err := os.Mkdir(syncDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(syncDir, "package.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "package.json")
	makeCloudTestLink(t, target, alias)
	s := &Skipper{cloud: newCloudRoots(home, []string{syncDir})}
	if s.SkipCloudPath(alias) {
		t.Fatal("locally available target in an explicitly selected sync root was skipped")
	}

	for _, path := range []string{target, syncDir} {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		attr, err := windows.GetFileAttributes(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetFileAttributes(p, attr|fileAttributeOffline); err != nil {
			t.Fatal(err)
		}
		if !s.SkipCloudPath(alias) {
			t.Errorf("followed link with offline path component %q", filepath.Base(path))
		}
		if err := windows.SetFileAttributes(p, attr); err != nil {
			t.Fatal(err)
		}
	}
}
