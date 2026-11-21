//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeveloperAliasUpgradeAndCollision(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "agent")
	t.Setenv("PATH", "/usr/bin:/bin")
	for range 2 {
		if err := configureAlias(home, bin, "install", "/bin/zsh", ""); err != nil {
			t.Fatal(err)
		}
	}
	profile, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	if err != nil || strings.Count(string(profile), "# StepSecurity developer CLI") != 1 {
		t.Fatalf("profile: %q %v", profile, err)
	}
	link := filepath.Join(home, ".local", "bin", "dmg")
	for _, v := range []string{"v1", "v2"} {
		if err := os.WriteFile(bin+".next", []byte(v), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(bin+".next", bin); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(link)
		if err != nil || string(got) != v {
			t.Fatalf("alias got %q %v", got, err)
		}
	}
	if err := configureAlias(home, bin, "uninstall", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("existing command"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := configureAlias(home, bin, "install", "/bin/zsh", ""); err == nil {
		t.Fatal("accepted a collision")
	}
	if err := configureAlias(home, bin, "uninstall", "", ""); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(link)
	if err != nil || string(b) != "existing command" {
		t.Fatalf("changed unrelated executable: %q %v", b, err)
	}
}
