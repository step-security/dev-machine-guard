//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/updateinstall"
)

func TestBootstrapAgentHelper(t *testing.T) {
	if os.Getenv("DMG_BOOTSTRAP_TEST") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("DMG_BOOTSTRAP_MARKER"), []byte("agent-started"), 0o600); err != nil {
		os.Exit(9)
	}
	os.Exit(0)
}

func TestBootstrap_RecoversMissingPairAndLaunchesAgent(t *testing.T) {
	dir := t.TempDir()
	bootstrap := filepath.Join(dir, updateinstall.Bootstrap)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-ldflags=-H windowsgui", "-o", bootstrap, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build bootstrap: %v\n%s", err, out)
	}
	launcher, err := os.ReadFile(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	me, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := os.ReadFile(me)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, ".update-backup-test")
	if err = os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := []map[string]any{}
	for _, f := range []struct {
		name string
		data []byte
	}{{updateinstall.Launcher, launcher}, {updateinstall.Agent, agent}} {
		if err = os.WriteFile(filepath.Join(backupDir, f.name), f.data, 0o755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(f.data)
		files = append(files, map[string]any{"name": f.name, "sha256": hex.EncodeToString(sum[:]), "existed": true})
	}
	raw, err := json.Marshal(map[string]any{"schema": 1, "directory": filepath.Base(backupDir), "files": files})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, ".update-transaction.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "started")
	cmd := exec.CommandContext(ctx, bootstrap, updateinstall.BootstrapFlag, "-test.run=^TestBootstrapAgentHelper$")
	cmd.Env = append(os.Environ(), "DMG_BOOTSTRAP_TEST=1", "DMG_BOOTSTRAP_MARKER="+marker)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, out)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "agent-started" {
		t.Fatalf("agent did not start: %q, %v", got, err)
	}
	if _, err = os.Stat(filepath.Join(dir, ".update-transaction.json")); !os.IsNotExist(err) {
		t.Fatal("recovery journal was not cleared")
	}
}
