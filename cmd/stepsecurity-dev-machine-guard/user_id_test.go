package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUserIDCLIHelper(t *testing.T) {
	if os.Getenv("DMG_USER_ID_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"dmg"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(90)
}
func TestUserIDCLIProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires isolated machine config roots on a native Windows runner")
	}
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".stepsecurity")
	if err := os.Mkdir(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(cfgDir, "config.json")
	// Include search_dirs without enterprise credentials: a saved scan setting
	// must not be misinterpreted as an explicitly requested enterprise update.
	original := []byte(`{"user_id":"abc","search_dirs":["/nonexistent-scan-fixture"]}`)
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(wantExit int, want string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestUserIDCLIHelper$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "DMG_USER_ID_CLI_HELPER=1", "HOME="+home, "USERPROFILE="+home, "STEPSECURITY_HOME="+cfgDir, "DMG_API_KEY=", "USER_EMAIL=other@example.com")
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != wantExit || !strings.Contains(string(out), want) {
			t.Fatalf("%v exit %d want %d; output %s", args, code, wantExit, out)
		}
		after, err := os.ReadFile(cfgPath)
		if err != nil || !bytes.Equal(original, after) {
			t.Fatalf("CLI modified assigned config: %s %v", after, err)
		}
	}
	run(0, "already configured with this value", "configure", "--non-interactive", "--user-id", "abc")
	run(0, "already configured with this value", "configure", "--user-id= abc ")
	run(1, "already set and cannot be changed", "configure", "--user-id=def")
	run(1, "Invalid user ID", "configure", "--user-id=")
	run(1, "requires a value", "configure", "--user-id", "--api-key", "hidden")
	run(0, "User ID:", "configure", "show")
	// A new process on a machine with a real detected identity must refuse setup.
	other := t.TempDir()
	home = other
	cfgDir = filepath.Join(other, ".stepsecurity")
	cfgPath = filepath.Join(cfgDir, "config.json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUserIDCLIHelper$", "--", "configure", "--non-interactive", "--user-id", "abc")
	cmd.Env = append(os.Environ(), "DMG_USER_ID_CLI_HELPER=1", "HOME="+other, "USERPROFILE="+other, "STEPSECURITY_HOME="+cfgDir, "DMG_API_KEY=", "USER_EMAIL=detected@example.com")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "already detected") {
		t.Fatalf("detected-user CLI: %s %v", out, err)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatalf("detected rejection created config: %v", err)
	}
	// Keep this fixture independent of config's custom decoder.
	var raw map[string]any
	if err := json.Unmarshal(original, &raw); err != nil || raw["user_id"] != "abc" {
		t.Fatal("bad fixture")
	}
}

func TestUserIDCLIInitialAssignmentLinuxRoot(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("native Linux root provisioning contract")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".stepsecurity")
	args := []string{"configure", "--non-interactive", "--user-id", "linux-user-123"}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestUserIDCLIHelper$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "DMG_USER_ID_CLI_HELPER=1", "HOME="+home, "USERPROFILE="+home, "STEPSECURITY_HOME="+dir, "USER_EMAIL=", "DEVELOPER_EMAIL=", "STEPSEC_DEVELOPER_EMAIL=", "DMG_API_KEY=")
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("provisioning %d: %s %v", i, out, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil || got["user_id"] != "linux-user-123" {
		t.Fatalf("actual Linux provisioning: %s %v", data, err)
	}
}

func TestConfigureExplicitDefaultSearchRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows config-root isolation required")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".stepsecurity")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	original := []byte(`{"customer_id":"test-org","api_key":"key","api_endpoint":"https://example.test","search_dirs":["/saved-scan-root"]}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUserIDCLIHelper$", "--", "configure", "--non-interactive", "--search-dirs", "$HOME")
	cmd.Env = append(os.Environ(), "DMG_USER_ID_CLI_HELPER=1", "HOME="+home, "USERPROFILE="+home, "STEPSECURITY_HOME="+dir, "DMG_API_KEY=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("configure: %s %v", out, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		SearchDirs []string `json:"search_dirs"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.SearchDirs) != 1 || stored.SearchDirs[0] != "$HOME" {
		t.Fatalf("explicit search dirs replaced: %v", stored.SearchDirs)
	}
}
