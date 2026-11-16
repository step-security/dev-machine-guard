package cli

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

	aievent "github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/config"
)

func TestUserIDHookProcessHelper(t *testing.T) {
	if os.Getenv("DMG_HOOK_ID_HELPER") != "1" {
		return
	}
	if home := os.Getenv("DMG_HOOK_TEST_HOME"); home != "" {
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
	}
	config.UserID = ""
	uploaderFactory = func() func(context.Context, aievent.Event) error {
		return func(_ context.Context, ev aievent.Event) error {
			data, err := json.Marshal(ev)
			if err != nil {
				return err
			}
			return os.WriteFile(os.Getenv("DMG_HOOK_EVENT_FILE"), data, 0o600)
		}
	}
	var out, stderr bytes.Buffer
	rc := RunHook(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`), &out, &stderr, []string{"claude-code", "PreToolUse"})
	if rc != 0 || stderr.Len() != 0 {
		os.Exit(91)
	}
	var response map[string]any
	if json.Unmarshal(out.Bytes(), &response) != nil || response["continue"] != true {
		os.Exit(92)
	}
	os.Exit(0)
}
func TestUserIDFreshHookProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows config-root isolation required")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".stepsecurity")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"user_id":"configured+hook@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	eventFile := filepath.Join(home, "event.json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUserIDHookProcessHelper$")
	cmd.Env = append(os.Environ(), "DMG_HOOK_ID_HELPER=1", "DMG_HOOK_TEST_HOME="+home, "DMG_HOOK_EVENT_FILE="+eventFile, "HOME="+home, "USERPROFILE="+home, "STEPSECURITY_HOME="+dir, "USER_EMAIL=changed@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hook process: %s %v", out, err)
	}
	raw, err := os.ReadFile(eventFile)
	if err != nil {
		t.Fatal(err)
	}
	var ev aievent.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.UserIdentity != "configured+hook@example.com" {
		t.Fatalf("hook startup lost persisted ID: %s", raw)
	}
}
