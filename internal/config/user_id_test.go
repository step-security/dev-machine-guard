package config

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func absentUser() *executor.Mock { m := executor.NewMock(); m.SetUsername("root"); return m }
func userOpts(value string) NonInteractiveOptions {
	return NonInteractiveOptions{Values: map[string]any{"user_id": value}}
}
func configBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(ConfigFilePath())
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func seedUserConfig(t *testing.T) {
	t.Helper()
	if err := save(&ConfigFile{UserID: "abc", CustomerID: "customer", APIKey: "test-key", APIEndpoint: "https://example.test", InstallDir: "/preserved"}); err != nil {
		t.Fatal(err)
	}
}
func TestUserIDLifetime(t *testing.T) {
	withHome(t)
	if err := runConfigureNonInteractive(userOpts(" abc "), absentUser()); err != nil {
		t.Fatal(err)
	}
	original := configBytes(t)
	for _, value := range []string{"abc", " abc "} {
		if err := runConfigureNonInteractive(userOpts(value), executor.NewMock()); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, configBytes(t)) {
			t.Fatal("idempotent retry rewrote config")
		}
	}
	for _, value := range []string{"def", "ABC", "", " ", "root", "unknown", "abc\n"} {
		if err := runConfigureNonInteractive(userOpts(value), absentUser()); err == nil {
			t.Fatalf("accepted replacement %q", value)
		}
		if !bytes.Equal(original, configBytes(t)) {
			t.Fatalf("failed replacement %q changed config", value)
		}
	}
	previous := UserID
	t.Cleanup(func() { UserID = previous })
	UserID = ""
	Load()
	if UserID != "abc" {
		t.Fatalf("restart load ID=%q", UserID)
	}
	if err := PersistMaxExecutionDuration("2h"); err != nil {
		t.Fatal(err)
	}
	got, err := readExistingStrict()
	if err != nil || got.UserID != "abc" || got.MaxExecutionDuration != "2h" {
		t.Fatalf("installer persistence: %+v %v", got, err)
	}
}

func TestUserIDConfigureValues(t *testing.T) {
	t.Run("community preferences with identical identity", func(t *testing.T) {
		withHome(t)
		if err := runConfigureNonInteractive(userOpts("abc"), absentUser()); err != nil {
			t.Fatal(err)
		}
		opts := userOpts(" abc ")
		opts.Values["color_mode"] = "never"
		opts.Values["enable_npm_scan"] = false
		if err := runConfigureNonInteractive(opts, executor.NewMock()); err != nil {
			t.Fatal(err)
		}
		got, err := readExistingStrict()
		if err != nil || got.UserID != "abc" || got.ColorMode != "never" || got.EnableNPMScan == nil || *got.EnableNPMScan {
			t.Fatalf("preferences with same ID: %+v, %v", got, err)
		}
	})
	for _, key := range []string{"user_id", "device_id"} {
		for _, value := range []any{nil, "", "bad/id", "root", "abc\n", 7} {
			t.Run(fmt.Sprintf("%s/%v", key, value), func(t *testing.T) {
				withHome(t)
				seedUserConfig(t)
				before := configBytes(t)
				opts := NonInteractiveOptions{Values: map[string]any{key: value, "color_mode": "never"}}
				if err := runConfigureNonInteractive(opts, absentUser()); err == nil {
					t.Fatal("accepted invalid identity through configure values")
				}
				if !bytes.Equal(before, configBytes(t)) {
					t.Fatal("rejected identity changed config")
				}
			})
		}
	}
	t.Run("normalized mutable device", func(t *testing.T) {
		withHome(t)
		seedUserConfig(t)
		for _, id := range []string{"device-1", " device-2 "} {
			opts := NonInteractiveOptions{Values: map[string]any{"device_id": id}}
			if err := runConfigureNonInteractive(opts, absentUser()); err != nil {
				t.Fatal(err)
			}
		}
		got, err := readExistingStrict()
		if err != nil || got.UserID != "abc" || got.DeviceID != "device-2" {
			t.Fatalf("mutable device: %+v, %v", got, err)
		}
	})
}
func TestUserIDEligibility(t *testing.T) {
	for _, source := range []string{"username", "USER_EMAIL", "DEVELOPER_EMAIL", "STEPSEC_DEVELOPER_EMAIL"} {
		t.Run(source, func(t *testing.T) {
			withHome(t)
			m := absentUser()
			if source == "username" {
				m.SetUsername("alice")
			} else {
				m.SetEnv(source, "alice@example.com")
			}
			if err := runConfigureNonInteractive(userOpts("abc"), m); err == nil || !strings.Contains(err.Error(), "already detected") {
				t.Fatalf("eligibility error=%v", err)
			}
			if _, err := os.Stat(ConfigFilePath()); !os.IsNotExist(err) {
				t.Fatalf("rejection created config: %v", err)
			}
		})
	}
	for _, sentinel := range []string{"", "unknown", "root", " ROOT "} {
		t.Run("missing_"+sentinel, func(t *testing.T) {
			withHome(t)
			m := executor.NewMock()
			m.SetUsername(sentinel)
			if err := runConfigureNonInteractive(userOpts("abc"), m); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestUserIDImport(t *testing.T) {
	for _, tc := range []struct {
		name, field, cli string
		ok               bool
	}{
		{"omitted", "", "", true}, {"same", `,"user_id":" abc "`, "", true},
		{"replacement", `,"user_id":"def"`, "", false}, {"empty", `,"user_id":""`, "", false},
		{"null", `,"user_id":null`, "", false}, {"number", `,"user_id":123`, "", false},
		{"duplicate", `,"user_id":"def","user_id":"abc"`, "", false},
		{"case_duplicate", `,"USER_ID":"def","user_id":"abc"`, "", false},
		{"conflicting", `,"user_id":"def"`, "abc", false},
		{"matching_cli", `,"user_id":"abc"`, "abc", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHome(t)
			seedUserConfig(t)
			before := configBytes(t)
			from := filepath.Join(t.TempDir(), "import.json")
			raw := `{"customer_id":"new-customer","api_key":"new-key","api_endpoint":"https://example.test"` + tc.field + `}`
			if err := os.WriteFile(from, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := NonInteractiveOptions{FromFile: from}
			if tc.cli != "" {
				opts.Values = map[string]any{"user_id": tc.cli}
			}
			err := runConfigureNonInteractive(opts, absentUser())
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v want %v: %v", err == nil, tc.ok, err)
			}
			if !tc.ok && !bytes.Equal(before, configBytes(t)) {
				t.Fatal("invalid import modified config")
			}
			if tc.ok {
				got, err := readExistingStrict()
				if err != nil || got.UserID != "abc" || got.CustomerID != "new-customer" {
					t.Fatalf("import: %+v %v", got, err)
				}
			}
		})
	}
}
func TestUserIDAssignmentFromFileAndCredentialFailure(t *testing.T) {
	withHome(t)
	from := filepath.Join(t.TempDir(), "import.json")
	data := []byte(`{"user_id":"abc","customer_id":"c","api_key":"key","api_endpoint":"https://example.test"}`)
	if err := os.WriteFile(from, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runConfigureNonInteractive(NonInteractiveOptions{FromFile: from}, absentUser()); err != nil {
		t.Fatal(err)
	}
	got, err := readExistingStrict()
	if err != nil || got.UserID != "abc" {
		t.Fatalf("import assignment %+v %v", got, err)
	}
	t.Run("missing_credentials", func(t *testing.T) {
		withHome(t)
		opts := userOpts("abc")
		opts.Values["customer_id"] = "customer"
		if err := runConfigureNonInteractive(opts, absentUser()); err == nil {
			t.Fatal("accepted partial enrollment")
		}
		if _, err := os.Stat(ConfigFilePath()); !os.IsNotExist(err) {
			t.Fatal("partial identity commit")
		}
	})
}
func TestUserIDFailsClosed(t *testing.T) {
	for _, raw := range []string{`{"user_id":"abc"`, `null`, `{"user_id":null}`, `{"user_id":true}`, `{"user_id":"abc","USER_ID":"def"}`} {
		t.Run(raw, func(t *testing.T) {
			withHome(t)
			if err := os.MkdirAll(filepath.Dir(ConfigFilePath()), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ConfigFilePath(), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			err := runConfigureNonInteractive(userOpts("def"), absentUser())
			if err == nil {
				t.Fatal("corrupt file counted as absent")
			}
			if !bytes.Equal([]byte(raw), configBytes(t)) {
				t.Fatal("corrupt file modified")
			}
			if err := PersistMaxExecutionDuration("2h"); err == nil {
				t.Fatal("persistence overwrote corrupt config")
			}
		})
	}
	t.Run("read_error", func(t *testing.T) {
		withHome(t)
		if err := os.MkdirAll(ConfigFilePath(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := runConfigureNonInteractive(userOpts("abc"), absentUser()); err == nil {
			t.Fatal("read error ignored")
		}
	})
}
func TestUserIDUnrelatedAndInteractiveConfigure(t *testing.T) {
	withHome(t)
	seedUserConfig(t)
	if err := runConfigureNonInteractive(NonInteractiveOptions{Values: map[string]any{"scan_frequency_hours": "8"}}, absentUser()); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	t.Cleanup(func() { os.Stdin = previous })
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Repeat("\n", 30)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	os.Stdin = f
	if err := RunConfigure(); err != nil {
		t.Fatal(err)
	}
	got, err := readExistingStrict()
	if err != nil || got.UserID != "abc" || got.InstallDir != "/preserved" || got.ScanFrequencyHours != "8" {
		t.Fatalf("unrelated updates: %+v %v", got, err)
	}
}

func TestUserIDInteractiveDeviceClear(t *testing.T) {
	withHome(t)
	seedUserConfig(t)
	opts := NonInteractiveOptions{Values: map[string]any{"device_id": "custom-device"}}
	if err := runConfigureNonInteractive(opts, absentUser()); err != nil {
		t.Fatal(err)
	}
	input, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := input.WriteString("-\n" + strings.Repeat("\n", 30)); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	t.Cleanup(func() { os.Stdin = previous })
	os.Stdin = input
	if err := RunConfigure(); err != nil {
		t.Fatal(err)
	}
	got, err := readExistingStrict()
	if err != nil || got.DeviceID != "" || got.UserID != "abc" || got.InstallDir != "/preserved" {
		t.Fatalf("device reset must preserve user ID and other settings: %+v, %v", got, err)
	}
}

// Helper runs in a fresh OS process so global state and the process lock really
// are independent. stdin is an explicit start barrier; stdout reports readiness.
func TestUserIDProcessHelper(t *testing.T) {
	if os.Getenv("DMG_USER_ID_TEST_HELPER") != "1" {
		return
	}
	fmt.Println("ready")
	var b [1]byte
	if _, err := io.ReadFull(os.Stdin, b[:]); err != nil {
		os.Exit(90)
	}
	var err error
	switch os.Getenv("DMG_USER_ID_TEST_MODE") {
	case "hold":
		var release func()
		release, err = lockConfig()
		if err == nil {
			defer release()
			fmt.Println("locked")
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
	case "duration":
		err = PersistMaxExecutionDuration("3h")
	case "snapshot":
		Load()
		if UserID != os.Getenv("DMG_USER_ID_TEST_VALUE") {
			os.Exit(91)
		}
	default:
		err = runConfigureNonInteractive(userOpts(os.Getenv("DMG_USER_ID_TEST_VALUE")), absentUser())
		if err == nil && os.Getenv("DMG_USER_ID_TEST_MODE") == "committed_hold" {
			fmt.Println("committed")
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
func TestUserIDProcesses(t *testing.T) {
	for _, scenario := range []string{"different", "same", "unrelated"} {
		t.Run(scenario, func(t *testing.T) {
			withHome(t)
			release, err := lockConfig()
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmds := make([]*exec.Cmd, 2)
			gates := make([]io.WriteCloser, 2)
			errs := make([]bytes.Buffer, 2)
			for i := range cmds {
				mode, value := "assign", "abc"
				if i == 1 && scenario == "different" {
					value = "def"
				}
				if i == 1 && scenario == "unrelated" {
					mode = "duration"
				}
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUserIDProcessHelper$")
				cmd.Env = append(os.Environ(), "DMG_USER_ID_TEST_HELPER=1", "DMG_USER_ID_TEST_MODE="+mode, "DMG_USER_ID_TEST_VALUE="+value)
				cmd.Stderr = &errs[i]
				pipe, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				gates[i], err = cmd.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				cmds[i] = cmd
				reader := bufio.NewReader(pipe)
				line, err := reader.ReadString('\n')
				if err != nil || line != "ready\n" {
					t.Fatalf("helper ready: %q %v", line, err)
				}
				go func() { _, _ = io.Copy(io.Discard, reader) }()
			}
			for _, gate := range gates {
				if _, err := gate.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				gate.Close()
			}
			release()
			successes := 0
			for _, cmd := range cmds {
				if cmd.Wait() == nil {
					successes++
				}
			}
			expected := 2
			if scenario == "different" {
				expected = 1
			}
			if successes != expected {
				t.Fatalf("%d successes want %d: %s / %s", successes, expected, &errs[0], &errs[1])
			}
			got, err := readExistingStrict()
			if err != nil {
				t.Fatal(err)
			}
			if got.UserID != "abc" && got.UserID != "def" {
				t.Fatalf("winner %+v", got)
			}
			if scenario == "unrelated" && got.MaxExecutionDuration != "3h" {
				t.Fatalf("lost unrelated write: %+v", got)
			}
			// Fresh process reads persisted identity without parent globals.
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUserIDProcessHelper$")
			cmd.Env = append(os.Environ(), "DMG_USER_ID_TEST_HELPER=1", "DMG_USER_ID_TEST_MODE=snapshot", "DMG_USER_ID_TEST_VALUE="+got.UserID)
			cmd.Stdin = strings.NewReader("1")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("restart: %s %v", out, err)
			}
		})
	}
}
func TestAtomicConfigFailure(t *testing.T) {
	// Real replacement failure: destination directory cannot be replaced by a file.
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "preserved")
	if err := os.WriteFile(marker, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(target, []byte(`{"user_id":"abc"}`), 0o600, false); err == nil {
		t.Fatal("replacement should fail")
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "original" {
		t.Fatalf("previous target lost: %q %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temp files leaked: %+v %v", entries, err)
	}
}
func TestConfigIdentityNullAndAlias(t *testing.T) {
	for _, raw := range []string{`{"USER_ID":"ROOT"}`, `{"USER_ID":null}`, `{"user_id":"abc","USER_ID":"def"}`} {
		var c ConfigFile
		if err := json.Unmarshal([]byte(raw), &c); err == nil {
			t.Fatalf("accepted alias bypass: %s %+v", raw, c)
		}
	}
}

func TestUserIDCrashReleasesLock(t *testing.T) {
	withHome(t)
	seedUserConfig(t)
	before := configBytes(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUserIDProcessHelper$")
	cmd.Env = append(os.Environ(), "DMG_USER_ID_TEST_HELPER=1", "DMG_USER_ID_TEST_MODE=hold")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	gate, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(pipe)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("ready %q %v", line, err)
	}
	if _, err := gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("lock %q %v", line, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if !bytes.Equal(before, configBytes(t)) {
		t.Fatal("interrupted transaction changed config")
	}
	if err := runConfigureNonInteractive(userOpts("abc"), absentUser()); err != nil {
		t.Fatalf("dead process retained lock: %v", err)
	}
}

func TestUserIDOnlyImport(t *testing.T) {
	for _, seed := range []bool{false, true} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			withHome(t)
			if seed {
				seedUserConfig(t)
			}
			from := filepath.Join(t.TempDir(), "identity.json")
			if err := os.WriteFile(from, []byte(`{"user_id":" abc "}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := runConfigureNonInteractive(NonInteractiveOptions{FromFile: from}, absentUser()); err != nil {
				t.Fatal(err)
			}
			got, err := readExistingStrict()
			if err != nil || got.UserID != "abc" {
				t.Fatalf("ID-only import %+v %v", got, err)
			}
			if seed && got.InstallDir != "/preserved" {
				t.Fatal("ID-only import cleared existing settings")
			}
		})
	}
}
func TestConfigLockTimeout(t *testing.T) {
	withHome(t)
	seedUserConfig(t)
	before := configBytes(t)
	release, err := lockConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUserIDProcessHelper$")
	cmd.Env = append(os.Environ(), "DMG_USER_ID_TEST_HELPER=1", "DMG_USER_ID_TEST_MODE=assign", "DMG_USER_ID_TEST_VALUE=def")
	cmd.Stdin = strings.NewReader("1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "configuration is busy") {
		t.Fatalf("timeout: %s %v", out, err)
	}
	if !bytes.Equal(before, configBytes(t)) {
		t.Fatal("lock timeout changed config")
	}
}
func FuzzConfigIdentityImport(f *testing.F) {
	for _, raw := range []string{`{}`, `null`, `{"user_id":"abc"}`, `{"user_id":"abc","USER_ID":"def"}`, `{"user_id":null}`, `{"user_id":"a\u0000b"}`} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		var cfg ConfigFile
		err := json.Unmarshal([]byte(raw), &cfg)
		if err != nil {
			return
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip ConfigFile
		if err := json.Unmarshal(data, &roundtrip); err != nil {
			t.Fatal(err)
		}
		if cfg.UserID != roundtrip.UserID {
			t.Fatal("unstable import")
		}
	})
}

type failedConfigFile struct {
	*os.File
	stage string
}

func (f *failedConfigFile) Write(data []byte) (int, error) {
	if f.stage == "write" {
		return 0, os.ErrPermission
	}
	if f.stage == "short_write" {
		return f.File.Write(data[:len(data)/2])
	}
	return f.File.Write(data)
}
func (f *failedConfigFile) Sync() error {
	if f.stage == "sync" {
		return os.ErrPermission
	}
	return f.File.Sync()
}
func (f *failedConfigFile) Close() error {
	err := f.File.Close()
	if f.stage == "close" {
		return os.ErrPermission
	}
	return err
}
func TestAtomicConfigFaults(t *testing.T) {
	for _, stage := range []string{"create", "write", "short_write", "sync", "close"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			original := []byte(`{"user_id":"original"}`)
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			create := func(dir string) (atomicConfigFile, error) {
				if stage == "create" {
					return nil, os.ErrPermission
				}
				f, err := os.CreateTemp(dir, ".config-*")
				if err != nil {
					return nil, err
				}
				return &failedConfigFile{f, stage}, nil
			}
			if err := writeAtomicFile(path, []byte(`{"user_id":"new"}`), 0o600, false, create); err == nil {
				t.Fatal("injected failure ignored")
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, got) {
				t.Fatalf("original lost: %q %v", got, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary file leaked: %+v %v", entries, err)
			}
		})
	}
}

func TestUserIDCrashAfterCommit(t *testing.T) {
	withHome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUserIDProcessHelper$")
	cmd.Env = append(os.Environ(), "DMG_USER_ID_TEST_HELPER=1", "DMG_USER_ID_TEST_MODE=committed_hold", "DMG_USER_ID_TEST_VALUE=abc")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	gate, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(pipe)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("ready %q %v", line, err)
	}
	if _, err := gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "committed\n" {
			break
		}
	}
	committed := configBytes(t)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := runConfigureNonInteractive(userOpts("abc"), executor.NewMock()); err != nil {
		t.Fatalf("committed retry: %v", err)
	}
	if !bytes.Equal(committed, configBytes(t)) {
		t.Fatal("response-loss retry changed identity")
	}
}

func TestUserIDReadOverrideCannotWriteDefault(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			withHome(t)
			seedUserConfig(t)
			target := WriteConfigFilePath()
			before, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			override := filepath.Join(t.TempDir(), "read-only.json")
			if present {
				if err := os.WriteFile(override, []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			previous := fileOverride
			SetFileOverride(override)
			t.Cleanup(func() { SetFileOverride(previous) })
			if err := runConfigureNonInteractive(userOpts("def"), absentUser()); err == nil {
				t.Fatal("write through read override accepted")
			}
			after, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("default config changed through override: %s %v", after, err)
			}
		})
	}
}
func TestConfiguredDeviceIDInputValidation(t *testing.T) {
	for _, value := range []string{"root", "UnKnOwN", "bad/id", "bad\n", strings.Repeat("a", 257), "new+device@example.com"} {
		t.Run(value, func(t *testing.T) {
			withHome(t)
			seedUserConfig(t)
			before := configBytes(t)
			data, err := json.Marshal(map[string]string{"device_id": value})
			if err != nil {
				t.Fatal(err)
			}
			from := filepath.Join(t.TempDir(), "device.json")
			if err := os.WriteFile(from, data, 0o600); err != nil {
				t.Fatal(err)
			}
			err = runConfigureNonInteractive(NonInteractiveOptions{FromFile: from}, absentUser())
			if value == "new+device@example.com" {
				if err != nil {
					t.Fatal(err)
				}
				got, err := readExistingStrict()
				if err != nil || got.DeviceID != value || got.UserID != "abc" {
					t.Fatalf("device import %+v %v", got, err)
				}
			} else {
				if err == nil {
					t.Fatal("invalid explicit device ID accepted")
				}
				if !bytes.Equal(before, configBytes(t)) {
					t.Fatal("invalid device ID changed config")
				}
			}
		})
	}
}

// A bootstrap file accepted by v1.18.1 still configures: an empty device_id
// clears the override (as "-" does, and as v1.18.1's merge did), null and an
// omitted key keep it, and a literal stored before validation existed stays
// readable. Non-empty values are still validated (above).
func TestFromFileDeviceIDCompatibility(t *testing.T) {
	const creds = `"customer_id":"customer","api_key":"test-key","api_endpoint":"https://example.test"`
	for _, tc := range []struct {
		name, deviceKey, stored, want string
	}{
		{"empty on a fresh install", `,"device_id":""`, "", ""},
		{"blank on a fresh install", `,"device_id":"  "`, "", ""},
		{"null on a fresh install", `,"device_id":null`, "", ""},
		{"case-variant key clears an override", `,"Device_ID":""`, "old-device", ""},
		{"empty clears an override", `,"device_id":""`, "old-device", ""},
		{"null keeps an override", `,"device_id":null`, "old-device", "old-device"},
		{"omitted keeps an override", ``, "old-device", "old-device"},
		{"omitted keeps a legacy literal", ``, "root", "root"},
		{"null keeps a legacy literal", `,"device_id":null`, "root", "root"},
		{"empty clears a legacy literal", `,"device_id":""`, "root", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHome(t)
			if tc.stored != "" {
				if err := save(&ConfigFile{DeviceID: tc.stored, CustomerID: "customer", APIKey: "old-key", APIEndpoint: "https://example.test"}); err != nil {
					t.Fatal(err)
				}
			}
			from := filepath.Join(t.TempDir(), "bootstrap.json")
			if err := os.WriteFile(from, []byte("{"+creds+tc.deviceKey+"}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := runConfigureNonInteractive(NonInteractiveOptions{FromFile: from}, absentUser()); err != nil {
				t.Fatalf("bootstrap file rejected: %v", err)
			}
			got, err := readExistingStrict()
			if err != nil {
				t.Fatal(err)
			}
			if got.DeviceID != tc.want || got.APIKey != "test-key" {
				t.Fatalf("device_id = %q api_key = %q, want device_id %q and the file's credentials", got.DeviceID, got.APIKey, tc.want)
			}
		})
	}
}
