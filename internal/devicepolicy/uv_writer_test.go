package devicepolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const uvExpected = "index-strategy = \"first-index\"\n\n[[index]]\nname = \"stepsecurity\"\nurl = \"https://registry.stepsecurity.io/python/simple\"\ndefault = true\nauthenticate = \"always\""

func TestUVMarkers_Canonical(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"DMG begin", dmgUVBegin, "# BEGIN StepSecurity Package Configuration uv -- managed by dmg"},
		{"DMG end", dmgUVEnd, "# END StepSecurity Package Configuration uv"},
		{"MDM begin", mdmUVBegin, "# BEGIN StepSecurity Package Configuration uv -- managed by mdm"},
		{"MDM end", mdmUVEnd, "# END StepSecurity Package Configuration uv"},
		{"disabled prefix", dmgUVDisabledPrefix, "# [stepsecurity-pypi-uv-dmg] "},
		{"created file", dmgUVCreatedFile, "# [stepsecurity-pypi-uv-dmg] created=true"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("marker = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func newUVTestWriter(t *testing.T, initial []byte, version string) (*UVWriter, *executor.Mock, string) {
	t.Helper()
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, ".config", "uv", "uv.toml")
	if initial != nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, initial, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := newSecureTestHomeAs(t, homeDir, "")
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	if runtime.GOOS == "windows" {
		mock.SetGOOS("windows")
		mock.SetEnv("APPDATA", filepath.Join(homeDir, ".config"))
	}
	mock.SetUsername("")
	mock.SetHomeDir(homeDir)
	probeBase := t.TempDir()
	probeDir := filepath.Join(probeBase, "dmg-uv-probe-test")
	if err := os.Mkdir(probeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mock.SetEnv("TMPDIR", probeBase)
	mock.SetCommand(probeDir, "", 0, "mktemp", "-d", filepath.Join(probeBase, "dmg-uv-probe-XXXXXXXX"))
	if version != "" {
		mock.SetPath("uv", "/opt/bin/uv")
		mock.SetCommand("uv "+version+"\n", "", 0, "uv", "--version")
	}
	writer, err := NewUVWriter(context.Background(), mock, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatalf("NewUVWriter: %v", err)
	}
	writer.exec = mock
	return writer, mock, path
}

func TestUVWriter_TransformsAndRestoresConflicts(t *testing.T) {
	initial := []byte("# keep\nindex-strategy = \"unsafe-best-match\"\ncache-dir = \"/tmp/cache\"\n\n[[index]]\nname = \"private\"\nurl = \"https://private.example/simple\"\ndefault = true\n\n[pip]\nextra-index-url = \"https://extra.example/simple\"\nresolution = \"highest\"\n")
	w, _, path := newUVTestWriter(t, initial, "0.10.0")

	got, err := w.Write(uvExpected)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got != uvExpected {
		t.Fatalf("Write = %q, want %q", got, uvExpected)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{dmgUVBegin, dmgUVEnd} {
		if !bytes.Contains(content, []byte(marker)) {
			t.Errorf("managed output missing marker %q:\n%s", marker, content)
		}
	}
	if bytes.Index(content, []byte(dmgUVBegin)) > bytes.Index(content, []byte("[[index]]")) {
		t.Fatalf("root managed settings appear after first table:\n%s", content)
	}
	for _, line := range []string{
		"index-strategy = \"unsafe-best-match\"",
		"[[index]]",
		"name = \"private\"",
		"url = \"https://private.example/simple\"",
		"default = true",
		"extra-index-url = \"https://extra.example/simple\"",
	} {
		if !bytes.Contains(content, []byte(dmgUVDisabledPrefix+line)) {
			t.Errorf("conflicting line %q was not reversibly disabled:\n%s", line, content)
		}
	}
	if !bytes.Contains(content, []byte("cache-dir = \"/tmp/cache\"")) || !bytes.Contains(content, []byte("resolution = \"highest\"")) {
		t.Fatalf("unrelated TOML was not preserved:\n%s", content)
	}
	if converged, err := w.Converged(uvExpected); err != nil || !converged {
		t.Fatalf("Converged = %v, %v, want true", converged, err)
	}

	changed, err := w.Clear()
	if err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, initial) {
		t.Fatalf("Clear restored:\n%q\nwant:\n%q", restored, initial)
	}
}

func TestUVWriter_PreservesMarkerTextInsideMultilineStrings(t *testing.T) {
	tests := []struct {
		name    string
		opening string
	}{
		{"basic", `"""`},
		{"literal", `'''`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			initial := []byte("message = " + tc.opening + "\nkeep\n" + dmgUVBegin + "\ninside\n" + dmgUVEnd + "\nkeep\n" + tc.opening + "\n")
			w, _, path := newUVTestWriter(t, initial, "0.10.0")
			if _, err := w.Write(uvExpected); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if changed, err := w.Clear(); err != nil || !changed {
				t.Fatalf("Clear = %v, %v, want changed", changed, err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, initial) {
				t.Fatalf("Clear restored:\n%q\nwant:\n%q", got, initial)
			}
		})
	}
}

func TestUVWriter_ClearRejectsInvalidRestoredTOML(t *testing.T) {
	w, _, path := newUVTestWriter(t, []byte("index-strategy = \"unsafe-best-match\"\n"), "0.10.0")
	if _, err := w.Write(uvExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	managed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	managed = bytes.Replace(managed,
		[]byte(dmgUVDisabledPrefix+"index-strategy = \"unsafe-best-match\""),
		[]byte(dmgUVDisabledPrefix+"index-strategy = ["), 1)
	if err := os.WriteFile(path, managed, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.Clear(); err == nil || changed {
		t.Fatalf("Clear = %v, %v, want unchanged error", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, managed) {
		t.Fatal("failed clear changed uv.toml")
	}
}

func TestUVWriter_ClearRestoresOriginalFilePresence(t *testing.T) {
	tests := []struct {
		name    string
		initial []byte
		exists  bool
	}{
		{"created file removed", nil, false},
		{"empty file retained", []byte{}, true},
		{"whitespace file retained", []byte(" \n"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, path := newUVTestWriter(t, tc.initial, "0.10.0")
			if _, err := w.Write(uvExpected); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if changed, err := w.Clear(); err != nil || !changed {
				t.Fatalf("Clear = %v, %v, want changed", changed, err)
			}
			got, err := os.ReadFile(path)
			if !tc.exists {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("ReadFile error = %v, want not exist", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.initial) {
				t.Fatalf("Clear restored %q, want %q", got, tc.initial)
			}
		})
	}
}

func TestUVWriter_CommentedTableHeaderRoundTrips(t *testing.T) {
	initial := []byte("[[index]] # user index\nname = \"private\"\nurl = \"https://private.example/simple\"\ndefault = true\n")
	w, _, path := newUVTestWriter(t, initial, "0.10.0")
	if _, err := w.Write(uvExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	changed, err := w.Clear()
	if err != nil || !changed {
		t.Fatalf("Clear = %v, %v", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatalf("round trip = %q, want %q", got, initial)
	}
}

func TestUVWriter_PreservesBOMCRLFAndIsIdempotent(t *testing.T) {
	initial := append([]byte{0xef, 0xbb, 0xbf}, []byte("cache-dir = \"cache\"\r\n")...)
	w, _, path := newUVTestWriter(t, initial, "0.10.0")
	if _, err := w.Write(uvExpected); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(first, []byte{0xef, 0xbb, 0xbf}) || bytes.Contains(bytes.ReplaceAll(first, []byte("\r\n"), nil), []byte("\n")) {
		t.Fatalf("BOM or CRLF style not preserved: %q", first)
	}
	if _, err := w.Write(uvExpected); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("idempotent write changed bytes")
	}
}

func TestUVWriter_RefusesMalformedAmbiguousAndMDMContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"malformed TOML", "cache-dir = [\n"},
		{"duplicate key", "cache-dir = \"a\"\ncache-dir = \"b\"\n"},
		{"duplicate marker", dmgUVBegin + "\n" + dmgUVEnd + "\n" + dmgUVBegin + "\n" + dmgUVEnd + "\n"},
		{"reversed marker", dmgUVEnd + "\n" + dmgUVBegin + "\n"},
		{"nested marker", dmgUVBegin + "\n" + dmgUVBegin + "\n" + dmgUVEnd + "\n" + dmgUVEnd + "\n"},
		{"mixed owner markers", dmgUVBegin + "\n" + mdmUVBegin + "\n" + dmgUVEnd + "\n"},
		{"incomplete marker", dmgUVBegin + "\nindex-strategy = \"first-index\"\n"},
		{"overlapping multiline conflict", "index-strategy = \"\"\"first-index\ncontinued\"\"\"\n"},
		{"MDM marker", mdmUVBegin + "\nindex-strategy = \"first-index\"\n" + mdmUVEnd + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, path := newUVTestWriter(t, []byte(tc.content), "0.10.0")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(uvExpected); err == nil {
				t.Fatal("Write succeeded, want refusal")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("refused write changed file")
			}
		})
	}
}

type failedUserEnvironmentExecutor struct {
	executor.Executor
}

func (e *failedUserEnvironmentExecutor) RunAsUser(context.Context, string, string) (string, error) {
	return "", context.DeadlineExceeded
}

type uvUserContextExecutor struct {
	*executor.Mock
	userEnv      string
	showSettings string
	tempBase     string
	createdDir   string
	mktempResult string
	runErr       error
	mktempCalled bool
}

func (e *uvUserContextExecutor) RunAsUser(_ context.Context, _, command string) (string, error) {
	switch {
	case strings.Contains(command, "XDG_CONFIG_HOME") && strings.Contains(command, "UV_INDEX_URL"):
		return e.userEnv, nil
	case command == "which 'uv'":
		return "/opt/bin/uv", nil
	case command == "'uv' '--version'":
		return "uv 0.10.0", nil
	case strings.HasPrefix(command, "'mktemp' '-d' "):
		e.mktempCalled = true
		if e.mktempResult != "" {
			return e.mktempResult, nil
		}
		dir, err := os.MkdirTemp(e.tempBase, "dmg-uv-probe-")
		e.createdDir = dir
		return dir, err
	case strings.HasPrefix(command, "cd "):
		if e.runErr != nil {
			return "", e.runErr
		}
		info, err := os.Stat(e.createdDir)
		if err != nil {
			return "", err
		}
		if info.Mode().Perm() != 0o700 {
			return "", fmt.Errorf("probe directory mode = %o", info.Mode().Perm())
		}
		return e.showSettings, nil
	default:
		return "", fmt.Errorf("unexpected user command %q", command)
	}
}

func newResolvedUserUVWriter(t *testing.T, userEnv, showSettings string) (*UVWriter, *uvUserContextExecutor, string) {
	t.Helper()
	homeDir := t.TempDir()
	home := newSecureTestHomeAs(t, homeDir, "alice")
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("alice")
	mock.SetHomeDir(homeDir)
	mock.SetEnv("XDG_CONFIG_HOME", filepath.Join(homeDir, "service-xdg"))
	tempBase := t.TempDir()
	userEnv = strings.ReplaceAll(userEnv, "{HOME}", homeDir)
	userEnv = strings.ReplaceAll(userEnv, "{TMP}", tempBase)
	inner := &uvUserContextExecutor{Mock: mock, userEnv: userEnv, showSettings: showSettings, tempBase: tempBase}
	writer, err := NewUVWriter(context.Background(), inner, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatalf("NewUVWriter: %v", err)
	}
	return writer, inner, homeDir
}

func TestUVWriter_UsesResolvedUserEnvironment(t *testing.T) {
	writer, _, resolvedHome := newResolvedUserUVWriter(t,
		"XDG_CONFIG_HOME={HOME}/user-xdg\x00UV_INDEX_URL=https://override.example/simple\x00",
		"")
	want := filepath.Join(resolvedHome, "user-xdg", "uv", "uv.toml")
	if got := writer.Location(); got != want {
		t.Fatalf("Location = %q, want resolved-user path %q", got, want)
	}
	if _, err := writer.Write(uvExpected); err != nil {
		t.Fatal(err)
	}
	observation, err := writer.Observation(context.Background(), uvExpected)
	if err != nil {
		t.Fatal(err)
	}
	if observation.OverrideSource != "environment" || observation.EffectiveStatus != "mismatch" {
		t.Fatalf("Observation = %+v, want resolved-user environment override", observation)
	}
}

func TestUVObservation_ParsesRealSettingsInTargetUserDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("target-user shell probing is Unix-only")
	}
	fixture, err := os.ReadFile(filepath.Join("testdata", "uv-show-settings-0.12.6.txt"))
	if err != nil {
		t.Fatal(err)
	}
	writer, inner, _ := newResolvedUserUVWriter(t, "TMPDIR={TMP}\x00", string(fixture))
	if _, err := writer.Write(uvExpected); err != nil {
		t.Fatal(err)
	}
	observation, err := writer.Observation(context.Background(), uvExpected)
	if err != nil {
		t.Fatal(err)
	}
	if observation.EffectiveStatus != "match" {
		t.Fatalf("Observation = %+v, want effective match", observation)
	}
	if !inner.mktempCalled {
		t.Fatal("uv probe directory was not created through the target-user executor")
	}
	if _, err := os.Stat(inner.createdDir); !os.IsNotExist(err) {
		t.Fatalf("probe directory remains after observation: %v", err)
	}
}

func TestUVProbeDirectory_DoesNotRemoveRejectedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("target-user mktemp probing is Unix-only")
	}
	writer, inner, _ := newResolvedUserUVWriter(t, "TMPDIR={TMP}\x00", "")
	victim := t.TempDir()
	sentinel := filepath.Join(victim, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	inner.mktempResult = victim

	if _, _, err := writer.probeDirectory(context.Background()); err == nil {
		t.Fatal("probeDirectory error = nil, want escaped-path refusal")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("rejected path was modified: %q, %v", got, err)
	}
}

func TestUVProbeSettings_RemovesTrustedDirectoryAfterCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("target-user mktemp probing is Unix-only")
	}
	writer, inner, _ := newResolvedUserUVWriter(t, "TMPDIR={TMP}\x00", "")
	inner.runErr = context.Canceled

	status, source, _ := writer.probeSettings(context.Background())
	if status != "unknown" || source != "unknown" {
		t.Fatalf("probeSettings = %q, %q, want unknown", status, source)
	}
	if _, err := os.Stat(inner.createdDir); !os.IsNotExist(err) {
		t.Fatalf("trusted probe directory remains after cancellation: %v", err)
	}
}

func TestParseUVShowSettings_RealFixture(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "uv-show-settings-0.12.6.txt"))
	if err != nil {
		t.Fatal(err)
	}
	status, registry := parseUVShowSettings(string(fixture), "https://registry.stepsecurity.io/python/simple")
	if status != "match" || registry != "https://registry.stepsecurity.io/python/simple" {
		t.Fatalf("parseUVShowSettings = %q, %q", status, registry)
	}
}

func TestParseUVVersion_StrictStableSemver(t *testing.T) {
	tests := []struct {
		output    string
		valid     bool
		supported bool
	}{
		{"uv 0.9.9", true, false},
		{"uv 0.10.0", true, true},
		{"uv 0.10.0-rc.1", false, false},
		{"uv 0.12.6 (7938ca5d5 2026-08-25 aarch64-apple-darwin)", true, true},
		{"uv 0.10", false, false},
		{"uv 0.10.0.1", false, false},
		{"changed format", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.output, func(t *testing.T) {
			major, minor, patch, valid := parseUVVersion(tc.output)
			if valid != tc.valid {
				t.Fatalf("parseUVVersion(%q) valid = %v, want %v", tc.output, valid, tc.valid)
			}
			if supported := valid && uvVersionAtLeast(major, minor, patch, 0, 10, 0); supported != tc.supported {
				t.Fatalf("parseUVVersion(%q) supported = %v, want %v", tc.output, supported, tc.supported)
			}
		})
	}
}

func TestUVWriter_JoinsVerificationAndRollbackFailures(t *testing.T) {
	w, _, _ := newUVTestWriter(t, nil, "0.10.0")
	w.registryURL = "https://different.example/simple"
	rollbackErr := errors.New("rollback failed")
	w.restoreSnapshot = func() error { return rollbackErr }
	if _, err := w.Write(uvExpected); !errors.Is(err, rollbackErr) || !strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("Write error = %v, want verification and rollback failures", err)
	}
}

func TestUVWriter_ClearRollsBackCleanupFailure(t *testing.T) {
	initial := []byte("cache-dir = \"keep\"\n")
	w, _, path := newUVTestWriter(t, initial, "0.10.0")
	if _, err := w.Write(uvExpected); err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("cleanup failed")
	w.purgeBackups = func() error { return cleanupErr }
	changed, err := w.Clear()
	if changed || !errors.Is(err, cleanupErr) {
		t.Fatalf("Clear = %v, %v, want rolled-back cleanup failure", changed, err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(got, []byte(dmgUVBegin)) || !bytes.Contains(got, []byte(dmgUVEnd)) {
		t.Fatalf("clear cleanup failure did not restore managed file:\n%s", got)
	}
}

func TestUVWriter_MDMOwnershipRejectsOtherLanes(t *testing.T) {
	tests := []struct {
		name    string
		initial string
	}{
		{"unmarked", uvExpected + "\n"},
		{"DMG marker", dmgUVBegin + "\n" + uvExpected + "\n" + dmgUVEnd + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, _ := newUVTestWriter(t, []byte(tc.initial), "0.10.0")
			owned, err := w.MDMOwned()
			if err != nil {
				t.Fatal(err)
			}
			if owned {
				t.Fatal("MDMOwned = true, want false")
			}
		})
	}
}

func TestUVObservation_AcceptsValidMDMMarkers(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "uv-show-settings-0.12.6.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mdm := []byte(mdmUVBegin + "\nindex-strategy = \"first-index\"\n\n[[index]]\nname = \"stepsecurity\"\nurl = \"https://registry.stepsecurity.io/python/simple\"\ndefault = true\nauthenticate = \"always\"\n" + mdmUVEnd + "\n")
	w, mock, _ := newUVTestWriter(t, mdm, "0.10.0")
	if owned, err := w.MDMOwned(); err != nil || !owned {
		t.Fatalf("MDMOwned = %v, %v, want true", owned, err)
	}
	mock.SetCommand(string(fixture), "", 0, "uv", "pip", "install", "--show-settings", uvProbePackage)
	observation, err := w.Observation(context.Background(), uvExpected)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ConfigStatus != "match" || observation.EffectiveStatus != "match" {
		t.Fatalf("Observation = %+v, want valid MDM match", observation)
	}
}

func TestNewUVWriter_UserEnvironmentFailureIsError(t *testing.T) {
	homeDir := t.TempDir()
	home := newSecureTestHomeAs(t, homeDir, "alice")
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHomeDir(homeDir)
	inner := &failedUserEnvironmentExecutor{Executor: mock}
	if _, err := NewUVWriter(context.Background(), inner, home, netrcTestPolicy(t)); err == nil {
		t.Fatal("NewUVWriter() error = nil, want environment inspection failure")
	}
}

func TestNewUVWriter_CanceledContextIsError(t *testing.T) {
	homeDir := t.TempDir()
	home := newSecureTestHomeAs(t, homeDir, "alice")
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHomeDir(homeDir)
	inner := &uvUserContextExecutor{Mock: mock, tempBase: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewUVWriter(ctx, inner, home, netrcTestPolicy(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("NewUVWriter() error = %v, want context.Canceled", err)
	}
}

func TestUVWriter_VersionBoundaryAndPaths(t *testing.T) {
	t.Run("unsupported installed uv remains untouched", func(t *testing.T) {
		initial := []byte("cache-dir = \"keep\"\n")
		w, _, path := newUVTestWriter(t, initial, "0.9.11")
		if _, err := w.Write(uvExpected); err == nil {
			t.Fatal("Write succeeded for unsupported uv")
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, initial) {
			t.Fatal("unsupported uv configuration changed")
		}
	})

	t.Run("XDG path", func(t *testing.T) {
		w, _, homeDir := newResolvedUserUVWriter(t, "XDG_CONFIG_HOME={HOME}/xdg\x00", "")
		if got, want := w.Location(), filepath.Join(homeDir, "xdg", "uv", "uv.toml"); got != want {
			t.Fatalf("Location = %q, want %q", got, want)
		}
	})

	t.Run("Windows APPDATA path", func(t *testing.T) {
		homeDir := t.TempDir()
		appData := filepath.Join(homeDir, "AppData", "Roaming")
		home := newSecureTestHome(t, homeDir)
		mock := executor.NewMock()
		mock.SetGOOS("windows")
		mock.SetHomeDir(homeDir)
		mock.SetEnv("APPDATA", appData)
		w, err := NewUVWriter(context.Background(), mock, home, netrcTestPolicy(t))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := w.Location(), filepath.Join(appData, "uv", "uv.toml"); got != want {
			t.Fatalf("Location = %q, want %q", got, want)
		}
	})

	t.Run("resolved user executor", func(t *testing.T) {
		homeDir := t.TempDir()
		home := newSecureTestHomeAs(t, homeDir, "alice")
		mock := executor.NewMock()
		mock.SetGOOS("darwin")
		mock.SetHomeDir(homeDir)
		inner := &uvUserContextExecutor{Mock: mock, tempBase: t.TempDir()}
		w, err := NewUVWriter(context.Background(), inner, home, netrcTestPolicy(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := w.exec.(*executor.UserAwareExecutor); !ok {
			t.Fatalf("executor = %T, want *executor.UserAwareExecutor", w.exec)
		}
	})
}

func TestUVObservation_UserEnvironmentFailureIsUnknown(t *testing.T) {
	w, mock, _ := newUVTestWriter(t, nil, "0.10.0")
	if _, err := w.Write(uvExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	mock.SetGOOS("linux")
	w.exec = executor.NewUserAwareExecutor(&failedUserEnvironmentExecutor{Executor: mock}, "alice")
	got, err := w.Observation(context.Background(), uvExpected)
	if err == nil {
		t.Fatal("Observation error = nil, want environment inspection failure")
	}
	if got.EffectiveStatus != "unknown" || got.OverrideSource != "unknown" {
		t.Fatalf("Observation = %+v, want unknown environment", got)
	}
}

func TestUVObservation_VersionsAndOverrides(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "uv-show-settings-0.12.6.txt"))
	if err != nil {
		t.Fatal(err)
	}
	showSettings := string(fixture)
	userinfoSettings := strings.Replace(showSettings,
		"https://registry.stepsecurity.io/python/simple",
		"https://user:SECRET@evil.example/simple", 1)
	tests := []struct {
		name          string
		version       string
		configure     func(*executor.Mock)
		showSettings  string
		wantConfig    string
		wantEffective string
		wantOverride  string
	}{
		{"uv absent", "", func(*executor.Mock) {}, "", "match", "not_installed", "none"},
		{"uv below minimum", "0.9.11", func(*executor.Mock) {}, "", "absent", "unsupported_version", "none"},
		{"uv prerelease", "0.10.0-rc.1", func(*executor.Mock) {}, "", "absent", "unsupported_version", "none"},
		{"uv minimum", "0.10.0", func(*executor.Mock) {}, showSettings, "match", "match", "none"},
		{"environment", "0.10.0", func(m *executor.Mock) { m.SetEnv("UV_INDEX_URL", "https://user:SECRET@evil.example/simple") }, "", "match", "mismatch", "environment"},
		{"explicit config", "0.10.0", func(m *executor.Mock) { m.SetEnv("UV_CONFIG_FILE", "/tmp/secret") }, "", "match", "mismatch", "explicit_config"},
		{"netrc override", "0.10.0", func(m *executor.Mock) { m.SetEnv("NETRC", "/tmp/secret") }, "", "match", "mismatch", "environment"},
		{"unknown output", "0.10.0", func(*executor.Mock) {}, "changed format\n", "match", "unknown", "unknown"},
		{"userinfo output", "0.10.0", func(*executor.Mock) {}, userinfoSettings, "match", "mismatch", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, mock, _ := newUVTestWriter(t, nil, tc.version)
			if tc.wantEffective != "unsupported_version" {
				if _, err := w.Write(uvExpected); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
			tc.configure(mock)
			if tc.version >= "0.10.0" && tc.showSettings != "" {
				mock.SetCommand(tc.showSettings, "", 0, "uv", "pip", "install", "--show-settings", "stepsecurity-policy-probe")
			}
			got, err := w.Observation(context.Background(), uvExpected)
			if err != nil {
				t.Fatalf("Observation: %v", err)
			}
			if got.ConfigStatus != tc.wantConfig || got.EffectiveStatus != tc.wantEffective || got.OverrideSource != tc.wantOverride {
				t.Fatalf("Observation = %+v, want config=%s effective=%s override=%s", got, tc.wantConfig, tc.wantEffective, tc.wantOverride)
			}
			if strings.Contains(got.RegistryURL, "SECRET") {
				t.Fatalf("Observation leaked URL userinfo: %+v", got)
			}
			if tc.name == "userinfo output" && got.RegistryURL != "" {
				t.Fatalf("userinfo registry URL = %q, want empty", got.RegistryURL)
			}
		})
	}
}
