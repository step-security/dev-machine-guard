package devicepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

const goEnvExpected = "GOPROXY=https://registry.stepsecurity.io/go"

func goTestPolicy(t *testing.T) GoPolicy {
	t.Helper()
	policy, err := ParseGoPolicy(json.RawMessage(validGoPolicyJSON()), "device-1")
	if err != nil {
		t.Fatalf("ParseGoPolicy: %v", err)
	}
	return policy
}

func newGoEnvTestWriter(t *testing.T, initial []byte) (*GoEnvWriter, *executor.Mock, string) {
	t.Helper()
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, ".config", "go", "env")
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
	mock.SetGOOS(model.PlatformLinux)
	mock.SetUsername("")
	mock.SetHomeDir(homeDir)
	w, err := NewGoEnvWriter(mock, home, goTestPolicy(t))
	if err != nil {
		t.Fatalf("NewGoEnvWriter: %v", err)
	}
	w.exec = mock
	return w, mock, path
}

func TestGoEnvWriter_TransformsAndExactlyRestores(t *testing.T) {
	private := "GOPRIVATE=corp.example/*\nGONOPROXY=corp.example/*\nGONOSUMDB=corp.example/*\nGOSUMDB=sum.golang.org"
	cases := map[string][]byte{
		"empty existing": {},
		"LF final":       []byte("# keep\nGOPROXY=https://proxy.golang.org,direct\n" + private + "\n"),
		"LF no final":    []byte("# keep\nGOPROXY=https://proxy.golang.org\nGOPROXY=direct\n" + private),
		"CRLF":           []byte(strings.ReplaceAll("# keep\nGOPROXY=https://proxy.golang.org\n"+private+"\n", "\n", "\r\n")),
		"BOM":            append([]byte{0xef, 0xbb, 0xbf}, []byte("# keep\n"+private+"\n")...),
	}
	for name, initial := range cases {
		t.Run(name, func(t *testing.T) {
			w, _, path := newGoEnvTestWriter(t, initial)
			if got, err := w.Write(goEnvExpected); err != nil || got != goEnvExpected {
				t.Fatalf("Write = %q, %v", got, err)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(content, []byte(dmgGoEnvBegin)) != 1 || bytes.Count(content, []byte(goEnvExpected)) != 1 {
				t.Fatalf("managed block is not canonical:\n%s", content)
			}
			for _, line := range []string{"GOPRIVATE=", "GONOPROXY=", "GONOSUMDB=", "GOSUMDB="} {
				if bytes.Count(content, []byte(line)) != bytes.Count(initial, []byte(line)) {
					t.Fatalf("%s changed:\n%s", line, content)
				}
			}
			if ok, err := w.Converged(goEnvExpected); err != nil || !ok {
				t.Fatalf("Converged = %v, %v", ok, err)
			}
			changed, err := w.Clear()
			if err != nil || !changed {
				t.Fatalf("Clear = %v, %v", changed, err)
			}
			restored, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restored, initial) {
				t.Fatalf("restored %q, want %q", restored, initial)
			}
			if changed, err := w.Clear(); err != nil || changed {
				t.Fatalf("second Clear = %v, %v", changed, err)
			}
		})
	}
}

func TestRewriteGoEnv_PreservesManagedOnlyCRLF(t *testing.T) {
	initial := []byte(dmgGoEnvBegin + "\r\n" + goEnvExpected + "\r\n" + goEnvEnd + "\r\n")
	got, err := rewriteGoEnv(initial, goEnvExpected, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatalf("rewriteGoEnv = %q, want %q", got, initial)
	}
}

func TestRewriteGoEnv_NormalizesCRLFAndExactlyRestores(t *testing.T) {
	initial := []byte("# keep\r\nGOPROXY=https://proxy.golang.org\r\nGOPRIVATE=corp.example/*\r\n")
	first, err := rewriteGoEnv(initial, goEnvExpected, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, []byte("\r")) || !bytes.Contains(first, []byte("# [stepsecurity-go-env-dmg] restore-crlf=true")) {
		t.Fatalf("rewriteGoEnv did not normalize CRLF with restoration metadata: %q", first)
	}
	second, err := rewriteGoEnv(first, goEnvExpected, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, first) {
		t.Fatalf("repeated rewrite = %q, want %q", second, first)
	}
	restored, changed, err := clearGoEnv(first)
	if err != nil || !changed {
		t.Fatalf("clearGoEnv = %q, %v, %v", restored, changed, err)
	}
	if !bytes.Equal(restored, initial) {
		t.Fatalf("clearGoEnv = %q, want %q", restored, initial)
	}
}

func TestGoEnvWriter_CreatedFileIsRemovedOnClear(t *testing.T) {
	w, _, path := newGoEnvTestWriter(t, nil)
	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.Clear(); err != nil || !changed {
		t.Fatalf("Clear = %v, %v", changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("created file remains: %v", err)
	}
}

func TestGoEnvWriter_CleanHomePlatformPaths(t *testing.T) {
	for _, goos := range []string{model.PlatformLinux, model.PlatformDarwin, model.PlatformWindows} {
		t.Run(goos, func(t *testing.T) {
			homeDir := t.TempDir()
			home := newSecureTestHomeAs(t, homeDir, "")
			mock := executor.NewMock()
			mock.SetGOOS(goos)
			if goos == model.PlatformWindows {
				mock.SetEnv("APPDATA", filepath.Join(homeDir, "AppData", "Roaming"))
			}
			w, err := NewGoEnvWriter(mock, home, goTestPolicy(t))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(goEnvExpected); err != nil {
				t.Fatal(err)
			}
			want, err := goUserEnvPath(mock, homeDir)
			if err != nil {
				t.Fatal(err)
			}
			if w.Location() != want {
				t.Fatalf("Location = %q, want %q", w.Location(), want)
			}
		})
	}
}

type noGoCommandExecutor struct {
	executor.Executor
	calls int
}

func (e *noGoCommandExecutor) Run(context.Context, string, ...string) (string, string, int, error) {
	e.calls++
	return "", "", 1, errors.New("unexpected command")
}

func (e *noGoCommandExecutor) RunWithTimeout(context.Context, time.Duration, string, ...string) (string, string, int, error) {
	e.calls++
	return "", "", 1, errors.New("unexpected command")
}

func (e *noGoCommandExecutor) RunInDir(context.Context, string, time.Duration, string, ...string) (string, string, int, error) {
	e.calls++
	return "", "", 1, errors.New("unexpected command")
}

func (e *noGoCommandExecutor) RunAsUser(context.Context, string, string) (string, error) {
	e.calls++
	return "", errors.New("unexpected command")
}

func (e *noGoCommandExecutor) LookPath(string) (string, error) {
	e.calls++
	return "", errors.New("unexpected command")
}

func TestGoEnvWriter_NeverLocatesOrExecutesGo(t *testing.T) {
	homeDir := t.TempDir()
	home := newSecureTestHomeAs(t, homeDir, "")
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformLinux)
	exec := &noGoCommandExecutor{Executor: mock}
	w, err := NewGoEnvWriter(exec, home, goTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Observation(goEnvExpected, filepath.Join(homeDir, ".netrc")); err != nil {
		t.Fatal(err)
	}
	if exec.calls != 0 {
		t.Fatalf("Go enforcement made %d external command calls", exec.calls)
	}
}

func TestGoEnvWriter_RepairsDriftAndPreservesPrivateSettings(t *testing.T) {
	initial := []byte("GOPRIVATE=secret.example/*\nGOPROXY=https://proxy.golang.org\n")
	w, _, path := newGoEnvTestWriter(t, initial)
	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("GOPROXY=https://proxy.golang.org|direct\n")
	_ = f.Close()
	if ok, err := w.Converged(goEnvExpected); err != nil || ok {
		t.Fatalf("Converged after drift = %v, %v", ok, err)
	}
	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if bytes.Count(content, []byte("GOPRIVATE=secret.example/*")) != 1 || !bytes.Contains(content, []byte(dmgGoEnvDisabledPrefix+"GOPROXY=https://proxy.golang.org|direct")) {
		t.Fatalf("drift repair changed unrelated data:\n%s", content)
	}
}

func TestGoEnvWriter_RejectsAmbiguousInput(t *testing.T) {
	cases := map[string][]byte{
		"invalid UTF-8":           {0xff},
		"NUL":                     []byte("GOPROXY=x\x00"),
		"lone CR":                 []byte("GOPROXY=x\rnext"),
		"mixed newline":           []byte("one\r\ntwo\n"),
		"orphan prefix":           []byte(dmgGoEnvDisabledPrefix + "GOPROXY=direct\n"),
		"incomplete":              []byte(dmgGoEnvBegin + "\n" + goEnvExpected + "\n"),
		"duplicate":               []byte(dmgGoEnvBegin + "\n" + goEnvExpected + "\n" + goEnvEnd + "\n" + dmgGoEnvBegin + "\n" + goEnvExpected + "\n" + goEnvEnd),
		"mixed owner":             []byte(mdmGoEnvBegin + "\n" + goEnvExpected + "\n" + goEnvEnd + "\n" + dmgGoEnvDisabledPrefix + "GOPROXY=direct"),
		"old CRLF marker":         []byte(dmgGoEnvBegin + "\n# [stepsecurity-go-env-dmg] newline=crlf\n" + goEnvExpected + "\n" + goEnvEnd),
		"duplicate values":        []byte(dmgGoEnvBegin + "\nGOPROXY=direct\n# GOPROXY=direct\n" + goEnvEnd),
		"unrelated managed value": []byte(dmgGoEnvBegin + "\nGOPRIVATE=example.test\n" + goEnvEnd),
		"empty MDM block":         []byte(mdmGoEnvBegin + "\n" + goEnvEnd),
		"commented MDM value":     []byte(mdmGoEnvBegin + "\n# GOPROXY=direct\n" + goEnvEnd),
		"oversized":               bytes.Repeat([]byte("x"), (1<<20)+1),
	}
	for name, initial := range cases {
		t.Run(name, func(t *testing.T) {
			w, _, path := newGoEnvTestWriter(t, initial)
			before, _ := os.ReadFile(path)
			if _, err := w.Write(goEnvExpected); err == nil {
				t.Fatal("Write() error = nil")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, before) {
				t.Fatal("rejected input was mutated")
			}
		})
	}
}

func TestGoEnvWriter_RejectsNonGOPROXYDisabledPayloadOnEnforceAndClear(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
		begin  string
	}{
		{"DMG", dmgGoEnvDisabledPrefix, dmgGoEnvBegin},
		{"MDM", mdmGoEnvDisabledPrefix, mdmGoEnvBegin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initial := []byte(tc.prefix + "GONOPROXY=corp.example\n" + tc.begin + "\n" + goEnvExpected + "\n" + goEnvEnd + "\n")
			w, _, path := newGoEnvTestWriter(t, initial)
			if err := w.ValidateTarget(); err == nil {
				t.Fatal("ValidateTarget() error = nil")
			}
			if changed, err := w.Clear(); err == nil || changed {
				t.Fatalf("Clear = %v, %v, want rejection", changed, err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, initial) {
				t.Fatal("rejected disabled payload was mutated")
			}
		})
	}
}

func TestGoEnvWriter_ObservesExactMDMShapeWithoutWriting(t *testing.T) {
	initial := []byte(strings.Join([]string{
		"GOPROXY=https://prior.example/go",
		mdmGoEnvDisabledPrefix + "GOPROXY=https://proxy.golang.org",
		mdmGoEnvBegin,
		mdmGoEnvRestoreCRLF,
		goEnvExpected,
		goEnvEnd,
		"GOPRIVATE=corp.example/*",
		"",
	}, "\n"))
	w, _, path := newGoEnvTestWriter(t, initial)
	hardenSecureTestFile(t, w.file)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := w.MDMOwned()
	if err != nil || !owned {
		t.Fatalf("MDMOwned = %v, %v", owned, err)
	}
	observed, err := w.Observation(goEnvExpected, filepath.Join(w.home.Path(), ".netrc"))
	if err != nil || observed.ConfigStatus != "match" || observed.EffectiveStatus != "match" || observed.OverrideSource != "none" {
		t.Fatalf("Observation = %#v, %v", observed, err)
	}
	if _, err := w.Write(goEnvExpected); err == nil {
		t.Fatal("Write() error = nil with MDM ownership")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatal("MDM inspection mutated the file")
	}

	if err := os.WriteFile(path, append(after, []byte("GOPROXY=https://proxy.golang.org\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	hardenSecureTestFile(t, w.file)
	observed, err = w.Observation(goEnvExpected, filepath.Join(w.home.Path(), ".netrc"))
	if err != nil || observed.ConfigStatus != "mismatch" {
		t.Fatalf("active line after MDM block = %#v, %v", observed, err)
	}
}

func TestScanGoEnv_MDMRestoreCRLFMarker(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"inside MDM block", mdmGoEnvBegin + "\n" + mdmGoEnvRestoreCRLF + "\n" + goEnvExpected + "\n" + goEnvEnd, false},
		{"outside block", mdmGoEnvRestoreCRLF + "\n" + mdmGoEnvBegin + "\n" + goEnvExpected + "\n" + goEnvEnd, true},
		{"inside DMG block", dmgGoEnvBegin + "\n" + mdmGoEnvRestoreCRLF + "\n" + goEnvExpected + "\n" + goEnvEnd, true},
		{"duplicated", mdmGoEnvBegin + "\n" + mdmGoEnvRestoreCRLF + "\n" + mdmGoEnvRestoreCRLF + "\n" + goEnvExpected + "\n" + goEnvEnd, true},
		{"different value", mdmGoEnvBegin + "\n# [stepsecurity-go-env-mdm] restore-crlf=false\n" + goEnvExpected + "\n" + goEnvEnd, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			analysis, err := scanGoEnv([]byte(tc.content))
			if (err != nil) != tc.wantErr {
				t.Fatalf("scanGoEnv() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && (analysis.owner != "mdm" || !analysis.restoreCRLF) {
				t.Fatalf("scanGoEnv() = %+v, want MDM CRLF restoration", analysis)
			}
		})
	}
}

func TestGoUserEnvPath(t *testing.T) {
	home := t.TempDir()
	externalRoot := t.TempDir()
	cases := []struct {
		name, goos, xdg, appdata, want string
		wantErr                        bool
	}{
		{"linux default", model.PlatformLinux, "", "", filepath.Join(home, ".config", "go", "env"), false},
		{"linux XDG", model.PlatformLinux, filepath.Join(home, "xdg"), "", filepath.Join(home, "xdg", "go", "env"), false},
		{"linux XDG trailing separator", model.PlatformLinux, filepath.Join(home, "xdg") + string(filepath.Separator), "", filepath.Join(home, "xdg", "go", "env"), false},
		{"darwin", model.PlatformDarwin, "", "", filepath.Join(home, "Library", "Application Support", "go", "env"), false},
		{"windows AppData", model.PlatformWindows, "", filepath.Join(home, "AppData", "Roaming"), filepath.Join(home, "AppData", "Roaming", "go", "env"), false},
		{"windows AppData trailing separator", model.PlatformWindows, "", filepath.Join(home, "AppData", "Roaming") + string(filepath.Separator), filepath.Join(home, "AppData", "Roaming", "go", "env"), false},
		{"external XDG", model.PlatformLinux, externalRoot, "", "", true},
		{"normalized AppData", model.PlatformWindows, "", filepath.Join(home, "AppData", "..", "Roaming"), filepath.Join(home, "Roaming", "go", "env"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS(tc.goos)
			mock.SetEnv("XDG_CONFIG_HOME", tc.xdg)
			mock.SetEnv("APPDATA", tc.appdata)
			got, err := goUserEnvPath(mock, home)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("goUserEnvPath = %q, %v; want %q, err=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestGoEnvObservationOverrides(t *testing.T) {
	w, mock, _ := newGoEnvTestWriter(t, nil)
	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, goproxy, goenv, netrc, goauth, status, source string
	}{
		{"none", "", "", "", "", "match", "none"},
		{"matching environment", w.registryURL, "", "", "", "match", "environment"},
		{"mismatching environment", "https://proxy.golang.org", "", "", "", "mismatch", "environment"},
		{"GOENV off", "", "off", "", "", "mismatch", "goenv"},
		{"relative GOENV", "", "relative-goenv", "", "", "mismatch", "goenv"},
		{"managed GOENV", "", w.Location(), "", "", "match", "none"},
		{"NETRC", "", "", filepath.Join(filepath.Dir(w.home.Path()), "other"), "", "mismatch", "netrc"},
		{"relative NETRC", "", "", "relative-netrc", "", "mismatch", "netrc"},
		{"managed NETRC", "", "", filepath.Join(w.home.Path(), ".netrc"), "", "match", "none"},
		{"GOAUTH netrc", "", "", "", "netrc", "match", "none"},
		{"GOAUTH off", "", "", "", "off", "unknown", "goauth"},
		{"multiple", "https://proxy.golang.org", "off", "", "", "mismatch", "multiple"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock.SetEnv("GOPROXY", tc.goproxy)
			mock.SetEnv("GOENV", tc.goenv)
			mock.SetEnv("NETRC", tc.netrc)
			mock.SetEnv("GOAUTH", tc.goauth)
			got, err := w.Observation(goEnvExpected, filepath.Join(w.home.Path(), ".netrc"))
			if err != nil || got.EffectiveStatus != tc.status || got.OverrideSource != tc.source {
				t.Fatalf("Observation = %#v, %v", got, err)
			}
		})
	}
}

type failingGoEnvExecutor struct{ executor.Executor }

func (failingGoEnvExecutor) RunAsUser(context.Context, string, string) (string, error) {
	return "", errors.New("environment capture failed")
}

type filesystemStatExecutor struct{ executor.Executor }

func (filesystemStatExecutor) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }

func TestGoEnvObservationCaptureFailureIsUnknown(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("Windows environment capture is supplied directly by the executor")
	}
	w, _, _ := newGoEnvTestWriter(t, nil)
	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	inner := executor.NewMock()
	inner.SetGOOS(model.PlatformLinux)
	w.exec = executor.NewUserAwareExecutor(failingGoEnvExecutor{Executor: inner}, "alice")
	observed, err := w.Observation(goEnvExpected, filepath.Join(w.home.Path(), ".netrc"))
	if err == nil || observed.EffectiveStatus != "unknown" || observed.OverrideSource != "unknown" {
		t.Fatalf("Observation = %#v, %v", observed, err)
	}
}

func TestSiblingMarkerChecksFailClosedOnUserEnvironmentCaptureFailure(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("Windows reads the target-user environment directly")
	}
	home := newSecureTestHomeAs(t, t.TempDir(), "alice")
	inner := executor.NewMock()
	inner.SetGOOS(model.PlatformLinux)
	exec := failingGoEnvExecutor{Executor: inner}
	for name, check := range map[string]func(executor.Executor, *secureuserfile.Home) (bool, error){
		"PyPI": hasPyPIDMGMarker,
		"Go":   hasGoDMGMarker,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := check(exec, home); err == nil {
				t.Fatal("sibling marker check error = nil")
			}
		})
	}
}

func TestGoSiblingMarkerOnDarwinDoesNotRequireEnvironmentCapture(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("Windows environment capture is supplied directly by the executor")
	}
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, "Library", "Application Support", "go", "env")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte(dmgGoEnvBegin + "\n" + goEnvExpected + "\n" + goEnvEnd + "\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	home := newSecureTestHomeAs(t, homeDir, "alice")
	inner := executor.NewMock()
	inner.SetGOOS(model.PlatformDarwin)
	inner.SetFile(path, content)
	managed, err := hasGoDMGMarker(failingGoEnvExecutor{Executor: inner}, home)
	if err != nil || !managed {
		t.Fatalf("hasGoDMGMarker = %v, %v", managed, err)
	}
}

func TestGoSiblingMarkerAbsentFileIgnoresUnusableParent(t *testing.T) {
	homeDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(homeDir, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(homeDir, ".config", "go")); err != nil {
		t.Fatal(err)
	}
	home := newSecureTestHomeAs(t, homeDir, "")
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformLinux)
	mock.SetHomeDir(homeDir)
	managed, err := hasGoDMGMarker(filesystemStatExecutor{Executor: mock}, home)
	if err != nil || managed {
		t.Fatalf("hasGoDMGMarker = %v, %v, want false, nil", managed, err)
	}
}

func TestGoEnvWriter_RecordedSymlinkTargetCannotBeRetargeted(t *testing.T) {
	homeDir := t.TempDir()
	dir := filepath.Join(homeDir, ".config", "go")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "env")
	if err := os.Symlink("a", link); err != nil {
		t.Fatal(err)
	}
	home := newSecureTestHomeAs(t, homeDir, "")
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformLinux)
	w, err := NewGoEnvWriter(mock, home, goTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(goEnvExpected); err != nil {
		t.Fatal(err)
	}
	state := AppliedTargetState{}
	if err := w.CompleteState(AppliedTargetState{}, false, &state); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(filepath.Join(dir, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b"), a, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", link); err != nil {
		t.Fatal(err)
	}
	beforeA, _ := os.ReadFile(filepath.Join(dir, "a"))
	beforeB, _ := os.ReadFile(filepath.Join(dir, "b"))
	if err := w.PrepareWrite(state, true); err == nil {
		t.Fatal("PrepareWrite() error = nil after retarget")
	}
	if err := w.PrepareClear(state, true); err == nil {
		t.Fatal("PrepareClear() error = nil after retarget")
	}
	afterA, _ := os.ReadFile(filepath.Join(dir, "a"))
	afterB, _ := os.ReadFile(filepath.Join(dir, "b"))
	if !bytes.Equal(afterA, beforeA) || !bytes.Equal(afterB, beforeB) {
		t.Fatal("retarget rejection mutated a file")
	}
}

func TestGoEnvWriter_LegacyPathlessStateRequiresCurrentMarkerProof(t *testing.T) {
	homeDir := t.TempDir()
	dir := filepath.Join(homeDir, ".config", "go")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	aPath, bPath := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	managed := []byte(dmgGoEnvBegin + "\n" + goEnvExpected + "\n" + goEnvEnd + "\n")
	if err := os.WriteFile(aPath, managed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bPath, []byte("# clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "env")
	if err := os.Symlink("a", link); err != nil {
		t.Fatal(err)
	}
	home := newSecureTestHomeAs(t, homeDir, "")
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformLinux)
	w, err := NewGoEnvWriter(mock, home, goTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	legacy := AppliedTargetState{AppliedHash: "sha256:legacy", WrittenSettings: map[string]string{goEnvOwnershipKey: GoEnvOwnershipValue}}
	if err := w.PrepareClear(legacy, true); err != nil {
		t.Fatalf("unchanged legacy target rejected: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", link); err != nil {
		t.Fatal(err)
	}
	beforeA, _ := os.ReadFile(aPath)
	beforeB, _ := os.ReadFile(bPath)
	if err := w.PrepareClear(legacy, true); err == nil {
		t.Fatal("PrepareClear() error = nil after legacy retarget")
	}
	if err := w.PrepareWrite(legacy, true); err == nil {
		t.Fatal("PrepareWrite() error = nil after legacy retarget")
	}
	afterA, _ := os.ReadFile(aPath)
	afterB, _ := os.ReadFile(bPath)
	if !bytes.Equal(afterA, beforeA) || !bytes.Equal(afterB, beforeB) {
		t.Fatal("legacy retarget rejection mutated files")
	}
}

func TestGoEnvWriter_RejectsEscapingSymlink(t *testing.T) {
	homeDir := t.TempDir()
	dir := filepath.Join(homeDir, ".config", "go")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	initial := []byte("do not change")
	if err := os.WriteFile(outside, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "env")); err != nil {
		t.Fatal(err)
	}
	home := newSecureTestHomeAs(t, homeDir, "")
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformLinux)
	w, err := NewGoEnvWriter(mock, home, goTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(goEnvExpected); err == nil {
		t.Fatal("Write() error = nil")
	}
	got, _ := os.ReadFile(outside)
	if !bytes.Equal(got, initial) {
		t.Fatal("escaping symlink target was mutated")
	}
}

func TestGoEnvWriter_RepairsMissingAssignment(t *testing.T) {
	for _, body := range []string{"", "#GOPROXY=direct", "# GOPROXY=direct"} {
		t.Run(body, func(t *testing.T) {
			w, _, path := newGoEnvTestWriter(t, []byte(dmgGoEnvBegin+"\n"+body+"\n"+goEnvEnd+"\nGOPRIVATE=example.test/*\n"))
			if _, err := w.Write(goEnvExpected); err != nil {
				t.Fatal(err)
			}
			if ok, err := w.Converged(goEnvExpected); err != nil || !ok {
				t.Fatalf("converged=%v err=%v", ok, err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte("GOPRIVATE=example.test/*")) {
				t.Fatal("unrelated setting lost")
			}
		})
	}
}
