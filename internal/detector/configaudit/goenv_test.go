package configaudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// clearGoEnvVars keeps the developer's own Go settings out of verified-process tests.
func clearGoEnvVars(t *testing.T) {
	t.Helper()
	for _, k := range append(slices.Clone(goEnvKeys), "GOENV", "XDG_CONFIG_HOME", "APPDATA") {
		t.Setenv(k, "")
	}
}

func goTestHome(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return home
}

func mustWriteGoFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func goProtectedFor(home string) func(string) string {
	protected, _ := GoProtection(home, nil)
	return protected
}

func goFileByScope(audit model.GoConfigAudit, scope string) model.GoConfigFile {
	for _, f := range audit.Files {
		if f.Scope == scope {
			return f
		}
	}
	return model.GoConfigFile{}
}

func goFindingCodes(audit model.GoConfigAudit) []string {
	var codes []string
	for _, f := range audit.Findings {
		codes = append(codes, f.Code+":"+f.Key)
	}
	return codes
}

func TestParseGoEnv(t *testing.T) {
	data := "# comment\nGOPROXY=https://a\nlower=1\n=x\nNOEQUALS\nGOPROXY=https://b\nGOPATH=/p\nGOPATH=/q\nUNLISTED=secret\nGO111MODULE=off\r\n"
	values, dups, crKey := parseGoEnv([]byte(data))
	if values["GOPROXY"] != "https://b" || values["GOPATH"] != "/q" {
		t.Errorf("last value must win: %v", values)
	}
	if _, ok := values["UNLISTED"]; ok {
		t.Error("non-allowlisted key must be dropped")
	}
	if !slices.Equal(dups, []string{"GOPROXY"}) {
		t.Errorf("dups = %v, want only the security key GOPROXY", dups)
	}
	if crKey != "GO111MODULE" || values["GO111MODULE"] != "off\r" {
		t.Errorf("crKey = %q, value %q; CR must be kept and reported", crKey, values["GO111MODULE"])
	}
}

func TestSanitizeGoSetting(t *testing.T) {
	tests := []struct {
		name, key, raw, want string
		redacted             bool
	}{
		{"proxy separators kept", "GOPROXY", "https://p.example/x, https://proxy.golang.org|direct", "https://p.example/x,https://proxy.golang.org|direct", false},
		{"proxy userinfo", "GOPROXY", "https://u:p@p.example/x,direct", "https://p.example/x,direct", true},
		{"proxy query and fragment", "GOPROXY", "https://p.example/?token=abc#frag", "https://p.example/", true},
		{"proxy schemeless creds", "GOPROXY", "u:p@p.example", goRedacted, true},
		{"proxy bare at", "GOPROXY", "user@p.example", goRedacted, true},
		{"proxy off", "GOPROXY", "off", "off", false},
		{"sumdb url", "GOSUMDB", "sum.example+key https://u:p@sum.example/?t=1", "sum.example+key https://sum.example/", true},
		{"sumdb off", "GOSUMDB", "off", "off", false},
		{"auth methods only", "GOAUTH", "netrc; git /home/dev/src; /usr/bin/helper --token abc", "netrc; git; command", true},
		{"auth off", "GOAUTH", "off", "off", false},
		{"flags kept", "GOFLAGS", "-mod=mod --modfile=/x/alt.mod", "-mod=mod --modfile=/x/alt.mod", false},
		{"flags dropped", "GOFLAGS", "-mod=vendor -ldflags=-X=secret -toolexec=/bin/sh", "-mod=vendor", true},
		{"flags quoted path", "GOFLAGS", `"-modfile=/home/dev/My Project/ci.mod" -mod=readonly`, `"-modfile=/home/dev/My Project/ci.mod" -mod=readonly`, false},
		{"flags quoted secret dropped", "GOFLAGS", `'-ldflags=-X main.key=s3cret' -mod=mod`, "-mod=mod", true},
		{"flags unterminated quote", "GOFLAGS", `"-modfile=/x/a.mod -toolexec=/bin/sh`, "", true},
		{"path raw", "GOPATH", "/home/dev/go", "/home/dev/go", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, redacted := sanitizeGoSetting(tc.key, tc.raw)
			if got != tc.want || redacted != tc.redacted {
				t.Errorf("sanitize(%s=%q) = %q, %v; want %q, %v", tc.key, tc.raw, got, redacted, tc.want, tc.redacted)
			}
		})
	}
}

// TestSplitGoFlags pins cmd/internal/quoted.Split semantics.
func TestSplitGoFlags(t *testing.T) {
	tests := []struct {
		name, raw string
		want      []string
		ok        bool
	}{
		{"empty", " \t", nil, true},
		{"whitespace kinds", "-a\t-b\n-c\r-d  -e", []string{"-a", "-b", "-c", "-d", "-e"}, true},
		{"double quoted", `"-modfile=/a b/c.mod" -mod=mod`, []string{"-modfile=/a b/c.mod", "-mod=mod"}, true},
		{"single quoted keeps double", `'-x="a b"'`, []string{`-x="a b"`}, true},
		{"no unescaping", `"-x=a\" -y`, []string{`-x=a\`, "-y"}, true},
		{"quote closes field", `"-a"-b`, []string{"-a", "-b"}, true},
		{"inner quote literal", `-x="a`, []string{`-x="a`}, true},
		{"unterminated", `-mod=mod '-modfile=/a`, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := splitGoFlags(tc.raw)
			if !slices.Equal(got, tc.want) || ok != tc.ok {
				t.Errorf("splitGoFlags(%q) = %q, %v; want %q, %v", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestGoEnvFindings(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
		dups   []string
		crKey  string
		want   []string
	}{
		{"clean default", map[string]string{"GOPROXY": "https://proxy.golang.org,direct"}, nil, "", nil},
		{"sumdb off", map[string]string{"GOSUMDB": "off"}, nil, "", []string{"go-001:GOSUMDB"}},
		{"insecure", map[string]string{"GOINSECURE": "*.corp"}, nil, "", []string{"go-002:GOINSECURE"}},
		{"private then public", map[string]string{"GOPROXY": "https://athens.corp,https://proxy.golang.org"}, nil, "", []string{"go-003:GOPROXY"}},
		{"private then direct pipe", map[string]string{"GOPROXY": "https://athens.corp|direct"}, nil, "", []string{"go-003:GOPROXY"}},
		{"private then off", map[string]string{"GOPROXY": "https://athens.corp,off,direct"}, nil, "", nil},
		{"credentials", map[string]string{"GOPROXY": "https://u:p@athens.corp"}, nil, "", []string{"go-004:GOPROXY"}},
		{"auth command", map[string]string{"GOAUTH": "netrc; /bin/helper"}, nil, "", []string{"go-005:GOAUTH"}},
		{"cr and dup", map[string]string{}, []string{"GOPROXY"}, "GO111MODULE", []string{"go-006:GO111MODULE", "go-006:GOPROXY"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := goEnvSource{file: model.GoConfigFile{SourceID: "id"}, values: tc.values, dups: tc.dups, crKey: tc.crKey}
			var got []string
			for _, f := range goEnvFindings(src) {
				if f.SourceID != "id" || f.Severity == "" || f.Detail == "" {
					t.Errorf("finding %+v lacks provenance or detail", f)
				}
				got = append(got, f.Code+":"+f.Key)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("findings = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGoEnvDefaultPaths(t *testing.T) {
	tests := []struct {
		goos, xdg, want string
	}{
		{model.PlatformDarwin, "", filepath.Join("/home/dev", "Library", "Application Support", "go", "env")},
		{model.PlatformLinux, "", filepath.Join("/home/dev", ".config", "go", "env")},
		{model.PlatformLinux, "/xdg", filepath.Join("/xdg", "go", "env")},
		{model.PlatformWindows, "", filepath.Join("/home/dev", "AppData", "Roaming", "go", "env")},
	}
	for _, tc := range tests {
		t.Run(tc.goos+tc.xdg, func(t *testing.T) {
			m := executor.NewMock()
			m.SetGOOS(tc.goos)
			m.SetEnv("XDG_CONFIG_HOME", tc.xdg)
			audit, _ := NewGoEnvDetector(m).Detect(context.Background(), GoEnvScope{Username: "dev", Home: "/home/dev", Roots: []string{"/home/dev"}, ProcessVerified: true})
			if got := goFileByScope(audit, model.GoConfigScopeUser).DefaultPath; got != tc.want {
				t.Errorf("default path = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGoEnvDetectContexts(t *testing.T) {
	scope := GoEnvScope{Username: "dev", Home: "/home/dev", Roots: []string{"/home/dev"}}
	t.Run("user unresolved", func(t *testing.T) {
		audit, snap := NewGoEnvDetector(executor.NewMock()).Detect(context.Background(), GoEnvScope{})
		if audit.Status != model.GoStatusPartial || !slices.Equal(audit.Reasons, []string{model.GoReasonUserUnresolved}) || !snap.RedirectUnknown {
			t.Errorf("audit = %+v, redirect=%v", audit, snap.RedirectUnknown)
		}
	})
	t.Run("unverified process ignored", func(t *testing.T) {
		m := executor.NewMock()
		m.SetGOOS(model.PlatformLinux)
		m.SetEnv("GOENV", "off")
		m.SetEnv("GOPROXY", "https://leak")
		audit, snap := NewGoEnvDetector(m).Detect(context.Background(), scope)
		proc := goFileByScope(audit, model.GoConfigScopeProcess)
		if proc.Status != model.GoConfigUnsupported || len(proc.Settings) != 0 || snap.values["GOPROXY"] != "" {
			t.Errorf("unverified process must not be read: %+v", proc)
		}
		if goFileByScope(audit, model.GoConfigScopeUser).Status == model.GoConfigDisabled {
			t.Error("unverified GOENV=off must not disable the user file")
		}
	})
	t.Run("GOENV off", func(t *testing.T) {
		m := executor.NewMock()
		m.SetGOOS(model.PlatformLinux)
		m.SetEnv("GOENV", "off")
		s := scope
		s.ProcessVerified = true
		audit, snap := NewGoEnvDetector(m).Detect(context.Background(), s)
		if goFileByScope(audit, model.GoConfigScopeUser).Status != model.GoConfigDisabled || snap.RedirectUnknown {
			t.Errorf("GOENV=off: %+v", audit.Files)
		}
	})
	t.Run("GOENV relative", func(t *testing.T) {
		m := executor.NewMock()
		m.SetGOOS(model.PlatformLinux)
		m.SetEnv("GOENV", "rel/env")
		s := scope
		s.ProcessVerified = true
		audit, snap := NewGoEnvDetector(m).Detect(context.Background(), s)
		user := goFileByScope(audit, model.GoConfigScopeUser)
		if user.Status != model.GoConfigUnsupported || user.Path != "" || !snap.RedirectUnknown || audit.Status != model.GoStatusPartial {
			t.Errorf("relative GOENV: %+v", user)
		}
	})
	t.Run("GOENV outside scope", func(t *testing.T) {
		m := executor.NewMock()
		m.SetGOOS(model.PlatformLinux)
		m.SetEnv("GOENV", "/etc/goenv")
		s := scope
		s.ProcessVerified = true
		audit, _ := NewGoEnvDetector(m).Detect(context.Background(), s)
		user := goFileByScope(audit, model.GoConfigScopeUser)
		if user.Status != model.GoConfigUnsupported || !slices.Equal(user.Reasons, []string{model.GoReasonOutsideApprovedRoots}) {
			t.Errorf("out-of-scope GOENV: %+v", user)
		}
	})
}

func TestGoEnvReadsRealFile(t *testing.T) {
	clearGoEnvVars(t)
	home := goTestHome(t)
	envFile := filepath.Join(home, "cfg", "goenv")
	mustWriteGoFile(t, envFile, "GOPROXY=https://u:secretpw@athens.corp/?token=tkn,direct\nGOPROXY=https://u:secretpw@athens.corp/?token=tkn|direct\nGOSUMDB=off\nGO111MODULE=off\nGOFLAGS=-mod=mod -modfile=/x/alt.mod -toolexec=/bin/evil\nGOMODCACHE=/custom/mod\nGOROOT="+filepath.Join(home, "sdk")+"\n")
	mustWriteGoFile(t, filepath.Join(home, "sdk", "go.env"), "GOPROXY=https://proxy.golang.org,direct\nGOTOOLCHAIN=auto\n")
	t.Setenv("GOENV", envFile)
	t.Setenv("GOBIN", "rel/bin")

	scope := GoEnvScope{Username: "dev", Home: home, Roots: []string{home}, Protected: goProtectedFor(home), ProcessVerified: true}
	audit, snap := NewGoEnvDetector(executor.NewReal()).Detect(context.Background(), scope)

	user := goFileByScope(audit, model.GoConfigScopeUser)
	if user.Status != model.GoConfigPresent || user.Path != envFile || !slices.Equal(user.Reasons, []string{model.GoReasonDuplicateKey}) {
		t.Fatalf("user file = %+v", user)
	}
	if tc := goFileByScope(audit, model.GoConfigScopeToolchain); tc.Status != model.GoConfigPresent || len(tc.Settings) != 2 {
		t.Errorf("toolchain file = %+v", tc)
	}
	if got := goFindingCodes(audit); !slices.Equal(got, []string{"go-001:GOSUMDB", "go-003:GOPROXY", "go-004:GOPROXY", "go-006:GOPROXY"}) {
		t.Errorf("findings = %v", got)
	}
	if audit.Status != model.GoStatusComplete {
		t.Errorf("status = %s %v, want complete", audit.Status, audit.Reasons)
	}
	// Process overrides the file; a relative GOBIN is unresolved, never defaulted.
	if root, ok := snap.BinRoot(home); ok || root != "rel/bin" {
		t.Errorf("BinRoot = %q, %v; want unresolved", root, ok)
	}
	if root, ok := snap.ModCacheRoot(home); !ok || root != "/custom/mod" {
		t.Errorf("ModCacheRoot = %q, %v", root, ok)
	}
	if modfile, ok := snap.Modfile(); modfile != "/x/alt.mod" || !ok || snap.RedirectUnknown {
		t.Errorf("Modfile = %q, %v, redirect=%v", modfile, ok, snap.RedirectUnknown)
	}
	out, _ := json.Marshal(audit)
	for _, secret := range []string{"secretpw", "tkn", "evil", "toolexec"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("serialized audit leaks %q: %s", secret, out)
		}
	}
}

func TestGoEnvInvalidAndUnreadable(t *testing.T) {
	clearGoEnvVars(t)
	home := goTestHome(t)
	crlf := filepath.Join(home, "crlf")
	mustWriteGoFile(t, crlf, "GO111MODULE=off\r\nGOPROXY=https://x\r\n")
	t.Setenv("GOENV", crlf)
	scope := GoEnvScope{Username: "dev", Home: home, Roots: []string{home}, Protected: goProtectedFor(home), ProcessVerified: true}
	audit, snap := NewGoEnvDetector(executor.NewReal()).Detect(context.Background(), scope)
	user := goFileByScope(audit, model.GoConfigScopeUser)
	if user.Status != model.GoConfigInvalid || len(user.Settings) != 0 || !snap.RedirectUnknown || audit.Status != model.GoStatusPartial {
		t.Errorf("CRLF file = %+v, redirect=%v", user, snap.RedirectUnknown)
	}
	if snap.values["GOPROXY"] != "" {
		t.Error("an invalid file must not feed the snapshot")
	}

	big := filepath.Join(home, "big")
	mustWriteGoFile(t, big, strings.Repeat("#", 64))
	t.Setenv("GOENV", big)
	old := maxGoEnvBytes
	maxGoEnvBytes = 16
	defer func() { maxGoEnvBytes = old }()
	audit, _ = NewGoEnvDetector(executor.NewReal()).Detect(context.Background(), scope)
	if user := goFileByScope(audit, model.GoConfigScopeUser); user.Status != model.GoConfigUnreadable || !slices.Equal(user.Reasons, []string{model.GoReasonSizeLimit}) {
		t.Errorf("oversized file = %+v", user)
	}

	t.Setenv("GOENV", filepath.Join(home, "missing"))
	audit, snap = NewGoEnvDetector(executor.NewReal()).Detect(context.Background(), scope)
	if user := goFileByScope(audit, model.GoConfigScopeUser); user.Status != model.GoConfigAbsent || snap.RedirectUnknown || audit.Status != model.GoStatusComplete {
		t.Errorf("missing file = %+v", user)
	}
}

// libraryRecorder fails any directory listing: the exact-file exception must
// open the default env file without enumerating Library.
type libraryRecorder struct {
	executor.Executor
	t *testing.T
}

func (r libraryRecorder) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	return libraryRecorder{Executor: r.Executor.GuardedFiles(roots, guard, max), t: r.t}
}

func (r libraryRecorder) ReadDir(path string) ([]os.DirEntry, error) {
	r.t.Errorf("unexpected ReadDir(%s)", path)
	return nil, os.ErrPermission
}

func (r libraryRecorder) ReadDirLimit(path string, _ int) ([]os.DirEntry, bool, error) {
	r.t.Errorf("unexpected ReadDirLimit(%s)", path)
	return nil, false, os.ErrPermission
}

func TestGoEnvDarwinExactDefault(t *testing.T) {
	if runtime.GOOS != model.PlatformDarwin {
		t.Skip("macOS default-path exception")
	}
	clearGoEnvVars(t)
	home := goTestHome(t)
	appSupport := filepath.Join(home, "Library", "Application Support")
	envFile := filepath.Join(appSupport, "go", "env")
	scope := GoEnvScope{Username: "dev", Home: home, Roots: []string{home}, Protected: goProtectedFor(home)}
	detect := func() model.GoConfigFile {
		t.Helper()
		audit, _ := NewGoEnvDetector(libraryRecorder{Executor: executor.NewReal(), t: t}).Detect(context.Background(), scope)
		return goFileByScope(audit, model.GoConfigScopeUser)
	}

	mustWriteGoFile(t, envFile, "GOPROXY=https://athens.corp,direct\n")
	if user := detect(); user.Status != model.GoConfigPresent || user.Path != envFile || len(user.Settings) != 1 {
		t.Fatalf("permitted default read = %+v", user)
	}

	// A leaf link to another Library subtree, and to its own directory.
	mustWriteGoFile(t, filepath.Join(home, "Library", "Other", "file"), "GOPROXY=https://leak\n")
	for _, target := range []string{filepath.Join("..", "..", "Other", "file"), ".."} {
		if err := os.Remove(envFile); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, envFile); err != nil {
			t.Fatal(err)
		}
		if user := detect(); user.Status != model.GoConfigSkippedProtected || len(user.Settings) != 0 {
			t.Errorf("leaf link to %s = %+v, want skipped_protected", target, user)
		}
	}

	// An ancestor redirected into Documents.
	if err := os.RemoveAll(appSupport); err != nil {
		t.Fatal(err)
	}
	mustWriteGoFile(t, filepath.Join(home, "Documents", "go", "env"), "GOPROXY=https://leak\n")
	if err := os.Symlink(filepath.Join(home, "Documents"), appSupport); err != nil {
		t.Fatal(err)
	}
	if user := detect(); user.Status != model.GoConfigSkippedProtected || len(user.Settings) != 0 {
		t.Errorf("redirected ancestor = %+v, want skipped_protected", user)
	}

	// A custom GOENV into another Library subtree, including a case variant of
	// the default, does not inherit the exception.
	scope.ProcessVerified = true
	for _, goenv := range []string{filepath.Join(home, "Library", "Other", "file"), filepath.Join(home, "library", "Application Support", "go", "env")} {
		t.Setenv("GOENV", goenv)
		if user := detect(); user.Status != model.GoConfigSkippedProtected {
			t.Errorf("custom GOENV %s = %+v, want skipped_protected", goenv, user)
		}
	}
}

func TestGoProtection(t *testing.T) {
	if runtime.GOOS != model.PlatformDarwin {
		t.Skip("protected directories exist only on macOS")
	}
	home := "/Users/dev"
	on := true
	protected, _ := GoProtection(home, &on) // a caller's TCC opt-in cannot widen Go access
	for path, want := range map[string]bool{
		"/Users/dev/Documents/x":      true,
		"/Users/dev/documents/x":      true,
		"/Users/dev/LIBRARY":          true,
		"/Users/dev/Documents.backup": false,
		"/Users/dev/code":             false,
	} {
		if got := protected(path) != ""; got != want {
			t.Errorf("protected(%s) = %v, want %v", path, got, want)
		}
	}
}
