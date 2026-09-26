package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// goTrap runs the Go scanner against the real filesystem while failing the
// test on any command, shell, machine-wide search or unguarded file access.
type goTrap struct {
	executor.Executor
	t       *testing.T
	current *user.User
	guarded bool
}

func (x *goTrap) trap(method string) {
	x.t.Helper()
	x.t.Errorf("go scan called forbidden executor method %s", method)
}

func (x *goTrap) unguarded(method string) bool {
	x.t.Helper()
	if !x.guarded {
		x.trap("unguarded " + method)
		return true
	}
	return false
}

func (x *goTrap) GuardedFiles(roots []string, guard func(string) string, maxReadBytes int64) executor.Executor {
	return &goTrap{Executor: x.Executor.GuardedFiles(roots, guard, maxReadBytes), t: x.t, current: x.current, guarded: true}
}

func (x *goTrap) ReadFile(path string) ([]byte, error) {
	if x.unguarded("ReadFile") {
		return nil, os.ErrPermission
	}
	return x.Executor.ReadFile(path)
}

func (x *goTrap) ReadDirLimit(path string, max int) ([]os.DirEntry, bool, error) {
	if x.unguarded("ReadDirLimit") {
		return nil, false, os.ErrPermission
	}
	return x.Executor.ReadDirLimit(path, max)
}

func (x *goTrap) Stat(path string) (os.FileInfo, error) {
	if x.unguarded("Stat") {
		return nil, os.ErrPermission
	}
	return x.Executor.Stat(path)
}

func (x *goTrap) EvalSymlinks(path string) (string, error) {
	if x.unguarded("EvalSymlinks") {
		return "", os.ErrPermission
	}
	return x.Executor.EvalSymlinks(path)
}

func (x *goTrap) CurrentUser() (*user.User, error) { return x.current, nil }

func (x *goTrap) Run(context.Context, string, ...string) (string, string, int, error) {
	x.trap("Run")
	return "", "", 1, os.ErrPermission
}

func (x *goTrap) RunWithTimeout(context.Context, time.Duration, string, ...string) (string, string, int, error) {
	x.trap("RunWithTimeout")
	return "", "", 1, os.ErrPermission
}

func (x *goTrap) RunInDir(context.Context, string, time.Duration, string, ...string) (string, string, int, error) {
	x.trap("RunInDir")
	return "", "", 1, os.ErrPermission
}

func (x *goTrap) RunAsUser(context.Context, string, string) (string, error) {
	x.trap("RunAsUser")
	return "", os.ErrPermission
}

func (x *goTrap) StartDetached(string, ...string) error {
	x.trap("StartDetached")
	return os.ErrPermission
}
func (x *goTrap) LookPath(string) (string, error) { x.trap("LookPath"); return "", os.ErrPermission }
func (x *goTrap) FileExists(string) bool          { x.trap("FileExists"); return false }
func (x *goTrap) DirExists(string) bool           { x.trap("DirExists"); return false }
func (x *goTrap) ReadDir(string) ([]os.DirEntry, error) {
	x.trap("ReadDir")
	return nil, os.ErrPermission
}
func (x *goTrap) Glob(string) ([]string, error)   { x.trap("Glob"); return nil, os.ErrPermission }
func (x *goTrap) Readlink(string) (string, error) { x.trap("Readlink"); return "", os.ErrPermission }
func (x *goTrap) HomeDir(string) (string, error)  { x.trap("HomeDir"); return "", os.ErrPermission }
func (x *goTrap) LoggedInUser() (*user.User, error) {
	x.trap("LoggedInUser")
	return nil, os.ErrPermission
}
func (x *goTrap) IsAppleCLTStub(context.Context, string) bool {
	x.trap("IsAppleCLTStub")
	return false
}

// goTestEnv clears every variable the Go audit may read from the process.
func goTestEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GO111MODULE", "GOAUTH", "GOBIN", "GOFLAGS", "GOINSECURE", "GOMODCACHE", "GONOPROXY", "GONOSUMDB",
		"GOPATH", "GOPRIVATE", "GOPROXY", "GOROOT", "GOSUMDB", "GOTOOLCHAIN", "GOVCS", "GOWORK", "GOENV",
		"XDG_CONFIG_HOME", "APPDATA",
	} {
		t.Setenv(k, "")
	}
}

// goTestHome returns a physical (symlink-free) home directory for the target.
func goTestHome(t *testing.T) string {
	t.Helper()
	goTestEnv(t)
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(tmp, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

func goTestTarget(home string) *user.User {
	return &user.User{Username: "dev", Uid: "1000", HomeDir: home}
}

// goTestScanner builds a scanner whose process runs as current; the default
// is another account, so the process environment is not the developer's.
func goTestScanner(t *testing.T, current *user.User) *GoScanner {
	t.Helper()
	if current == nil {
		current = &user.User{Username: "agent", Uid: "1001"}
	}
	return NewGoScanner(&goTrap{Executor: executor.NewReal(), t: t, current: current}, progress.NewNoop())
}

func goWrite(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // umask-independent
		t.Fatal(err)
	}
}

func goMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func goFindSource(inv *model.GoInventory, kind, path string) *model.GoSource {
	for i := range inv.Sources {
		if inv.Sources[i].Kind == kind && inv.Sources[i].Path == path {
			return &inv.Sources[i]
		}
	}
	return nil
}

func goMustSource(t *testing.T, inv *model.GoInventory, kind, path string) *model.GoSource {
	t.Helper()
	src := goFindSource(inv, kind, path)
	if src == nil {
		t.Fatalf("no %s source for %s", kind, path)
	}
	return src
}

func goFindProject(inv *model.GoInventory, manifest string) *model.GoProject {
	for i := range inv.Projects {
		if inv.Projects[i].ManifestPath == manifest {
			return &inv.Projects[i]
		}
	}
	return nil
}

func goFindRequirement(p *model.GoProject, path string) *model.GoRequirement {
	for i := range p.Requirements {
		if p.Requirements[i].ModulePath == path {
			return &p.Requirements[i]
		}
	}
	return nil
}

func goFindCached(inv *model.GoInventory, path, version string) *model.GoCachedModule {
	for i := range inv.CachedModules {
		if inv.CachedModules[i].ModulePath == path && inv.CachedModules[i].ObservedVersion == version {
			return &inv.CachedModules[i]
		}
	}
	return nil
}

func goArtifactStatus(c *model.GoCachedModule, kind string) string {
	for _, a := range c.Artifacts {
		if a.Kind == kind {
			return a.Status
		}
	}
	return ""
}

func goChecksumValues(ev model.GoChecksumEvidence) []string {
	var out []string
	for _, c := range ev.RecordedChecksums {
		out = append(out, c.Kind+" "+c.Source+" "+c.Value)
	}
	return out
}

func goStatusOf(t *testing.T, got, want, what string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

// goCheckIntegrity asserts every referenced source ID resolves to a source.
func goCheckIntegrity(t *testing.T, inv *model.GoInventory) {
	t.Helper()
	ids := map[string]bool{}
	for _, s := range inv.Sources {
		if ids[s.SourceID] {
			t.Errorf("duplicate source %s (%s %s)", s.SourceID, s.Kind, s.Path)
		}
		ids[s.SourceID] = true
	}
	ref := func(id, what string) {
		if id != "" && !ids[id] {
			t.Errorf("%s references unknown source %s", what, id)
		}
	}
	for _, s := range inv.Sources {
		ref(s.ParentSourceID, "parent of "+s.Path)
		for _, d := range s.DiscoveredSources {
			ref(d, "discovered by "+s.Path)
		}
	}
	checksums := func(ev model.GoChecksumEvidence, what string) {
		for _, c := range ev.RecordedChecksums {
			ref(c.SourceID, what+" checksum")
		}
	}
	for _, p := range inv.Projects {
		ref(p.SourceID, "project "+p.ManifestPath)
		for _, r := range p.Requirements {
			checksums(r.GoChecksumEvidence, r.ModulePath)
		}
	}
	for _, w := range inv.Workspaces {
		ref(w.SourceID, "workspace "+w.Path)
		for _, m := range w.Members {
			ref(m.ProjectSourceID, "member "+m.DeclaredPath)
		}
	}
	for _, v := range inv.VendoredModules {
		ref(v.SourceID, "vendored "+v.ModulePath)
		checksums(v.GoChecksumEvidence, v.ModulePath)
	}
	for _, c := range inv.CachedModules {
		ref(c.SourceID, "cached "+c.ModulePath)
		checksums(c.GoChecksumEvidence, c.ModulePath)
	}
	for _, tool := range inv.InstalledTools {
		ref(tool.SourceID, "tool "+tool.BinaryPath)
		checksums(tool.GoChecksumEvidence, tool.BinaryPath)
	}
}

func goScanJSON(t *testing.T, inv *model.GoInventory, audit *model.GoConfigAudit) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"go_inventory": inv, "go_config_audit": audit})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// goTestFixture lays out one developer home exercising every collector.
func goTestFixture(t *testing.T, home string) {
	t.Helper()
	app := filepath.Join(home, "code", "app")
	goWrite(t, filepath.Join(app, "go.mod"), `module example.com/app

go 1.24

require (
	github.com/BurntSushi/toml v1.3.2
	golang.org/x/text v0.14.0 // indirect
	example.com/old v0.9.0
)

replace example.com/old => example.com/new v1.0.0

replace example.com/local => ../local

exclude golang.org/x/text v0.13.0

tool golang.org/x/tools/cmd/stringer
`, 0o644)
	goWrite(t, filepath.Join(app, "go.sum"), strings.Join([]string{
		"github.com/BurntSushi/toml v1.3.2 " + goTestH1("toml"),
		"github.com/BurntSushi/toml v1.3.2/go.mod " + goTestH1("toml.mod"),
		"golang.org/x/text v0.14.0 " + goTestH1("text"),
		"example.com/new v1.0.0 " + goTestH1("new"),
		"example.com/orphan v1.0.0 " + goTestH1("orphan"),
	}, "\n")+"\n", 0o644)
	goWrite(t, filepath.Join(app, "vendor", "modules.txt"), `# github.com/BurntSushi/toml v1.3.2
## explicit; go 1.18
github.com/BurntSushi/toml
# golang.org/x/text v0.14.0
## explicit
golang.org/x/text/unicode
# example.com/old v0.9.0 => example.com/new v1.0.0
## explicit
example.com/old/pkg
`, 0o644)
	goMkdir(t, filepath.Join(app, "vendor", "github.com", "BurntSushi", "toml"))
	goWrite(t, filepath.Join(app, "vendor", "example.com", "old", "pkg", "go.mod"), "module example.com/old\n", 0o644)
	goWrite(t, filepath.Join(app, "nested", "go.mod"), "module example.com/app/nested\n\ngo 1.24\n\nrequire github.com/BurntSushi/toml v1.2.0\n", 0o644)
	// Not projects: dependency stores and version-control internals.
	goWrite(t, filepath.Join(app, "node_modules", "x", "go.mod"), "module example.com/nm\n", 0o644)
	goWrite(t, filepath.Join(app, ".git", "go.mod"), "module example.com/git\n", 0o644)
	goWrite(t, filepath.Join(home, ".projects", "w", "go.mod"), "module example.com/w\n", 0o644)

	outside := t.TempDir()
	ws := filepath.Join(home, "code", "ws")
	goWrite(t, filepath.Join(ws, "go.work"), fmt.Sprintf(`go 1.24

use (
	./a
	./missing
	%s
)

replace example.com/r => example.com/r2 v1.1.0
`, filepath.ToSlash(outside)), 0o644)
	goWrite(t, filepath.Join(ws, "go.work.sum"), strings.Join([]string{
		"github.com/BurntSushi/toml v1.3.2 " + goTestH1("ws.toml"),
		"example.com/r2 v1.1.0 " + goTestH1("r2"),
	}, "\n")+"\n", 0o644)
	goWrite(t, filepath.Join(ws, "a", "go.mod"), "module example.com/a\n\ngo 1.24\n\nrequire (\n\tgithub.com/BurntSushi/toml v1.3.2\n\texample.com/r v1.0.0\n)\n", 0o644)

	cache := filepath.Join(home, "go", "pkg", "mod")
	goWrite(t, filepath.Join(cache, "go.mod"), "module example.com/incache\n", 0o644) // never a project
	dl := filepath.Join(cache, "cache", "download")
	goWrite(t, filepath.Join(cache, "github.com", "!burnt!sushi", "toml@v1.3.2", "toml.go"), "package toml\n", 0o644)
	// A cached module's own manifest is never read: its requirement is not evidence.
	goWrite(t, filepath.Join(cache, "github.com", "!burnt!sushi", "toml@v1.3.2", "go.mod"), "module github.com/BurntSushi/toml\n\nrequire example.com/bonly v1.0.0\n", 0o644)
	tomlV := filepath.Join(dl, "github.com", "!burnt!sushi", "toml", "@v")
	goWrite(t, filepath.Join(tomlV, "v1.3.2.zip"), string(goTestZip(t, "github.com/BurntSushi/toml@v1.3.2/toml.go")), 0o644)
	goWrite(t, filepath.Join(tomlV, "v1.3.2.ziphash"), goTestH1("cache.toml")+"\n", 0o644)
	goWrite(t, filepath.Join(tomlV, "v1.3.2.mod"), "module github.com/BurntSushi/toml\n\nrequire example.com/bonly v1.0.0\n", 0o644)
	goMkdir(t, filepath.Join(cache, "example.com", "inprogress@v1.0.0"))
	goWrite(t, filepath.Join(dl, "example.com", "inprogress", "@v", "v1.0.0.partial"), "", 0o644)
	goWrite(t, filepath.Join(dl, "example.com", "inprogress", "@v", "v1.0.0.ziphash"), goTestH1("inprogress")+"\n", 0o644)
	goWrite(t, filepath.Join(dl, "example.com", "inprogress", "@v", "v1.0.0.zip"), string(goTestZip(t, "example.com/inprogress@v1.0.0/a.go")), 0o644)
	goWrite(t, filepath.Join(dl, "example.com", "archiveonly", "@v", "v1.2.0.zip"), string(goTestZip(t, "example.com/archiveonly@v1.2.0/a.go")), 0o644)
	goWrite(t, filepath.Join(dl, "example.com", "mismatch", "@v", "v1.0.0.zip"), string(goTestZip(t, "example.com/other@v1.0.0/a.go")), 0o644)
	goWrite(t, filepath.Join(dl, "example.com", "metaonly", "@v", "v1.0.0.mod"), "module example.com/metaonly\n", 0o644)
	goWrite(t, filepath.Join(dl, "example.com", "metaonly", "@v", "v1.0.0.info"), "{}\n", 0o644)
	goWrite(t, filepath.Join(dl, "sumdb", "sum.golang.org", "latest"), "x\n", 0o644)
	goMkdir(t, filepath.Join(cache, "golang.org", "toolchain@v0.0.1-go1.24.0.darwin-arm64"))
	goWrite(t, filepath.Join(dl, "golang.org", "toolchain", "@v", "v0.0.1-go1.24.0.darwin-arm64.zip"), "not opened", 0o644)
	goMkdir(t, filepath.Join(cache, "example.com", "tmp@v1.0.0.tmp-123"))
	goMkdir(t, filepath.Join(cache, "example.com", "bad@notaversion"))

	bin := filepath.Join(home, "go", "bin")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	goWrite(t, filepath.Join(bin, "tool"), string(exe), 0o755)
	goWrite(t, filepath.Join(bin, "trunc"), string(exe[:4096]), 0o755)
	goWrite(t, filepath.Join(bin, "script"), "#!/bin/sh\necho hi\n", 0o755)
	goWrite(t, filepath.Join(bin, "stale"), "#!/bin/sh\n", 0o644)
	goMkdir(t, filepath.Join(bin, "subdir"))
	goWrite(t, filepath.Join(outside, "escape"), "#!/bin/sh\n", 0o755)
	if err := os.Symlink(filepath.Join(outside, "escape"), filepath.Join(bin, "escape")); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS == model.PlatformDarwin {
		goWrite(t, filepath.Join(home, "Documents", "p", "go.mod"), "module example.com/private\n", 0o644)
	}
}

func TestGoScanner_Fixture(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("fixture relies on exec bits and symlinks")
	}
	home := goTestHome(t)
	goTestFixture(t, home)
	s := goTestScanner(t, nil)
	inv, audit := s.Scan(context.Background(), goTestTarget(home), []string{home}, nil)
	goCheckIntegrity(t, inv)

	app := filepath.Join(home, "code", "app")
	ws := filepath.Join(home, "code", "ws")
	cache := filepath.Join(home, "go", "pkg", "mod")
	bin := filepath.Join(home, "go", "bin")

	t.Run("projects", func(t *testing.T) {
		var got []string
		for _, p := range inv.Projects {
			got = append(got, p.ManifestPath)
		}
		want := []string{
			filepath.Join(home, ".projects", "w", "go.mod"),
			filepath.Join(app, "go.mod"),
			filepath.Join(app, "nested", "go.mod"),
			filepath.Join(ws, "a", "go.mod"),
		}
		if !slices.Equal(got, want) {
			t.Errorf("projects = %v, want %v", got, want)
		}
		root := goMustSource(t, inv, model.GoSourceProjectSearchRoot, home)
		goStatusOf(t, root.Status, model.GoStatusComplete, "search root status")
		if n := len(root.DiscoveredSources); n != 5 { // four go.mod + one go.work
			t.Errorf("search root discovered %d sources, want 5", n)
		}
	})

	t.Run("checksums", func(t *testing.T) {
		p := goFindProject(inv, filepath.Join(app, "go.mod"))
		sum := goMustSource(t, inv, model.GoSourceChecksumFile, filepath.Join(app, "go.sum"))
		goStatusOf(t, sum.ParentSourceID, p.SourceID, "go.sum parent")
		toml := goFindRequirement(p, "github.com/BurntSushi/toml")
		goStatusOf(t, toml.ChecksumStatus, model.GoChecksumRecorded, "toml checksum")
		wantToml := []string{
			"module_content project_go_sum " + goTestH1("toml"),
			"go_mod project_go_sum " + goTestH1("toml.mod"),
		}
		if got := goChecksumValues(toml.GoChecksumEvidence); !slices.Equal(got, wantToml) {
			t.Errorf("toml checksums = %v, want %v", got, wantToml)
		}
		if c := toml.RecordedChecksums[0]; c.SourceID != sum.SourceID || c.SourcePath != sum.Path || c.Verification != model.GoChecksumNotVerified {
			t.Errorf("toml checksum provenance = %+v", c)
		}
		goStatusOf(t, goFindRequirement(p, "golang.org/x/text").ChecksumStatus, model.GoChecksumRecorded, "indirect x/text checksum")
		goStatusOf(t, goFindRequirement(p, "example.com/old").ChecksumStatus, model.GoChecksumAbsent, "replaced requirement checksum")
		if goFindRequirement(p, "example.com/orphan") != nil {
			t.Error("a checksum-only go.sum line created a requirement")
		}
		for _, r := range p.Replacements {
			switch r.FromPath {
			case "example.com/old":
				goStatusOf(t, r.ChecksumStatus, model.GoChecksumRecorded, "versioned provider checksum")
			case "example.com/local":
				goStatusOf(t, r.ChecksumStatus, model.GoChecksumNotApplicable, "local replacement checksum")
			}
		}

		nested := goFindProject(inv, filepath.Join(app, "nested", "go.mod"))
		nestedSum := goMustSource(t, inv, model.GoSourceChecksumFile, filepath.Join(app, "nested", "go.sum"))
		goStatusOf(t, nestedSum.Presence, model.GoPresenceAbsent, "missing go.sum presence")
		goStatusOf(t, nestedSum.Status, model.GoStatusComplete, "missing go.sum status")
		goStatusOf(t, nested.Requirements[0].ChecksumStatus, model.GoChecksumAbsent, "nested checksum")
	})

	t.Run("vendor", func(t *testing.T) {
		vendorDir := filepath.Join(app, "vendor")
		src := goMustSource(t, inv, model.GoSourceVendorRoot, vendorDir)
		goStatusOf(t, src.Status, model.GoStatusComplete, "vendor status")
		if slices.Contains(src.Reasons, model.GoReasonVendorMismatch) {
			t.Error("consistent vendor reported vendor_mismatch")
		}
		var got []string
		for _, v := range inv.VendoredModules {
			got = append(got, v.ModulePath+" "+strings.Join(v.PackagePaths, ",")+" "+v.ChecksumStatus)
		}
		want := []string{
			"example.com/old example.com/old/pkg not_applicable",
			"github.com/BurntSushi/toml github.com/BurntSushi/toml recorded",
		}
		if !slices.Equal(got, want) {
			t.Errorf("vendored = %v, want %v", got, want)
		}
		if r := inv.VendoredModules[0].Replacement; r == nil || r.ChecksumStatus != model.GoChecksumRecorded {
			t.Errorf("vendored replacement = %+v, want recorded provider checksum", r)
		}
		if goFindSource(inv, model.GoSourceProjectManifest, filepath.Join(vendorDir, "example.com", "old", "pkg", "go.mod")) != nil {
			t.Error("a go.mod inside vendor/ was treated as a project")
		}
	})

	t.Run("workspace", func(t *testing.T) {
		if len(inv.Workspaces) != 1 {
			t.Fatalf("workspaces = %d, want 1", len(inv.Workspaces))
		}
		w := inv.Workspaces[0]
		a := goFindProject(inv, filepath.Join(ws, "a", "go.mod"))
		reasons := map[string]string{}
		for _, m := range w.Members {
			reasons[m.DeclaredPath] = m.Reason
			if m.DeclaredPath == "./a" && m.ProjectSourceID != a.SourceID {
				t.Errorf("member ./a linked to %q, want %q", m.ProjectSourceID, a.SourceID)
			}
		}
		for declared, want := range map[string]string{"./a": "", "./missing": model.GoReasonMemberNotDiscovered} {
			goStatusOf(t, reasons[declared], want, "member "+declared+" reason")
		}
		outsideReasons := 0
		for _, r := range reasons {
			if r == model.GoReasonOutsideApprovedRoots {
				outsideReasons++
			}
		}
		if outsideReasons != 1 {
			t.Errorf("members outside roots = %d, want 1 (%v)", outsideReasons, reasons)
		}
		if !slices.Equal(a.WorkspacePaths, []string{filepath.Join(ws, "go.work")}) {
			t.Errorf("member workspace_paths = %v", a.WorkspacePaths)
		}
		// go.work.sum reaches the member alongside its own (absent) go.sum.
		if got := goChecksumValues(goFindRequirement(a, "github.com/BurntSushi/toml").GoChecksumEvidence); !slices.Equal(got,
			[]string{"module_content workspace_go_work_sum " + goTestH1("ws.toml")}) {
			t.Errorf("member toml checksums = %v", got)
		}
		goStatusOf(t, w.Replacements[0].ChecksumStatus, model.GoChecksumRecorded, "workspace provider checksum")
		// Never applied to a project that is not a member.
		app := goFindProject(inv, filepath.Join(app, "go.mod"))
		for _, c := range goFindRequirement(app, "github.com/BurntSushi/toml").RecordedChecksums {
			if c.Source == model.GoChecksumSourceWorkspaceGoWorkSum {
				t.Error("go.work.sum enriched a non-member project")
			}
		}
	})

	t.Run("cache", func(t *testing.T) {
		src := goMustSource(t, inv, model.GoSourceCacheRoot, cache)
		goStatusOf(t, src.Status, model.GoStatusPartial, "cache root status")
		// inprogress is mid-extraction, mismatch holds foreign entries and
		// bad@notaversion is not a module version.
		if want := []string{model.GoReasonExtractionIncomplete, model.GoReasonParseError, model.GoReasonUnsupportedEntry}; !slices.Equal(src.Reasons, want) {
			t.Errorf("cache root reasons = %v, want %v", src.Reasons, want)
		}
		rows := []struct {
			path, version, extracted, archive, checksum string
		}{
			{"example.com/archiveonly", "v1.2.0", "", model.GoArtifactPresent, model.GoChecksumAbsent},
			// A readable archive survives an in-progress extraction.
			{"example.com/inprogress", "v1.0.0", model.GoArtifactPartial, model.GoArtifactPresent, model.GoChecksumRecorded},
			{"example.com/mismatch", "v1.0.0", "", model.GoArtifactUnreadable, model.GoChecksumAbsent},
			{"github.com/BurntSushi/toml", "v1.3.2", model.GoArtifactPresent, model.GoArtifactPresent, model.GoChecksumRecorded},
			{"golang.org/toolchain", "v0.0.1-go1.24.0.darwin-arm64", model.GoArtifactPresent, model.GoArtifactPartial, model.GoChecksumAbsent},
		}
		if len(inv.CachedModules) != len(rows) {
			t.Errorf("cached modules = %+v, want %d", inv.CachedModules, len(rows))
		}
		for _, r := range rows {
			c := goFindCached(inv, r.path, r.version)
			if c == nil {
				t.Errorf("missing cached %s@%s", r.path, r.version)
				continue
			}
			goStatusOf(t, goArtifactStatus(c, model.GoArtifactExtractedSource), r.extracted, r.path+" extracted")
			goStatusOf(t, goArtifactStatus(c, model.GoArtifactArchivePresent), r.archive, r.path+" archive")
			goStatusOf(t, c.ChecksumStatus, r.checksum, r.path+" checksum")
		}
		toml := goFindCached(inv, "github.com/BurntSushi/toml", "v1.3.2")
		if got := goChecksumValues(toml.GoChecksumEvidence); !slices.Equal(got, []string{"module_content cache_ziphash " + goTestH1("cache.toml")}) {
			t.Errorf("cache toml checksums = %v", got)
		}
		for _, c := range inv.CachedModules {
			if c.ModulePath == "example.com/bonly" {
				t.Error("a cached module's requirement became cache evidence")
			}
		}
		for _, p := range inv.Projects {
			if goPathWithin(p.ManifestPath, cache) {
				t.Errorf("cached module manifest %s became a project", p.ManifestPath)
			}
		}
		zh := goMustSource(t, inv, model.GoSourceChecksumFile, filepath.Join(cache, "cache", "download", "github.com", "!burnt!sushi", "toml", "@v", "v1.3.2.ziphash"))
		goStatusOf(t, zh.ParentSourceID, src.SourceID, "ziphash parent")
	})

	t.Run("bin", func(t *testing.T) {
		root := goMustSource(t, inv, model.GoSourceBinRoot, bin)
		goStatusOf(t, root.Status, model.GoStatusComplete, "bin root status")
		for name, want := range map[string]string{
			"tool": model.GoStatusComplete, "script": model.GoStatusComplete,
			"trunc": model.GoStatusPartial, "escape": model.GoStatusSkipped,
		} {
			b := goMustSource(t, inv, model.GoSourceBinary, filepath.Join(bin, name))
			goStatusOf(t, b.Status, want, name+" status")
			goStatusOf(t, b.ParentSourceID, root.SourceID, name+" parent")
			if !slices.Contains(root.DiscoveredSources, b.SourceID) {
				t.Errorf("bin root does not list %s", name)
			}
		}
		goStatusOf(t, goMustSource(t, inv, model.GoSourceBinary, filepath.Join(bin, "trunc")).Reasons[0], model.GoReasonBuildInfoUnusable, "trunc reason")
		goStatusOf(t, goMustSource(t, inv, model.GoSourceBinary, filepath.Join(bin, "escape")).Reasons[0], model.GoReasonOutsideApprovedRoots, "escape reason")
		if goFindSource(inv, model.GoSourceBinary, filepath.Join(bin, "stale")) != nil {
			t.Error("non-executable file became a binary source")
		}
		if len(inv.InstalledTools) != 1 {
			t.Fatalf("tools = %+v, want only the Go test binary", inv.InstalledTools)
		}
		tool := inv.InstalledTools[0]
		goStatusOf(t, tool.BinaryPath, filepath.Join(bin, "tool"), "tool path")
		goStatusOf(t, tool.MainModulePath, "github.com/step-security/dev-machine-guard", "tool main module")
		goStatusOf(t, tool.VersionStatus, model.GoVersionUnknown, "tool version status")
	})

	t.Run("status", func(t *testing.T) {
		goStatusOf(t, inv.Status, model.GoStatusPartial, "inventory status")
		want := []string{
			model.GoReasonBuildInfoUnusable, model.GoReasonExtractionIncomplete, model.GoReasonOutsideApprovedRoots,
			model.GoReasonParseError, model.GoReasonUnsupportedEntry,
		}
		if !slices.Equal(inv.Reasons, want) {
			t.Errorf("inventory reasons = %v, want %v", inv.Reasons, want)
		}
		if runtime.GOOS == model.PlatformDarwin && goFindProject(inv, filepath.Join(home, "Documents", "p", "go.mod")) != nil {
			t.Error("protected Documents project was read")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		inv2, audit2 := s.Scan(context.Background(), goTestTarget(home), []string{home}, nil)
		if a, b := goScanJSON(t, inv, audit), goScanJSON(t, inv2, audit2); !bytes.Equal(a, b) {
			t.Errorf("second scan differs:\n%s\n%s", a, b)
		}
	})
}

func TestGoScanner_Declines(t *testing.T) {
	home := goTestHome(t)
	tests := []struct {
		name   string
		target *user.User
	}{
		{"nil target", nil},
		{"no username", &user.User{Uid: "1000", HomeDir: home}},
		{"no home", &user.User{Username: "dev", Uid: "1000"}},
		{"root", &user.User{Username: "root", Uid: "0", HomeDir: home}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A bare Mock fails every file read, so any access would surface as a reason.
			inv, audit := NewGoScanner(executor.NewMock(), progress.NewNoop()).Scan(context.Background(), tc.target, []string{home}, nil)
			if inv.Status != model.GoStatusPartial || !slices.Equal(inv.Reasons, []string{model.GoReasonUserUnresolved}) || len(inv.Sources) != 0 {
				t.Errorf("inventory = %+v, want user_unresolved envelope", inv)
			}
			if audit.Status != model.GoStatusPartial || !slices.Contains(audit.Reasons, model.GoReasonUserUnresolved) {
				t.Errorf("audit = %+v, want user_unresolved", audit)
			}
		})
	}
}

func TestGoScanner_Roots(t *testing.T) {
	home := goTestHome(t)
	code := filepath.Join(home, "code")
	goWrite(t, filepath.Join(code, "p", "go.mod"), "module example.com/p\n", 0o644)
	private := filepath.Join(home, "private")
	s := goTestScanner(t, nil)
	s.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
				if p == private || goPathWithin(p, private) {
					return model.GoReasonSkippedProtected
				}
				return ""
			}, func(string) bool {
				return false
			}
	}
	inv, _ := s.Scan(context.Background(), goTestTarget(home),
		[]string{"", home, code, code + string(filepath.Separator), filepath.Join(home, "missing"), private}, nil)
	goCheckIntegrity(t, inv)

	if !slices.Contains(inv.Reasons, model.GoReasonPathUnresolved) {
		t.Errorf("empty root reasons = %v, want path_unresolved", inv.Reasons)
	}
	if goFindSource(inv, model.GoSourceProjectSearchRoot, code) != nil {
		t.Error("nested root emitted its own source")
	}
	missing := goMustSource(t, inv, model.GoSourceProjectSearchRoot, filepath.Join(home, "missing"))
	goStatusOf(t, missing.Presence, model.GoPresenceAbsent, "missing root presence")
	goStatusOf(t, missing.Status, model.GoStatusComplete, "missing root status")
	prot := goMustSource(t, inv, model.GoSourceProjectSearchRoot, private)
	goStatusOf(t, prot.Status, model.GoStatusSkipped, "protected root status")
	var roots int
	for _, src := range inv.Sources {
		if src.Kind == model.GoSourceProjectSearchRoot {
			roots++
		}
	}
	if roots != 3 {
		t.Errorf("search root sources = %d, want 3 (home, missing, private)", roots)
	}
	m := goMustSource(t, inv, model.GoSourceProjectManifest, filepath.Join(code, "p", "go.mod"))
	goStatusOf(t, m.ParentSourceID, goMustSource(t, inv, model.GoSourceProjectSearchRoot, home).SourceID, "folded manifest owner")

	// An explicitly configured relative root is normalized before any
	// containment check, the way --search-dirs code would be.
	t.Chdir(home)
	inv, _ = s.Scan(context.Background(), goTestTarget(home), []string{"code"}, nil)
	root := goMustSource(t, inv, model.GoSourceProjectSearchRoot, code)
	goStatusOf(t, root.Status, model.GoStatusComplete, "relative root status")
	m = goMustSource(t, inv, model.GoSourceProjectManifest, filepath.Join(code, "p", "go.mod"))
	goStatusOf(t, m.ParentSourceID, root.SourceID, "relative root manifest owner")
}

func goLimit[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func TestGoScanner_Limits(t *testing.T) {
	t.Run("entry", func(t *testing.T) {
		home := goTestHome(t)
		for _, d := range []string{"a", "b", "c"} {
			goMkdir(t, filepath.Join(home, "code", d))
		}
		goLimit(t, &maxGoWalkEntries, 2)
		inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), []string{filepath.Join(home, "code")}, nil)
		src := goMustSource(t, inv, model.GoSourceProjectSearchRoot, filepath.Join(home, "code"))
		goStatusOf(t, src.Status, model.GoStatusPartial, "entry-capped root")
		if !slices.Contains(src.Reasons, model.GoReasonEntryLimit) {
			t.Errorf("reasons = %v, want entry_limit", src.Reasons)
		}
	})
	t.Run("depth", func(t *testing.T) {
		home := goTestHome(t)
		deep := filepath.Join(home, "code", "a", "b", "go.mod")
		goWrite(t, deep, "module example.com/b\n", 0o644)
		goLimit(t, &maxGoWalkDepth, 1)
		inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), []string{filepath.Join(home, "code")}, nil)
		src := goMustSource(t, inv, model.GoSourceProjectSearchRoot, filepath.Join(home, "code"))
		if !slices.Contains(src.Reasons, model.GoReasonDepthLimit) || goFindProject(inv, deep) != nil {
			t.Errorf("depth-capped root = %+v, projects = %d", src, len(inv.Projects))
		}
	})
	t.Run("records", func(t *testing.T) {
		home := goTestHome(t)
		big := filepath.Join(home, "code", "big", "go.mod")
		goWrite(t, big, "module example.com/big\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n)\n", 0o644)
		goLimit(t, &maxGoRecords, 2)
		inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), []string{filepath.Join(home, "code")}, nil)
		src := goMustSource(t, inv, model.GoSourceProjectManifest, big)
		if len(inv.Projects) != 0 || !slices.Contains(src.Reasons, model.GoReasonRecordLimit) || inv.Status != model.GoStatusPartial {
			t.Errorf("record-capped: projects=%d source=%+v status=%s", len(inv.Projects), src, inv.Status)
		}
	})
	t.Run("output", func(t *testing.T) {
		home := goTestHome(t)
		goLimit(t, &maxGoOutputBytes, 10)
		inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), []string{home}, nil)
		if inv.Status != model.GoStatusPartial || !slices.Equal(inv.Reasons, []string{model.GoReasonOutputSizeLimit}) || len(inv.Sources) != 0 {
			t.Errorf("oversize inventory = %+v, want output_size_limit envelope", inv)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		home := goTestHome(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		inv, _ := goTestScanner(t, nil).Scan(ctx, goTestTarget(home), []string{home}, nil)
		if inv.Status != model.GoStatusPartial || !slices.Contains(inv.Reasons, model.GoReasonDeadlineExceeded) {
			t.Errorf("cancelled scan = %s %v, want partial deadline_exceeded", inv.Status, inv.Reasons)
		}
		for _, src := range inv.Sources {
			if src.Status == model.GoStatusComplete {
				t.Errorf("source %s %s complete after cancellation", src.Kind, src.Path)
			}
		}
	})
}

func TestGoScanner_WalkBoundaries(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("uses POSIX symlinks")
	}
	home := goTestHome(t)
	code := filepath.Join(home, "code")
	outside := t.TempDir()
	goWrite(t, filepath.Join(outside, "proj", "go.mod"), "module example.com/outside\n", 0o644)
	goMkdir(t, code)
	if err := os.Symlink(filepath.Join(outside, "proj"), filepath.Join(code, "dirlink")); err != nil {
		t.Fatal(err)
	}
	goMkdir(t, filepath.Join(code, "filelink"))
	if err := os.Symlink(filepath.Join(outside, "proj", "go.mod"), filepath.Join(code, "filelink", "go.mod")); err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(code, "mnt")
	goWrite(t, filepath.Join(mount, "go.mod"), "module example.com/mnt\n", 0o644)

	s := goTestScanner(t, nil)
	s.protection = func(string, *bool) (func(string) string, func(string) bool) {
		volume := func(p string) bool { return p == mount || goPathWithin(p, mount) }
		return func(p string) string {
			if volume(p) {
				return model.GoReasonSkippedProtected
			}
			return ""
		}, volume
	}
	inv, _ := s.Scan(context.Background(), goTestTarget(home), []string{code}, nil)
	goCheckIntegrity(t, inv)

	if len(inv.Projects) != 0 {
		t.Errorf("projects = %+v, want none (dir link not followed, file link refused, mount skipped)", inv.Projects)
	}
	link := goMustSource(t, inv, model.GoSourceProjectManifest, filepath.Join(code, "filelink", "go.mod"))
	goStatusOf(t, link.Status, model.GoStatusSkipped, "escaping go.mod link")
	if !slices.Equal(link.Reasons, []string{model.GoReasonOutsideApprovedRoots}) {
		t.Errorf("escaping link reasons = %v", link.Reasons)
	}
	root := goMustSource(t, inv, model.GoSourceProjectSearchRoot, code)
	goStatusOf(t, root.Status, model.GoStatusPartial, "root with excluded mount")
	if !slices.Contains(root.Reasons, model.GoReasonSkippedProtected) {
		t.Errorf("root reasons = %v, want skipped_protected for the volume", root.Reasons)
	}
}

func TestGoScanner_Redirects(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("uses POSIX symlinks")
	}
	t.Run("relative GOBIN", func(t *testing.T) {
		home := goTestHome(t)
		t.Setenv("GOBIN", "bin")
		inv, _ := goTestScanner(t, &user.User{Uid: "1000"}).Scan(context.Background(), goTestTarget(home), nil, nil)
		for _, src := range inv.Sources {
			if src.Kind == model.GoSourceBinRoot {
				t.Errorf("relative GOBIN produced bin root %s", src.Path)
			}
		}
		if !slices.Contains(inv.Reasons, model.GoReasonPathUnresolved) {
			t.Errorf("reasons = %v, want path_unresolved", inv.Reasons)
		}
	})
	t.Run("unverified process env ignored", func(t *testing.T) {
		home := goTestHome(t)
		t.Setenv("GOBIN", filepath.Join(home, "elsewhere"))
		inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), nil, nil)
		goMustSource(t, inv, model.GoSourceBinRoot, filepath.Join(home, "go", "bin"))
	})
	t.Run("GOPATH link outside scope", func(t *testing.T) {
		home := goTestHome(t)
		other := t.TempDir()
		goWrite(t, filepath.Join(other, "bin", "tool"), "#!/bin/sh\n", 0o755)
		goMkdir(t, filepath.Join(other, "pkg", "mod"))
		if err := os.Symlink(other, filepath.Join(home, "go")); err != nil {
			t.Fatal(err)
		}
		inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), nil, nil)
		for _, kind := range []string{model.GoSourceBinRoot, model.GoSourceCacheRoot} {
			src := goMustSource(t, inv, kind, filepath.Join(home, "go", map[string]string{model.GoSourceBinRoot: "bin", model.GoSourceCacheRoot: filepath.Join("pkg", "mod")}[kind]))
			goStatusOf(t, src.Status, model.GoStatusSkipped, kind+" status")
			if !slices.Equal(src.Reasons, []string{model.GoReasonOutsideApprovedRoots}) {
				t.Errorf("%s reasons = %v", kind, src.Reasons)
			}
		}
		if goFindSource(inv, model.GoSourceBinary, filepath.Join(home, "go", "bin", "tool")) != nil {
			t.Error("binary behind an escaping GOPATH was read")
		}
	})
}

func TestGoScanner_ChecksumEdges(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("uses POSIX permissions")
	}
	home := goTestHome(t)
	code := filepath.Join(home, "code")
	manifest := filepath.Join(code, "p", "go.mod")
	goWrite(t, manifest, "module example.com/p\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n)\n", 0o644)
	sumPath := filepath.Join(code, "p", "go.sum")
	lineA := "example.com/a v1.0.0 " + goTestH1("a")
	lineB := "example.com/b v1.0.0 " + goTestH1("b")
	goWrite(t, sumPath, lineA+"\n"+lineB+"\n", 0o644)
	s := goTestScanner(t, nil)
	scan := func() *model.GoProject {
		t.Helper()
		inv, _ := s.Scan(context.Background(), goTestTarget(home), []string{code}, nil)
		p := goFindProject(inv, manifest)
		if p == nil {
			t.Fatal("project missing")
		}
		return p
	}

	p := scan()
	goStatusOf(t, goFindRequirement(p, "example.com/a").ChecksumStatus, model.GoChecksumRecorded, "a before")
	goWrite(t, sumPath, lineB+"\n", 0o644)
	p = scan()
	goStatusOf(t, goFindRequirement(p, "example.com/a").ChecksumStatus, model.GoChecksumAbsent, "a after removal")
	goStatusOf(t, goFindRequirement(p, "example.com/b").ChecksumStatus, model.GoChecksumRecorded, "b after removal")

	// An invalid token never becomes a recorded checksum; the requirement stays.
	goWrite(t, sumPath, lineA+"\nexample.com/b v1.0.0 h1:not-base64\n", 0o644)
	p = scan()
	if b := goFindRequirement(p, "example.com/b"); b == nil || b.ChecksumStatus != model.GoChecksumInvalid || len(b.RecordedChecksums) != 0 {
		t.Errorf("invalid token requirement = %+v, want invalid with no checksums", b)
	}
	// An unattributable bad line may have held any module's hash, so a match
	// from that file keeps its value but is not a complete record.
	if a := goFindRequirement(p, "example.com/a"); a.ChecksumStatus != model.GoChecksumPartial || len(a.RecordedChecksums) != 1 {
		t.Errorf("a beside an invalid line = %+v, want partial with its checksum kept", a)
	}

	// An over-long line inside the byte limit leaves checksum coverage
	// incomplete but keeps the matches already recovered.
	goWrite(t, sumPath, lineA+"\n"+lineB+strings.Repeat(" ", maxGoSumLineBytes)+"\n", 0o644)
	p = scan()
	a := goFindRequirement(p, "example.com/a")
	if a.ChecksumStatus != model.GoChecksumPartial || len(a.RecordedChecksums) != 1 {
		t.Errorf("a beside an over-long line = %+v, want partial with its checksum kept", a)
	}
	goStatusOf(t, goFindRequirement(p, "example.com/b").ChecksumStatus, model.GoChecksumPartial, "b on the over-long line")

	if os.Geteuid() == 0 {
		t.Skip("root reads a chmod 000 file")
	}
	goWrite(t, sumPath, lineA+"\n", 0o000)
	p = scan()
	goStatusOf(t, goFindRequirement(p, "example.com/a").ChecksumStatus, model.GoChecksumUnreadable, "unreadable go.sum")
}

// TestGoScanner_VerifiedEnvNoSecrets runs as the developer with credentials
// in the Go env file and process env: the alternate modfile is honored and no
// secret reaches the output or the logs.
func TestGoScanner_VerifiedEnvNoSecrets(t *testing.T) {
	home := goTestHome(t)
	app := filepath.Join(home, "code", "app")
	goWrite(t, filepath.Join(app, "go.mod"), "module example.com/app\n", 0o644)
	alt := filepath.Join(app, "alt.mod")
	goWrite(t, alt, "module example.com/app\n\nrequire example.com/a v1.0.0\n", 0o644)
	goWrite(t, filepath.Join(app, "alt.sum"), "example.com/a v1.0.0 "+goTestH1("alt.a")+"\n", 0o644)
	envFile := filepath.Join(home, "cfg", "goenv")
	goWrite(t, envFile, strings.Join([]string{
		"GOPROXY=https://alice:hunter2@proxy.corp.example/mod?token=tok3n#frag3,direct",
		"GOFLAGS=-modfile=" + alt + " -ldflags=-X=main.key=zzsecret",
		"GOPRIVATE=example.com/private",
	}, "\n")+"\n", 0o644)
	t.Setenv("GOENV", envFile)
	t.Setenv("GOAUTH", "command /usr/local/bin/helper --token=cmdsecret")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	s := NewGoScanner(&goTrap{Executor: executor.NewReal(), t: t, current: &user.User{Uid: "1000"}}, progress.NewLogger(progress.LevelDebug))
	inv, audit := s.Scan(context.Background(), goTestTarget(home), []string{home}, nil)
	os.Stderr = stderr
	_ = w.Close()
	logs, _ := io.ReadAll(r)

	goCheckIntegrity(t, inv)
	altSrc := goMustSource(t, inv, model.GoSourceAlternateManifest, alt)
	sum := goMustSource(t, inv, model.GoSourceChecksumFile, filepath.Join(app, "alt.sum"))
	goStatusOf(t, sum.ParentSourceID, altSrc.SourceID, "alt.sum parent")
	goStatusOf(t, altSrc.ParentSourceID, goMustSource(t, inv, model.GoSourceProjectManifest, filepath.Join(app, "go.mod")).SourceID, "alternate manifest parent")
	p := goFindProject(inv, alt)
	if p == nil || p.Path != app {
		t.Fatalf("alternate project = %+v", p)
	}
	goStatusOf(t, p.Requirements[0].ChecksumStatus, model.GoChecksumRecorded, "alt requirement checksum")

	out := goScanJSON(t, inv, audit)
	for _, secret := range []string{"alice", "hunter2", "tok3n", "frag3", "zzsecret", "cmdsecret", "/usr/local/bin/helper"} {
		if bytes.Contains(out, []byte(secret)) {
			t.Errorf("output leaks %q", secret)
		}
		if bytes.Contains(logs, []byte(secret)) {
			t.Errorf("logs leak %q", secret)
		}
	}
	if !bytes.Contains(out, []byte("proxy.corp.example")) {
		t.Error("sanitized GOPROXY host missing from the audit")
	}
}

// TestGoScanner_CacheMarkerUnreadable: when a module's @v listing cannot be
// read, its .partial and .ziphash state is unknown, so extraction is not
// declared complete and the checksum is unreadable rather than absent.
func TestGoScanner_CacheMarkerUnreadable(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows || os.Geteuid() == 0 {
		t.Skip("uses POSIX permissions")
	}
	home := goTestHome(t)
	cache := filepath.Join(home, "go", "pkg", "mod")
	goMkdir(t, filepath.Join(cache, "example.com", "m@v1.0.0"))
	vDir := filepath.Join(cache, "cache", "download", "example.com", "m", "@v")
	goWrite(t, filepath.Join(vDir, "v1.0.0.ziphash"), goTestH1("m")+"\n", 0o644)
	goMkdir(t, filepath.Join(cache, "example.com", "other@v1.0.0"))
	if err := os.Chmod(vDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(vDir, 0o755) })

	inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), nil, nil)
	src := goMustSource(t, inv, model.GoSourceCacheRoot, cache)
	if src.Status != model.GoStatusPartial || !slices.Contains(src.Reasons, model.GoReasonPermissionDenied) {
		t.Errorf("cache root = %s %v, want partial permission_denied", src.Status, src.Reasons)
	}
	m := goFindCached(inv, "example.com/m", "v1.0.0")
	if m == nil {
		t.Fatal("extracted module dropped when its marker check failed")
	}
	goStatusOf(t, goArtifactStatus(m, model.GoArtifactExtractedSource), model.GoArtifactPartial, "extracted with unreadable marker")
	goStatusOf(t, m.ChecksumStatus, model.GoChecksumUnreadable, "checksum with unreadable marker")
	// A module with no @v directory at all is still an ordinary absence.
	goStatusOf(t, goFindCached(inv, "example.com/other", "v1.0.0").ChecksumStatus, model.GoChecksumAbsent, "unlisted module checksum")
}

func TestGoScanner_BinOversize(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("uses exec bits")
	}
	home := goTestHome(t)
	bin := filepath.Join(home, "go", "bin")
	goWrite(t, filepath.Join(bin, "big"), "#!/bin/sh\n"+strings.Repeat("#", 64)+"\n", 0o755)
	goLimit(t, &maxGoBinaryBytes, 16)
	inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), nil, nil)
	b := goMustSource(t, inv, model.GoSourceBinary, filepath.Join(bin, "big"))
	if b.Status != model.GoStatusPartial || !slices.Equal(b.Reasons, []string{model.GoReasonSizeLimit}) || len(inv.InstalledTools) != 0 {
		t.Errorf("oversized binary = %+v, tools = %d", b, len(inv.InstalledTools))
	}
	goStatusOf(t, goMustSource(t, inv, model.GoSourceBinRoot, bin).Status, model.GoStatusComplete, "bin root with an oversized child")
}

// TestGoScanner_CacheCoverage: an artifact that cannot be established
// degrades the cache root, so a complete root never implies absence, while
// independently readable evidence survives.
func TestGoScanner_CacheCoverage(t *testing.T) {
	const mod = "example.com/m@v1.0.0"
	good := func(t *testing.T) string { return string(goTestZip(t, mod+"/a.go")) }
	tests := []struct {
		name                string
		extracted           bool
		files               func(t *testing.T) map[string]string // @v file name -> content
		entryCap            int
		reasons             []string
		wantExtr, wantArchv string
	}{
		{"complete", true, func(t *testing.T) map[string]string {
			return map[string]string{"v1.0.0.zip": good(t), "v1.0.0.ziphash": goTestH1("m")}
		}, 0, []string{}, model.GoArtifactPresent, model.GoArtifactPresent},
		{"partial marker", true, func(t *testing.T) map[string]string {
			return map[string]string{"v1.0.0.zip": good(t), "v1.0.0.ziphash": goTestH1("m"), "v1.0.0.partial": ""}
		}, 0, []string{model.GoReasonExtractionIncomplete}, model.GoArtifactPartial, model.GoArtifactPresent},
		{"ziphash missing", true, func(t *testing.T) map[string]string {
			return map[string]string{"v1.0.0.zip": good(t)}
		}, 0, []string{model.GoReasonExtractionIncomplete}, model.GoArtifactPartial, model.GoArtifactPresent},
		{"malformed zip", false, func(t *testing.T) map[string]string {
			return map[string]string{"v1.0.0.zip": "not a zip"}
		}, 0, []string{model.GoReasonParseError}, "", model.GoArtifactUnreadable},
		{"zip outside prefix", false, func(t *testing.T) map[string]string {
			return map[string]string{"v1.0.0.zip": string(goTestZip(t, "example.com/other@v1.0.0/a.go"))}
		}, 0, []string{model.GoReasonParseError}, "", model.GoArtifactUnreadable},
		{"zip entry cap", false, func(t *testing.T) map[string]string {
			return map[string]string{"v1.0.0.zip": string(goTestZip(t, mod+"/a.go", mod+"/b.go"))}
		}, 1, []string{model.GoReasonEntryLimit}, "", model.GoArtifactPartial},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			cache := filepath.Join(home, "go", "pkg", "mod")
			if tc.extracted {
				goWrite(t, filepath.Join(cache, "example.com", "m@v1.0.0", "a.go"), "package m\n", 0o644)
			}
			for name, data := range tc.files(t) {
				goWrite(t, filepath.Join(cache, "cache", "download", "example.com", "m", "@v", name), data, 0o644)
			}
			// Deliberately unopened toolchain archives never degrade the root.
			goWrite(t, filepath.Join(cache, "cache", "download", "golang.org", "toolchain", "@v", "v0.0.1-go1.24.0.linux-amd64.zip"), "not opened", 0o644)
			if tc.entryCap > 0 {
				goLimit(t, &maxGoZipEntries, tc.entryCap)
			}
			inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), nil, nil)
			src := goMustSource(t, inv, model.GoSourceCacheRoot, cache)
			if !slices.Equal(src.Reasons, tc.reasons) {
				t.Errorf("cache root reasons = %v, want %v", src.Reasons, tc.reasons)
			}
			want := model.GoStatusComplete
			if len(tc.reasons) > 0 {
				want = model.GoStatusPartial
			}
			goStatusOf(t, src.Status, want, "cache root status")
			goStatusOf(t, inv.Status, want, "inventory status")
			m := goFindCached(inv, "example.com/m", "v1.0.0")
			if m == nil {
				t.Fatal("module evidence dropped")
			}
			goStatusOf(t, goArtifactStatus(m, model.GoArtifactExtractedSource), tc.wantExtr, "extracted")
			goStatusOf(t, goArtifactStatus(m, model.GoArtifactArchivePresent), tc.wantArchv, "archive")
		})
	}
}

// TestGoScanner_VendorUnreadable: a package directory that cannot be checked
// is not absence, so the vendor root turns partial instead of retiring the
// module; a genuinely missing directory stays an authoritative absence.
func TestGoScanner_VendorUnreadable(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows || os.Geteuid() == 0 {
		t.Skip("uses POSIX permissions")
	}
	for _, tc := range []struct {
		name       string
		deny       bool
		wantStatus string
		wantMods   []string
	}{
		{"missing directory is absence", false, model.GoStatusComplete, []string{"example.com/b"}},
		{"denied directory is partial", true, model.GoStatusPartial, []string{"example.com/b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			app := filepath.Join(home, "app")
			goWrite(t, filepath.Join(app, "go.mod"), "module example.com/app\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n)\n", 0o644)
			goWrite(t, filepath.Join(app, "vendor", "modules.txt"),
				"# example.com/a v1.0.0\n## explicit\nexample.com/a/pkg\n# example.com/b v1.0.0\n## explicit\nexample.com/b\n", 0o644)
			goMkdir(t, filepath.Join(app, "vendor", "example.com", "b"))
			if tc.deny {
				denied := filepath.Join(app, "vendor", "example.com", "a")
				goMkdir(t, filepath.Join(denied, "pkg"))
				if err := os.Chmod(denied, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })
			}
			inv, _ := goTestScanner(t, nil).Scan(context.Background(), goTestTarget(home), []string{home}, nil)
			src := goMustSource(t, inv, model.GoSourceVendorRoot, filepath.Join(app, "vendor"))
			goStatusOf(t, src.Status, tc.wantStatus, "vendor root status")
			if tc.deny && !slices.Equal(src.Reasons, []string{model.GoReasonPermissionDenied}) {
				t.Errorf("vendor root reasons = %v, want permission_denied", src.Reasons)
			}
			var mods []string
			for _, v := range inv.VendoredModules {
				mods = append(mods, v.ModulePath)
			}
			if !slices.Equal(mods, tc.wantMods) {
				t.Errorf("vendored = %v, want %v", mods, tc.wantMods)
			}
		})
	}
}

// TestGoScanner_QuotedModfile: GOFLAGS is split the way cmd/go splits it, so
// a quoted -modfile with spaces is found; a value Go would reject is
// reported unresolved rather than guessed.
func TestGoScanner_QuotedModfile(t *testing.T) {
	home := goTestHome(t)
	app := filepath.Join(home, "My Project")
	goWrite(t, filepath.Join(app, "go.mod"), "module example.com/app\n", 0o644)
	alt := filepath.Join(app, "ci.mod")
	goWrite(t, alt, "module example.com/app\n\nrequire example.com/a v1.0.0\n", 0o644)
	goWrite(t, filepath.Join(app, "ci.sum"), "example.com/a v1.0.0 "+goTestH1("ci.a")+"\n", 0o644)
	for _, tc := range []struct {
		name, flags string
		found       bool
	}{
		{"quoted path", `"-modfile=` + alt + `" -mod=readonly`, true},
		{"unterminated quote", `"-modfile=` + alt + ` -mod=readonly`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOFLAGS", tc.flags)
			inv, _ := goTestScanner(t, &user.User{Uid: "1000"}).Scan(context.Background(), goTestTarget(home), []string{home}, nil)
			goCheckIntegrity(t, inv)
			p := goFindProject(inv, alt)
			if (p != nil) != tc.found {
				t.Fatalf("alternate project found = %v, want %v", p != nil, tc.found)
			}
			if tc.found {
				goStatusOf(t, p.Requirements[0].ChecksumStatus, model.GoChecksumRecorded, "alt requirement checksum")
			} else if !slices.Contains(inv.Reasons, model.GoReasonAlternateManifestUnresolved) {
				t.Errorf("inventory reasons = %v, want alternate_manifest_unresolved", inv.Reasons)
			}
		})
	}
}
