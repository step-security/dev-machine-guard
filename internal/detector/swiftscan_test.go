package detector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// swiftTrap adds the Swift never-read files: manifests, netrc, Git
// internals, checkouts, SwiftPM security state and Xcode build products. It
// also reports a chosen platform so one host covers every layout.
type swiftTrap struct {
	*rubyTrap
	goos       string
	lists      map[string]int
	listErrors map[string]error
}

func (x *swiftTrap) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	return &swiftTrap{x.rubyTrap.GuardedFiles(roots, guard, max).(*rubyTrap), x.goos, x.lists, x.listErrors}
}
func (x *swiftTrap) GOOS() string { return x.goos }
func (x *swiftTrap) ReadDirLimit(path string, max int) ([]os.DirEntry, bool, error) {
	x.lists[filepath.Clean(path)]++
	if err := x.listErrors[filepath.Clean(path)]; err != nil {
		return nil, false, err
	}
	return x.rubyTrap.ReadDirLimit(path, max)
}
func (x *swiftTrap) ReadFile(path string) ([]byte, error) {
	name := filepath.Base(path)
	forbidden := []string{"Build", "Logs", "Index.noindex", "security", "checkouts", "objects", "refs"}
	if name == ".netrc" || name == "HEAD" || swiftManifest(name) || slices.ContainsFunc(strings.Split(filepath.ToSlash(path), "/"), func(p string) bool { return slices.Contains(forbidden, p) }) {
		x.t.Fatalf("read forbidden file %s", path)
	}
	return x.rubyTrap.ReadFile(path)
}

func swiftTestScanner(t *testing.T, home, goos string) (*SwiftScanner, *swiftTrap) {
	t.Helper()
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("fixture paths are POSIX")
	}
	_, inner := rubyTestScanner(t, home)
	x := &swiftTrap{rubyTrap: inner, goos: goos, lists: map[string]int{}, listErrors: map[string]error{}}
	s := NewSwiftScanner(x, progress.NewNoop())
	s.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(string) string { return "" }, func(string) bool { return false }
	}
	return s, x
}

// swiftTCC refuses all of ~/Library, as macOS privacy protection does for walks.
func swiftTCC(home string) func(string, *bool) (func(string) string, func(string) bool) {
	lib := strings.ToLower(filepath.Join(home, "Library"))
	return func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if k := strings.ToLower(filepath.Clean(p)); k == lib || strings.HasPrefix(k, lib+"/") {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
}

const swiftLabHome = "/Users/supermac/swift-inventory-lab-20261104"

// swiftCopy writes a native fixture, relocating its recorded lab paths.
func swiftCopy(t *testing.T, name, dest, lab string) {
	t.Helper()
	goWrite(t, dest, strings.ReplaceAll(string(swiftFixture(t, name)), swiftLabHome, lab), 0o600)
}

func swiftPlist(workspace string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>WorkspacePath</key><string>` + workspace + `</string></dict></plist>`
}

func swiftDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// swiftWriteFixture builds a macOS developer home from the lab bytes.
func swiftWriteFixture(t *testing.T, home, root string) {
	t.Helper()
	lab := filepath.Join(home, "lab")
	app := filepath.Join(root, "app")
	goWrite(t, filepath.Join(app, "Package.swift"), "CANARY_MANIFEST", 0o600)
	goWrite(t, filepath.Join(app, "Package@swift-5.9.swift"), "CANARY_MANIFEST", 0o600)
	swiftCopy(t, "resolved-v3.json", filepath.Join(app, "Package.resolved"), lab)
	swiftCopy(t, "workspace-edited-macos.json", filepath.Join(app, ".build", "workspace-state.json"), lab)
	goWrite(t, filepath.Join(app, ".build", "checkouts", "swift-numerics", "Package.swift"), "CANARY_MANIFEST", 0o600)
	goWrite(t, filepath.Join(app, "Packages", "swift-algorithms", "Package.swift"), "CANARY_MANIFEST", 0o600)
	swiftCopy(t, "mirrors-modern.json", filepath.Join(app, ".swiftpm", "configuration", "mirrors.json"), lab)
	// The auxiliary workspace Xcode generates for a package is never a project.
	goWrite(t, filepath.Join(app, ".swiftpm", "xcode", "package.xcworkspace", "contents.xcworkspacedata"), "<Workspace/>", 0o600)

	ios := filepath.Join(root, "ios")
	goWrite(t, filepath.Join(ios, "App.xcodeproj", "project.pbxproj"), "CANARY_PROJECT", 0o600)
	swiftCopy(t, "resolved-xcode-app.json", filepath.Join(ios, "App.xcodeproj", "project.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved"), lab)
	swiftCopy(t, "resolved-branch.json", filepath.Join(ios, "Suite.xcworkspace", "xcshareddata", "swiftpm", "Package.resolved"), lab)

	// A custom scratch path holds checkouts whose manifests are not projects.
	scratch := filepath.Join(root, "scratch")
	swiftCopy(t, "workspace-v1-mirror.json", filepath.Join(scratch, "workspace-state.json"), lab)
	goWrite(t, filepath.Join(scratch, "checkouts", "RenamedAlgorithms", "Package.swift"), "CANARY_MANIFEST", 0o600)

	plugin := filepath.Join(root, "plugin")
	goWrite(t, filepath.Join(plugin, "Package.swift"), "CANARY_MANIFEST", 0o600)
	swiftCopy(t, "workspace-binary-plugin.json", filepath.Join(plugin, ".build", "workspace-state.json"), lab)
	swiftDir(t, filepath.Join(lab, "projects", "BinaryPlugin", ".build", "artifacts", "swiftlintplugins", "SwiftLintBinary", "SwiftLintBinary.artifactbundle"))

	lib := filepath.Join(home, "Library")
	cache := filepath.Join(lib, "Caches", "org.swift.swiftpm")
	repo := filepath.Join(cache, "repositories", "swift-algorithms-1a2b3c4d")
	goWrite(t, filepath.Join(repo, "config"), "[core]\n\tbare = true\n[remote \"origin\"]\n\turl = https://github.com/apple/swift-algorithms.git\n", 0o600)
	goWrite(t, filepath.Join(repo, "HEAD"), "ref: refs/heads/main\n", 0o600)
	swiftDir(t, filepath.Join(repo, "objects"))
	swiftDir(t, filepath.Join(repo, "refs"))
	download := filepath.Join(cache, "registry", "downloads", "exampleregistry", "HelloWorld", "1.0.0")
	goWrite(t, filepath.Join(download, "Package.swift"), "CANARY_MANIFEST", 0o600)
	swiftCopy(t, "registry-receipt.json", filepath.Join(download, ".registry-metadata"), lab)

	derived := filepath.Join(lib, "Developer", "Xcode", "DerivedData")
	goWrite(t, filepath.Join(derived, "App-abc", "info.plist"), swiftPlist(filepath.Join(ios, "App.xcodeproj")), 0o600)
	swiftCopy(t, "workspace-xcode.json", filepath.Join(derived, "App-abc", "SourcePackages", "workspace-state.json"), lab)
	swiftDir(t, filepath.Join(derived, "App-abc", "SourcePackages", "checkouts", "swift-algorithms"))
	goWrite(t, filepath.Join(derived, "App-abc", "Build", "Intermediates.noindex", "x.json"), "CANARY_BUILD", 0o600)
	swiftCopy(t, "workspace-path-linux.json", filepath.Join(derived, "Other-def", "SourcePackages", "workspace-state.json"), lab)
	swiftDir(t, filepath.Join(derived, "ModuleCache.noindex"))

	config := filepath.Join(lib, "org.swift.swiftpm")
	swiftCopy(t, "registries.json", filepath.Join(config, "configuration", "registries.json"), lab)
	swiftCopy(t, "mirrors-legacy.json", filepath.Join(config, "mirrors.json"), lab)
	goWrite(t, filepath.Join(config, "security", "fingerprints", "x.json"), "CANARY_FINGERPRINT", 0o600)
	goWrite(t, filepath.Join(lib, "Mail", "inbox"), "CANARY_MAIL", 0o600)
	goWrite(t, filepath.Join(home, ".netrc"), "machine example.invalid login dev password CANARY_NETRC\n", 0o600)
}

func swiftSource(t *testing.T, inv *model.SwiftInventory, kind, path string) model.SwiftSource {
	t.Helper()
	for _, s := range inv.Sources {
		if s.Kind == kind && s.Path == path {
			return s
		}
	}
	t.Fatalf("no %s source at %s", kind, path)
	return model.SwiftSource{}
}

func swiftPackages(inv *model.SwiftInventory, evidence, name string) []model.SwiftPackage {
	out := []model.SwiftPackage{}
	for _, p := range inv.Packages {
		if p.Evidence == evidence && p.PackageName == name {
			out = append(out, p)
		}
	}
	return out
}

func swiftJSON(t *testing.T, v ...any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// swiftAssertRefs checks the graph the backend validates: unique sources,
// existing parents and children, evidence on its owning kind.
func swiftAssertRefs(t *testing.T, inv *model.SwiftInventory) {
	t.Helper()
	byID := map[string]model.SwiftSource{}
	for _, s := range inv.Sources {
		if _, dup := byID[s.SourceID]; dup {
			t.Errorf("duplicate source %s", s.Path)
		}
		byID[s.SourceID] = s
	}
	for _, s := range inv.Sources {
		if _, ok := byID[s.ParentSourceID]; s.ParentSourceID != "" && !ok {
			t.Errorf("source %s has missing parent", s.Path)
		}
		for _, child := range s.DiscoveredSources {
			if byID[child].ParentSourceID != s.SourceID {
				t.Errorf("source %s lists a child it does not own", s.Path)
			}
		}
		if s.Status == "complete" && s.Presence == "unknown" {
			t.Errorf("complete source %s has unknown presence", s.Path)
		}
	}
	owners := map[string]string{"locked_package": "lockfile", "managed_dependency": "workspace_state", "artifact_reference": "workspace_state",
		"cached_repository": "cached_repository", "cached_registry_package": "cached_registry_package"}
	for _, p := range inv.Packages {
		if src, ok := byID[p.SourceID]; !ok || src.Kind != owners[p.Evidence] || src.Path != p.SourcePath {
			t.Errorf("package %s %s on source %+v", p.Evidence, p.PackageName, src)
		}
		if (p.VersionStatus == "known") != (p.Version != "") || p.RecordedChecksums == nil || p.Reasons == nil {
			t.Errorf("package shape %+v", p)
		}
	}
	for _, p := range inv.Projects {
		if src, ok := byID[p.SourceID]; !ok || src.Kind != "project" || src.Path != p.ProjectPath {
			t.Errorf("project %s on source %+v", p.ProjectPath, src)
		}
	}
}

func TestSwiftScanFixture(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	swiftWriteFixture(t, home, root)
	scanner, x := swiftTestScanner(t, home, model.PlatformDarwin)
	scanner.protection = swiftTCC(home)
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	swiftAssertRefs(t, inv)
	if inv.Status != "complete" || audit.Status != "complete" {
		t.Fatalf("inventory = %s %v, audit = %s %v", inv.Status, inv.Reasons, audit.Status, audit.Reasons)
	}
	out := swiftJSON(t, inv, audit)
	for _, canary := range []string{"CANARY", "supermac", "password"} {
		if strings.Contains(out, canary) {
			t.Errorf("output contains %q", canary)
		}
	}

	app, ios, scratch := filepath.Join(root, "app"), filepath.Join(root, "ios"), filepath.Join(root, "scratch")
	projects := []model.SwiftProject{}
	for _, p := range inv.Projects {
		projects = append(projects, model.SwiftProject{ProjectPath: p.ProjectPath, Tool: p.Tool})
	}
	want := []model.SwiftProject{{ProjectPath: app, Tool: "swiftpm"}, {ProjectPath: filepath.Join(ios, "App.xcodeproj"), Tool: "xcode"},
		{ProjectPath: filepath.Join(ios, "Suite.xcworkspace"), Tool: "xcode"}, {ProjectPath: filepath.Join(root, "plugin"), Tool: "swiftpm"}}
	if !slices.Equal(projects, want) {
		t.Errorf("projects = %+v", projects)
	}
	walk := swiftSource(t, inv, "project_search_root", root)
	if walk.DiscoveredSources == nil {
		t.Error("completed walk lacks discovered_sources")
	}
	for _, name := range []string{"Package.swift", "Package@swift-5.9.swift"} {
		swiftSource(t, inv, "manifest", filepath.Join(app, name))
	}

	// Lock pins are selections in their project.
	locked := swiftPackages(inv, "locked_package", "swift-algorithms")
	if len(locked) != 3 {
		t.Fatalf("locked swift-algorithms = %+v", locked)
	}
	for _, p := range locked {
		if p.ProjectPath == filepath.Join(ios, "Suite.xcworkspace") && (p.Branch != "main" || p.VersionStatus != "unknown" || p.Tool != "xcode") {
			t.Errorf("branch pin = %+v", p)
		}
		if p.ProjectPath == app && (p.Version != "1.2.1" || p.Tool != "swiftpm" || p.Scope != "project" || p.Origin.URL != "https://github.com/apple/swift-algorithms.git") {
			t.Errorf("app pin = %+v", p)
		}
	}

	// The edited dependency lives in the package's Packages folder; its history is not its version.
	edited := swiftPackages(inv, "managed_dependency", "swift-algorithms")
	var appEdited, derived *model.SwiftPackage
	for i, p := range edited {
		switch p.SourcePath {
		case filepath.Join(app, ".build", "workspace-state.json"):
			appEdited = &edited[i]
		case filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "App-abc", "SourcePackages", "workspace-state.json"):
			derived = &edited[i]
		}
	}
	if appEdited == nil || appEdited.ManagedState != "edited" || appEdited.VersionStatus != "unknown" || appEdited.BasedOn == nil || appEdited.BasedOn.Version != "1.2.1" ||
		*appEdited.Installation != (model.SwiftInstallation{Path: filepath.Join(app, "Packages", "swift-algorithms"), PathStatus: "resolved", Presence: "present"}) {
		t.Errorf("edited = %+v", appEdited)
	}
	for _, p := range swiftPackages(inv, "managed_dependency", "swift-numerics") {
		if p.ProjectPath == app && *p.Installation != (model.SwiftInstallation{Path: filepath.Join(app, ".build", "checkouts", "swift-numerics"), PathStatus: "resolved", Presence: "present"}) {
			t.Errorf("checkout = %+v", p)
		}
	}

	// DerivedData state joins only the project its plist names.
	if derived == nil || derived.ProjectPath != filepath.Join(ios, "App.xcodeproj") || derived.Scope != "project" || derived.Tool != "xcode" || derived.Installation.Presence != "present" {
		t.Errorf("derived = %+v", derived)
	}
	other := swiftPackages(inv, "managed_dependency", "local library")
	if len(other) != 1 || other[0].ProjectPath != "" || other[0].Scope != "user" || other[0].Origin.Kind != "path" || other[0].Installation.Presence != "absent" {
		t.Errorf("unassociated derived = %+v", other)
	}

	// A detached scratch directory is evidence with no proven project.
	renamed := swiftPackages(inv, "managed_dependency", "renamedalgorithms")
	if len(renamed) != 1 || renamed[0].Scope != "unknown" || renamed[0].Tool != "unknown" || renamed[0].ProjectPath != "" || renamed[0].Origin.Kind != "path" ||
		renamed[0].Installation.Path != filepath.Join(scratch, "checkouts", "RenamedAlgorithms") {
		t.Errorf("scratch = %+v", renamed)
	}
	if src := swiftSource(t, inv, "workspace_state", filepath.Join(scratch, "workspace-state.json")); src.ParentSourceID != walk.SourceID {
		t.Errorf("scratch source = %+v", src)
	}

	// A binary artifact takes its version from the one matching checkout.
	artifact := swiftPackages(inv, "artifact_reference", "swiftlintplugins")
	if len(artifact) != 1 || artifact[0].Version != "0.63.2" || artifact[0].Origin.Kind != "git" || artifact[0].Artifact.Kind != "artifact_archive" ||
		artifact[0].Artifact.URL == "" || len(artifact[0].RecordedChecksums) != 1 || artifact[0].RecordedChecksums[0].SourceKind != "workspace_state" ||
		artifact[0].Installation.Presence != "present" {
		t.Errorf("artifact = %+v", artifact)
	}

	repo := swiftPackages(inv, "cached_repository", "swift-algorithms")
	if len(repo) != 1 || repo[0].Origin.URL != "https://github.com/apple/swift-algorithms.git" || repo[0].Scope != "user" || repo[0].Tool != "unknown" || repo[0].VersionStatus != "unknown" {
		t.Errorf("cached repository = %+v", repo)
	}
	registry := swiftPackages(inv, "cached_registry_package", "exampleregistry.helloworld")
	if len(registry) != 1 || registry[0].Version != "1.0.0" || registry[0].Origin != (model.SwiftOrigin{Kind: "registry", URL: "http://127.0.0.1:8080"}) {
		t.Errorf("cached registry package = %+v", registry)
	}
	for _, p := range inv.Packages {
		if strings.Contains(p.SourcePath, string(filepath.Separator)+"Build"+string(filepath.Separator)) || p.ProjectPath == filepath.Join(scratch, "checkouts", "RenamedAlgorithms") {
			t.Errorf("unexpected package %+v", p)
		}
	}

	// Only the three SwiftPM roots under ~/Library are read; the rest is never listed.
	for path := range x.lists {
		if rel, err := filepath.Rel(filepath.Join(home, "Library"), path); err == nil && !strings.HasPrefix(rel, "..") &&
			!strings.HasPrefix(rel, filepath.Join("Caches", "org.swift.swiftpm")) && !strings.HasPrefix(rel, "org.swift.swiftpm") && !strings.HasPrefix(rel, filepath.Join("Developer", "Xcode", "DerivedData")) {
			t.Errorf("listed %s", path)
		}
	}

	files := map[string]string{}
	for _, f := range audit.Files {
		files[f.Path] = f.Scope + " " + f.Status
	}
	config := filepath.Join(home, "Library", "org.swift.swiftpm")
	for path, want := range map[string]string{
		filepath.Join(config, "configuration", "registries.json"):       "user present",
		filepath.Join(config, "configuration", "mirrors.json"):          "user absent",
		filepath.Join(config, "mirrors.json"):                           "user present",
		filepath.Join(app, ".swiftpm", "configuration", "mirrors.json"): "project present",
	} {
		if files[path] != want {
			t.Errorf("audit file %s = %q, want %q", path, files[path], want)
		}
	}
	if len(audit.CredentialFiles) != 1 || audit.CredentialFiles[0].Presence != "present" {
		t.Errorf("credential files = %+v", audit.CredentialFiles)
	}
	if len(audit.Findings) != 1 || audit.Findings[0].Code != "swift-001" {
		t.Errorf("findings = %+v", audit.Findings)
	}
	contexts := map[string]string{}
	for _, c := range audit.Contexts {
		contexts[c.ProjectPath] = c.SelectionStatus
	}
	if len(contexts) != 5 || contexts[""] != "observed" || contexts[app] != "observed" {
		t.Errorf("contexts = %+v", audit.Contexts)
	}
}

func TestSwiftScanEmptyHome(t *testing.T) {
	for _, goos := range []string{model.PlatformDarwin, model.PlatformLinux, model.PlatformWindows} {
		t.Run(goos, func(t *testing.T) {
			home := goTestHome(t)
			scanner, _ := swiftTestScanner(t, home, goos)
			inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{filepath.Join(home, "missing")}, nil)
			swiftAssertRefs(t, inv)
			if inv.Status != "complete" || len(inv.Packages) != 0 || audit.Status != "complete" {
				t.Fatalf("inventory = %+v audit = %+v", inv, audit)
			}
			roots := map[string]string{
				model.PlatformDarwin:  filepath.Join(home, "Library", "Caches", "org.swift.swiftpm"),
				model.PlatformLinux:   filepath.Join(home, ".cache", "org.swift.swiftpm"),
				model.PlatformWindows: filepath.Join(home, "AppData", "Local", "Temp", "org.swift.swiftpm"),
			}
			if src := swiftSource(t, inv, "cache_root", roots[goos]); src.Presence != "absent" || src.Status != "complete" {
				t.Errorf("default cache = %+v", src)
			}
			// An absent root proves no children: the key is omitted, not empty.
			if out := swiftJSON(t, inv); strings.Contains(out, "discovered_sources") {
				t.Errorf("absent roots carry discovered_sources: %s", out)
			}
		})
	}
}

// discovered_sources is [] for a completed empty listing and omitted when
// any listing of its owner failed.
func TestSwiftScanDiscoveredSources(t *testing.T) {
	home := goTestHome(t)
	empty, broken := filepath.Join(home, "empty"), filepath.Join(home, "broken")
	swiftDir(t, empty)
	goWrite(t, filepath.Join(broken, "app", "Package.swift"), "", 0o600)
	scanner, x := swiftTestScanner(t, home, model.PlatformLinux)
	x.listErrors[filepath.Join(broken, "app")] = os.ErrPermission
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{empty, broken}, nil)
	swiftAssertRefs(t, inv)
	raw := map[string]json.RawMessage{}
	for _, s := range inv.Sources {
		data, _ := json.Marshal(s)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(data, &fields)
		raw[s.Path] = fields["discovered_sources"]
	}
	if string(raw[empty]) != "[]" || raw[broken] != nil {
		t.Errorf("empty = %s, broken = %s", raw[empty], raw[broken])
	}
	if src := swiftSource(t, inv, "project_search_root", broken); src.Status != "partial" || !slices.Contains(src.Reasons, "permission_denied") || audit.Status != "partial" {
		t.Errorf("broken walk = %+v audit = %s", src, audit.Status)
	}
}

func TestSwiftScanDeclines(t *testing.T) {
	home := goTestHome(t)
	swiftWriteFixture(t, home, filepath.Join(home, "projects"))
	service := goTestTarget(home)
	service.Username, service.Uid = "root", "0"
	for _, tc := range []struct {
		name   string
		target *user.User
	}{{"nil", nil}, {"service", service}, {"relative home", &user.User{Username: "dev", Uid: "1000", HomeDir: "home"}}} {
		t.Run(tc.name, func(t *testing.T) {
			scanner, x := swiftTestScanner(t, home, model.PlatformDarwin)
			inv, audit := scanner.Scan(context.Background(), tc.target, []string{home}, nil)
			if inv.Status != "partial" || !slices.Equal(inv.Reasons, []string{"user_unresolved"}) || len(inv.Sources) != 0 || audit.Status != "partial" || len(audit.Contexts) != 0 || *x.calls != 0 {
				t.Fatalf("inventory = %+v audit = %+v calls = %d", inv, audit, *x.calls)
			}
		})
	}
}

func TestSwiftScanCanceled(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	swiftWriteFixture(t, home, root)
	scanner, x := swiftTestScanner(t, home, model.PlatformDarwin)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv, audit := scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	if *x.calls != 0 || len(x.reads) != 0 || len(inv.Packages) != 0 || !slices.Contains(inv.Reasons, "deadline_exceeded") || audit.Status != "partial" {
		t.Fatalf("filesystem calls = %d reads = %v inventory = %+v", *x.calls, x.reads, inv)
	}
}

func TestSwiftScanLimits(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	swiftWriteFixture(t, home, root)
	scanner, _ := swiftTestScanner(t, home, model.PlatformDarwin)
	full, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	total := len(full.Sources) + len(full.Projects) + len(full.Packages)
	for _, tc := range []struct {
		name   string
		set    func()
		reason string
	}{
		{"exact records", func() { maxSwiftRecords = total }, ""},
		{"records", func() { maxSwiftRecords = total - 1 }, "record_limit"},
		{"output", func() { maxSwiftOutputBytes = goJSONSize(full) + (256 << 10) - 4096 }, "output_size_limit"},
		{"walk entries", func() { maxSwiftWalkEntries = 3 }, "entry_limit"},
		{"depth", func() { maxSwiftWalkDepth = 0 }, "depth_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, output, entries, depth := maxSwiftRecords, maxSwiftOutputBytes, maxSwiftWalkEntries, maxSwiftWalkDepth
			defer func() {
				maxSwiftRecords, maxSwiftOutputBytes, maxSwiftWalkEntries, maxSwiftWalkDepth = records, output, entries, depth
			}()
			tc.set()
			scanner, _ := swiftTestScanner(t, home, model.PlatformDarwin)
			inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
			swiftAssertRefs(t, inv)
			if tc.reason == "" {
				if inv.Status != "complete" || len(inv.Packages) != len(full.Packages) {
					t.Fatalf("at the limit: %s %v, packages = %d of %d", inv.Status, inv.Reasons, len(inv.Packages), len(full.Packages))
				}
				return
			}
			// Only a cut walk can hide project configuration from the audit.
			walkCut := tc.reason == "entry_limit" || tc.reason == "depth_limit"
			if !slices.Contains(inv.Reasons, tc.reason) || len(inv.Packages) >= len(full.Packages) || walkCut && audit.Status != "partial" {
				t.Fatalf("packages = %d of %d, reasons = %v, audit = %s", len(inv.Packages), len(full.Packages), inv.Reasons, audit.Status)
			}
			if walk := swiftSource(t, inv, "project_search_root", root); walkCut && walk.DiscoveredSources != nil {
				t.Errorf("cut walk keeps discovered_sources %v", walk.DiscoveredSources)
			}
		})
	}
}

// A walk whose last listing spends the entry budget is cut only when folders
// remain queued.
func TestSwiftScanExactWalkBudget(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
		cut   bool
	}{
		{"folder queued", "app", true},
		{"nothing queued", "README", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := maxSwiftWalkEntries
			defer func() { maxSwiftWalkEntries = old }()
			maxSwiftWalkEntries = 1
			home := goTestHome(t)
			root := filepath.Join(home, "src")
			if tc.cut {
				goWrite(t, filepath.Join(root, "app", "Package.swift"), "", 0o600)
			} else {
				goWrite(t, filepath.Join(root, "README"), "", 0o600)
			}
			scanner, _ := swiftTestScanner(t, home, model.PlatformLinux)
			inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
			swiftAssertRefs(t, inv)
			walk := swiftSource(t, inv, "project_search_root", root)
			if tc.cut {
				if walk.Status != "partial" || !slices.Contains(walk.Reasons, "entry_limit") || walk.DiscoveredSources != nil ||
					inv.Status != "partial" || audit.Status != "partial" {
					t.Errorf("walk = %+v inventory = %s audit = %s", walk, inv.Status, audit.Status)
				}
				return
			}
			if walk.Status != "complete" || walk.DiscoveredSources == nil || inv.Status != "complete" || audit.Status != "complete" {
				t.Errorf("walk = %+v inventory = %s %v audit = %s", walk, inv.Status, inv.Reasons, audit.Status)
			}
		})
	}
}

// A version 1 lock URL with a query or fragment never reaches the wire, even
// as a package name; its neighbors stay.
func TestSwiftScanUnsafeLockURL(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "src")
	lock := filepath.Join(root, "app", "Package.resolved")
	goWrite(t, filepath.Join(root, "app", "Package.swift"), "", 0o600)
	goWrite(t, lock, `{"version":1,"object":{"pins":[`+
		`{"package":"Widgets","repositoryURL":"https://example.invalid/widgets.git?token=REVIEW_CANARY","state":{"revision":"r1","version":"1.0.0"}},`+
		`{"package":"Frag","repositoryURL":"https://example.invalid/frag.git#REVIEW_CANARY","state":{"revision":"r2","version":"1.0.0"}},`+
		`{"package":"Root","repositoryURL":"https://user:REVIEW_CANARY@example.invalid/","state":{"revision":"r4","version":"1.0.0"}},`+
		`{"package":"Token","repositoryURL":"https://REVIEW_CANARY@example.invalid","state":{"revision":"r5","version":"1.0.0"}},`+
		`{"package":"Numerics","repositoryURL":"https://github.com/apple/swift-numerics.git","state":{"revision":"r3","version":"1.0.2"}}]}}`, 0o600)
	// A cached repository whose origin is a credential-bearing root URL.
	cache := filepath.Join(home, ".cache", "org.swift.swiftpm")
	repo := filepath.Join(cache, "repositories", "root-1a2b")
	goWrite(t, filepath.Join(repo, "config"), "[core]\n\tbare = true\n[remote \"origin\"]\n\turl = https://user:REVIEW_CANARY@example.invalid/\n", 0o600)
	goWrite(t, filepath.Join(repo, "HEAD"), "ref: refs/heads/main\n", 0o600)
	swiftDir(t, filepath.Join(repo, "objects"))
	swiftDir(t, filepath.Join(repo, "refs"))
	scanner, _ := swiftTestScanner(t, home, model.PlatformLinux)
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	swiftAssertRefs(t, inv)
	if src := swiftSource(t, inv, "cache_root", cache); !slices.Equal(src.Reasons, []string{"origin_unresolved"}) {
		t.Errorf("cache root = %+v", src)
	}
	if raw := swiftJSON(t, inv, audit); strings.Contains(strings.ToLower(raw), "canary") {
		t.Fatalf("canary reached the wire: %s", raw)
	}
	if p := swiftPackages(inv, "locked_package", "swift-numerics"); len(p) != 1 || p[0].Version != "1.0.2" || p[0].Origin.URL != "https://github.com/apple/swift-numerics.git" {
		t.Errorf("normal pin = %+v", p)
	}
	if src := swiftSource(t, inv, "lockfile", lock); src.Status != "partial" || !slices.Equal(src.Reasons, []string{"parse_error"}) || len(inv.Packages) != 1 {
		t.Errorf("lockfile = %+v packages = %+v", src, inv.Packages)
	}
}

// A recorded identity equal to a credential-bearing location's last
// component is dropped from every evidence kind. A mirror identity that
// differs from its location and a local name with spaces stay.
func TestSwiftScanCredentialIdentity(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "src")
	app := filepath.Join(root, "app")
	goWrite(t, filepath.Join(app, "Package.swift"), "", 0o600)
	bad := `{"identity":"review_canary@example.invalid","kind":"remoteSourceControl","location":"https://REVIEW_CANARY@example.invalid/"}`
	mirror := `{"identity":"swift-algorithms","kind":"remoteSourceControl","location":"https://mirror.example.invalid/renamed.git"}`
	local := `{"identity":"local library","kind":"fileSystem","location":"/src/Local Library"}`
	goWrite(t, filepath.Join(app, "Package.resolved"), `{"version":3,"pins":[`+
		`{"identity":"review_canary@example.invalid","kind":"remoteSourceControl","location":"https://REVIEW_CANARY@example.invalid/","state":{"version":"1.0.0","revision":"r"}},`+
		`{"identity":"swift-algorithms","kind":"remoteSourceControl","location":"https://mirror.example.invalid/renamed.git","state":{"version":"1.2.0","revision":"r2"}}]}`, 0o600)
	checkout := `"state":{"name":"sourceControlCheckout","checkoutState":{"revision":"r","version":"1.0.0"}},"subpath":"x"`
	goWrite(t, filepath.Join(app, ".build", "workspace-state.json"), `{"version":7,"object":{"dependencies":[`+
		`{"basedOn":null,"packageRef":`+bad+`,`+checkout+`},{"basedOn":null,"packageRef":`+mirror+`,`+checkout+`},`+
		`{"basedOn":null,"packageRef":`+local+`,"state":{"name":"fileSystem","path":"/src/Local Library"},"subpath":"local library"}],`+
		`"artifacts":[{"packageRef":`+bad+`,"targetName":"Bin","path":"/opt/Bin.xcframework","source":{"type":"local"},"kind":"xcframework"}],"prebuilts":[]}}`, 0o600)
	scanner, _ := swiftTestScanner(t, home, model.PlatformLinux)
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	swiftAssertRefs(t, inv)
	if raw := swiftJSON(t, inv, audit); strings.Contains(strings.ToLower(raw), "canary") {
		t.Fatalf("canary reached the wire: %s", raw)
	}
	for _, tc := range []struct{ evidence, name string }{
		{"locked_package", "swift-algorithms"}, {"managed_dependency", "swift-algorithms"}, {"managed_dependency", "local library"},
	} {
		if len(swiftPackages(inv, tc.evidence, tc.name)) != 1 {
			t.Errorf("%s %s missing: %+v", tc.evidence, tc.name, inv.Packages)
		}
	}
	if len(inv.Packages) != 3 {
		t.Errorf("packages = %+v", inv.Packages)
	}
	for _, kind := range []string{"lockfile", "workspace_state"} {
		for _, s := range inv.Sources {
			if s.Kind == kind && !slices.Contains(s.Reasons, "parse_error") {
				t.Errorf("%s = %+v", kind, s)
			}
		}
	}
}

// Selecting an Xcode bundle directly finds what scanning its parent finds.
// A workspace embedded in a project or generated for a package is not a
// project of its own.
func TestSwiftScanSelectedBundle(t *testing.T) {
	lock := `{"version":3,"pins":[{"identity":"safe","kind":"remoteSourceControl","location":"https://example.invalid/safe.git","state":{"version":"1.0.0","revision":"r"}}]}`
	for _, ext := range []string{".xcworkspace", ".xcodeproj"} {
		t.Run(ext, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "src")
			bundle := filepath.Join(root, "app"+ext)
			base := bundle
			if ext == ".xcodeproj" {
				base = filepath.Join(bundle, "project.xcworkspace")
			}
			goWrite(t, filepath.Join(base, "xcshareddata", "swiftpm", "Package.resolved"), lock, 0o600)
			scanner, _ := swiftTestScanner(t, home, model.PlatformDarwin)
			for _, dir := range []string{root, bundle} {
				inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{dir}, nil)
				swiftAssertRefs(t, inv)
				if len(inv.Projects) != 1 || inv.Projects[0].ProjectPath != bundle || len(inv.Packages) != 1 || inv.Packages[0].ProjectPath != bundle {
					t.Errorf("scan of %s: projects = %+v packages = %+v", dir, inv.Projects, inv.Packages)
				}
			}
		})
	}
	t.Run("auxiliary", func(t *testing.T) {
		home := goTestHome(t)
		aux := []string{
			filepath.Join(home, "src", "app.xcodeproj", "project.xcworkspace"),
			filepath.Join(home, "src", "pkg", ".swiftpm", "xcode", "package.xcworkspace"),
		}
		for _, dir := range aux {
			swiftDir(t, filepath.Join(dir, "xcshareddata", "swiftpm"))
		}
		scanner, _ := swiftTestScanner(t, home, model.PlatformDarwin)
		inv, _ := scanner.Scan(context.Background(), goTestTarget(home), aux, nil)
		if len(inv.Projects) != 0 {
			t.Errorf("projects = %+v", inv.Projects)
		}
	})
}

// The Library exception admits SwiftPM's roots for readers rooted there. A
// link out of a root, an alias elsewhere in ~/Library and the walk itself
// stay refused, and a network volume is refused first.
func TestSwiftScanLibraryBoundary(t *testing.T) {
	home := goTestHome(t)
	lib := filepath.Join(home, "Library")
	cache := filepath.Join(lib, "Caches", "org.swift.swiftpm")
	mail := filepath.Join(lib, "Mail")
	goWrite(t, filepath.Join(mail, "repositories", "x", "config"), "[core]\nbare = true\n[remote \"origin\"]\nurl = https://example.invalid/CANARY_MAIL.git\n", 0o600)
	swiftDir(t, filepath.Join(cache, "repositories"))
	swiftDir(t, filepath.Join(home, ".swiftpm"))
	if err := os.Symlink(mail, filepath.Join(home, ".swiftpm", "cache")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := os.Symlink(filepath.Join(mail, "repositories", "x"), filepath.Join(cache, "repositories", "escape")); err != nil {
		t.Fatal(err)
	}
	scanner, x := swiftTestScanner(t, home, model.PlatformDarwin)
	scanner.protection = swiftTCC(home)
	inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{home}, nil)
	swiftAssertRefs(t, inv)
	if strings.Contains(swiftJSON(t, inv), "CANARY") {
		t.Error("Library content outside the SwiftPM roots reached the inventory")
	}
	for path := range x.lists {
		if path == lib || path == mail || strings.HasPrefix(path, mail+string(filepath.Separator)) {
			t.Errorf("listed %s", path)
		}
	}
	for path := range x.reads {
		if strings.HasPrefix(path, mail) {
			t.Errorf("read %s", path)
		}
	}
	for _, s := range inv.Sources {
		if s.Kind == "cache_root" && strings.HasPrefix(s.Path, mail) {
			t.Errorf("alias into ~/Library/Mail became root %+v", s)
		}
	}
	if walk := swiftSource(t, inv, "project_search_root", home); !slices.Contains(walk.Reasons, "skipped_protected") {
		t.Errorf("walk = %+v", walk)
	}

	t.Run("network volume", func(t *testing.T) {
		scanner, _ := swiftTestScanner(t, home, model.PlatformDarwin)
		scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
			return func(string) string { return "" }, func(p string) bool { return strings.HasPrefix(p, cache) }
		}
		inv, _ := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
		if src := swiftSource(t, inv, "cache_root", cache); src.Presence != "unknown" || !slices.Contains(src.Reasons, "refused_network_volume") {
			t.Errorf("network cache = %+v", src)
		}
	})
}

// Inventory readers under ~/Library keep SwiftPM's security folder
// existence-only, whether a build-directory lead names it directly or a
// metadata link reaches its relocated target.
func TestSwiftScanLibrarySecurity(t *testing.T) {
	for _, mode := range []string{"direct", "relocated"} {
		t.Run(mode, func(t *testing.T) {
			relocated := mode == "relocated"
			home := goTestHome(t)
			lib := filepath.Join(home, "Library", "org.swift.swiftpm")
			security := filepath.Join(lib, "security")
			scanner, x := swiftTestScanner(t, home, model.PlatformDarwin)
			scanner.protection = swiftTCC(home)
			target, lead := security, security
			if relocated {
				target, lead = filepath.Join(lib, "history"), filepath.Join(lib, "scratch")
				swiftDir(t, target)
				swiftDir(t, lead)
				if err := os.Symlink(target, security); err != nil {
					t.Skip("symlinks unavailable:", err)
				}
				if err := os.Symlink(filepath.Join(target, "workspace-state.json"), filepath.Join(lead, "workspace-state.json")); err != nil {
					t.Fatal(err)
				}
			}
			x.env["SWIFTPM_BUILD_DIR"] = lead
			file := filepath.Join(target, "workspace-state.json")
			swiftCopy(t, "workspace-macos.json", file, filepath.Join(home, "lab"))
			allowed := filepath.Join(lib, "configuration", "mirrors.json")
			goWrite(t, allowed, `{"object":[],"version":1}`, 0o600)
			inv, audit := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
			if x.reads[file] != 0 || len(inv.Packages) != 0 {
				t.Errorf("security metadata reads = %d packages = %+v", x.reads[file], inv.Packages)
			}
			if x.reads[allowed] != 1 || !slices.ContainsFunc(audit.Files, func(f model.RubyConfigFile) bool { return f.Path == allowed && f.Status == "present" }) {
				t.Errorf("allowed Library config reads = %d files = %+v", x.reads[allowed], audit.Files)
			}
		})
	}
}

// Linux reads ~/.cache plus a verified XDG_CACHE_HOME lead; the ~/.swiftpm
// cache link never duplicates its target; a build-directory lead is a
// custom location, never walked into projects.
func TestSwiftScanLinuxLeads(t *testing.T) {
	home := goTestHome(t)
	lab := filepath.Join(home, "lab")
	cache := filepath.Join(home, ".cache", "org.swift.swiftpm")
	repo := filepath.Join(cache, "repositories", "lib-1")
	goWrite(t, filepath.Join(repo, "config"), "[core]\nbare = true\n[remote \"origin\"]\nurl = git@github.com:acme/Lib.git\n", 0o600)
	goWrite(t, filepath.Join(repo, "HEAD"), "", 0o600)
	swiftDir(t, filepath.Join(repo, "objects"))
	swiftDir(t, filepath.Join(repo, "refs"))
	swiftDir(t, filepath.Join(home, ".swiftpm"))
	if err := os.Symlink(cache, filepath.Join(home, ".swiftpm", "cache")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	xdg := filepath.Join(home, "xdg-cache")
	swiftDir(t, filepath.Join(xdg, "org.swift.swiftpm"))
	root := filepath.Join(home, "src")
	build := filepath.Join(root, "out")
	swiftCopy(t, "workspace-macos.json", filepath.Join(build, "workspace-state.json"), lab)
	goWrite(t, filepath.Join(build, "checkouts", "swift-numerics", "Package.swift"), "", 0o600)
	swiftCopy(t, "mirrors-modern.json", filepath.Join(home, ".swiftpm", "configuration", "mirrors.json"), lab)
	scanner, x := swiftTestScanner(t, home, model.PlatformLinux)
	x.env["XDG_CACHE_HOME"] = xdg
	x.env["SWIFTPM_BUILD_DIR"] = build
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	swiftAssertRefs(t, inv)
	if len(inv.Projects) != 0 {
		t.Errorf("projects = %+v", inv.Projects)
	}
	roots := []string{}
	for _, s := range inv.Sources {
		if s.Kind == "cache_root" {
			roots = append(roots, s.Path)
		}
	}
	if !slices.Equal(roots, []string{cache, filepath.Join(xdg, "org.swift.swiftpm")}) {
		t.Errorf("cache roots = %v", roots)
	}
	if p := swiftPackages(inv, "cached_repository", "lib"); len(p) != 1 || p[0].Origin.URL != "git@github.com:acme/Lib.git" {
		t.Errorf("cached repository = %+v", p)
	}
	walk := swiftSource(t, inv, "project_search_root", root)
	state := swiftSource(t, inv, "workspace_state", filepath.Join(build, "workspace-state.json"))
	if state.ParentSourceID != walk.SourceID {
		t.Errorf("lead state = %+v", state)
	}
	for _, p := range swiftPackages(inv, "managed_dependency", "swift-numerics") {
		if p.Scope != "custom" || p.Tool != "swiftpm" || p.ProjectPath != "" || p.Installation.Presence != "present" {
			t.Errorf("lead package = %+v", p)
		}
	}
	if !strings.Contains(swiftJSON(t, audit), filepath.Join(home, ".swiftpm", "configuration", "mirrors.json")) {
		t.Errorf("user mirrors missing: %s", swiftJSON(t, audit))
	}

	t.Run("relative leads", func(t *testing.T) {
		scanner, x := swiftTestScanner(t, home, model.PlatformLinux)
		x.env["SWIFTPM_BUILD_DIR"] = "out"
		inv, audit := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
		if !slices.Contains(inv.Reasons, "path_unresolved") || audit.Status != "complete" {
			t.Errorf("inventory = %v, audit = %s %v", inv.Reasons, audit.Status, audit.Reasons)
		}
	})
	t.Run("unverified process", func(t *testing.T) {
		scanner, x := swiftTestScanner(t, home, model.PlatformLinux)
		x.current = &user.User{Username: "agent", Uid: "1001"}
		inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if audit.Status != "partial" || !slices.Contains(audit.Reasons, "user_unresolved") {
			t.Errorf("audit = %s %v", audit.Status, audit.Reasons)
		}
		// Without the lead the build directory is an ordinary walked scratch.
		for _, p := range swiftPackages(inv, "managed_dependency", "swift-numerics") {
			if p.Scope != "unknown" {
				t.Errorf("package = %+v", p)
			}
		}
	})
}

func TestSwiftScanRegistryLayouts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     []string
		files    map[string]string
		packages int
		reason   string
	}{
		{"released", []string{"acme", "Lib", "1.0.0"}, map[string]string{"Package.swift": "", ".registry-metadata": `{"registry":"https://r.example.invalid/"}`}, 1, ""},
		{"development storage key", []string{"acme", "Lib", "1.0.0", "abc"}, map[string]string{"Package.swift": "", ".registry-metadata": `{"registry":"https://r.example.invalid"}`}, 0, "unsupported_layout"},
		{"invalid scope", []string{"-acme", "Lib", "1.0.0"}, map[string]string{"Package.swift": ""}, 0, "unsupported_layout"},
		{"invalid version", []string{"acme", "Lib", "1.0"}, map[string]string{"Package.swift": ""}, 0, "unsupported_layout"},
		{"missing manifest", []string{"acme", "Lib", "1.0.0"}, map[string]string{".registry-metadata": `{"registry":"https://r.example.invalid"}`}, 0, "unsupported_layout"},
		{"missing receipt", []string{"acme", "Lib", "1.0.0"}, map[string]string{"Package.swift": ""}, 0, "unsupported_layout"},
		{"malformed receipt", []string{"acme", "Lib", "1.0.0"}, map[string]string{"Package.swift": "", ".registry-metadata": `{"registry":`}, 0, "parse_error"},
		{"credential receipt", []string{"acme", "Lib", "1.0.0"}, map[string]string{"Package.swift": "", ".registry-metadata": `{"registry":"https://u:CANARY@r.example.invalid"}`}, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			cache := filepath.Join(home, ".cache", "org.swift.swiftpm")
			dir := filepath.Join(append([]string{cache, "registry", "downloads"}, tc.path...)...)
			swiftDir(t, dir)
			for name, data := range tc.files {
				goWrite(t, filepath.Join(dir, name), data, 0o600)
			}
			scanner, _ := swiftTestScanner(t, home, model.PlatformLinux)
			inv, _ := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
			swiftAssertRefs(t, inv)
			src := swiftSource(t, inv, "cache_root", cache)
			if len(inv.Packages) != tc.packages || tc.reason != "" && !slices.Contains(src.Reasons, tc.reason) || tc.reason == "" && src.Status != "complete" {
				t.Fatalf("packages = %+v root = %+v", inv.Packages, src)
			}
			if strings.Contains(swiftJSON(t, inv), "CANARY") {
				t.Error("receipt credential leaked")
			}
			if tc.packages == 1 {
				p := inv.Packages[0]
				if p.PackageName != "acme.lib" || p.Version != "1.0.0" || p.SourcePath != filepath.Join(dir, ".registry-metadata") {
					t.Errorf("package = %+v", p)
				}
				if tc.name == "credential receipt" && (p.Origin.Kind != "unknown" || !slices.Equal(p.Reasons, []string{"origin_unresolved"})) {
					t.Errorf("credential receipt origin = %+v %v", p.Origin, p.Reasons)
				}
				if tc.name == "released" && p.Origin != (model.SwiftOrigin{Kind: "registry", URL: "https://r.example.invalid"}) {
					t.Errorf("origin = %+v", p.Origin)
				}
			}
		})
	}
}

// A cached repository without a single literal origin is skipped; its hashed
// folder name never becomes an identity.
func TestSwiftScanCachedRepositories(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		git          bool
		packages     int
		reason       string
	}{
		{"origin", "[core]\nbare = true\n[remote \"origin\"]\nurl = /src/Local.git\n", true, 1, ""},
		{"no origin", "[core]\nbare = true\n", true, 0, "origin_unresolved"},
		{"two origins", "[core]\nbare = true\n[remote \"origin\"]\nurl = a\nurl = b\n", true, 0, "origin_unresolved"},
		{"not bare", "[core]\nbare = false\n[remote \"origin\"]\nurl = https://example.invalid/x.git\n", true, 0, "origin_unresolved"},
		{"credential origin", "[core]\nbare = true\n[remote \"origin\"]\nurl = https://example.invalid/x.git?t=CANARY\n", true, 0, "origin_unresolved"},
		{"not a repository", "[core]\nbare = true\n", false, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			cache := filepath.Join(home, ".cache", "org.swift.swiftpm")
			repo := filepath.Join(cache, "repositories", "hashed-name-1234")
			goWrite(t, filepath.Join(repo, "config"), tc.config, 0o600)
			if tc.git {
				goWrite(t, filepath.Join(repo, "HEAD"), "", 0o600)
				swiftDir(t, filepath.Join(repo, "objects"))
				swiftDir(t, filepath.Join(repo, "refs"))
			}
			scanner, _ := swiftTestScanner(t, home, model.PlatformLinux)
			inv, _ := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
			swiftAssertRefs(t, inv)
			src := swiftSource(t, inv, "cache_root", cache)
			if len(inv.Packages) != tc.packages || (tc.reason == "") != (src.Status == "complete") || tc.reason != "" && !slices.Contains(src.Reasons, tc.reason) {
				t.Fatalf("packages = %+v root = %+v", inv.Packages, src)
			}
			if tc.packages == 1 && (inv.Packages[0].PackageName != "local" || inv.Packages[0].Origin != (model.SwiftOrigin{Kind: "path", Path: "/src/Local.git"})) {
				t.Errorf("package = %+v", inv.Packages[0])
			}
			if strings.Contains(swiftJSON(t, inv), "hashed-name") && tc.packages == 0 {
				t.Error("skipped repository surfaced")
			}
		})
	}
}

// Workspace-state facts: installation paths by state, receipts and artifacts.
func TestSwiftScanWorkspaceState(t *testing.T) {
	const sum = "1111111111111111111111111111111111111111111111111111111111111111"
	ref := func(identity, location string) string {
		return `{"identity":"` + identity + `","kind":"remoteSourceControl","location":"` + location + `","name":"` + identity + `"}`
	}
	checkout := func(identity, subpath string) string {
		return `{"basedOn":null,"packageRef":` + ref(identity, "https://example.invalid/"+identity+".git") + `,"state":{"name":"sourceControlCheckout","checkoutState":{"revision":"r","version":"1.0.0"}},"subpath":"` + subpath + `"}`
	}
	registry := `{"basedOn":null,"packageRef":{"identity":"acme.lib","kind":"registry","location":"acme.lib","name":"Lib"},"state":{"name":"registryDownload","version":"2.0.0","scmUrl":"https://example.invalid/lib.git"},"subpath":"acme/Lib/2.0.0"}`
	artifact := func(identity, checksum string) string {
		return `{"packageRef":` + ref(identity, "https://example.invalid/"+identity+".git") + `,"targetName":"Bin","path":"/opt/artifacts/Bin.xcframework","source":{"type":"remote","url":"https://u:CANARY@example.invalid/bin.zip","checksum":"` + checksum + `"},"kind":"xcframework"}`
	}
	ws := func(deps, artifacts []string) string {
		return `{"version":7,"object":{"dependencies":[` + strings.Join(deps, ",") + `],"artifacts":[` + strings.Join(artifacts, ",") + `],"prebuilts":[]}}`
	}
	home := goTestHome(t)
	root := filepath.Join(home, "src")
	app := filepath.Join(root, "app")
	goWrite(t, filepath.Join(app, "Package.swift"), "", 0o600)
	goWrite(t, filepath.Join(app, ".build", "workspace-state.json"), ws(
		[]string{checkout("present", "present"), checkout("absent", "absent"), checkout("escape", "../../etc"), registry},
		[]string{artifact("present", sum), artifact("absent", "NOT-HEX"), artifact("orphan", "")}), 0o600)
	swiftDir(t, filepath.Join(app, ".build", "checkouts", "present"))
	goWrite(t, filepath.Join(app, ".build", "registry", "downloads", "acme", "Lib", "2.0.0", ".registry-metadata"), `{"registry":"https://registry.example.invalid"}`, 0o600)
	scanner, _ := swiftTestScanner(t, home, model.PlatformLinux)
	inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	swiftAssertRefs(t, inv)
	if strings.Contains(swiftJSON(t, inv), "CANARY") {
		t.Error("artifact URL credential leaked")
	}
	install := func(name string) model.SwiftInstallation {
		p := swiftPackages(inv, "managed_dependency", name)
		if len(p) != 1 || p[0].Installation == nil {
			t.Fatalf("%s = %+v", name, p)
		}
		return *p[0].Installation
	}
	scratch := filepath.Join(app, ".build")
	for name, want := range map[string]model.SwiftInstallation{
		"present":  {Path: filepath.Join(scratch, "checkouts", "present"), PathStatus: "resolved", Presence: "present"},
		"absent":   {Path: filepath.Join(scratch, "checkouts", "absent"), PathStatus: "resolved", Presence: "absent"},
		"escape":   {PathStatus: "unresolved", Presence: "unknown"},
		"acme.lib": {Path: filepath.Join(scratch, "registry", "downloads", "acme", "Lib", "2.0.0"), PathStatus: "resolved", Presence: "present"},
	} {
		if got := install(name); got != want {
			t.Errorf("%s installation = %+v, want %+v", name, got, want)
		}
	}
	reg := swiftPackages(inv, "managed_dependency", "acme.lib")[0]
	if reg.Origin != (model.SwiftOrigin{Kind: "registry", URL: "https://registry.example.invalid"}) || reg.OriginalLocation != "https://example.invalid/lib.git" || reg.Version != "2.0.0" || reg.ManagedState != "registry" {
		t.Errorf("registry dependency = %+v", reg)
	}
	state := swiftSource(t, inv, "workspace_state", filepath.Join(scratch, "workspace-state.json"))
	if !slices.Equal(state.Reasons, []string{"checksum_invalid", "path_unresolved"}) {
		t.Errorf("state reasons = %v", state.Reasons)
	}
	for _, tc := range []struct {
		name, version string
		checksums     int
		reasons       []string
		origin        string
	}{
		{"present", "1.0.0", 1, []string{}, "git"},
		{"absent", "1.0.0", 0, []string{"checksum_invalid"}, "git"},
		{"orphan", "", 0, []string{}, "git"},
	} {
		p := swiftPackages(inv, "artifact_reference", tc.name)
		if len(p) != 1 || p[0].Version != tc.version || len(p[0].RecordedChecksums) != tc.checksums || !slices.Equal(p[0].Reasons, tc.reasons) || p[0].Origin.Kind != tc.origin ||
			p[0].Artifact.URL != "" || p[0].Installation.Presence != "absent" {
			t.Errorf("artifact %s = %+v", tc.name, p)
		}
	}

	t.Run("ambiguous and edited joins", func(t *testing.T) {
		home := goTestHome(t)
		dir := filepath.Join(home, "scratch")
		edited := `{"basedOn":` + checkout("lib", "lib") + `,"packageRef":` + ref("lib", "https://example.invalid/lib.git") + `,"state":{"name":"edited","path":null},"subpath":"lib"}`
		goWrite(t, filepath.Join(dir, "workspace-state.json"), ws([]string{edited, checkout("dup", "a"), checkout("dup", "b")}, []string{artifact("lib", sum), artifact("dup", sum)}), 0o600)
		scanner, _ := swiftTestScanner(t, home, model.PlatformLinux)
		inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{dir}, nil)
		for _, name := range []string{"lib", "dup"} {
			if p := swiftPackages(inv, "artifact_reference", name); len(p) != 1 || p[0].VersionStatus != "unknown" {
				t.Errorf("%s artifact = %+v", name, p)
			}
		}
		// Outside a package's .build, an edited dependency's folder is unproven.
		if p := swiftPackages(inv, "managed_dependency", "lib"); len(p) != 1 || p[0].Installation.PathStatus != "unresolved" || p[0].BasedOn == nil {
			t.Errorf("edited = %+v", p)
		}
	})
}

// A configuration folder that cannot be listed leaves its project and its
// audit context partial.
func TestSwiftScanUnlistedConfigFolder(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "src")
	app := filepath.Join(root, "app")
	goWrite(t, filepath.Join(app, "Package.swift"), "", 0o600)
	goWrite(t, filepath.Join(app, ".swiftpm", "configuration", "registries.json"), `{"version":1,"registries":{}}`, 0o600)
	scanner, x := swiftTestScanner(t, home, model.PlatformLinux)
	x.listErrors[filepath.Join(app, ".swiftpm", "configuration")] = os.ErrPermission
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if src := swiftSource(t, inv, "project", app); src.Status != "partial" || src.DiscoveredSources != nil {
		t.Errorf("project = %+v", src)
	}
	found := false
	for _, c := range audit.Contexts {
		if c.ProjectPath == app {
			found = c.SelectionStatus == "partial"
		}
	}
	if !found || audit.Status != "partial" {
		t.Errorf("audit = %s contexts = %+v", audit.Status, audit.Contexts)
	}
}

// Unreadable or unsupported state degrades its own source and keeps the scan.
func TestSwiftScanMetadataFailures(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		err        error
		reason     string
		presence   string
	}{
		{"unsupported version", `{"version":3,"object":{"dependencies":[],"artifacts":[]}}`, nil, "unsupported_format", "present"},
		{"malformed", `{"version":`, nil, "parse_error", "present"},
		{"unreadable", `{}`, os.ErrPermission, "permission_denied", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "src")
			path := filepath.Join(root, "app", ".build", "workspace-state.json")
			goWrite(t, filepath.Join(root, "app", "Package.swift"), "", 0o600)
			goWrite(t, filepath.Join(root, "app", "Package.resolved"), string(swiftFixture(t, "resolved-v2.json")), 0o600)
			goWrite(t, path, tc.data, 0o600)
			scanner, x := swiftTestScanner(t, home, model.PlatformLinux)
			if tc.err != nil {
				x.readErrors[path] = tc.err
			}
			inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
			swiftAssertRefs(t, inv)
			src := swiftSource(t, inv, "workspace_state", path)
			if src.Presence != tc.presence || !slices.Contains(src.Reasons, tc.reason) || len(swiftPackages(inv, "locked_package", "swift-numerics")) != 1 {
				t.Errorf("source = %+v packages = %d", src, len(inv.Packages))
			}
			if project := swiftSource(t, inv, "project", filepath.Join(root, "app")); project.Status != "partial" {
				t.Errorf("degradation did not reach the project: %+v", project)
			}
		})
	}
	t.Run("missing plist", func(t *testing.T) {
		home := goTestHome(t)
		state := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "X-1", "SourcePackages", "workspace-state.json")
		goWrite(t, state, string(swiftFixture(t, "workspace-macos.json")), 0o600)
		goWrite(t, filepath.Join(filepath.Dir(filepath.Dir(state)), "info.plist"), "garbage", 0o600)
		scanner, _ := swiftTestScanner(t, home, model.PlatformDarwin)
		inv, _ := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
		if src := swiftSource(t, inv, "workspace_state", state); !slices.Equal(src.Reasons, []string{"parse_error"}) || len(inv.Packages) != 2 {
			t.Errorf("source = %+v packages = %d", src, len(inv.Packages))
		}
	})
}

func TestSwiftScanNoProtectedReads(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	swiftWriteFixture(t, home, root)
	scanner, x := swiftTestScanner(t, home, model.PlatformDarwin)
	x.readErrors[filepath.Join(home, ".netrc")] = errors.New("read netrc")
	_, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root, home}, nil)
	if x.reads[filepath.Join(home, ".netrc")] != 0 {
		t.Error("netrc read")
	}
	if len(audit.CredentialFiles) != 1 || audit.CredentialFiles[0].Path != filepath.Join(home, ".netrc") {
		t.Errorf("credential files = %+v", audit.CredentialFiles)
	}
}
