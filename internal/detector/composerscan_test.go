package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

type composerTrap struct {
	*goTrap
	env        map[string]string
	denied     map[string]error
	readErrors map[string]error
	reads      map[string]int
	afterRead  func(string)
}

func (x *composerTrap) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	return &composerTrap{goTrap: &goTrap{Executor: x.Executor.GuardedFiles(roots, guard, max), t: x.t, current: x.current, guarded: true}, env: x.env, denied: x.denied, reads: x.reads, readErrors: x.readErrors, afterRead: x.afterRead}
}
func (x *composerTrap) Getenv(key string) string {
	if x.current.Uid != "1000" {
		x.t.Errorf("read process environment for a different developer: %s", key)
	}
	return x.env[key]
}
func (x *composerTrap) HasEnvPrefix(prefix string) bool {
	if x.current.Uid != "1000" {
		x.t.Error("read process environment names for a different developer")
	}
	for k := range x.env {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}
func (x *composerTrap) Stat(path string) (os.FileInfo, error) {
	if err := x.denied[filepath.Clean(path)]; err != nil {
		return nil, err
	}
	if path == "/etc/xdg" {
		return nil, os.ErrNotExist
	}
	return x.goTrap.Stat(path)
}
func (x *composerTrap) ReadFile(path string) ([]byte, error) {
	name := filepath.Base(path)
	if name == "auth.json" || strings.HasSuffix(name, ".php") {
		x.t.Fatalf("read forbidden file %s", name)
	}
	x.reads[filepath.Clean(path)]++
	if err := x.denied[filepath.Clean(path)]; err != nil {
		return nil, err
	}
	if err := x.readErrors[filepath.Clean(path)]; err != nil {
		return nil, err
	}
	data, err := x.goTrap.ReadFile(path)
	if x.afterRead != nil {
		x.afterRead(path)
	}
	return data, err
}
func composerTestScanner(t *testing.T, home string) (*ComposerScanner, *composerTrap) {
	t.Helper()
	x := &composerTrap{goTrap: &goTrap{Executor: executor.NewReal(), t: t, current: goTestTarget(home)}, env: map[string]string{}, denied: map[string]error{}, reads: map[string]int{}, readErrors: map[string]error{}}
	s := NewComposerScanner(x, progress.NewNoop())
	s.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(string) string { return "" }, func(string) bool { return false }
	}
	return s, x
}
func composerWriteProject(t *testing.T, dir string) {
	t.Helper()
	goWrite(t, filepath.Join(dir, "composer.json"), `{"name":"example/app","require":{"example/lib":"^2"},"require-dev":{"example/dev":"^1"}}`, 0o600)
	goWrite(t, filepath.Join(dir, "composer.lock"), `{"packages":[{"name":"example/lib","version":"2.1.0"},{"name":"example/transitive","version":"1.0.0"}],"packages-dev":[{"name":"example/dev","version":"1.1.0"}]}`, 0o600)
	goWrite(t, filepath.Join(dir, "vendor", "composer", "installed.json"), `{"packages":[{"name":"example/lib","version":"1.9.0","install-path":"../example/lib"},{"name":"example/meta","version":"1.0.0","type":"metapackage","install-path":null}],"dev-package-names":[]}`, 0o600)
	goWrite(t, filepath.Join(dir, "vendor", "example", "lib", "composer.json"), `{"require-dev":{"example/phantom":"*"}}`, 0o600)
}
func composerSource(t *testing.T, inv *model.ComposerInventory, path string) model.ComposerSource {
	t.Helper()
	for _, src := range inv.Sources {
		if src.Path == path {
			return src
		}
	}
	t.Fatalf("no source for %s", path)
	return model.ComposerSource{}
}
func composerAssertRefs(t *testing.T, inv *model.ComposerInventory, audit *model.ComposerConfigAudit) {
	t.Helper()
	ids := map[string]bool{}
	for _, s := range inv.Sources {
		if ids[s.SourceID] {
			t.Error("duplicate source")
		}
		ids[s.SourceID] = true
	}
	ref := func(id string) {
		if !ids[id] {
			t.Errorf("dangling inventory source %s", id)
		}
	}
	for _, s := range inv.Sources {
		if s.ParentSourceID != "" {
			ref(s.ParentSourceID)
		}
		for _, id := range s.DiscoveredSources {
			ref(id)
		}
	}
	for _, p := range inv.Packages {
		ref(p.SourceID)
		for _, hash := range p.RecordedChecksums {
			ref(hash.SourceID)
		}
	}
	for _, p := range inv.Projects {
		ref(p.ManifestSourceID)
	}
	files := map[string]bool{}
	for _, f := range audit.Files {
		files[f.SourceID] = true
	}
	for _, c := range audit.Contexts {
		for _, id := range c.ConfigSourceIDs {
			if !files[id] {
				t.Error("dangling config context")
			}
		}
	}
	for _, f := range audit.Findings {
		if !files[f.SourceID] {
			t.Error("dangling finding")
		}
	}
	for _, v := range []any{inv, audit} {
		data, _ := json.Marshal(v)
		if bytes.Contains(data, []byte(":null")) {
			t.Fatal("null array")
		}
	}
}
func TestComposerScanIndependentEvidenceAndDeterminism(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	app := filepath.Join(root, ".hidden", "app")
	composerWriteProject(t, app)
	scanner, _ := composerTestScanner(t, home)
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root, root, app}, nil)
	if len(inv.Projects) != 1 || len(inv.Packages) != 7 {
		t.Fatalf("projects=%d packages=%+v", len(inv.Projects), inv.Packages)
	}
	if inv.Status != "complete" || audit.Status != "complete" {
		t.Fatalf("coverage %v %v", inv.Reasons, audit.Reasons)
	}
	counts := map[string]int{}
	for _, p := range inv.Packages {
		counts[p.Evidence]++
		if p.PackageName == "example/phantom" {
			t.Fatal("vendor dev requirement became project")
		}
		if p.Evidence == "installed_package" {
			if p.PackageName == "example/meta" {
				if p.Installation.Presence != "not_applicable" {
					t.Fatal("metapackage presence")
				}
			} else if p.Installation.Presence != "present" {
				t.Fatalf("installation %+v", p)
			}
		}
	}
	if counts["declared_requirement"] != 2 || counts["locked_package"] != 3 || counts["installed_package"] != 2 {
		t.Fatal(counts)
	}
	composerAssertRefs(t, inv, audit)
	again, aa := scanner.Scan(context.Background(), goTestTarget(home), []string{root, root, app}, nil)
	b, _ := json.Marshal([]any{inv, audit})
	b2, _ := json.Marshal([]any{again, aa})
	if !bytes.Equal(b, b2) {
		t.Fatal("unchanged scan differs")
	}
}
func TestComposerScanReceiptPresenceAndRecovery(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	composerWriteProject(t, root)
	scanner, x := composerTestScanner(t, home)
	receipt := filepath.Join(root, "vendor", "composer", "installed.json")
	lib := filepath.Join(root, "vendor", "example", "lib")
	scan := func() *model.ComposerInventory {
		i, a := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		composerAssertRefs(t, i, a)
		return i
	}
	first := scan()
	if err := os.RemoveAll(lib); err != nil {
		t.Fatal(err)
	}
	missing := scan()
	for _, p := range missing.Packages {
		if p.PackageName == "example/lib" && p.Evidence == "installed_package" && p.Installation.Presence != "absent" {
			t.Fatalf("missing %+v", p)
		}
	}
	x.denied[lib] = os.ErrPermission
	denied := scan()
	if composerSource(t, denied, receipt).Status != "complete" {
		t.Fatal("directory denial degraded receipt enumeration")
	}
	for _, p := range denied.Packages {
		if p.PackageName == "example/lib" && p.Evidence == "installed_package" && (p.Installation.Presence != "unknown" || !slices.Contains(p.Reasons, "permission_denied")) {
			t.Fatalf("denied %+v", p)
		}
	}
	delete(x.denied, lib)
	goWrite(t, filepath.Join(lib, "composer.json"), `{}`, 0o600)
	restored := scan()
	if !reflect.DeepEqual(first, restored) {
		t.Fatal("restoration changed stable snapshot")
	}
	x.denied[receipt] = os.ErrPermission
	partial := scan()
	if composerSource(t, partial, receipt).Status != "partial" || len(partial.Packages) != 5 {
		t.Fatal("receipt denial lost unrelated evidence")
	}
	delete(x.denied, receipt)
	if !reflect.DeepEqual(first, scan()) {
		t.Fatal("source recovery differs")
	}
	goWrite(t, receipt, `{"packages":[],"dev-package-names":[]}`, 0o600)
	empty := scan()
	if composerSource(t, empty, receipt).Status != "complete" || len(empty.Packages) != 5 {
		t.Fatal("complete empty receipt ownership")
	}
	if err := os.Remove(receipt); err != nil {
		t.Fatal(err)
	}
	goWrite(t, filepath.Join(filepath.Dir(receipt), "installed.php"), "<?php NEVER_EXECUTE;", 0o600)
	unsupported := scan()
	if src := composerSource(t, unsupported, receipt); src.Status != "partial" || !slices.Contains(src.Reasons, "unsupported_format") {
		t.Fatalf("PHP only %+v", src)
	}
}
func TestComposerScanCustomAlternateGlobalAndOrphan(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	app := filepath.Join(root, "app")
	customHome := filepath.Join(home, "custom-composer")
	manifest := filepath.Join(app, "backend.json")
	goWrite(t, manifest, `{"require":{"example/lib":"^1"},"config":{"vendor-dir":"deps/php"}}`, 0o600)
	goWrite(t, composerLockPath(manifest), `{"packages":[{"name":"example/lib","version":"1.0.0"}]}`, 0o600)
	goWrite(t, filepath.Join(app, "deps", "php", "composer", "installed.json"), `[{"name":"example/lib","version":"1.0.0"}]`, 0o600)
	composerWriteProject(t, customHome)
	orphan := filepath.Join(root, "copied-libraries")
	goWrite(t, filepath.Join(orphan, "composer", "installed.json"), `[{"name":"example/orphan","version":"2.0.0"}]`, 0o600)
	goWrite(t, filepath.Join(orphan, "example", "orphan", "composer.json"), `{"require-dev":{"example/phantom":"*"}}`, 0o600)
	scanner, x := composerTestScanner(t, home)
	x.env["COMPOSER"] = manifest
	x.env["COMPOSER_HOME"] = customHome
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	composerAssertRefs(t, inv, audit)
	if len(inv.Projects) != 2 {
		t.Fatalf("projects %+v", inv.Projects)
	}
	hasGlobal, hasOrphan := false, false
	for _, p := range inv.Packages {
		if p.Scope == "global" {
			hasGlobal = true
		}
		if p.PackageName == "example/orphan" {
			hasOrphan = true
			if p.Scope != "unknown" || p.ProjectPath != "" || p.Installation.PathStatus != "inferred" {
				t.Fatalf("orphan %+v", p)
			}
		}
		if p.PackageName == "example/phantom" {
			t.Fatal("nested vendor project")
		}
	}
	if !hasGlobal || !hasOrphan {
		t.Fatal("missing scopes")
	}
	for _, p := range inv.Projects {
		if p.Scope == "global" && filepath.Base(p.ManifestPath) != "composer.json" {
			t.Fatal("alternate COMPOSER applied globally")
		}
	}
}
func TestComposerScanUnknownProcessAndDeveloper(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	composerWriteProject(t, root)
	scanner, x := composerTestScanner(t, home)
	x.current = &user.User{Uid: "0", Username: "root", HomeDir: "/root"}
	if runtime.GOOS == "windows" {
		x.current.Uid = "S-1-5-18"
	}
	x.env["COMPOSER_HOME"] = "/not-the-developer"
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if len(inv.Packages) != 7 || audit.Status != "partial" || inv.Projects[0].SelectionStatus != "partial" {
		t.Fatal("unverified process handling")
	}
	x.reads = map[string]int{}
	for _, target := range []*user.User{nil, {Username: x.current.Username, Uid: x.current.Uid, HomeDir: home}, {Username: "unknown", Uid: "9"}} {
		inv, audit = scanner.Scan(context.Background(), target, []string{root}, nil)
		if inv.Status != "partial" || audit.Status != "partial" || len(inv.Sources) > 0 || len(x.reads) > 0 {
			t.Fatal("unresolved developer accessed files")
		}
	}
}
func TestComposerScanLimitsAndMalformedNeighbor(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	composerWriteProject(t, filepath.Join(root, "a"))
	composerWriteProject(t, filepath.Join(root, "b"))
	scanner, x := composerTestScanner(t, home)
	full, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	owned := func(inv *model.ComposerInventory) map[string]int {
		m := map[string]int{}
		for _, p := range inv.Packages {
			m[p.SourceID]++
		}
		for _, p := range inv.Projects {
			m[p.ManifestSourceID]++
		}
		for _, s := range inv.Sources {
			m[s.ParentSourceID]++
		}
		return m
	}
	want := owned(full)
	old := maxComposerRecords
	t.Cleanup(func() { maxComposerRecords = old })
	total := len(full.Sources) + len(full.Projects) + len(full.Packages)
	for budget := 1; budget < total; budget++ {
		maxComposerRecords = budget
		inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if inv.Status != "partial" || len(inv.Sources)+len(inv.Projects)+len(inv.Packages) > budget {
			t.Fatalf("budget %d counts", budget)
		}
		composerAssertRefs(t, inv, audit)
		got := owned(inv)
		for _, src := range inv.Sources {
			if src.Status == "complete" && got[src.SourceID] != want[src.SourceID] {
				t.Fatalf("budget %d complete owner %s: %d != %d", budget, src.Path, got[src.SourceID], want[src.SourceID])
			}
		}
	}
	maxComposerRecords = old
	broken := filepath.Join(root, "a", "composer.lock")
	goWrite(t, broken, `{"packages":[`, 0o600)
	inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if composerSource(t, inv, broken).Status != "partial" || len(inv.Packages) != 11 {
		t.Fatal("malformed neighbor lost valid facts")
	}
	// Oversize refusal happens before ReadFile.
	previous := maxComposerMetadataBytes
	maxComposerMetadataBytes = 16
	t.Cleanup(func() { maxComposerMetadataBytes = previous })
	x.reads = map[string]int{}
	inv, _ = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	// The small malformed lock remains independently readable; every larger
	// manifest and receipt must be refused before ReadFile.
	if !slices.Contains(inv.Reasons, "size_limit") || len(x.reads) != 1 || x.reads[broken] != 1 {
		t.Fatal("read oversized metadata or skipped the bounded independent lock")
	}
}
func TestComposerScanWalkLimitsDeadlineAndGuards(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	composerWriteProject(t, filepath.Join(root, "a"))
	composerWriteProject(t, filepath.Join(root, "z", "deep"))
	scanner, _ := composerTestScanner(t, home)
	oldEntries, oldDepth := maxComposerWalkEntries, maxComposerWalkDepth
	t.Cleanup(func() { maxComposerWalkEntries, maxComposerWalkDepth = oldEntries, oldDepth })
	for _, tc := range []struct {
		entries, depth int
		reason         string
	}{{1, 128, "entry_limit"}, {100_000, 0, "depth_limit"}} {
		maxComposerWalkEntries, maxComposerWalkDepth = tc.entries, tc.depth
		inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
		if !slices.Contains(inv.Reasons, tc.reason) {
			t.Fatalf("%s %v", tc.reason, inv.Reasons)
		}
		composerAssertRefs(t, inv, audit)
	}
	maxComposerWalkEntries, maxComposerWalkDepth = oldEntries, oldDepth
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv, _ := scanner.Scan(ctx, goTestTarget(home), []string{root}, nil)
	if !slices.Contains(inv.Reasons, "deadline_exceeded") {
		t.Fatal("canceled scan complete")
	}
	protected := filepath.Join(root, "z")
	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if p == protected || strings.HasPrefix(p, protected+string(filepath.Separator)) {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root, protected}, nil)
	if len(inv.Packages) != 7 || !slices.Contains(inv.Reasons, "skipped_protected") {
		t.Fatal("protected sibling isolation")
	}
	composerAssertRefs(t, inv, audit)
}
func TestComposerScanSafeSymlinkAndLocalOrigin(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows {
		t.Skip("native junction coverage runs on Windows VM; Unix symlink test")
	}
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	app := filepath.Join(root, "app")
	source := filepath.Join(home, "local-lib")
	goWrite(t, filepath.Join(source, "composer.json"), `{"require-dev":{"example/phantom":"*"}}`, 0o600)
	goWrite(t, filepath.Join(app, "composer.json"), `{"require":{"example/lib":"*"}}`, 0o600)
	receipt := filepath.Join(app, "vendor", "composer", "installed.json")
	body := fmt.Sprintf(`{"packages":[{"name":"example/lib","version":"dev-main","install-path":"../example/lib","dist":{"type":"path","url":%q,"reference":"local-snapshot"}}]}`, source)
	goWrite(t, receipt, body, 0o600)
	link := filepath.Join(app, "vendor", "example", "lib")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	scanner, _ := composerTestScanner(t, home)
	inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	for _, p := range inv.Packages {
		if p.Evidence == "installed_package" && (p.Origin.Kind != "local" || p.Origin.Path != source || p.Installation.Presence != "present") {
			t.Fatalf("local %+v", p)
		}
		if p.PackageName == "example/phantom" {
			t.Fatal("followed local package manifest")
		}
	}
	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if p == source || strings.HasPrefix(p, source+string(filepath.Separator)) {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
	inv, _ = scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	for _, p := range inv.Packages {
		if p.Evidence == "installed_package" && (p.Installation.Presence != "unknown" || p.Origin.Kind != "unknown") {
			t.Fatal("protected link target")
		}
	}
	if composerSource(t, inv, receipt).Status != "complete" {
		t.Fatal("presence changed source completeness")
	}
}
func TestComposerScanChangedDuringRead(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	composerWriteProject(t, root)
	scanner, x := composerTestScanner(t, home)
	// Stat succeeds; the file disappears before ReadFile.
	path := filepath.Join(root, "composer.lock")
	x.readErrors[path] = os.ErrNotExist
	inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	src := composerSource(t, inv, path)
	if src.Presence != "unknown" || !slices.Contains(src.Reasons, "changed_during_scan") {
		t.Fatalf("changed source %+v", src)
	}
}

func TestComposerScanOutputLimit(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "code")
	composerWriteProject(t, root)
	scanner, _ := composerTestScanner(t, home)
	old := maxComposerOutputBytes
	maxComposerOutputBytes = 32
	t.Cleanup(func() { maxComposerOutputBytes = old })
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if inv.Status != "partial" || !slices.Contains(inv.Reasons, "output_size_limit") || len(inv.Packages) > 0 {
		t.Fatal("output fallback")
	}
	composerAssertRefs(t, inv, audit)
}

func TestComposerScanPrunesConfiguredCacheBeforeAnyProject(t *testing.T) {
	home := goTestHome(t)
	cache := filepath.Join(home, "a-cache")
	composerWriteProject(t, filepath.Join(cache, "composer", "cached-repository"))
	scanner, x := composerTestScanner(t, home)
	if runtime.GOOS == "windows" {
		x.env["LOCALAPPDATA"] = cache
	} else {
		x.env["XDG_CACHE_HOME"] = cache
	}
	inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{home}, nil)
	if len(inv.Packages) != 0 || len(inv.Projects) != 0 {
		t.Fatal("cache metadata became project inventory")
	}
}

func TestComposerScanDistinctInstallPathsAndLegacyInference(t *testing.T) {
	home := goTestHome(t)
	app := filepath.Join(home, "app")
	goWrite(t, filepath.Join(app, "composer.json"), `{}`, 0o600)
	receipt := filepath.Join(app, "vendor", "composer", "installed.json")
	goWrite(t, receipt, `[{"name":"example/lib","version":"1","install-path":"../copy-a"},{"name":"example/lib","version":"1","install-path":"../copy-b"},{"name":"example/legacy","version":"1","type":"library","target-dir":"Legacy"},{"name":"example/custom","version":"1","type":"custom-installer"}]`, 0o600)
	goWrite(t, filepath.Join(app, "vendor", "example", "legacy", "Legacy", "marker"), "", 0o600)
	scanner, _ := composerTestScanner(t, home)
	inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{app}, nil)
	if len(inv.Packages) != 4 {
		t.Fatalf("distinct installations collapsed: %d", len(inv.Packages))
	}
	for _, p := range inv.Packages {
		if p.PackageName == "example/legacy" && (p.Installation.PathStatus != "inferred" || p.Installation.Presence != "present") {
			t.Fatal("legacy library path not inferred")
		}
		if p.PackageName == "example/custom" && p.Installation.PathStatus != "unresolved" {
			t.Fatal("custom installer path guessed")
		}
	}
}

func TestComposerScanLateVendorAndCacheSelection(t *testing.T) {
	for _, kind := range []string{"vendor-dir", "cache-dir"} {
		t.Run(kind, func(t *testing.T) {
			home := goTestHome(t)
			copied := filepath.Join(home, "a-copied")
			app := filepath.Join(home, "z-app")
			// No outer receipt identifies this directory until z-app is read.
			composerWriteProject(t, filepath.Join(copied, "example", "dependency"))
			body, _ := json.Marshal(map[string]any{"require": map[string]string{"example/root": "^1"}, "config": map[string]string{kind: copied}})
			goWrite(t, filepath.Join(app, "composer.json"), string(body), 0o600)
			scanner, _ := composerTestScanner(t, home)
			inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{copied, app}, nil)
			composerAssertRefs(t, inv, audit)
			if len(inv.Projects) != 1 || len(inv.Packages) != 1 || inv.Packages[0].PackageName != "example/root" {
				t.Fatalf("nested dependency became root evidence: %d projects, %d packages", len(inv.Projects), len(inv.Packages))
			}
			for _, f := range audit.Files {
				if f.Scope == "project" && f.Path != filepath.Join(app, "composer.json") {
					t.Fatal("nested dependency config survived")
				}
			}
		})
	}
}

func TestComposerScanNetworkRefusal(t *testing.T) {
	home := goTestHome(t)
	app := filepath.Join(home, "app")
	composerWriteProject(t, app)
	scanner, x := composerTestScanner(t, home)
	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		blocked := func(p string) bool { return p == app || strings.HasPrefix(p, app+string(filepath.Separator)) }
		return func(p string) string {
			if blocked(p) {
				return "skipped_protected"
			}
			return ""
		}, blocked
	}
	inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{app}, nil)
	if !slices.Contains(inv.Reasons, "refused_network_volume") || len(inv.Packages) != 0 || len(x.reads) != 0 {
		t.Fatal("refused network volume was read or reported absent")
	}
	composerAssertRefs(t, inv, audit)
}

func TestComposerScanWindowsJunction(t *testing.T) {
	if runtime.GOOS != model.PlatformWindows {
		t.Skip("requires Windows junction support")
	}
	home := goTestHome(t)
	app := filepath.Join(home, "app")
	target := filepath.Join(home, "local-package")
	goWrite(t, filepath.Join(target, "marker"), "", 0o600)
	goWrite(t, filepath.Join(app, "composer.json"), `{}`, 0o600)
	goWrite(t, filepath.Join(app, "vendor", "composer", "installed.json"), `{"packages":[{"name":"example/local","version":"dev-main","type":"library","install-path":"../example/local"}],"dev-package-names":[]}`, 0o600)
	link := filepath.Join(app, "vendor", "example", "local")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	// Test setup only: the scanner's trap still rejects every command. Directory
	// junctions do not require the symlink privilege used by os.Symlink.
	_, _, code, err := executor.NewReal().RunWithTimeout(context.Background(), 10*time.Second, "cmd.exe", "/c", "mklink", "/J", link, target)
	if err != nil || code != 0 {
		t.Fatalf("creating test junction: code=%d err=%v", code, err)
	}
	scanner, _ := composerTestScanner(t, home)
	inv, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{app}, nil)
	if len(inv.Packages) != 1 || inv.Packages[0].Installation.Presence != "present" {
		t.Fatal("safe junction not resolved")
	}
	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if p == target || strings.HasPrefix(p, target+string(filepath.Separator)) {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
	inv, _ = scanner.Scan(context.Background(), goTestTarget(home), []string{app}, nil)
	if len(inv.Packages) != 1 || inv.Packages[0].Installation.Presence != "unknown" || !slices.Contains(inv.Packages[0].Reasons, "skipped_protected") {
		t.Fatal("junction bypassed target protection")
	}
}

func TestComposerScanCancelledAfterManifestRead(t *testing.T) {
	home := goTestHome(t)
	app := filepath.Join(home, "app")
	composerWriteProject(t, app)
	scanner, x := composerTestScanner(t, home)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manifest := filepath.Join(app, "composer.json")
	x.afterRead = func(path string) {
		if path == manifest {
			cancel()
		}
	}
	inv, audit := scanner.Scan(ctx, goTestTarget(home), []string{app}, nil)
	composerAssertRefs(t, inv, audit)
	if inv.Status != "partial" || !slices.Contains(inv.Reasons, "deadline_exceeded") {
		t.Fatal("cancelled scan did not report partial coverage")
	}
	if len(inv.Projects) != 0 || len(inv.Packages) != 0 {
		t.Fatal("emitted project facts after cancellation interrupted initialization")
	}
	if x.reads[composerLockPath(manifest)] != 0 || composerSource(t, inv, manifest).Status != "partial" {
		t.Fatal("cancellation did not stop later reads and degrade the source")
	}
}

func TestComposerScanLockSurvivesManifestFailure(t *testing.T) {
	for _, fault := range []string{"invalid", "denied"} {
		t.Run(fault, func(t *testing.T) {
			home := goTestHome(t)
			app := filepath.Join(home, "app")
			composerWriteProject(t, app)
			scanner, x := composerTestScanner(t, home)
			manifest := filepath.Join(app, "composer.json")
			if fault == "invalid" {
				goWrite(t, manifest, `{"require":`, 0o600)
			} else {
				x.denied[manifest] = os.ErrPermission
			}
			inv, audit := scanner.Scan(context.Background(), goTestTarget(home), []string{app}, nil)
			composerAssertRefs(t, inv, audit)
			locked := 0
			for _, p := range inv.Packages {
				if p.Evidence == "declared_requirement" {
					t.Fatal("invented declaration from failed manifest")
				}
				if p.Evidence == "locked_package" {
					locked++
					if p.ProjectPath != app || p.Scope != "project" {
						t.Fatal("lost lockfile path context")
					}
				}
			}
			if locked != 3 {
				t.Fatalf("readable lock has %d packages, want 3", locked)
			}
			if composerSource(t, inv, manifest).Status != "partial" || composerSource(t, inv, composerLockPath(manifest)).Status != "complete" {
				t.Fatal("manifest failure changed independent lock coverage")
			}
		})
	}
}
