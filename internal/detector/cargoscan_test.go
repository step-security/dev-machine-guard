package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// cargoTestScan scans home with code as the search root. The process runs as
// another account, so its environment is never read.
func cargoTestScan(t *testing.T, home, code string) (*model.CargoInventory, *model.CargoConfigAudit) {
	t.Helper()
	exec := &goTrap{Executor: executor.NewReal(), t: t, current: &user.User{Username: "agent", Uid: "1001"}}
	return NewCargoScanner(exec, progress.NewNoop()).Scan(context.Background(), goTestTarget(home), []string{code}, nil)
}

func cargoWritePackage(t *testing.T, dir, name string) {
	t.Helper()
	goWrite(t, filepath.Join(dir, "Cargo.toml"), "[package]\nname = \""+name+"\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nlog = \"0.4\"\n", 0o644)
	goWrite(t, filepath.Join(dir, "Cargo.lock"), `version = 4

[[package]]
name = "`+name+`"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
`, 0o644)
}

func TestCargoScan_CleanScanHasNoNullArrays(t *testing.T) {
	home := goTestHome(t)
	code := filepath.Join(home, "code")
	cargoWritePackage(t, filepath.Join(code, "app"), "app")

	inv, audit := cargoTestScan(t, home, code)
	if inv.Status != model.CargoStatusComplete || audit.Status != model.CargoStatusComplete {
		t.Fatalf("status = %s %v / %s %v, want complete", inv.Status, inv.Reasons, audit.Status, audit.Reasons)
	}
	for name, v := range map[string]any{"inventory": inv, "audit": audit} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("null")) {
			t.Errorf("%s serializes a null: %s", name, b)
		}
	}
}

// cargoOwned counts the rows each source owns and lists its children.
func cargoOwned(inv *model.CargoInventory) map[string]string {
	counts := map[string][3]int{}
	for _, p := range inv.Projects {
		c := counts[p.ManifestSourceID]
		c[0]++
		counts[p.ManifestSourceID] = c
	}
	for _, w := range inv.Workspaces {
		c := counts[w.ManifestSourceID]
		c[1]++
		counts[w.ManifestSourceID] = c
	}
	for _, p := range inv.Packages {
		c := counts[p.SourceID]
		c[2]++
		counts[p.SourceID] = c
	}
	out := map[string]string{}
	for _, s := range inv.Sources {
		out[s.SourceID] = fmt.Sprint(counts[s.SourceID], s.DiscoveredSources)
	}
	return out
}

// Under every budget short of the full record count, a source left complete
// must own exactly what it owns in an unlimited scan.
func TestCargoScan_RecordLimitMarksUnfinishedOwners(t *testing.T) {
	home := goTestHome(t)
	code := filepath.Join(home, "code")
	for _, name := range []string{"a", "b"} {
		cargoWritePackage(t, filepath.Join(code, name), name)
	}
	ws := filepath.Join(code, "ws")
	goWrite(t, filepath.Join(ws, "Cargo.toml"), "[workspace]\nmembers = [\"m1\", \"m2\"]\n", 0o644)
	cargoWritePackage(t, filepath.Join(ws, "m1"), "m1")
	cargoWritePackage(t, filepath.Join(ws, "m2"), "m2")
	saved := maxCargoRecords
	t.Cleanup(func() { maxCargoRecords = saved })

	full, _ := cargoTestScan(t, home, code)
	want := cargoOwned(full)
	total := len(full.Sources) + len(full.Projects) + len(full.Workspaces) + len(full.Packages)
	for budget := 1; budget < total; budget++ {
		maxCargoRecords = budget
		inv, _ := cargoTestScan(t, home, code)
		if inv.Status != model.CargoStatusPartial || !slices.Contains(inv.Reasons, model.CargoReasonRecordLimit) {
			t.Errorf("budget %d: status = %s %v, want partial with record_limit", budget, inv.Status, inv.Reasons)
		}
		got := cargoOwned(inv)
		for _, s := range inv.Sources {
			if s.Status == model.CargoStatusComplete && got[s.SourceID] != want[s.SourceID] {
				t.Errorf("budget %d: complete %s %s owns %s, want %s", budget, s.Kind, s.Path, got[s.SourceID], want[s.SourceID])
			}
		}
	}
}

func TestCargoScan_InheritedPathDependencyKeepsLockedPackage(t *testing.T) {
	home := goTestHome(t)
	code := filepath.Join(home, "code")
	ws := filepath.Join(code, "ws")
	goWrite(t, filepath.Join(ws, "Cargo.toml"), `[workspace]
members = ["app"]

[workspace.dependencies]
shared = { path = "shared" }
ext = { path = "../../outside/ext" }
unused = { path = "../../outside/unused" }
`, 0o644)
	goWrite(t, filepath.Join(ws, "app", "Cargo.toml"), "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nshared.workspace = true\next.workspace = true\n", 0o644)
	goWrite(t, filepath.Join(ws, "shared", "Cargo.toml"), "[package]\nname = \"shared\"\nversion = \"0.2.0\"\n", 0o644)
	// Outside the search root: only an inherited entry is followed.
	outside := filepath.Join(home, "outside")
	goWrite(t, filepath.Join(outside, "ext", "Cargo.toml"), "[package]\nname = \"ext\"\nversion = \"0.3.0\"\n", 0o644)
	goWrite(t, filepath.Join(outside, "unused", "Cargo.toml"), "[package]\nname = \"unused\"\nversion = \"0.4.0\"\n\n[dependencies]\nserde = \"1\"\n", 0o644)
	goWrite(t, filepath.Join(ws, "Cargo.lock"), `version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["ext", "shared"]

[[package]]
name = "ext"
version = "0.3.0"

[[package]]
name = "shared"
version = "0.2.0"
`, 0o644)

	inv, _ := cargoTestScan(t, home, code)
	var locked []model.CargoPackage
	for _, p := range inv.Packages {
		if p.Evidence == model.CargoEvidenceLockedPackage {
			locked = append(locked, p)
		}
	}
	shared, ext := filepath.Join(ws, "shared"), filepath.Join(outside, "ext")
	if len(locked) != 2 || locked[0].PackageName != "ext" || locked[0].Origin.Path != ext ||
		locked[1].PackageName != "shared" || locked[1].ObservedVersion != "0.2.0" || locked[1].Origin.Path != shared {
		t.Errorf("locked packages = %+v, want ext at %s and shared 0.2.0 at %s", locked, ext, shared)
	}
	for _, p := range inv.Projects {
		if p.PackageName == "unused" {
			t.Errorf("unused workspace dependency was followed: %+v", p)
		}
	}
	if len(inv.Workspaces) != 1 || !slices.ContainsFunc(inv.Workspaces[0].Members, func(m model.CargoWorkspaceMember) bool {
		return m.ManifestPath == filepath.Join(shared, "Cargo.toml")
	}) {
		t.Errorf("workspaces = %+v, want shared admitted as a member", inv.Workspaces)
	}
}

func TestCargoScan_UnreadableBinIsUnreadable(t *testing.T) {
	if runtime.GOOS == model.PlatformWindows || os.Geteuid() == 0 {
		t.Skip("needs Unix directory permissions that bind the caller")
	}
	home := goTestHome(t)
	cargoHome := filepath.Join(home, ".cargo")
	goWrite(t, filepath.Join(cargoHome, ".crates.toml"), `[v1]
"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)" = ["rg"]
`, 0o644)
	bin := filepath.Join(cargoHome, "bin")
	goWrite(t, filepath.Join(bin, "rg"), "", 0o755)
	if err := os.Chmod(bin, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bin, 0o755) })

	inv, _ := cargoTestScan(t, home, filepath.Join(home, "code"))
	if inv.Status != model.CargoStatusPartial || !slices.Contains(inv.Reasons, model.CargoReasonPermissionDenied) {
		t.Errorf("inventory = %s %v, want partial with permission_denied", inv.Status, inv.Reasons)
	}
	for _, src := range inv.Sources {
		if src.Kind == model.CargoSourceInstallRoot && src.Path == cargoHome &&
			(src.Status != model.CargoStatusPartial || !slices.Contains(src.Reasons, model.CargoReasonPermissionDenied)) {
			t.Errorf("install source = %s %v, want partial with permission_denied", src.Status, src.Reasons)
		}
	}
	for _, p := range inv.Packages {
		if p.Evidence != model.CargoEvidenceInstalledTool {
			continue
		}
		if p.Installation.Status != model.CargoInstallPartial || len(p.Installation.Bins) != 1 || p.Installation.Bins[0].Presence != model.CargoBinUnreadable {
			t.Errorf("installation = %+v, want partial with an unreadable bin", p.Installation)
		}
		return
	}
	t.Fatal("no installed_tool record")
}

func TestCargoScan_ConfigPatchWorkspace(t *testing.T) {
	home := goTestHome(t)
	code := filepath.Join(home, "code")
	app := filepath.Join(code, "app")
	ws := filepath.Join(home, "outside", "workspace")
	goWrite(t, filepath.Join(app, "Cargo.toml"), "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nwidgets = \"1\"\n", 0o644)
	goWrite(t, filepath.Join(app, ".cargo", "config.toml"), fmt.Sprintf("[patch.crates-io]\nwidgets = { path = %q }\n", filepath.ToSlash(filepath.Join(ws, "member"))), 0o644)
	goWrite(t, filepath.Join(ws, "Cargo.toml"), `[workspace]
members = ["member"]
[workspace.package]
version = "1.2.3"
[workspace.dependencies]
helper = { path = "helper", package = "actual-helper" }
`, 0o644)
	goWrite(t, filepath.Join(ws, "member", "Cargo.toml"), `[package]
name = "widgets"
version.workspace = true
workspace = ".."
[dependencies]
helper.workspace = true
`, 0o644)
	goWrite(t, filepath.Join(ws, "helper", "Cargo.toml"), "[package]\nname = \"actual-helper\"\nversion = \"0.1.0\"\n", 0o644)
	for _, dir := range []string{app, filepath.Join(ws, "member"), filepath.Join(ws, "helper")} {
		goWrite(t, filepath.Join(dir, "src", "lib.rs"), "", 0o644)
	}
	inv, audit := cargoTestScan(t, home, code)
	var widgets, helper, contextFound bool
	for _, p := range inv.Projects {
		if p.PackageName == "widgets" {
			widgets = true
			if p.PackageVersion != "1.2.3" || p.WorkspaceManifestPath != filepath.Join(ws, "Cargo.toml") {
				t.Errorf("widgets version = %q, workspace = %q, want inherited version and workspace", p.PackageVersion, p.WorkspaceManifestPath)
			}
		}
	}
	for _, p := range inv.Packages {
		if p.Evidence == model.CargoEvidenceDeclaredRequirement && p.PackageName == "actual-helper" {
			helper = p.Origin.Kind == model.CargoOriginLocal && p.Origin.Path == filepath.Join(ws, "helper")
		}
		if p.PackageName == "helper" {
			t.Errorf("dependency alias emitted as package name: %+v", p)
		}
	}
	for _, c := range audit.Contexts {
		if c.ProjectPath == filepath.Join(ws, "member") && c.WorkspacePath == ws {
			contextFound = true
		}
	}
	if !widgets || !helper || !contextFound {
		t.Errorf("widgets=%v, inherited helper=%v, config context=%v, want all true", widgets, helper, contextFound)
	}
}

func TestCargoScan_LocalLockOriginRequiresReference(t *testing.T) {
	for _, tc := range []struct {
		name                string
		present, transitive bool
	}{
		{name: "missing"},
		{name: "direct", present: true},
		{name: "transitive", present: true, transitive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			code := filepath.Join(home, "code")
			referenced := filepath.Join(home, "outside", "shared")
			goWrite(t, filepath.Join(code, "app", "Cargo.toml"), `[package]
name = "app"
version = "0.1.0"
[dependencies]
shared = {path = "../../outside/shared"}
`, 0o644)
			goWrite(t, filepath.Join(code, "app", "Cargo.lock"), `version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["shared"]
[[package]]
name = "shared"
version = "1.2.3"
`, 0o644)
			manifest := "[package]\nname = \"shared\"\nversion = \"1.2.3\"\n"
			goWrite(t, filepath.Join(code, "unrelated", "Cargo.toml"), manifest, 0o644)
			if tc.present {
				goWrite(t, filepath.Join(referenced, "Cargo.toml"), manifest, 0o644)
			}
			if tc.transitive {
				goWrite(t, filepath.Join(code, "app", "Cargo.lock"), `version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["bridge"]
[[package]]
name = "bridge"
version = "0.1.0"
dependencies = ["shared"]
[[package]]
name = "shared"
version = "1.2.3"
`, 0o644)
				goWrite(t, filepath.Join(code, "app", "Cargo.toml"), "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nbridge = {path = \"../../outside/bridge\"}\n", 0o644)
				goWrite(t, filepath.Join(home, "outside", "bridge", "Cargo.toml"), "[package]\nname = \"bridge\"\nversion = \"0.1.0\"\n[dependencies]\nshared = {path = \"../shared\"}\n", 0o644)
			}
			inv, _ := cargoTestScan(t, home, code)
			found := false
			for _, p := range inv.Packages {
				if p.Evidence != model.CargoEvidenceLockedPackage || p.PackageName != "shared" {
					continue
				}
				found = true
				kind, path := model.CargoOriginLocalUnknown, filepath.Join(code, "app", "Cargo.lock")
				if tc.present {
					kind, path = model.CargoOriginLocal, referenced
				}
				if p.Origin.Kind != kind || p.Origin.Path != path {
					t.Errorf("locked shared origin = %s %s, want %s %s", p.Origin.Kind, p.Origin.Path, kind, path)
				}
			}
			if !found {
				t.Fatal("locked shared package missing")
			}
		})
	}
}
