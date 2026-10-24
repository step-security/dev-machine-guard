//go:build windows

package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
	"golang.org/x/sys/windows"
)

func TestAppliedStateWindowsUsesTargetUserSecurity(t *testing.T) {
	homeDir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	target, restore, err := ConfigureCacheTarget(secureTestExecutor{Executor: executor.NewReal(), user: u}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	home, err := secureuserfile.OpenUserHome(target)
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	path := CachePath()

	for _, hash := range []string{"first", "replacement"} {
		if err := WriteAppliedState(CategoryIDEExtension, TargetVSCode, AppliedTargetState{AppliedHash: hash}); err != nil {
			t.Fatal(err)
		}
	}
	for _, object := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Dir(path), secureuserfile.ParentMode},
		{path + stateLockSuffix, secureuserfile.FileMode},
		{path, secureuserfile.FileMode},
	} {
		file, err := os.Open(object.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := home.VerifyOwner(file, filepath.Base(object.path)); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		secure, err := home.MetadataSecure(file, object.mode)
		_ = file.Close()
		if err != nil || !secure {
			t.Fatalf("metadata %q = %v, %v", object.path, secure, err)
		}
	}
}

// The legacy fixtures are what the retained 1.15 release driver
// (dmg-windows-state-v115-repro, state-repro seed) leaves behind: an IDE sibling
// record plus the npm record and block, with a synthetic token. 1.15 records the
// rendered block itself under written_settings.npmrc, has none of the newer
// file_created/resolved_path fields, and writes the state without the strict
// DACL, so it inherits its parent's ACL.
const (
	legacyNPMPolicy = `{"ecosystem":"npm","registry_url":"https://registry.example.com/javascript","auth":{"scheme":"stepsecurity_device_token","api_key":"testkey"}}`
	legacyNPMHash   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	legacyIDEHash   = "sibling-unchanged"
	legacyNPMRC     = "# unrelated user setting\nfund=false\n" +
		"# BEGIN StepSecurity Secure Registry -- managed by dmg\n" +
		"registry=https://registry.example.com/javascript\n" +
		"//registry.example.com/javascript/:_authToken=testkey::dev:test-device\n" +
		"# END StepSecurity Secure Registry\n"
)

const legacyStateFixture = `{
  "schema_version": 1,
  "categories": {
    "ide_extension": {
      "targets": {
        "vscode": {"applied_hash": "sibling-unchanged", "written_settings": {"test": "preserve"}, "fetched_at": "2026-09-01T00:00:00Z"}
      }
    },
    "package_config": {
      "targets": {
        "npm": {"applied_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "written_settings": {"npmrc": "registry=https://registry.example.com/javascript\n//registry.example.com/javascript/:_authToken=testkey::dev:test-device"}, "fetched_at": "2026-09-01T00:00:00Z"}
      }
    }
  }
}
`

// configureLegacyWindowsState pins the cache to a temporary home seeded with
// the legacy fixture and an inherited-ACL lock, and returns the state path, a
// sink of the warnings ReadAppliedState emits, and the target executor.
// targetSID overrides the target user's SID when non-empty.
func configureLegacyWindowsState(t *testing.T, seed bool, targetSID string) (string, *[]string, executor.Executor) {
	t.Helper()
	homeDir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	ownerUID := u.Uid
	if targetSID != "" {
		u.Uid = targetSID
	}
	path := filepath.Join(homeDir, ".stepsecurity", CacheFilename)
	if seed {
		if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		// The 1.15 lab state granted the owner only inherited Modify, so a
		// standard user cannot assign ownership on the directory, lock or state.
		setInheritedModifyOnly(t, filepath.Dir(path), ownerUID)
		for name, data := range map[string]string{path: legacyStateFixture, path + stateLockSuffix: ""} {
			if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	var warnings []string
	warnf := func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }
	target, restore, err := ConfigureCacheTarget(secureTestExecutor{Executor: executor.NewReal(), user: u}, warnf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	// A foreign target cannot inspect the fixture's metadata at all; only the
	// correctly owned fixture must start out readable but insecure.
	if seed && targetSID == "" {
		if secure, err := cacheStateFile.MetadataSecure(cacheFileMode); err != nil || secure {
			t.Fatalf("legacy fixture metadata = %v, %v, want insecure", secure, err)
		}
	}
	return path, &warnings, target
}

func requireStateBytes(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("state bytes = %q, %v, want unchanged legacy fixture", got, err)
	}
}

func requireRepairedQuietly(t *testing.T, warnings []string) {
	t.Helper()
	if secure, err := cacheStateFile.MetadataSecure(cacheFileMode); err != nil || !secure {
		t.Fatalf("repaired state metadata = %v, %v, want secure", secure, err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %q, want none", warnings)
	}
}

func requireRecord(t *testing.T, category, target, wantHash string) {
	t.Helper()
	got, ok := ReadAppliedState(category, target)
	if !ok || got.AppliedHash != wantHash {
		t.Fatalf("ReadAppliedState(%s, %s) = %+v, %v, want hash %s", category, target, got, ok, wantHash)
	}
}

func TestAppliedStateWindowsRepairsLegacyStateFromEveryEntryPoint(t *testing.T) {
	tests := []struct {
		name  string
		first func(t *testing.T, path string)
	}{
		{"read", func(t *testing.T, path string) {
			requireRecord(t, CategoryPackageConfig, TargetNPM, legacyNPMHash)
			requireStateBytes(t, path, legacyStateFixture)
		}},
		{"write", func(t *testing.T, _ string) {
			if err := WriteAppliedState(CategoryPackageConfig, TargetNPM, AppliedTargetState{AppliedHash: "sha256:npm-next"}); err != nil {
				t.Fatalf("WriteAppliedState: %v", err)
			}
			requireRecord(t, CategoryPackageConfig, TargetNPM, "sha256:npm-next")
		}},
		{"probe", func(t *testing.T, path string) {
			if err := ProbeAppliedStateWritable(); err != nil {
				t.Fatalf("ProbeAppliedStateWritable: %v", err)
			}
			requireStateBytes(t, path, legacyStateFixture)
		}},
		{"clear", func(t *testing.T, _ string) {
			if err := ClearAppliedState(CategoryPackageConfig, TargetNPM); err != nil {
				t.Fatalf("ClearAppliedState: %v", err)
			}
			if got, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM); ok {
				t.Fatalf("cleared npm record still present: %+v", got)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, warnings, _ := configureLegacyWindowsState(t, true, "")
			tc.first(t, path)
			requireRecord(t, CategoryIDEExtension, TargetVSCode, legacyIDEHash)
			requireRepairedQuietly(t, *warnings)
		})
	}
}

func TestAppliedStateWindowsLegacyStateWaitsForPeerLock(t *testing.T) {
	path, warnings, exec := configureLegacyWindowsState(t, true, "")
	npmPath := filepath.Join(filepath.Dir(filepath.Dir(path)), ".npmrc")
	if err := os.WriteFile(npmPath, []byte(legacyNPMRC), 0o600); err != nil {
		t.Fatal(err)
	}
	holdStateLockUntilCleanup(t)

	for range 2 {
		if got, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM); ok {
			t.Fatalf("read without the lock returned %+v, want not owned", got)
		}
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], string(errStateLockBusy)) {
		t.Fatalf("warnings = %q, want one lock-busy warning", *warnings)
	}
	if err := WriteAppliedState(CategoryPackageConfig, TargetNPM, AppliedTargetState{AppliedHash: "sha256:x"}); !errors.Is(err, errStateLockBusy) {
		t.Fatalf("WriteAppliedState error = %v, want errStateLockBusy", err)
	}
	if secure, err := cacheStateFile.MetadataSecure(cacheFileMode); err != nil || secure {
		t.Fatalf("state metadata = %v, %v, want unrepaired while a peer holds the lock", secure, err)
	}
	// A clear that cannot repair and read its record must not remove the block.
	if err := runLegacyNPMLane(exec, &fakeReporter{}, true); !errors.Is(err, errStateLockBusy) {
		t.Fatalf("npm clear error = %v, want errStateLockBusy", err)
	}
	if got, err := os.ReadFile(npmPath); err != nil || string(got) != legacyNPMRC {
		t.Fatalf("npmrc after refused clear = %q, %v, want unchanged", got, err)
	}
	requireStateBytes(t, path, legacyStateFixture)
}

func TestAppliedStateWindowsWrongOwnerIsReportedNotRepaired(t *testing.T) {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	path, warnings, _ := configureLegacyWindowsState(t, true, systemSID.String())
	if ownerSID(t, path).Equals(systemSID) {
		t.Skip("fixture is already owned by SYSTEM")
	}
	before := ownerSID(t, path)

	if _, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("wrong-owner state read as owned")
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "devicepolicy: read applied state:") {
		t.Fatalf("warnings = %q, want one read failure", *warnings)
	}
	if err := ClearAppliedState(CategoryPackageConfig, TargetNPM); !errors.Is(err, secureuserfile.ErrTargetUnusable) {
		t.Fatalf("ClearAppliedState error = %v, want ErrTargetUnusable", err)
	}
	requireStateBytes(t, path, legacyStateFixture)
	if after := ownerSID(t, path); !after.Equals(before) {
		t.Fatalf("owner changed from %s to %s", before, after)
	}
}

func TestAppliedStateWindowsReadWithoutStateCreatesNothing(t *testing.T) {
	path, warnings, _ := configureLegacyWindowsState(t, false, "")
	if _, ok := ReadAppliedState(CategoryPackageConfig, TargetNPM); ok {
		t.Fatal("absent state read as owned")
	}
	if _, err := os.Lstat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("state directory created by a read: %v", err)
	}
	if len(*warnings) != 0 {
		t.Fatalf("warnings = %q, want none", *warnings)
	}
}

func setInheritedModifyOnly(t *testing.T, dir, ownerUID string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;0x1301bf;;;" + ownerUID + ")(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

// TestAppliedStateWindowsLegacyNPMLaneRepairsAndKeepsSibling drives the npm lane
// over the 1.15 fixture: enforcement and removal each repair the state first,
// remove only the owned block and record, and keep the IDE sibling. Clear as the
// first operation after the upgrade must still restore the user's file.
func TestAppliedStateWindowsLegacyNPMLaneRepairsAndKeepsSibling(t *testing.T) {
	tests := []struct {
		name  string
		steps []bool // true = clear
	}{
		{"apply repeat clear", []bool{false, false, true, true}},
		{"clear first", []bool{true, true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, warnings, exec := configureLegacyWindowsState(t, true, "")
			npmPath := filepath.Join(filepath.Dir(filepath.Dir(path)), ".npmrc")
			if err := os.WriteFile(npmPath, []byte(legacyNPMRC), 0o600); err != nil {
				t.Fatal(err)
			}
			for i, clear := range tc.steps {
				rep := &fakeReporter{}
				if err := runLegacyNPMLane(exec, rep, clear); err != nil {
					t.Fatalf("step %d (clear=%v): %v", i, clear, err)
				}
				npm, err := os.ReadFile(npmPath)
				if err != nil || !strings.Contains(string(npm), "fund=false") {
					t.Fatalf("step %d: unrelated npm setting lost: %v", i, err)
				}
				managed := strings.Contains(string(npm), "registry=https://registry.example.com/javascript")
				_, owned := ReadAppliedState(CategoryPackageConfig, TargetNPM)
				if clear {
					if managed || owned {
						t.Fatalf("step %d: after clear block=%v record=%v, want both gone", i, managed, owned)
					}
				} else {
					if !managed || !owned || len(rep.reports) == 0 {
						t.Fatalf("step %d: after apply block=%v record=%v reports=%d", i, managed, owned, len(rep.reports))
					}
					if got := rep.reports[len(rep.reports)-1].State; got != StateCompliant && got != StateDriftDetected {
						t.Fatalf("step %d: report state = %q, want compliant or drift_detected", i, got)
					}
				}
				requireRecord(t, CategoryIDEExtension, TargetVSCode, legacyIDEHash)
				requireRepairedQuietly(t, *warnings)
			}
		})
	}
}

// runLegacyNPMLane is one npm reconcile cycle, wired as main wires the lane.
func runLegacyNPMLane(exec executor.Executor, rep *fakeReporter, clear bool) error {
	ep := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetNPM, Hash: legacyNPMHash, Enforcement: "dmg"}
	if clear {
		ep.Clear = true
	} else {
		ep.Policy = json.RawMessage(legacyNPMPolicy)
	}
	var w *NPMRCWriter
	r := &Reconciler{
		Fetcher: &fakeFetcher{ep: ep}, Reporter: rep, CustomerID: "test-org", DeviceID: "test-device",
		Platform: "windows", Category: CategoryPackageConfig, Target: TargetNPM,
		Render:              func(raw json.RawMessage) (string, error) { return RenderNPMRCBlock(raw, "test-device") },
		OwnsByMarker:        true,
		OwnershipKey:        NPMOwnedKey,
		OwnershipStateValue: NPMOwnershipValue,
	}
	r.InitWriter = func() error {
		var err error
		if w, err = NewNPMRCWriter(exec); err != nil {
			return err
		}
		r.Writer = w
		r.Converged = w.Converged
		r.CompleteState = w.CompleteState
		r.PrepareClear = w.PrepareClear
		r.ProbeExpected = w.ProbeExpected
		r.RestoreSnapshot = w.RestoreSnapshot
		r.ProbeContent = w.ProbeContentNPM
		return nil
	}
	err := r.Reconcile(context.Background())
	if w != nil {
		_ = w.Close()
	}
	return err
}

func ownerSID(t *testing.T, path string) *windows.SID {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		t.Fatalf("owner(%q): %v", path, err)
	}
	return owner
}
