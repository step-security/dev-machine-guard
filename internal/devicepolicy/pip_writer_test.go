package devicepolicy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const pipExpected = "index-url = https://registry.stepsecurity.io/python/simple\nno-index = false"

func TestPipMarkers_Canonical(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"DMG begin", dmgPipBegin, "# BEGIN StepSecurity Package Configuration pip -- managed by dmg"},
		{"DMG end", dmgPipEnd, "# END StepSecurity Package Configuration pip"},
		{"MDM begin", mdmPipBegin, "# BEGIN StepSecurity Package Configuration pip -- managed by mdm"},
		{"MDM end", mdmPipEnd, "# END StepSecurity Package Configuration pip"},
		{"disabled prefix", dmgPipDisabledPrefix, "# [stepsecurity-pypi-pip-dmg] "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("marker = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func newPipTestWriter(t *testing.T, initial []byte) (*PipWriter, *executor.Mock, string) {
	t.Helper()
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, ".config", "pip", "pip.conf")
	if initial != nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, initial, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("")
	mock.SetHomeDir(homeDir)
	writer, err := NewPipWriter(context.Background(), mock, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatalf("NewPipWriter: %v", err)
	}
	writer.exec = mock
	return writer, mock, path
}

type pipSymlinkFixture struct {
	writer           *PipWriter
	state            AppliedTargetState
	targetA, targetB string
	beforeA, beforeB []byte
}

func newPipSymlinkTestWriter(t *testing.T, retarget bool) pipSymlinkFixture {
	t.Helper()
	homeDir := t.TempDir()
	configDir := filepath.Join(homeDir, ".config", "pip")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	targetA := filepath.Join(configDir, "target-a.conf")
	targetB := filepath.Join(configDir, "target-b.conf")
	if err := os.WriteFile(targetA, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetB, []byte("[global]\ntimeout = 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(configDir, "pip.conf")
	if err := os.Symlink("target-a.conf", link); err != nil {
		t.Fatal(err)
	}

	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHomeDir(homeDir)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	exec := &coordinatorUserExecutor{Mock: mock, user: &user.User{Username: current.Username, HomeDir: homeDir}}
	w, err := NewPipWriter(context.Background(), exec, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatal(err)
	}
	state := AppliedTargetState{}
	if err := w.CompleteState(AppliedTargetState{}, false, &state); err != nil {
		t.Fatal(err)
	}
	if retarget {
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("target-b.conf", link); err != nil {
			t.Fatal(err)
		}
	}
	beforeA, err := os.ReadFile(targetA)
	if err != nil {
		t.Fatal(err)
	}
	beforeB, err := os.ReadFile(targetB)
	if err != nil {
		t.Fatal(err)
	}
	return pipSymlinkFixture{writer: w, state: state, targetA: targetA, targetB: targetB, beforeA: beforeA, beforeB: beforeB}
}

func TestPipWriter_TransformsAndRestoresConflicts(t *testing.T) {
	initial := []byte("# keep\n[install]\nfind_links: ./wheelhouse\nno_index = true\ntrusted-host = old.example\n[global]\ntimeout = 30\nINDEX_URL = https://old.example/simple\nextra-index-url =\n  https://one.example/simple\n  https://two.example/simple\n")
	w, _, path := newPipTestWriter(t, initial)

	got, err := w.Write(pipExpected)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got != pipExpected {
		t.Fatalf("Write = %q, want %q", got, pipExpected)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{dmgPipBegin, dmgPipEnd} {
		if !bytes.Contains(content, []byte(marker)) {
			t.Errorf("managed output missing marker %q:\n%s", marker, content)
		}
	}
	for _, line := range []string{
		"INDEX_URL = https://old.example/simple",
		"extra-index-url =",
		"  https://one.example/simple",
		"  https://two.example/simple",
		"find_links: ./wheelhouse",
		"no_index = true",
	} {
		if !bytes.Contains(content, []byte(dmgPipDisabledPrefix+line)) {
			t.Errorf("conflict block line %q was not reversibly disabled:\n%s", line, content)
		}
	}
	if !bytes.Contains(content, []byte("[global]\n"+dmgPipBegin+"\n"+pipExpected+"\n"+dmgPipEnd)) {
		t.Errorf("managed block was not placed inside existing [global]:\n%s", content)
	}
	if converged, err := w.Converged(pipExpected); err != nil || !converged {
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

func TestPipWriter_ClearManagedBlockWithoutOwnershipState(t *testing.T) {
	w, _, path := newPipTestWriter(t, []byte("[global]\ntimeout = 30\n"))
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatal(err)
	}

	if err := w.PrepareClear(AppliedTargetState{}, false); err != nil {
		t.Fatalf("PrepareClear without state: %v", err)
	}
	changed, err := w.Clear()
	if err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "[global]\ntimeout = 30\n"; string(got) != want {
		t.Fatalf("clear restored %q, want %q", got, want)
	}
}

func TestPipWriter_RepeatedClearWithoutOwnershipStateOrMarker(t *testing.T) {
	w, _, path := newPipTestWriter(t, nil)

	for i := range 2 {
		if err := w.PrepareClear(AppliedTargetState{}, false); err != nil {
			t.Fatalf("PrepareClear %d: %v", i+1, err)
		}
		changed, err := w.Clear()
		if err != nil || changed {
			t.Fatalf("Clear %d = %v, %v, want no-op", i+1, changed, err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clean clear created pip config: %v", err)
	}
}

func TestPipWriter_RetargetedSymlinkFailsClearClosed(t *testing.T) {
	f := newPipSymlinkTestWriter(t, true)
	if _, err := f.writer.Write(pipExpected); err != nil {
		t.Fatal(err)
	}
	nextState := AppliedTargetState{}
	if err := f.writer.CompleteState(f.state, true, &nextState); err == nil {
		t.Fatal("retargeted symlink enforcement replaced the recorded target")
	}
	if err := f.writer.RestoreSnapshot(); err != nil {
		t.Fatalf("rollback retargeted enforcement: %v", err)
	}

	if err := f.writer.PrepareClear(f.state, true); err == nil {
		t.Fatal("retargeted symlink clear succeeded")
	}
	if afterB, err := os.ReadFile(f.targetB); err != nil || !bytes.Equal(afterB, f.beforeB) {
		t.Fatalf("target B changed: %q, %v", afterB, err)
	}
	if afterA, err := os.ReadFile(f.targetA); err != nil || !bytes.Contains(afterA, []byte(dmgPipBegin)) {
		t.Fatalf("target A lost managed block: %q, %v", afterA, err)
	}
}

func TestPipWriter_SameHashRetargetFailsBeforeConvergence(t *testing.T) {
	withTempCache(t)
	f := newPipSymlinkTestWriter(t, true)
	if err := os.WriteFile(f.targetB, f.beforeA, 0o600); err != nil {
		t.Fatal(err)
	}
	f.beforeB = append([]byte(nil), f.beforeA...)
	f.state.AppliedHash = "sha256:H"
	f.state.WrittenSettings = map[string]string{pypiPipOwnershipKey: pipExpected}
	if err := WriteAppliedState(CategoryPackageConfig, PyPIPipOwnershipTarget, f.state); err != nil {
		t.Fatal(err)
	}
	component := &pypiComponent{
		name:            "pip",
		ownershipTarget: PyPIPipOwnershipTarget,
		ownershipKey:    pypiPipOwnershipKey,
		writer:          f.writer,
		expected:        pipExpected,
		converged:       f.writer.Converged,
		restoreSnapshot: f.writer.RestoreSnapshot,
		completeState:   f.writer.CompleteState,
		prepareWrite:    f.writer.PrepareWrite,
		prepareClear:    f.writer.PrepareClear,
	}
	coordinator := &PyPICoordinator{CustomerID: "customer", DeviceID: "device", Platform: "linux"}
	effective := coordinatorPolicy(`["pip"]`, f.state.AppliedHash, enforcementDMG)

	if err := coordinator.childReconciler(effective, component, &coordinatorReporter{}).Reconcile(context.Background()); err == nil {
		t.Fatal("same-hash enforcement after symlink retarget succeeded")
	}
	if afterA, err := os.ReadFile(f.targetA); err != nil || !bytes.Equal(afterA, f.beforeA) {
		t.Fatalf("target A changed: %q, %v", afterA, err)
	}
	if afterB, err := os.ReadFile(f.targetB); err != nil || !bytes.Equal(afterB, f.beforeB) {
		t.Fatalf("target B changed: %q, %v", afterB, err)
	}
	state, ok := ReadAppliedState(CategoryPackageConfig, PyPIPipOwnershipTarget)
	if !ok || !reflect.DeepEqual(state, f.state) {
		t.Fatalf("state = %+v, %v, want retained pinned state", state, ok)
	}
}

func TestPipWriter_LegacyStateRetargetFailsBeforeMutation(t *testing.T) {
	tests := []struct {
		name      string
		effective EffectivePolicy
	}{
		{"clear", EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true, Enforcement: enforcementDMG}},
		{"enforce", coordinatorPolicy(`["pip"]`, "sha256:new", enforcementDMG)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withTempCache(t)
			f := newPipSymlinkTestWriter(t, true)
			legacy := AppliedTargetState{
				AppliedHash:     "sha256:legacy",
				WrittenSettings: map[string]string{pypiPipOwnershipKey: pipExpected},
			}
			if err := WriteAppliedState(CategoryPackageConfig, PyPIPipOwnershipTarget, legacy); err != nil {
				t.Fatal(err)
			}
			component := &pypiComponent{
				name:            "pip",
				ownershipTarget: PyPIPipOwnershipTarget,
				ownershipKey:    pypiPipOwnershipKey,
				writer:          f.writer,
				expected:        pipExpected,
				converged:       f.writer.Converged,
				restoreSnapshot: f.writer.RestoreSnapshot,
				completeState:   f.writer.CompleteState,
				prepareWrite:    f.writer.PrepareWrite,
				prepareClear:    f.writer.PrepareClear,
			}
			coordinator := &PyPICoordinator{CustomerID: "customer", DeviceID: "device", Platform: "linux"}

			if err := coordinator.childReconciler(tc.effective, component, &coordinatorReporter{}).Reconcile(context.Background()); err == nil {
				t.Fatalf("legacy %s after symlink retarget succeeded", tc.name)
			}
			if afterA, err := os.ReadFile(f.targetA); err != nil || !bytes.Equal(afterA, f.beforeA) {
				t.Fatalf("target A changed: %q, %v", afterA, err)
			}
			if afterB, err := os.ReadFile(f.targetB); err != nil || !bytes.Equal(afterB, f.beforeB) {
				t.Fatalf("target B changed: %q, %v", afterB, err)
			}
			state, ok := ReadAppliedState(CategoryPackageConfig, PyPIPipOwnershipTarget)
			if !ok || state.AppliedHash != legacy.AppliedHash || len(state.ResolvedPaths) != 0 {
				t.Fatalf("legacy state = %+v, %v, want retained without resolved paths", state, ok)
			}
		})
	}
}

func TestPipWriter_LegacyStateUnchangedSymlinkClears(t *testing.T) {
	withTempCache(t)
	f := newPipSymlinkTestWriter(t, false)
	legacy := AppliedTargetState{
		AppliedHash:     "sha256:legacy",
		WrittenSettings: map[string]string{pypiPipOwnershipKey: pipExpected},
	}
	if err := WriteAppliedState(CategoryPackageConfig, PyPIPipOwnershipTarget, legacy); err != nil {
		t.Fatal(err)
	}
	component := &pypiComponent{
		name:            "pip",
		ownershipTarget: PyPIPipOwnershipTarget,
		ownershipKey:    pypiPipOwnershipKey,
		writer:          f.writer,
		expected:        pipExpected,
		converged:       f.writer.Converged,
		restoreSnapshot: f.writer.RestoreSnapshot,
		completeState:   f.writer.CompleteState,
		prepareWrite:    f.writer.PrepareWrite,
		prepareClear:    f.writer.PrepareClear,
	}
	coordinator := &PyPICoordinator{CustomerID: "customer", DeviceID: "device", Platform: "linux"}
	effective := EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true, Enforcement: enforcementDMG}

	if err := coordinator.childReconciler(effective, component, &coordinatorReporter{}).Reconcile(context.Background()); err != nil {
		t.Fatalf("clear unchanged legacy symlink: %v", err)
	}
	if afterA, err := os.ReadFile(f.targetA); err != nil || len(afterA) != 0 {
		t.Fatalf("target A = %q, %v, want restored empty file", afterA, err)
	}
	if afterB, err := os.ReadFile(f.targetB); err != nil || !bytes.Equal(afterB, f.beforeB) {
		t.Fatalf("target B changed: %q, %v", afterB, err)
	}
	if state, ok := ReadAppliedState(CategoryPackageConfig, PyPIPipOwnershipTarget); ok {
		t.Fatalf("state retained after clear: %+v", state)
	}
}

func TestPipWriter_AppendsGlobalAndPreservesBOMCRLF(t *testing.T) {
	initial := []byte("\ufeff# comment\r\n[download]\r\ntimeout = 15\r\n")
	w, _, path := newPipTestWriter(t, initial)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte("\ufeff")) {
		t.Fatal("UTF-8 BOM was not preserved")
	}
	withoutCRLF := bytes.ReplaceAll(got, []byte("\r\n"), nil)
	if bytes.Contains(withoutCRLF, []byte{'\n'}) {
		t.Fatalf("managed output mixed newline styles: %q", got)
	}
	if !bytes.Contains(got, []byte("\r\n"+dmgPipBegin+"\r\n"+pipAppendMetadata)) || !bytes.Contains(got, []byte("\r\n[global]\r\n"+strings.ReplaceAll(pipExpected, "\n", "\r\n"))) {
		t.Fatalf("missing appended [global] managed block: %q", got)
	}
	before := append([]byte(nil), got...)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("idempotent Write: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("idempotent write changed bytes:\nbefore=%q\nafter=%q", before, after)
	}
}

func TestPipWriter_CommentedGlobalHeaderRoundTrips(t *testing.T) {
	initial := []byte("[global] # user comment\ncache-dir = /tmp/cache\n")
	w, _, path := newPipTestWriter(t, initial)
	if _, err := w.Write(pipExpected); err != nil {
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

func TestPipWriter_GlobalHeaderWithoutFinalNewlineRestoresExactly(t *testing.T) {
	initial := []byte("[global]")
	w, _, path := newPipTestWriter(t, initial)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("idempotent Write: %v", err)
	}
	if changed, err := w.Clear(); err != nil || !changed {
		t.Fatalf("Clear = %v, %v, want changed", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatalf("Clear restored %q, want %q", got, initial)
	}
}

func TestPipWriter_RefusesMalformedAndDuplicateINI(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"option before section", []byte("index-url = https://old.example/simple\n")},
		{"duplicate section", []byte("[global]\ntimeout=1\n[GLOBAL]\ntimeout=2\n")},
		{"normalized duplicate option", []byte("[global]\nindex_url=https://one.example\nINDEX-URL=https://two.example\n")},
		{"orphan continuation", []byte("[global]\n  continuation\n")},
		{"malformed section", []byte("[global\ntimeout=1\n")},
		{"lone carriage return", []byte("[global]\rindex-url=x\n")},
		{"invalid UTF-8", []byte{0xff, 0xfe}},
		{"duplicate begin marker", []byte("[global]\n" + dmgPipBegin + "\n" + dmgPipBegin + "\n" + pipExpected + "\n" + dmgPipEnd + "\n")},
		{"MDM marker conflict", []byte("[global]\n" + mdmPipBegin + "\n" + pipExpected + "\n" + mdmPipEnd + "\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, path := newPipTestWriter(t, tc.body)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(pipExpected); err == nil {
				t.Fatal("Write error = nil, want fail-closed refusal")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("refused write changed file: before=%q after=%q", before, after)
			}
		})
	}
}

func TestPipWriter_DriftRepairAndMultipleUserFiles(t *testing.T) {
	homeDir := t.TempDir()
	current := filepath.Join(homeDir, ".config", "pip", "pip.conf")
	legacy := filepath.Join(homeDir, ".pip", "pip.conf")
	for path, body := range map[string]string{
		current: "[global]\ntimeout=30\n",
		legacy:  "[install]\nextra-index-url=https://legacy.example/simple\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("")
	mock.SetHomeDir(homeDir)
	mock.SetFile(current, nil)
	mock.SetFile(legacy, nil)
	w, err := NewPipWriter(context.Background(), mock, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{current, legacy} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(content, []byte(dmgPipBegin)) {
			t.Errorf("%s was not managed:\n%s", path, content)
		}
	}
	content, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, []byte("extra-index-url=https://drift.example/simple\n")...)
	if err := os.WriteFile(current, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if converged, err := w.Converged(pipExpected); err != nil || converged {
		t.Fatalf("Converged after drift = %v, %v, want false", converged, err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("drift repair: %v", err)
	}
	if converged, err := w.Converged(pipExpected); err != nil || !converged {
		t.Fatalf("Converged after repair = %v, %v, want true", converged, err)
	}
}

func TestPipWriter_ActualFullStateDriftReportsAndSettles(t *testing.T) {
	withTempCache(t)
	w, _, path := newPipTestWriter(t, []byte("[global]\nfind-links = https://mirror.example/simple\n"))
	reporter := &coordinatorReporter{}
	effective := coordinatorPolicy(`["pip"]`, "sha256:H", enforcementDMG)
	component := &pypiComponent{
		name:            "pip",
		ownershipTarget: PyPIPipOwnershipTarget,
		ownershipKey:    pypiPipOwnershipKey,
		writer:          w,
		expected:        pipExpected,
		converged:       w.Converged,
		fullStateDrift:  true,
		restoreSnapshot: w.RestoreSnapshot,
		completeState:   w.CompleteState,
		prepareClear:    w.PrepareClear,
	}
	coordinator := &PyPICoordinator{CustomerID: "customer", DeviceID: "device", Platform: "linux"}
	reconciler := coordinator.childReconciler(effective, component, reporter)
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	drifted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	drifted = bytes.Replace(drifted, []byte(dmgPipDisabledPrefix+"find-links = https://mirror.example/simple"), []byte("find-links = https://mirror.example/simple"), 1)
	if err := os.WriteFile(path, drifted, 0o600); err != nil {
		t.Fatal(err)
	}
	reporter.reports = nil
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reporter.reports) != 1 || reporter.reports[0].State != StateDriftDetected {
		t.Fatalf("drift reports = %+v", reporter.reports)
	}
	repaired, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(repaired, []byte(dmgPipDisabledPrefix+"find-links = https://mirror.example/simple")) {
		t.Fatalf("effective pip drift was not disabled:\n%s", repaired)
	}
	backupsBefore, err := filepath.Glob(path + pipBackupPrefix + "*.bak")
	if err != nil {
		t.Fatal(err)
	}

	reporter.reports = nil
	if err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	backupsAfter, err := filepath.Glob(path + pipBackupPrefix + "*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(reporter.reports) != 1 || reporter.reports[0].State != StateCompliant || len(backupsAfter) != len(backupsBefore) {
		t.Fatalf("settled cycle reports=%+v backups=%d->%d, want compliant no-write", reporter.reports, len(backupsBefore), len(backupsAfter))
	}
}

func TestPipWriter_MultiFileFailureRollsBackEarlierFiles(t *testing.T) {
	homeDir := t.TempDir()
	current := filepath.Join(homeDir, ".config", "pip", "pip.conf")
	legacy := filepath.Join(homeDir, ".pip", "pip.conf")
	initial := map[string][]byte{
		current: []byte("[global]\ntimeout=30\n"),
		legacy:  []byte("[global]\nextra-index-url=https://legacy.example/simple\n"),
	}
	for path, body := range initial {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := newSecureTestHome(t, homeDir)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetUsername("")
	mock.SetHomeDir(homeDir)
	mock.SetFile(current, nil)
	mock.SetFile(legacy, nil)
	w, err := NewPipWriter(context.Background(), mock, home, netrcTestPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(legacy); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err == nil {
		t.Fatal("Write error = nil, want second-file refusal")
	}
	got, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	if want := initial[current]; !bytes.Equal(got, want) {
		t.Fatalf("current file after rollback = %q, want %q", got, want)
	}
}

func TestPipWriter_SecurityAndMDMMarker(t *testing.T) {
	w, _, path := newPipTestWriter(t, []byte("[global]\ntimeout=30\n"))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatal(err)
	}
	if enforcePOSIXMetadata {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
		}
	}
	if has, err := w.HasMDMMarker(); err != nil || has {
		t.Fatalf("HasMDMMarker = %v, %v, want false", has, err)
	}
	if err := os.WriteFile(path, []byte("[global]\n"+mdmPipBegin+"\n"+pipExpected+"\n"+mdmPipEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if has, err := w.HasMDMMarker(); err != nil || !has {
		t.Fatalf("HasMDMMarker = %v, %v, want true", has, err)
	}
}

func TestPipObservation_UserEnvironmentFailureIsUnknown(t *testing.T) {
	w, mock, _ := newPipTestWriter(t, nil)
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.exec = executor.NewUserAwareExecutor(&failedUserEnvironmentExecutor{Executor: mock}, "alice")
	got, err := w.Observation(context.Background(), pipExpected)
	if err == nil {
		t.Fatal("Observation error = nil, want environment inspection failure")
	}
	if got.EffectiveStatus != "unknown" || got.OverrideSource != "unknown" {
		t.Fatalf("Observation = %+v, want unknown environment", got)
	}
}

func TestPipObservedStaticConvergedAcceptsOnlyCanonicalMDMCreatedBlocks(t *testing.T) {
	created := "# [stepsecurity-pypi-pip-mdm] created=true"
	tests := []struct {
		name string
		body []string
		want bool
	}{
		{"settings only", strings.Split(pipExpected, "\n"), true},
		{"created", append([]string{created}, strings.Split(pipExpected, "\n")...), false},
		{"global", append([]string{"[global]"}, strings.Split(pipExpected, "\n")...), true},
		{"created global", append([]string{created, "[global]"}, strings.Split(pipExpected, "\n")...), true},
		{"reordered", append([]string{"[global]", created}, strings.Split(pipExpected, "\n")...), false},
		{"duplicate", append([]string{created, created}, strings.Split(pipExpected, "\n")...), false},
		{"unknown", append([]string{"# unknown"}, strings.Split(pipExpected, "\n")...), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, path := newPipTestWriter(t, nil)
			content := strings.Join(append(append([]string{mdmPipBegin}, tc.body...), mdmPipEnd, ""), "\n")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, managed := range w.files {
				if managed.current {
					hardenSecureTestFile(t, managed.file)
				}
			}
			got, err := w.observedStaticConverged(pipExpected)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("observedStaticConverged = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPipObservation_AcceptsExactGeneratedMDMArtifacts(t *testing.T) {
	created := "# BEGIN StepSecurity Package Configuration pip -- managed by mdm\n" +
		"# [stepsecurity-pypi-pip-mdm] created=true\n" +
		"[global]\n" + pipExpected + "\n" +
		"# END StepSecurity Package Configuration pip\n"
	existingGlobal := "[global]\n" +
		"# BEGIN StepSecurity Package Configuration pip -- managed by mdm\n" + pipExpected + "\n" +
		"# END StepSecurity Package Configuration pip\n"
	existingWithoutGlobal := "[install]\nuser = true\n" +
		"# BEGIN StepSecurity Package Configuration pip -- managed by mdm\n" +
		"[global]\n" + pipExpected + "\n" +
		"# END StepSecurity Package Configuration pip\n"
	tests := []struct {
		name string
		body string
	}{
		{"macOS created primary pip.conf", created},
		{"Linux created primary pip.conf", created},
		{"Windows created primary pip.ini", strings.ReplaceAll(created, "\n", "\r\n")},
		{"POSIX existing alternate with global", existingGlobal},
		{"Windows existing alternate without global", strings.ReplaceAll(existingWithoutGlobal, "\n", "\r\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, _ := newPipTestWriter(t, []byte(tc.body))
			for _, managed := range w.files {
				if managed.current {
					hardenSecureTestFile(t, managed.file)
				}
			}
			if owned, err := w.MDMOwned(); err != nil || !owned {
				t.Fatalf("MDMOwned = %v, %v, want true", owned, err)
			}
			observation, err := w.Observation(context.Background(), pipExpected)
			if err != nil || observation.ConfigStatus != "match" {
				t.Fatalf("Observation = %+v, %v, want generated artifact match", observation, err)
			}
		})
	}
}

func TestPipObservation_VersionBoundaryAndAbsent(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		wantEffective string
	}{
		{"pip absent", "", "not_installed"},
		{"pip below 20.2", "19.3.1", "unknown"},
		{"pip 20.2", "20.2", "match"},
		{"current pip", "25.2", "match"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, mock, _ := newPipTestWriter(t, nil)
			if _, err := w.Write(pipExpected); err != nil {
				t.Fatal(err)
			}
			if tc.version != "" {
				mock.SetPath("pip", "/opt/bin/pip")
				mock.SetCommand("pip "+tc.version+" from /opt/pip\n", "", 0, "pip", "--version")
				mock.SetCommand("user:\n", "", 0, "pip", "config", "debug")
				mock.SetCommand("global.index-url='https://registry.stepsecurity.io/python/simple'\nglobal.no-index='false'\n", "", 0, "pip", "config", "list", "-v")
				w.invocations = [][]string{{"pip"}}
			}
			got, err := w.Observation(context.Background(), pipExpected)
			if err != nil {
				t.Fatalf("Observation: %v", err)
			}
			if got.ConfigStatus != "match" || got.EffectiveStatus != tc.wantEffective || got.OverrideSource != "none" {
				t.Fatalf("Observation = %+v, want config match, effective %s, no override", got, tc.wantEffective)
			}
		})
	}
}

func TestPipObservation_OverridesAndUnknownOutput(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*executor.Mock)
		listOutput    string
		wantEffective string
		wantOverride  string
	}{
		{"environment", func(m *executor.Mock) { m.SetEnv("PIP_INDEX_URL", "https://user:SECRET@evil.example/simple") }, "", "mismatch", "environment"},
		{"explicit config", func(m *executor.Mock) { m.SetEnv("PIP_CONFIG_FILE", "/tmp/secret-path") }, "", "mismatch", "explicit_config"},
		{"virtualenv", func(m *executor.Mock) { m.SetEnv("VIRTUAL_ENV", "/tmp/venv") }, "", "mismatch", "virtualenv"},
		{"system config", func(*executor.Mock) {}, "global.index-url='https://evil.example/simple' from /etc/pip.conf\nglobal.no-index='false' from /etc/pip.conf\n", "mismatch", "system_config"},
		{"command section", func(*executor.Mock) {}, "install.index-url='https://evil.example/simple'\nglobal.index-url='https://registry.stepsecurity.io/python/simple'\nglobal.no-index='false'\n", "mismatch", "command_section"},
		{"unknown output", func(*executor.Mock) {}, "changed format without equals\n", "unknown", "unknown"},
		{"userinfo mismatch", func(*executor.Mock) {}, "global.index-url='https://user:SECRET@evil.example/simple'\nglobal.no-index='false'\n", "mismatch", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, mock, _ := newPipTestWriter(t, nil)
			if _, err := w.Write(pipExpected); err != nil {
				t.Fatal(err)
			}
			mock.SetPath("pip", "/opt/bin/pip")
			mock.SetCommand("pip 25.2 from /opt/pip\n", "", 0, "pip", "--version")
			mock.SetCommand("user:\n", "", 0, "pip", "config", "debug")
			mock.SetCommand(tc.listOutput, "", 0, "pip", "config", "list", "-v")
			tc.configure(mock)
			w.invocations = [][]string{{"pip"}}

			got, err := w.Observation(context.Background(), pipExpected)
			if err != nil {
				t.Fatalf("Observation: %v", err)
			}
			if got.EffectiveStatus != tc.wantEffective || got.OverrideSource != tc.wantOverride {
				t.Fatalf("Observation = %+v, want effective=%s override=%s", got, tc.wantEffective, tc.wantOverride)
			}
			if strings.Contains(got.RegistryURL, "SECRET") || (err != nil && strings.Contains(err.Error(), "SECRET")) {
				t.Fatalf("Observation leaked URL userinfo: %+v, %v", got, err)
			}
			if tc.name == "userinfo mismatch" && got.RegistryURL != "" {
				t.Fatalf("userinfo registry URL = %q, want empty", got.RegistryURL)
			}
		})
	}
}

func TestPipWriter_MDMOwnershipRejectsOtherLanes(t *testing.T) {
	tests := []struct {
		name    string
		initial string
	}{
		{"unmarked", "[global]\n" + pipExpected + "\n"},
		{"DMG marker", "[global]\n" + dmgPipBegin + "\n" + pipExpected + "\n" + dmgPipEnd + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, _, _ := newPipTestWriter(t, []byte(tc.initial))
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

func TestPipObservation_MDMManagedStaticConfiguration(t *testing.T) {
	initial := []byte("[global]\n" + mdmPipBegin + "\n" + pipExpected + "\n" + mdmPipEnd + "\n")
	w, _, _ := newPipTestWriter(t, initial)
	for _, managed := range w.files {
		if managed.current {
			hardenSecureTestFile(t, managed.file)
		}
	}
	if owned, err := w.MDMOwned(); err != nil || !owned {
		t.Fatalf("MDMOwned = %v, %v, want true", owned, err)
	}
	got, err := w.Observation(context.Background(), pipExpected)
	if err != nil {
		t.Fatalf("Observation: %v", err)
	}
	if got.ConfigStatus != "match" || got.EffectiveStatus != "not_installed" || got.RegistryURL != "https://registry.stepsecurity.io/python/simple" {
		t.Fatalf("Observation = %+v, want matching MDM static config", got)
	}
}

func TestPipWriter_ExpectedValidationAndSnapshotRestore(t *testing.T) {
	w, _, path := newPipTestWriter(t, []byte("[global]\ntimeout=30\n"))
	if _, err := w.Write("index-url = https://evil.example/simple\nno-index = false"); err == nil {
		t.Fatal("Write accepted settings not rendered from policy")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pipExpected); err != nil {
		t.Fatal(err)
	}
	if err := w.RestoreSnapshot(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("RestoreSnapshot = %q, want %q", after, before)
	}
	if _, err := w.Write(pipExpected); err != nil && !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("Write after restore: %v", err)
	}
}
