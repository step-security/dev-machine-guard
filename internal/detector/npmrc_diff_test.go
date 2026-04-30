package detector

import (
	"context"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// fakeAudit is a small builder for a fresh audit used across diff tests.
// One user .npmrc with three entries; the env var slice is empty unless
// the test customizes it. Every test starts from this and tweaks for
// scenario-specific changes.
func fakeAudit() *model.NPMRCAudit {
	return &model.NPMRCAudit{
		Available: true,
		Files: []model.NPMRCFile{
			{
				Path:        "/u/.npmrc",
				Scope:       "user",
				Exists:      true,
				Readable:    true,
				SHA256:      "sha-A",
				SizeBytes:   100,
				Mode:        "0600",
				OwnerName:   "alice",
				GroupName:   "alice",
				ModTimeUnix: 1_700_000_000,
				Entries: []model.NPMRCEntry{
					{Key: "registry", DisplayValue: "https://npm.org/", ValueSHA256: "v-reg-A"},
					{Key: "//npm.org/:_authToken", DisplayValue: "***1234", ValueSHA256: "v-auth-A", IsAuth: true},
					{Key: "ca", DisplayValue: "ca-data", ValueSHA256: "v-ca-A", IsArray: true},
				},
			},
		},
		Env: []model.NPMRCEnvVar{
			{Name: "NPM_TOKEN", Set: false},
			{Name: "NODE_OPTIONS", Set: false},
		},
	}
}

// snapshotOf converts the fake audit into the on-disk snapshot form so
// diff tests can pretend a previous scan happened.
func snapshotOf(a *model.NPMRCAudit, takenAt int64) *model.NPMRCSnapshot {
	s := BuildNPMRCSnapshot(a, takenAt, "host")
	return &s
}

func TestDiffNPMRC_FirstRun(t *testing.T) {
	cur := fakeAudit()
	d := DiffNPMRC(nil, cur, 1_700_000_500)
	if d == nil {
		t.Fatal("nil diff")
	}
	if !d.FirstRun {
		t.Error("FirstRun should be true when prev is nil")
	}
	if d.HasChanges() {
		t.Error("first run should have no listed changes")
	}
}

func TestDiffNPMRC_NoChange(t *testing.T) {
	cur := fakeAudit()
	prev := snapshotOf(cur, 1_700_000_000)
	d := DiffNPMRC(prev, cur, 1_700_000_500)
	if d.FirstRun {
		t.Error("not a first run")
	}
	if d.HasChanges() {
		t.Errorf("expected no changes, got %+v", d)
	}
}

func TestDiffNPMRC_FileAdded(t *testing.T) {
	cur := fakeAudit()
	// prev had no files at all.
	prev := &model.NPMRCSnapshot{SnapshotVersion: CurrentNPMRCSnapshotVersion, TakenAt: 1_700_000_000}
	d := DiffNPMRC(prev, cur, 1_700_000_500)
	if len(d.AddedFiles) != 1 || d.AddedFiles[0].Path != "/u/.npmrc" {
		t.Errorf("expected /u/.npmrc to be added, got %+v", d.AddedFiles)
	}
}

func TestDiffNPMRC_FileRemoved(t *testing.T) {
	prev := snapshotOf(fakeAudit(), 1_700_000_000)
	// current has no files (e.g., user wiped their config).
	cur := &model.NPMRCAudit{Files: []model.NPMRCFile{}, Env: fakeAudit().Env}
	d := DiffNPMRC(prev, cur, 1_700_000_500)
	if len(d.RemovedFiles) != 1 || d.RemovedFiles[0].Path != "/u/.npmrc" {
		t.Errorf("expected /u/.npmrc to be removed, got %+v", d.RemovedFiles)
	}
}

func TestDiffNPMRC_OwnerAndModeChange(t *testing.T) {
	prev := snapshotOf(fakeAudit(), 1_700_000_000)

	cur := fakeAudit()
	cur.Files[0].OwnerName = "root"
	cur.Files[0].Mode = "0666"

	d := DiffNPMRC(prev, cur, 1_700_000_500)
	if len(d.ModifiedFiles) != 1 {
		t.Fatalf("expected 1 modified file, got %d", len(d.ModifiedFiles))
	}
	mod := d.ModifiedFiles[0]
	if mod.OwnerChanged == nil || mod.OwnerChanged.From != "alice" || mod.OwnerChanged.To != "root" {
		t.Errorf("owner change wrong: %+v", mod.OwnerChanged)
	}
	if mod.ModeChanged == nil || mod.ModeChanged.From != "0600" || mod.ModeChanged.To != "0666" {
		t.Errorf("mode change wrong: %+v", mod.ModeChanged)
	}
}

func TestDiffNPMRC_EntryRotated(t *testing.T) {
	prev := snapshotOf(fakeAudit(), 1_700_000_000)

	cur := fakeAudit()
	// auth value rotated; sha changes.
	cur.Files[0].Entries[1].ValueSHA256 = "v-auth-B"
	cur.Files[0].SHA256 = "sha-B" // file content also differs in reality

	d := DiffNPMRC(prev, cur, 1_700_000_500)
	if len(d.ModifiedFiles) != 1 {
		t.Fatalf("expected 1 modified, got %d: %+v", len(d.ModifiedFiles), d)
	}
	mod := d.ModifiedFiles[0]

	// Should have a value-changed for the auth key.
	var foundAuth bool
	for _, ce := range mod.ChangedEntries {
		if ce.Key == "//npm.org/:_authToken" {
			foundAuth = true
			if !ce.IsAuth {
				t.Errorf("expected IsAuth on auth diff")
			}
			if ce.PreviousSHA256 != "v-auth-A" || ce.CurrentSHA256 != "v-auth-B" {
				t.Errorf("sha pair wrong: %+v", ce)
			}
		}
	}
	if !foundAuth {
		t.Errorf("auth-token rotation not detected: %+v", mod.ChangedEntries)
	}
	// Should NOT show the rotated entry as added or removed (we suppress
	// double-counting).
	for _, e := range mod.AddedEntries {
		if e.Key == "//npm.org/:_authToken" {
			t.Errorf("rotated auth key should not appear in AddedEntries: %+v", e)
		}
	}
	for _, e := range mod.RemovedEntries {
		if e.Key == "//npm.org/:_authToken" {
			t.Errorf("rotated auth key should not appear in RemovedEntries: %+v", e)
		}
	}
	// Auth diff sorts to the top.
	if mod.ChangedEntries[0].Key != "//npm.org/:_authToken" {
		t.Errorf("auth change should be first: %+v", mod.ChangedEntries)
	}
}

func TestDiffNPMRC_EntryAdded(t *testing.T) {
	prev := snapshotOf(fakeAudit(), 1_700_000_000)

	cur := fakeAudit()
	cur.Files[0].SHA256 = "sha-B"
	cur.Files[0].Entries = append(cur.Files[0].Entries, model.NPMRCEntry{
		Key: "ignore-scripts", DisplayValue: "true", ValueSHA256: "v-ig",
	})

	d := DiffNPMRC(prev, cur, 1_700_000_500)
	if len(d.ModifiedFiles) != 1 {
		t.Fatalf("expected 1 modified, got %d", len(d.ModifiedFiles))
	}
	mod := d.ModifiedFiles[0]
	if len(mod.AddedEntries) != 1 || mod.AddedEntries[0].Key != "ignore-scripts" {
		t.Errorf("expected ignore-scripts added, got %+v", mod.AddedEntries)
	}
}

func TestDiffNPMRC_EnvAppearedAndRotated(t *testing.T) {
	prev := snapshotOf(fakeAudit(), 1_700_000_000)

	cur := fakeAudit()
	// NPM_TOKEN newly set.
	cur.Env[0].Set = true
	cur.Env[0].ValueSHA256 = "tok-1"
	// NODE_OPTIONS unchanged.

	d := DiffNPMRC(prev, cur, 1_700_000_500)
	if len(d.EnvChanges) != 1 {
		t.Fatalf("expected 1 env change, got %d: %+v", len(d.EnvChanges), d.EnvChanges)
	}
	if d.EnvChanges[0].Type != "appeared" || d.EnvChanges[0].Name != "NPM_TOKEN" {
		t.Errorf("wrong env change: %+v", d.EnvChanges[0])
	}

	// Now rotate it.
	prev2 := snapshotOf(cur, 1_700_000_500)
	cur2 := fakeAudit()
	cur2.Env[0].Set = true
	cur2.Env[0].ValueSHA256 = "tok-2"
	d2 := DiffNPMRC(prev2, cur2, 1_700_000_900)
	if len(d2.EnvChanges) != 1 || d2.EnvChanges[0].Type != "value_changed" {
		t.Fatalf("expected value_changed, got %+v", d2.EnvChanges)
	}
}

func TestSaveLoadNPMRCSnapshot_RoundTrip(t *testing.T) {
	// Use HOME-redirect via t.TempDir + os.Setenv so we don't write to the
	// real ~/.stepsecurity in CI.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	s := snapshotOf(fakeAudit(), 1_700_000_000)
	if err := SaveNPMRCSnapshot(s); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadNPMRCSnapshot()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded snapshot is nil")
	}
	if loaded.SnapshotVersion != CurrentNPMRCSnapshotVersion {
		t.Errorf("version: got %d", loaded.SnapshotVersion)
	}
	if len(loaded.Files) != 1 || loaded.Files[0].Path != "/u/.npmrc" {
		t.Errorf("file roundtrip failed: %+v", loaded.Files)
	}
}

func TestLoadNPMRCSnapshot_MissingReturnsNilNil(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	got, err := LoadNPMRCSnapshot()
	if err != nil {
		t.Errorf("missing snapshot should not return an error, got %v", err)
	}
	if got != nil {
		t.Errorf("missing snapshot should return nil, got %+v", got)
	}
}

func TestLoadNPMRCSnapshot_VersionMismatch(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Write a snapshot with a future version.
	bad := &model.NPMRCSnapshot{SnapshotVersion: 999, TakenAt: 1}
	if err := SaveNPMRCSnapshot(bad); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	got, err := LoadNPMRCSnapshot()
	if got != nil {
		t.Errorf("expected nil snapshot for version mismatch, got %+v", got)
	}
	if err == nil || !strings.Contains(err.Error(), "version mismatch") {
		t.Errorf("expected version-mismatch error, got %v", err)
	}
}

func TestEnrichAttribution_OwnerAndMode(t *testing.T) {
	mock := executor.NewMock()
	// Stub `ps` so attribution can also append a process snapshot.
	mock.SetCommand(`  PID USER     COMM     ARGS
  101 alice    sh       sh -c npm install
  202 alice    npm      npm install evil-pkg
  303 alice    cat      cat /home/alice/.npmrc
`, "", 0, "ps", "-eo", "pid,user,comm,args")

	diff := &model.NPMRCDiff{
		ModifiedFiles: []model.NPMRCFileModification{
			{
				Path:         "/u/.npmrc",
				OwnerChanged: &model.NPMRCStringChange{From: "alice", To: "root"},
				ModeChanged:  &model.NPMRCStringChange{From: "0600", To: "0666"},
				ContentChanged: true,
			},
		},
	}
	EnrichAttribution(context.Background(), mock, diff, 1_700_000_500)

	mod := diff.ModifiedFiles[0]
	if len(mod.AttributionNotes) == 0 {
		t.Fatal("expected notes")
	}
	combined := strings.Join(mod.AttributionNotes, " ")
	if !strings.Contains(combined, "owner changed") {
		t.Errorf("missing owner-change note: %q", combined)
	}
	if !strings.Contains(combined, "permissions relaxed") {
		t.Errorf("expected permissions-relaxed note: %q", combined)
	}
	// `cat` is in the suspect list (we match "cat" via "sh"-pattern? no — check)
	// `sh` and `npm` are explicit. "cat" is NOT — that's correct, we only
	// flag plausible-writers.
	if len(mod.Suspects) == 0 {
		t.Fatal("expected at least one suspect (sh or npm)")
	}
	// At least one suspect should mention npm or sh.
	var sawWriter bool
	for _, s := range mod.Suspects {
		if strings.Contains(strings.ToLower(s.Cmd), "npm") || strings.Contains(strings.ToLower(s.Cmd), "sh ") {
			sawWriter = true
		}
	}
	if !sawWriter {
		t.Errorf("expected npm or sh in suspects, got %+v", mod.Suspects)
	}
}

func TestIsModeRelaxed(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{"0600", "0644", true},  // group/world read added
		{"0600", "0666", true},  // group/world write added
		{"0644", "0600", false}, // tightened
		{"0644", "0644", false}, // unchanged
		{"0700", "0755", true},  // group/world rx added
	}
	for _, c := range cases {
		got := isModeRelaxed(c.from, c.to)
		if got != c.want {
			t.Errorf("isModeRelaxed(%q→%q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}
