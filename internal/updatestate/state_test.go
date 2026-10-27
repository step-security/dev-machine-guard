package updatestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleState() *State {
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	return &State{
		Current:   "1.19.0",
		Previous:  "1.18.2",
		Probation: &Probation{Version: "1.19.0", Since: at, OK: 1, SmokeOK: true},
		Quarantine: map[string]Quarantine{
			"1.18.9": {Reason: "health_failed", At: at},
		},
		Updater:         Updater{Version: "1.18.2", ConsecutiveFailures: 1},
		SwitchDeferrals: 2,
		Dedupe:          map[string]time.Time{"update_check_failed:1.19.1": at},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := sampleState()
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, corrupt, err := Load(path)
	if err != nil || corrupt {
		t.Fatalf("Load: corrupt=%v err=%v", corrupt, err)
	}
	want.Schema = SchemaVersion
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}
	// Minimal state: optional fields empty, maps normalized to {}.
	if err := Save(path, &State{Current: "1.0.0"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, frag := range []string{`"schema": 1`, `"probation": null`, `"quarantine": {}`, `"dedupe": {}`} {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("saved state lacks %s:\n%s", frag, raw)
		}
	}
	SweepTemps(path)
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("leftover files after Save: %v", entries)
	}
}

func TestLoadMissing(t *testing.T) {
	st, corrupt, err := Load(filepath.Join(t.TempDir(), "state.json"))
	if st != nil || corrupt || err != nil {
		t.Fatalf("Load(missing) = %v, %v, %v", st, corrupt, err)
	}
}

func TestLoadCorrupt(t *testing.T) {
	cases := map[string]string{
		"empty":                ``,
		"garbage":              "\x00\xffnot json",
		"truncated":            `{"schema":1,"current":"1.2.3"`,
		"array":                `[]`,
		"null":                 `null`,
		"schema 0":             `{"current":"1.2.3"}`,
		"schema 2 bad current": `{"schema":2,"current":"x"}`,
		"no current":           `{"schema":1}`,
		"bad current":          `{"schema":1,"current":"..\\..\\evil"}`,
		"prerelease":           `{"schema":1,"current":"1.2.3-rc.1"}`,
		"bad previous":         `{"schema":1,"current":"1.2.3","previous":"x"}`,
		"bad probation":        `{"schema":1,"current":"1.2.3","probation":{"version":""}}`,
		"neg probation":        `{"schema":1,"current":"1.2.3","probation":{"version":"1.2.3","bad":-1}}`,
		"bad quarantine":       `{"schema":1,"current":"1.2.3","quarantine":{"../x":{}}}`,
		"bad updater":          `{"schema":1,"current":"1.2.3","updater":{"version":"v1"}}`,
		"neg deferrals":        `{"schema":1,"current":"1.2.3","switch_deferrals":-1}`,
		"bad time":             `{"schema":1,"current":"1.2.3","dedupe":{"k":"yesterday"}}`,
		"wrong type":           `{"schema":"1","current":"1.2.3"}`,
		"trailing garbage":     `{"schema":1,"current":"1.2.3"} x`,
		"oversize":             `{"schema":1,"current":"1.2.3","pad":"` + strings.Repeat("a", maxStateSize) + `"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			st, corrupt, err := Load(path)
			if st != nil || !corrupt || err != nil {
				t.Fatalf("Load = %+v, corrupt=%v, err=%v; want corrupt", st, corrupt, err)
			}
		})
	}
	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if st, corrupt, err := Load(path); st != nil || (!corrupt && err == nil) {
			t.Fatalf("Load(dir) = %v, %v, %v", st, corrupt, err)
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("symlink", func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "real.json")
			if err := Save(target, sampleState()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "state.json")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			if st, corrupt, err := Load(path); st != nil || !corrupt || err != nil {
				t.Fatalf("Load(symlink) = %v, %v, %v", st, corrupt, err)
			}
		})
	}
}

func TestLoadIgnoresUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	body := `{"schema":1,"current":"1.2.3","future_field":{"x":1},"probation":null}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	st, corrupt, err := Load(path)
	if err != nil || corrupt || st.Current != "1.2.3" {
		t.Fatalf("Load = %+v, %v, %v", st, corrupt, err)
	}
}

func TestSaveRefusesInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	for _, st := range []*State{{}, {Current: "1.2"}, {Current: "1.2.3", Previous: "x"}} {
		if err := Save(path, st); err == nil {
			t.Errorf("Save(%+v) succeeded", st)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid Save wrote a file")
	}
}

func stubCheckpoint(t *testing.T, fn func(string) error) {
	t.Helper()
	old := checkpoint
	checkpoint = fn
	t.Cleanup(func() { checkpoint = old })
}

func TestSaveCheckpointErrors(t *testing.T) {
	injected := errors.New("injected")
	var seen []string
	stubCheckpoint(t, func(name string) error {
		seen = append(seen, name)
		if name == os.Getenv("TEST_FAIL_AT") {
			return injected
		}
		return nil
	})
	path := filepath.Join(t.TempDir(), "state.json")
	old := &State{Current: "1.18.2"}
	if err := Save(path, old); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 {
		t.Fatalf("Save without prefix hit checkpoints %v", seen)
	}
	newer := &State{Current: "1.19.0", Previous: "1.18.2"}

	t.Setenv("TEST_FAIL_AT", "S6.state-temp")
	if err := SaveCheckpointed(path, newer, "S6"); !errors.Is(err, injected) {
		t.Fatalf("err at state-temp = %v", err)
	}
	if st, _, _ := Load(path); st.Current != "1.18.2" {
		t.Fatalf("state-temp failure changed state to %q", st.Current)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("temp file leaked: %v", entries)
	}

	t.Setenv("TEST_FAIL_AT", "rollback.state-renamed")
	if err := SaveCheckpointed(path, newer, "rollback"); !errors.Is(err, injected) {
		t.Fatalf("err at state-renamed = %v", err)
	}
	if st, _, _ := Load(path); st.Current != "1.19.0" {
		t.Fatalf("state-renamed: state is %q, want new", st.Current)
	}
	want := []string{"S6.state-temp", "rollback.state-temp", "rollback.state-renamed"}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("checkpoints %v, want %v", seen, want)
	}
}

func TestSweepTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, n := range []string{".state.json.tmp-123", ".state.json.tmp-abc", "state.json", "other.tmp-1", ".runs.json.tmp-1"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	SweepTemps(path)
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{".runs.json.tmp-1", "other.tmp-1", "state.json"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("after sweep %v, want %v", names, want)
	}
}

// R-F1-2: a newer schema-1 writer's extra keys (top level and nested)
// survive Load -> mutate -> Save by this version.
func TestUnknownFieldsSurviveSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	in := `{"schema":1,"current":"1.20.0","previous":"1.19.0","future_top":{"a":[1,2]},
	 "probation":{"version":"1.20.0","since":"2026-10-19T00:00:00Z","ok":0,"bad":1,"smoke_ok":true,"future_p":"x"},
	 "quarantine":{"1.18.0":{"reason":"inconclusive","at":"2026-10-19T00:00:00Z","until":"2026-10-26T00:00:00Z","future_q":7}},
	 "updater":{"version":"1.19.0","consecutive_failures":0,"future_u":true},
	 "outbox":[{"execution_id":"e1","update_event":"update_ok","at":"2026-10-19T00:00:00Z","future_o":{"k":1}}],
	 "switch_deferrals":0,"dedupe":{}}`
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	st, corrupt, err := Load(path)
	if err != nil || corrupt {
		t.Fatalf("load: %v corrupt=%v", err, corrupt)
	}
	st.SwitchDeferrals = 2
	st.Probation.Bad = 2
	if err := Save(path, st); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(out["future_top"]) != "map[a:[1 2]]" || out["switch_deferrals"] != float64(2) {
		t.Fatalf("top level: %s", data)
	}
	p := out["probation"].(map[string]any)
	q := out["quarantine"].(map[string]any)["1.18.0"].(map[string]any)
	u := out["updater"].(map[string]any)
	o := out["outbox"].([]any)[0].(map[string]any)
	if fmt.Sprint(o["future_o"]) != "map[k:1]" || o["execution_id"] != "e1" {
		t.Fatalf("outbox entry: %s", data)
	}
	if p["future_p"] != "x" || p["bad"] != float64(2) || q["future_q"] != float64(7) || q["until"] != "2026-10-26T00:00:00Z" || u["future_u"] != true {
		t.Fatalf("nested: %s", data)
	}
	again, _, _ := Load(path)
	if again.Quarantine["1.18.0"].Until.IsZero() {
		t.Fatal("until lost on reload")
	}
}

// R-F1-3: a valid state that omits or nulls the maps loads with empty,
// writable maps.
func TestLoadNeverReturnsNilMaps(t *testing.T) {
	for _, body := range []string{
		`{"schema":1,"current":"1.2.3"}`,
		`{"schema":1,"current":"1.2.3","quarantine":null,"dedupe":null}`,
	} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		st, corrupt, err := Load(path)
		if err != nil || corrupt || st == nil {
			t.Fatalf("%s: %v corrupt=%v", body, err, corrupt)
		}
		if st.Quarantine == nil || st.Dedupe == nil {
			t.Fatalf("%s: nil maps", body)
		}
		st.Quarantine["1.2.4"] = Quarantine{Reason: "x"}
		st.Dedupe["k"] = time.Now()
	}
}

// R-F1-5: a directory at the state.json path is corrupt, not an I/O
// error, on every OS (Windows CreateFile refused directories before).
func TestDirectoryAtStatePathIsCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	st, corrupt, err := Load(path)
	if err != nil || !corrupt || st != nil {
		t.Fatalf("Load(dir) = %v, corrupt=%v, err=%v; want corrupt", st, corrupt, err)
	}
	if recs := ReadRuns(path); recs != nil {
		t.Fatalf("ReadRuns(dir) = %v", recs)
	}
}

// D15: a newer schema is read for its known fields and written back with
// its schema number and everything else intact, never treated as corrupt.
func TestHigherSchemaIsReadAndPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	in := `{"schema":2,"current":"1.20.0","previous":"1.19.0","new_v2":{"x":1},
	 "probation":{"version":"1.20.0","since":"2026-10-19T00:00:00Z","ok":0,"bad":0,"smoke_ok":true,"v2_p":true}}`
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	st, corrupt, err := Load(path)
	if err != nil || corrupt || st == nil || st.Current != "1.20.0" || st.Schema != 2 {
		t.Fatalf("Load = %+v corrupt=%v err=%v", st, corrupt, err)
	}
	st.Probation.Bad = 1
	if err := Save(path, st); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &out)
	if out["schema"] != float64(2) || fmt.Sprint(out["new_v2"]) != "map[x:1]" || out["probation"].(map[string]any)["v2_p"] != true {
		t.Fatalf("schema-2 state not preserved: %s", data)
	}
}

// B4(b): the bootstrap's updater-record write bumps generation like every
// other writer, so the updater's "did my write land" check stays sound.
func TestSaveUpdaterRecordBumpsGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st := &State{Schema: 1, Current: "1.20.0"}
	if err := Save(path, st); err != nil {
		t.Fatal(err)
	}
	before := st.Generation
	if err := SaveUpdaterRecord(path, "", func(string, int) (string, int) { return "1.20.0", 1 }); err != nil {
		t.Fatal(err)
	}
	got, _, err := Load(path)
	if err != nil || got.Generation != before+1 || got.Updater.ConsecutiveFailures != 1 {
		t.Fatalf("after record: gen %d (want %d), %+v, %v", got.Generation, before+1, got.Updater, err)
	}
	// The updater's next save goes on from there.
	if err := Save(path, got); err != nil {
		t.Fatal(err)
	}
	again, _, _ := Load(path)
	if again.Generation != before+2 || again.Updater.ConsecutiveFailures != 1 {
		t.Fatalf("updater after record: %+v", again)
	}
}
