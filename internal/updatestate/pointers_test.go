package updatestate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeStateFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPointers(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantCorr bool
		want     *Pointers
	}{
		{"schema1", `{"schema":1,"current":"1.2.3","previous":"1.2.2","probation":{"version":"1.2.3"},"updater":{"version":"1.2.2","consecutive_failures":3}}`,
			false, &Pointers{Schema: 1, Current: "1.2.3", Previous: "1.2.2", Probation: "1.2.3", UpdaterVersion: "1.2.2", UpdaterFailures: 3}},
		{"schema1 extra fields", `{"schema":1,"current":"1.2.3","future":{"x":1}}`, false, &Pointers{Schema: 1, Current: "1.2.3"}},
		{"higher schema reads pointers only", `{"schema":7,"current":"2.0.0","previous":"bogus","probation":"???","updater":5}`,
			false, &Pointers{Schema: 7, Current: "2.0.0"}},
		{"higher schema bad current", `{"schema":2,"current":"..\\x"}`, true, nil},
		{"schema0", `{"schema":0,"current":"1.2.3"}`, true, nil},
		{"traversal", `{"schema":1,"current":"..\\x"}`, true, nil},
		{"garbage", `not json`, true, nil},
		{"empty", ``, true, nil},
		{"schema1 invalid counter still resolves (R-B-1)", `{"schema":1,"current":"1.2.3","switch_deferrals":-1}`, false, &Pointers{Schema: 1, Current: "1.2.3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, corrupt, err := LoadPointers(writeStateFile(t, tc.body))
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if corrupt != tc.wantCorr {
				t.Fatalf("corrupt = %v, want %v", corrupt, tc.wantCorr)
			}
			if tc.want == nil {
				if p != nil {
					t.Fatalf("p = %+v, want nil", p)
				}
				return
			}
			if *p != *tc.want {
				t.Fatalf("p = %+v, want %+v", *p, *tc.want)
			}
		})
	}
}

func TestLoadPointers_MissingAndHuge(t *testing.T) {
	p, corrupt, err := LoadPointers(filepath.Join(t.TempDir(), "nope.json"))
	if p != nil || corrupt || err != nil {
		t.Fatalf("missing: %v %v %v", p, corrupt, err)
	}
	huge := `{"schema":1,"current":"1.2.3","pad":"` + strings.Repeat("a", maxStateSize) + `"}`
	p, corrupt, err = LoadPointers(writeStateFile(t, huge))
	if p != nil || !corrupt || err != nil {
		t.Fatalf("huge: %v %v %v", p, corrupt, err)
	}
}

func TestResolveRunVersion(t *testing.T) {
	l := Layout{InstallRoot: t.TempDir(), DataRoot: t.TempDir()}
	mk := func(dir string, files ...string) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if v, why := ResolveRunVersion(l, nil); why != FallbackNothingRunnable || v != (Version{}) {
		t.Fatalf("empty: %v %q", v, why)
	}
	mk(filepath.Join(l.InstallRoot, "seed", "1.0.0"), AgentFile, LauncherFile)
	mk(filepath.Join(l.InstallRoot, "seed", "0.9.0"), AgentFile, LauncherFile)
	mk(filepath.Join(l.InstallRoot, "seed", "2.0.0"), AgentFile) // incomplete: ignored
	if v, why := ResolveRunVersion(l, nil); v.String() != "1.0.0" || why != FallbackStateMissing {
		t.Fatalf("missing state: %v %q", v, why)
	}
	st := &State{Schema: 1, Current: "1.2.0", Previous: "1.1.0"}
	mk(l.VersionDir(Version{1, 1, 0}), AgentFile, LauncherFile)
	if v, why := ResolveRunVersion(l, st); v.String() != "1.1.0" || why != FallbackCurrentMissing+":1.2.0" {
		t.Fatalf("previous: %v %q", v, why)
	}
	mk(l.VersionDir(Version{1, 2, 0}), LauncherFile)
	if _, why := ResolveRunVersion(l, st); why != FallbackCurrentIncomplete+":1.2.0" {
		t.Fatalf("incomplete: %q", why)
	}
	mk(l.VersionDir(Version{1, 2, 0}), AgentFile)
	if v, why := ResolveRunVersion(l, st); v.String() != "1.2.0" || why != "" {
		t.Fatalf("current: %v %q", v, why)
	}
}

// The frozen bootstrap read contract: a schema-2 file with fields this build
// doesn't know still yields current/previous, unlike Load.
func TestLoadPointers_Schema2ExtraFields(t *testing.T) {
	path := writeStateFile(t, `{"schema":2,"current":"1.4.0","previous":"1.3.0","probation":{"version":"1.4.0","new":1},"quarantine":"changed-type","brand_new":{"x":[1,2]}}`)
	if _, corrupt, _ := Load(path); !corrupt {
		t.Fatal("Load should treat schema 2 as corrupt (updater rule)")
	}
	p, corrupt, err := LoadPointers(path)
	if err != nil || corrupt || p == nil || p.Current != "1.4.0" || p.Previous != "1.3.0" || p.Schema != 2 {
		t.Fatalf("p=%+v corrupt=%v err=%v", p, corrupt, err)
	}
	// Existing fields keep their meaning in a newer schema (additive-only).
	if p.Probation != "1.4.0" {
		t.Fatalf("schema-2 probation not read: %+v", p)
	}
}

// R-B-1: the frozen read contract is schema/current/previous only. Fields a
// future writer may legally change (RC versions in quarantine, updater or
// probation; odd counters; changed types) never make the state unreadable.
func TestLoadPointers_FrozenContractIgnoresOtherFields(t *testing.T) {
	for name, body := range map[string]string{
		"rc quarantine key": `{"schema":1,"current":"1.21.0","previous":"1.20.0","quarantine":{"1.22.0-rc.1":{"reason":"x"}}}`,
		"rc updater":        `{"schema":1,"current":"1.21.0","previous":"1.20.0","updater":{"version":"1.22.0-rc.1","consecutive_failures":1}}`,
		"rc probation":      `{"schema":1,"current":"1.21.0","previous":"1.20.0","probation":{"version":"1.22.0-rc.1"}}`,
		"negative counter":  `{"schema":1,"current":"1.21.0","previous":"1.20.0","switch_deferrals":-1}`,
		"changed types":     `{"schema":1,"current":"1.21.0","previous":"1.20.0","probation":"x","updater":7,"dedupe":[1]}`,
		"newer schema":      `{"schema":3,"current":"1.21.0","previous":"1.20.0","probation":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			p, corrupt, err := LoadPointers(writeStateFile(t, body))
			if err != nil || corrupt || p == nil || p.Current != "1.21.0" || p.Previous != "1.20.0" {
				t.Fatalf("p=%+v corrupt=%v err=%v", p, corrupt, err)
			}
		})
	}
	// An invalid or non-string previous is dropped, never corrupt.
	p, corrupt, _ := LoadPointers(writeStateFile(t, `{"schema":1,"current":"1.21.0","previous":5}`))
	if corrupt || p == nil || p.Previous != "" {
		t.Fatalf("non-string previous: p=%+v corrupt=%v", p, corrupt)
	}
	// Only current (strict) and schema (>= 1) can make it unreadable.
	for _, body := range []string{`{"schema":1,"current":"1.21.0-rc.1"}`, `{"schema":"1","current":"1.21.0"}`, `{"schema":0,"current":"1.21.0"}`, `{"schema":1,"current":7}`} {
		if _, corrupt, _ := LoadPointers(writeStateFile(t, body)); !corrupt {
			t.Errorf("%s: want corrupt", body)
		}
	}
}
