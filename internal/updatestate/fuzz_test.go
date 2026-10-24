package updatestate

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func FuzzDecodeState(f *testing.F) {
	for _, s := range []string{
		`{"schema":1,"current":"1.19.0","previous":"1.18.2","probation":{"version":"1.19.0","since":"2026-10-19T00:00:00Z","ok":0,"bad":1,"smoke_ok":true},"quarantine":{"1.18.9":{"reason":"x","at":"2026-10-19T00:00:00Z"}},"updater":{"version":"1.18.2","consecutive_failures":2},"switch_deferrals":1,"dedupe":{"k":"2026-10-19T00:00:00Z"}}`,
		`{"schema":1,"current":"1.2.3"}`, `{"schema":2}`, `null`, ``, `{"schema":1,"current":"01.2.3"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := decodeState(data)
		if err != nil {
			return
		}
		// Anything accepted must save and load back to the same state.
		path := filepath.Join(t.TempDir(), "state.json")
		if err := Save(path, st); err != nil {
			t.Fatalf("accepted state does not save: %v", err)
		}
		got, corrupt, err := Load(path)
		if err != nil || corrupt {
			t.Fatalf("saved state reloads corrupt=%v err=%v", corrupt, err)
		}
		a, _ := json.Marshal(got)
		if st.Schema < SchemaVersion {
			st.Schema = SchemaVersion
		}
		if st.Quarantine == nil {
			st.Quarantine = map[string]Quarantine{}
		}
		if st.Dedupe == nil {
			st.Dedupe = got.Dedupe
		}
		b, _ := json.Marshal(st)
		if string(a) != string(b) {
			t.Fatalf("round trip changed state:\n%s\n%s", a, b)
		}
	})
}

func FuzzDecodeRuns(f *testing.F) {
	for _, s := range []string{
		`{"records":[{"version":"1.19.0","execution_id":"e","started":true,"exit_code":0,"at":"2026-10-19T00:00:00Z"}]}`,
		`{"records":[{"version":"1.19.0","watchdog_killed":true}]}`, `garbage`, `{"records":null}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		recs := decodeRuns(data)
		// The reader never trims (R-F1-10); the 64 KiB read bound caps it.
		for _, r := range recs {
			if !validVersion(r.Version) {
				t.Fatalf("invalid version kept: %q", r.Version)
			}
			_ = ClassifyRun(r)
		}
	})
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"1.2.3", "0.0.0", "01.2.3", "1.2.3-rc.1", "4294967296.0.0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)
		if err == nil && v.String() != s {
			t.Fatalf("ParseVersion(%q) = %v: not canonical", s, v)
		}
	})
}
