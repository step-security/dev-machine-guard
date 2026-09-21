package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func FuzzCanonicalHashJSON(f *testing.F) {
	for _, s := range []string{`{"b":2,"a":1}`, `[1,1.0,null,true,"é"]`, `{"x":1,"x":2}`, `1e999`, `{`, "", "\xff"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16*1024 {
			t.Skip()
		}
		hash, err := CanonicalHashJSON(data)
		if len(hash) != len(hashPrefix)+64 {
			t.Fatal("missing or malformed hash")
		}
		if err != nil {
			sum := sha256.Sum256(data)
			if hash != hashPrefix+hex.EncodeToString(sum[:]) {
				t.Fatal("invalid JSON lost raw-byte fingerprint")
			}
			return
		}
		var compact, indent bytes.Buffer
		if err := json.Compact(&compact, data); err != nil {
			t.Fatal(err)
		}
		if err := json.Indent(&indent, data, "", "  "); err != nil {
			t.Fatal(err)
		}
		for _, equivalent := range [][]byte{compact.Bytes(), indent.Bytes()} {
			got, err := CanonicalHashJSON(equivalent)
			if err != nil || got != hash {
				t.Fatal("formatting changed inventory hash")
			}
		}
	})
}

func FuzzStateTransitions(f *testing.F) {
	f.Add([]byte{0, 0, 32, 1, 2, 2, 3, 0, 64, 4, 4, 5, 6, 7})
	f.Add([]byte{})
	f.Add([]byte{255, 0, 128, 192, 32, 96})
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 128 {
			t.Skip()
		}
		type key struct{ eco, path string }
		type record struct {
			hash, upload              string
			first, verified, uploaded time.Time
		}
		expected := map[key]record{}
		pending := map[key]bool{}
		s := New("fuzz")
		epoch := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i, op := range ops {
			eco := EcosystemNPM
			if op&4 != 0 {
				eco = EcosystemPython
			}
			path := fmt.Sprintf("/project/%d", (op>>3)&3)
			k := key{eco, path}
			now := epoch.Add(time.Duration(i) * time.Second)
			switch op & 3 {
			case 0, 1:
				hash := fmt.Sprintf("hash-%d", (op>>5)&1)
				full := op&64 != 0
				failed := op&3 == 1
				r := ScanRecord{Path: path, Hash: hash, PackageManager: "fixture"}
				if failed {
					r.ExitCode = 1
				}
				old, exists := expected[k]
				wantChanged := full || failed || !exists || old.hash != hash
				changed, unchanged := s.Partition(eco, []ScanRecord{r}, full)
				if wantChanged {
					if len(changed) != 1 || changed[0] != path || len(unchanged) != 0 {
						t.Fatal("changed partition mismatch")
					}
				} else if len(unchanged) != 1 || unchanged[0] != path || len(changed) != 0 {
					t.Fatal("unchanged partition mismatch")
				}
				execID := fmt.Sprintf("run-%d", i)
				var npm, py []ScanRecord
				if eco == EcosystemNPM {
					npm = []ScanRecord{r}
				} else {
					py = []ScanRecord{r}
				}
				s.CommitAfterUpload(now, execID, "fuzz", npm, py, nil, nil, full)
				if !failed {
					next := old
					next.hash = hash
					next.verified = now
					if !exists {
						next.first = now
					}
					if wantChanged {
						next.upload = execID
						next.uploaded = now
					}
					expected[k] = next
				}
			case 2:
				s.MarkRemovedPending(eco, []string{path, path}, now)
				pending[k] = true
			case 3:
				if pending[k] {
					s.AckRemovals([]PendingRemoval{{Ecosystem: eco, Path: path}})
					s.DropRemovedFromProjects(eco, []string{path})
					delete(pending, k)
					delete(expected, k)
				}
			}
			if len(s.NPMProjects)+len(s.PythonProjects) != len(expected) {
				t.Fatal("inventory entry count mismatch")
			}
			for k, want := range expected {
				entries := s.NPMProjects
				if k.eco == EcosystemPython {
					entries = s.PythonProjects
				}
				got, ok := entries[k.path]
				if !ok || got.ScanOutputHash != want.hash || got.LastUploadedExecutionID != want.upload || !got.FirstSeenAt.Equal(want.first) || !got.LastVerifiedAt.Equal(want.verified) || !got.LastUploadedAt.Equal(want.uploaded) {
					t.Fatalf("inventory/provenance mismatch after step %d", i)
				}
			}
			if len(s.RemovedPendingAck) != len(pending) {
				t.Fatal("pending removals lost or duplicated")
			}
			for _, p := range s.RemovedPendingAck {
				if !pending[key{p.Ecosystem, p.Path}] {
					t.Fatal("cross-ecosystem removal")
				}
			}
		}
	})
}
