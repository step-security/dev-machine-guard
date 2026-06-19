package state

import (
	"encoding/base64"
	"testing"
)

func TestScanRecordFromBase64_HashesDecodedPayload(t *testing.T) {
	raw := []byte(`{"name":"svc","version":"1.0.0"}`)
	encoded := base64.StdEncoding.EncodeToString(raw)
	wantHash, _ := CanonicalHashJSON(raw)

	r := ScanRecordFromBase64("/p", "npm", "10.2.0", encoded, 0)
	if r.Hash != wantHash {
		t.Errorf("hash mismatch: got %s want %s", r.Hash, wantHash)
	}
	if r.Path != "/p" || r.PackageManager != "npm" || r.PMVersion != "10.2.0" || r.ExitCode != 0 {
		t.Errorf("metadata not propagated: %+v", r)
	}
}

func TestScanRecordFromBase64_InvalidBase64FallsBackToRawString(t *testing.T) {
	bad := "not!valid!base64"
	wantHash, _ := CanonicalHashJSON([]byte(bad))

	r := ScanRecordFromBase64("/p", "npm", "", bad, 1)
	if r.Hash != wantHash {
		t.Errorf("fallback hash mismatch: got %s want %s", r.Hash, wantHash)
	}
	if r.ExitCode != 1 {
		t.Errorf("exit code lost: %d", r.ExitCode)
	}
}

func TestScanRecordFromBase64_KeyReorderingStable(t *testing.T) {
	a := base64.StdEncoding.EncodeToString([]byte(`{"a":1,"b":2}`))
	b := base64.StdEncoding.EncodeToString([]byte(`{"b":2,"a":1}`))
	ra := ScanRecordFromBase64("/p", "npm", "", a, 0)
	rb := ScanRecordFromBase64("/p", "npm", "", b, 0)
	if ra.Hash != rb.Hash {
		t.Errorf("key-reordered JSON should hash equal: %s vs %s", ra.Hash, rb.Hash)
	}
}
