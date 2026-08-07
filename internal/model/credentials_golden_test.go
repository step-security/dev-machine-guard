package model

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// goldenPath holds one credential snapshot exercising every field, every
// protection state, every reason code and both host-report shapes.
const goldenPath = "testdata/credential_scan_golden.json"

// TestCredentialScanGolden_RoundTripsWithNoDroppedField is the contract check between
// this struct and the reader on the other end of the wire. Both sides are
// hand-maintained Go types in separate repositories, and the reader discards a field
// it does not know rather than rejecting it — so a field renamed here does not fail
// anything, it silently stops arriving. This fixture is the same bytes on both sides,
// and each side asserts its struct carries every field and emits every one back.
func TestCredentialScanGolden_RoundTripsWithNoDroppedField(t *testing.T) {
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	// A field in the fixture that this struct has no home for is a field this agent
	// would never send, which is how the two shapes drift apart unnoticed.
	var info CredentialScanInfo
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&info); err != nil {
		t.Fatalf("golden payload does not fit CredentialScanInfo: %v", err)
	}

	// A field decoded but not emitted back is the same drift the other way, so the
	// comparison is on the re-encoded document rather than on the struct.
	encoded, err := json.Marshal(&info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want := decodeGeneric(t, raw)
	got := decodeGeneric(t, encoded)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the payload\n got: %s\nwant: %s", encoded, raw)
	}
}

// TestCredentialScanGolden_CoversTheWholeVocabulary keeps the fixture honest. Its
// value is entirely in what it exercises, so one that has quietly stopped covering a
// state is worse than none: it passes while the field it protects goes unchecked.
func TestCredentialScanGolden_CoversTheWholeVocabulary(t *testing.T) {
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var info CredentialScanInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	protections, roots := map[string]bool{}, map[string]bool{}
	statuses, storages, reasons := map[string]bool{}, map[string]bool{}, map[string]bool{}
	// The two shapes a host report takes: one the CLI answered for and one it did
	// not, the second being where an empty scope list must not read as no permissions.
	var observed, withheld bool
	for _, f := range info.Findings {
		protections[f.Protection] = true
		if root, _, ok := strings.Cut(f.Location, "/"); ok {
			roots[root] = true
		}
		for _, h := range f.GitHub {
			statuses[h.AuthenticationStatus] = true
			storages[h.CredentialStorage] = true
			switch h.ScopeStatus {
			case CredentialScopeObserved:
				observed = len(h.Scopes) > 0
			case CredentialScopeUnavailable:
				withheld = len(h.Scopes) == 0
			}
		}
	}
	for _, e := range info.Errors {
		reasons[e.ReasonCode] = true
	}

	for _, tt := range []struct {
		what string
		got  map[string]bool
		want []string
	}{
		{"protection", protections, []string{
			CredentialProtectionPlaintext,
			CredentialProtectionProtected,
			CredentialProtectionExternal,
			CredentialProtectionUnknown,
		}},
		// Every reason code has to be reachable from a fixture, or the reader cannot
		// test that an incomplete snapshot renders as incomplete. skipped_no_user is
		// the one omission: it replaces the whole scan rather than joining one.
		{"reason_code", reasons, []string{
			CredentialReasonRefusedTCC,
			CredentialReasonRefusedOutsideRoots,
			CredentialReasonPermissionDenied,
			CredentialReasonLocationUnresolved,
			CredentialReasonUnsupportedEncoding,
			CredentialReasonCapped,
			CredentialReasonTimedOut,
		}},
		// Both host vocabularies in full. The reader groups hosts by these and
		// refuses a value it does not know, so drift costs the whole snapshot.
		{"authentication_status", statuses, []string{
			CredentialAuthAuthenticated, CredentialAuthNotAuthenticated, CredentialAuthUnknown,
		}},
		{"credential_storage", storages, []string{
			CredentialStorageInlineFile, CredentialStorageKeyring, CredentialStorageUnknown,
		}},
		// Every root token, including the opaque one, whose identifier segment
		// is the part a reader validates and an agent is likeliest to omit.
		{"location root", roots, []string{"$HOME", "$APPDATA", "$XDG_CONFIG_HOME", "$ABS"}},
	} {
		for _, want := range tt.want {
			if !tt.got[want] {
				t.Errorf("golden payload has no %s %q", tt.what, want)
			}
		}
	}

	if !observed || !withheld {
		t.Error("golden payload must carry both a reported and an unreported host")
	}
	// The run states its principal as well as each finding: a reader deciding
	// whether it can honour the snapshot at all has only the run in front of it.
	if info.CollectionPrincipal != CredentialPrincipalAgentEffective {
		t.Errorf("collection_principal = %q, want %q", info.CollectionPrincipal, CredentialPrincipalAgentEffective)
	}
	if info.CatalogVersion == "" {
		t.Error("golden payload must declare a catalog_version")
	}
	// Both incompleteness flags, since a snapshot that replaces its predecessor
	// is the only thing left to carry them.
	if info.ScanComplete || !info.Truncated {
		t.Error("golden payload must exercise an incomplete, truncated snapshot")
	}
	if info.PayloadSchemaVersion != CurrentCredentialSchemaVersion {
		t.Errorf("golden payload declares schema %d, want %d", info.PayloadSchemaVersion, CurrentCredentialSchemaVersion)
	}
}

func decodeGeneric(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}
