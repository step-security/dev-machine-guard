package model

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// goldenPath holds one credential snapshot exercising every field, every source,
// every protection state and every reason code. The same bytes are the contract
// the reader in the other repository is tested against.
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

	protections, roots, categories := map[string]bool{}, map[string]bool{}, map[string]bool{}
	sources := map[string]bool{}
	for _, f := range info.Findings {
		protections[f.Protection] = true
		categories[f.Category] = true
		sources[f.SourceID] = true
		if root, _, ok := strings.Cut(f.Location, "/"); ok {
			roots[root] = true
		}
		// A finding is material that was found, so a count of none is a row
		// asserting a credential nobody located.
		if f.Count <= 0 {
			t.Errorf("%s: count = %d, want at least one credential", f.SourceID, f.Count)
		}
	}
	reasons := map[string]bool{}
	for _, e := range info.Errors {
		reasons[e.ReasonCode] = true
	}

	for _, tt := range []struct {
		what string
		got  map[string]bool
		want []string
	}{
		// Two states and no third: every finding is material that is either usable
		// straight out of the file or not.
		{"protection", protections, []string{
			CredentialProtectionPlaintext,
			CredentialProtectionProtected,
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
			CredentialReasonUnrecognizedFormat,
		}},
		{"category", categories, []string{
			CredentialCategoryCloud,
			CredentialCategorySourceControl,
			CredentialCategoryPackageReg,
			CredentialCategoryContainers,
			CredentialCategoryInfrastructure,
			CredentialCategoryAPIClients,
		}},
		// Every root token, including the opaque one, whose identifier segment
		// is the part a reader validates and an agent is likeliest to omit.
		{"location root", roots, []string{"$HOME", "$APPDATA", "$XDG_CONFIG_HOME", "$ABS"}},
		// The whole catalog, so the reader is exercised against every identifier it
		// will ever be asked to group by.
		{"source", sources, []string{
			"aws_credentials", "aws_config", "gcp_adc",
			"ssh_private_keys", "git_credentials", "netrc",
			"github_cli_hosts", "npmrc", "pypirc",
			"docker_config", "kubeconfig",
			"terraform_credentials", "vault_token",
			"insomnia",
		}},
	} {
		for _, want := range tt.want {
			if !tt.got[want] {
				t.Errorf("golden payload has no %s %q", tt.what, want)
			}
		}
	}
	if len(sources) != 14 {
		t.Errorf("golden payload covers %d sources, want the whole catalog of 14", len(sources))
	}

	// The mixed result the three-state parser produces: one source both reported a
	// credential and could not interpret the rest of its file. A reader that treats
	// a finding as proof the source was fully understood breaks on exactly this row.
	if !hasError(info, "kubeconfig", CredentialReasonUnrecognizedFormat) {
		t.Error("golden payload must demonstrate a source that is both reported and incomplete")
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

// TestCredentialScanGolden_CarriesNoRetiredVocabulary is a check on the bytes
// rather than on the decoded struct, because that is where the retired vocabulary
// would survive: a reader keyed on any of these groups findings by a value this
// agent no longer sends, and would show an empty category rather than an error.
func TestCredentialScanGolden_CarriesNoRetiredVocabulary(t *testing.T) {
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	for _, retired := range []string{
		"gitconfig_helper", "github_cli_status", "mcp_config", "ai_mcp",
		`"external"`, `"unknown"`, `"github":`, "scope_status", "credential_storage",
		"authentication_status", "account_count",
	} {
		if bytes.Contains(raw, []byte(retired)) {
			t.Errorf("golden payload carries retired vocabulary %q", retired)
		}
	}
}

func hasError(info CredentialScanInfo, sourceID, reason string) bool {
	for _, e := range info.Errors {
		if e.SourceID == sourceID && e.ReasonCode == reason {
			return true
		}
	}
	return false
}

func decodeGeneric(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}
