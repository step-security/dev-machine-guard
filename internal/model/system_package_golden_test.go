package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestSystemPackageGoldenContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/system_package_inventory_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "f308a2fae4b01f867f169d4650cffe9a6b92272df63dbed81977f75d32b0e81d" {
		t.Fatal("shared system package fixture digest changed; update both producer and consumer after review")
	}
	var pair struct {
		Scans     []SystemPackageScanResult `json:"system_package_scans"`
		Inventory *SystemPackageInventory   `json:"system_package_inventory"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pair); err != nil {
		t.Fatal(err)
	}
	if pair.Inventory == nil || pair.Inventory.SchemaVersion != SystemPackageInventorySchemaVersion {
		t.Fatal("missing or unexpected inventory section")
	}
	encoded, err := json.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodeGeneric(t, encoded), decodeGeneric(t, raw)) {
		t.Fatal("wire round-trip dropped a field")
	}
	seen := map[string]bool{}
	for _, s := range pair.Scans {
		seen["status:"+s.Status], seen["scope:"+s.Scope] = true, true
		if s.Status != SystemPackageStatusComplete && s.Error == "" {
			t.Errorf("%s %s is %s without an error", s.ScanType, s.SourceID, s.Status)
		}
		if s.PackagesCount != len(s.Packages) {
			t.Errorf("%s %s count %d, %d packages", s.ScanType, s.SourceID, s.PackagesCount, len(s.Packages))
		}
		for _, p := range s.Packages {
			if p.Scope != s.Scope {
				t.Errorf("%s package scope %s in a %s scan", p.Name, p.Scope, s.Scope)
			}
			if p.Epoch > 0 {
				seen["rpm_epoch"] = true
			}
			if len(p.Outputs) > 1 {
				seen["nix_multi_output"] = true
			}
			if p.Active != nil && !*p.Active {
				seen["nix_inactive"] = true
			}
		}
	}
	for _, key := range []string{"status:complete", "status:partial", "status:failed", "scope:machine", "scope:user",
		"rpm_epoch", "nix_multi_output", "nix_inactive"} {
		if !seen[key] {
			t.Errorf("fixture does not exercise %s", key)
		}
	}
}
