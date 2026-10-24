//go:build !selfupdate_faults

package faultinject

import "testing"

func TestPointIsNoOpWithoutTag(t *testing.T) {
	t.Setenv("DMG_FAULT", "S0.locked:err,S0.locked:kill")
	t.Setenv("DMG_FAULT_TRACE", t.TempDir()+"/trace")
	if Enabled {
		t.Fatal("Enabled = true without the selfupdate_faults tag")
	}
	if err := Point("S0.locked"); err != nil {
		t.Fatalf("Point = %v, want nil", err)
	}
}
