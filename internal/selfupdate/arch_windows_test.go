//go:build windows

package selfupdate

import "testing"

func TestArchForMachine(t *testing.T) {
	if archForMachine(0x8664) != "amd64" || archForMachine(0xAA64) != "arm64" || archForMachine(0x14c) != "" {
		t.Fatal("machine mapping wrong")
	}
	if a := nativeArch(); a != "amd64" && a != "arm64" {
		t.Fatalf("nativeArch = %q on a Windows runner", a)
	}
}

func TestLoadMachineProxyDoesNotFail(t *testing.T) {
	// Runners usually have no WinHTTP proxy; this only proves the call is safe.
	_ = loadMachineProxy()
}
