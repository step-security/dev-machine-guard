//go:build !windows

package fwpath

// The on-device firewall this package locates is Windows-only.
func programFiles() string { return "" }

func programData() string { return "" }
