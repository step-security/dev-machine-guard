//go:build !selfupdate_faults

package faultinject

// Enabled reports whether fault injection is compiled in.
const Enabled = false

// Point is a no-op without the selfupdate_faults build tag.
func Point(string) error { return nil }
