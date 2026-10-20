//go:build windows

package tcc

import "testing"

func TestHasDirPrefix_DriveRoot(t *testing.T) {
	if !hasDirPrefix(`Z:\proj`, `Z:\`) {
		t.Error(`Z:\proj must be under Z:\`)
	}
	if hasDirPrefix(`C:\Users\a\Z`, `Z:\`) {
		t.Error("unrelated path must not match")
	}
}
