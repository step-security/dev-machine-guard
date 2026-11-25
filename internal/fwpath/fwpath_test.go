package fwpath

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		if Dir() != "" || Exe() != "" || DataDir() != "" {
			t.Fatalf("non-Windows paths not empty: %q %q %q", Dir(), Exe(), DataDir())
		}
		return
	}
	if !strings.HasSuffix(strings.ToLower(Dir()), strings.ToLower(`\StepSecurity\OnDeviceFirewall`)) {
		t.Errorf("Dir() = %q", Dir())
	}
	if Exe() != filepath.Join(Dir(), ExeName) {
		t.Errorf("Exe() = %q", Exe())
	}
	if !strings.HasSuffix(strings.ToLower(DataDir()), strings.ToLower(`\StepSecurity\OnDeviceFirewall`)) {
		t.Errorf("DataDir() = %q", DataDir())
	}
}
