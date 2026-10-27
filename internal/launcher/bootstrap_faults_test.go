//go:build selfupdate_faults

package launcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdoptSeed_FaultAtCopiedLeavesNoStagingAndNoPointer(t *testing.T) {
	t.Setenv("DMG_FAULT", "adopt.copied:err")
	f := newFixture(t)
	f.adopt(f.seed("1.5.0"))
	entries, _ := os.ReadDir(f.layout.VersionsDir())
	if len(entries) != 0 {
		t.Fatalf("versions not empty: %v", entries)
	}
	if _, err := os.Stat(f.layout.StateFile()); !os.IsNotExist(err) {
		t.Fatal("state points at a seed that was never renamed in")
	}
	// The next adopt converges.
	t.Setenv("DMG_FAULT", "")
	f.adopt(filepath.Join(f.layout.InstallRoot, "seed", "1.5.0"))
	if f.load().Current != "1.5.0" {
		t.Fatal("did not converge")
	}
}

func TestAdoptSeed_FaultAtStateTempKeepsOldState(t *testing.T) {
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.4.0"}`)
	f.version("1.4.0")
	t.Setenv("DMG_FAULT", "adopt.state-temp:err")
	f.adopt(f.seed("1.5.0"))
	if f.load().Current != "1.4.0" {
		t.Fatal("state changed despite the fault")
	}
	t.Setenv("DMG_FAULT", "")
	f.adopt(filepath.Join(f.layout.InstallRoot, "seed", "1.5.0"))
	if st := f.load(); st.Current != "1.5.0" || st.Previous != "1.4.0" {
		t.Fatalf("did not converge: %+v", st)
	}
}

func TestRun_CheckpointErrorsDoNotBlockLaunch(t *testing.T) {
	t.Setenv("DMG_FAULT", "boot.resolved:err,boot.launched:err")
	trace := filepath.Join(t.TempDir(), "trace")
	t.Setenv("DMG_FAULT_TRACE", trace)
	f := newFixture(t)
	f.state(`{"schema":1,"current":"1.2.0"}`)
	f.version("1.2.0")
	if code := f.b.Run(scanArgs(f.layout.DataRoot)); code != 0 || len(f.sp.calls) != 1 {
		t.Fatalf("code=%d calls=%d", code, len(f.sp.calls))
	}
	got, _ := os.ReadFile(trace)
	if !strings.Contains(string(got), "boot.resolved\nboot.launched\n") {
		t.Fatalf("trace = %q", got)
	}
}
