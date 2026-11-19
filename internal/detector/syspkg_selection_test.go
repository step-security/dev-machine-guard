package detector

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestPrimarySystemManager(t *testing.T) {
	for _, tc := range []struct {
		name, rpm, dpkg, wantManager, wantPackage string
		exit                                      int
	}{
		{"empty rpm falls through", "", "jq\t1.8", "dpkg", "jq", 0},
		{"two populated databases keep priority", "bash\t5", "jq\t1.8", "rpm", "bash", 0},
		{"all empty keep first", "", "", "rpm", "", 0},
		{"failed rpm retains selection", "", "jq\t1.8", "rpm", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := executor.NewMock()
			ex.SetGOOS("linux")
			for i, out := range []string{tc.rpm, tc.dpkg} {
				pm := sysPkgSpecs[i]
				ex.SetPath(pm.Binary, "/usr/bin/"+pm.Binary)
				code := 0
				if i == 0 {
					code = tc.exit
				}
				ex.SetCommand(out, "", code, pm.Binary, pm.ListCmd...)
				ex.SetCommand(pm.Name+" version", "", 0, pm.Binary, pm.VersionCmd...)
			}
			pm, pkgs := NewSystemPkgDetector(ex).Detect(t.Context())
			if pm == nil || pm.Name != tc.wantManager || pm.Version != tc.wantManager+" version" {
				t.Fatalf("manager = %+v, want %s", pm, tc.wantManager)
			}
			if tc.wantPackage == "" {
				if len(pkgs) != 0 {
					t.Fatalf("expected empty list, got %v", pkgs)
				}
			} else if len(pkgs) != 1 || pkgs[0].Name != tc.wantPackage {
				t.Fatalf("packages = %v, want %s", pkgs, tc.wantPackage)
			}
		})
	}
}
