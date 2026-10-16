package device

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestIdentityIgnoresEnvironmentHostnameAndUser(t *testing.T) {
	ResetIDCache()
	t.Cleanup(ResetIDCache)
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("HOST-1"))
	for _, tc := range []struct{ hostname, user, override string }{{"pool-1", "first-user", "first-id"}, {"renamed-host", "second-user", "{hostname}-{user}"}} {
		mock.SetHostname(tc.hostname)
		mock.SetUsername(tc.user)
		mock.SetEnv("STEPSEC_DEVICE_ID", tc.override)
		if got := ID(Gather(context.Background(), mock)); got != "HOST-1" {
			t.Fatalf("machine identity changed to %q", got)
		}
	}
}
func TestIsServiceAccount(t *testing.T) {
	for _, tc := range []struct {
		platform, user string
		root, want     bool
	}{
		{"windows", `NT AUTHORITY\SYSTEM`, true, true}, {"windows", "SYSTEM", true, true}, {"windows", `NT SERVICE\agent`, false, true},
		{"windows", "HOST$", false, true}, {"windows", `EXAMPLE\developer`, false, false}, {"linux", "root", true, true}, {"linux", "developer", false, false},
	} {
		mock := executor.NewMock()
		mock.SetGOOS(tc.platform)
		mock.SetIsRoot(tc.root)
		if got := IsServiceAccount(mock, tc.user); got != tc.want {
			t.Errorf("IsServiceAccount(%q) = %v, want %v", tc.user, got, tc.want)
		}
	}
}
