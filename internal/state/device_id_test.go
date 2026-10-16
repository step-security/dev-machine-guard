package state

import (
	"testing"
	"time"
)

func TestForDevice(t *testing.T) {
	s := New("1.0")
	s.DeviceID = "old-device"
	s.LastFullSyncAt = time.Now()
	s.NPMProjects["/project"] = ProjectEntry{}
	if got := s.ForDevice("old-device", "1.0"); got != s {
		t.Fatal("same identity discarded inventory")
	}
	for _, id := range []string{"old-device", ""} {
		s.DeviceID = id
		got := s.ForDevice("custom-device", "1.0")
		if got.DeviceID != "custom-device" || len(got.NPMProjects) != 0 || !got.LastFullSyncAt.IsZero() {
			t.Fatalf("new identity must start with empty inventory: %+v", got)
		}
	}
}
