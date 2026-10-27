//go:build !windows

package launcher

import (
	"testing"
	"time"
)

func TestSpawnHidden_ExitCodeAndDeadline(t *testing.T) {
	started := false
	res := SpawnHidden("/bin/sh", []string{"-c", "exit 3"}, nil, 0, func() { started = true })
	if !res.Started || !started || res.ExitCode != 3 || res.Killed {
		t.Fatalf("exit 3: %+v", res)
	}
	res = SpawnHidden("/bin/sh", []string{"-c", "sleep 30"}, nil, 200*time.Millisecond, nil)
	if !res.Started || !res.Killed {
		t.Fatalf("deadline: %+v", res)
	}
	res = SpawnHidden("/nonexistent/task.exe", nil, nil, 0, nil)
	if res.Started || res.Err == nil {
		t.Fatalf("missing binary: %+v", res)
	}
}
