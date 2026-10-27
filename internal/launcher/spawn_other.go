//go:build !windows

package launcher

import (
	"os/exec"
	"time"
)

// SpawnHidden runs the child directly; off Windows there is no console or
// job object to manage, and only the direct child is killed on deadline.
func SpawnHidden(path string, args, env []string, deadline time.Duration, onStart func()) SpawnResult {
	cmd := exec.Command(path, args...) // #nosec G204 -- the bootstrap launches its own resolved version binaries
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return SpawnResult{Err: err}
	}
	if onStart != nil {
		onStart()
	}
	return waitWithDeadline(cmd, deadline, func() { _ = cmd.Process.Kill() })
}
