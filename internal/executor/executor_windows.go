//go:build windows

package executor

import (
	"context"
	"os/exec"
	"strings"
)

func (r *Real) IsRoot() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

func (r *Real) RunAsUser(ctx context.Context, _ string, command string) (string, error) {
	stdout, _, _, err := r.Run(ctx, "cmd", "/c", command)
	return strings.TrimSpace(stdout), err
}
