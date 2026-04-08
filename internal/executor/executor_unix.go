//go:build !windows

package executor

import (
	"context"
	"os"
	"strings"
)

func (r *Real) IsRoot() bool {
	return os.Getuid() == 0
}

func (r *Real) RunAsUser(ctx context.Context, username, command string) (string, error) {
	if !r.IsRoot() {
		stdout, _, _, err := r.Run(ctx, "bash", "-c", command)
		return strings.TrimSpace(stdout), err
	}
	stdout, _, _, err := r.Run(ctx, "sudo", "-H", "-u", username, "bash", "-l", "-c", command)
	return strings.TrimSpace(stdout), err
}
