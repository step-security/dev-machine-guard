//go:build windows

package executor

import (
	"context"
	"strings"

	"golang.org/x/sys/windows"
)

func (r *Real) IsRoot() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func (r *Real) RunAsUser(ctx context.Context, _ string, command string) (string, error) {
	stdout, _, _, err := r.Run(ctx, "cmd", "/c", command)
	return strings.TrimSpace(stdout), err
}
