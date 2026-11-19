//go:build windows

package main

import (
	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// scheduledSelfUpdate is a no-op on Windows: the MSI's SYSTEM update task
// (`self-update --system`, run through the bootstrap) owns updates there.
func scheduledSelfUpdate(executor.Executor, *progress.Logger, *cli.Config) {}
