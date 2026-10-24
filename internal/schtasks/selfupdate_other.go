//go:build !windows

package schtasks

import (
	"time"

	"github.com/step-security/dev-machine-guard/internal/progress"
)

func stopDMGProcessesPlatform(string, time.Duration, *progress.Logger) error { return nil }

func deleteRunningVersionPlatform() error { return nil }
