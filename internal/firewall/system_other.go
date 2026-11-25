//go:build !windows

package firewall

import (
	"errors"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// errUnsupported: the on-device firewall this package manages is
// Windows-only (macOS and Linux installs keep it with the loader).
var errUnsupported = errors.New("the on-device firewall is managed by the agent on Windows only")

// NewSystem off Windows: nothing is present and nothing can be changed.
func NewSystem(exec executor.Executor) System {
	return System{
		Run:             exec.RunWithTimeout,
		Service:         noService{},
		ImageRunning:    func(string) bool { return false },
		MSIVersion:      func() (string, error) { return "", errUnsupported },
		VerifyPublisher: func(string, string) error { return errUnsupported },
		InstallerBusy:   func() bool { return false },
		Elevated:        exec.IsRoot,
		Lock:            func() (func(), error) { return nil, errUnsupported },
	}
}

type noService struct{}

func (noService) Status() (ServiceStatus, error) { return ServiceStatus{}, nil }
func (noService) Stop() error                    { return errUnsupported }
func (noService) Start() error                   { return errUnsupported }
func (noService) Delete() error                  { return errUnsupported }
