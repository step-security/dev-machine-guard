//go:build windows

package firewall

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/step-security/dev-machine-guard/internal/authenticode"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/selfupdate"
	"github.com/step-security/dev-machine-guard/internal/winproc"
)

// NewSystem is the real OS seam: commands through exec (console hidden),
// SCM, the MSI's registry value, Authenticode and the loader's mutex.
func NewSystem(exec executor.Executor) System {
	return System{
		Run:             exec.RunWithTimeout,
		Service:         scmService{name: ServiceName},
		ImageRunning:    winproc.ImageRunning,
		MSIVersion:      msiAgentVersion,
		VerifyPublisher: authenticode.SamePublisher,
		InstallerBusy:   selfupdate.InstallerBusy,
		Elevated:        exec.IsRoot,
		Lock: func() (func(), error) {
			l, err := lock.AcquireNamed(MutexName)
			if errors.Is(err, lock.ErrHeld) {
				return nil, fmt.Errorf("%w: %v", ErrLockHeld, err)
			}
			if err != nil {
				return nil, err
			}
			return l.Release, nil
		},
	}
}

// msiAgentVersion reads HKLM\Software\StepSecurity AgentVersion, which only
// the MSI writes (self-update writes RunningVersion).
func msiAgentVersion() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\StepSecurity`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("AgentVersion")
	return v, err
}

// scmService opens the service with only the rights each call needs, so a
// standard user can still query it.
type scmService struct{ name string }

func (s scmService) open(access uint32) (*mgr.Service, func(), error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, err
	}
	name, err := windows.UTF16PtrFromString(s.name)
	if err != nil {
		_ = windows.CloseServiceHandle(m)
		return nil, nil, err
	}
	h, err := windows.OpenService(m, name, access)
	if err != nil {
		_ = windows.CloseServiceHandle(m)
		return nil, nil, err
	}
	return &mgr.Service{Name: s.name, Handle: h}, func() {
		_ = windows.CloseServiceHandle(h)
		_ = windows.CloseServiceHandle(m)
	}, nil
}

func (s scmService) Status() (ServiceStatus, error) {
	svcH, done, err := s.open(windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return ServiceStatus{}, nil
	}
	if err != nil {
		return ServiceStatus{}, err
	}
	defer done()
	q, err := svcH.Query()
	if err != nil {
		return ServiceStatus{}, err
	}
	st := ServiceStatus{Exists: true, Running: q.State == svc.Running, Stopped: q.State == svc.Stopped}
	if c, err := svcH.Config(); err == nil {
		st.BinaryPath = c.BinaryPathName
	}
	return st, nil
}

func (s scmService) Stop() error {
	svcH, done, err := s.open(windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	if _, err := svcH.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	return nil
}

func (s scmService) Start() error {
	svcH, done, err := s.open(windows.SERVICE_START)
	if err != nil {
		return err
	}
	defer done()
	if err := svcH.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

func (s scmService) Delete() error {
	svcH, done, err := s.open(windows.DELETE)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer done()
	// Marked for deletion already: it goes once its last handle closes.
	if err := svcH.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	return nil
}
