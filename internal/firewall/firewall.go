// Package firewall installs, upgrades and removes the Windows on-device
// firewall (the StepSecurityOnDeviceFirewall service, fwpath.Exe) on MSI
// installs, where no PowerShell loader runs. It mirrors the Windows loader's
// firewall step (stepsecurity-loader.ps1, Install-OnDeviceFirewall and
// friends): the same latest-firewall request,
// install directory, named mutex, verification, upgrade with rollback, removal
// and on_device_firewall_* run-status codes.
//
// Who calls it, and when:
//   - Reconcile: the SYSTEM update tick (`self-update --system`), after the
//     agent's own update, only from an MSI layout. On a loader install the
//     loader owns the firewall and this package is never reached.
//   - Uninstall: the agent's `uninstall` on an MSI layout (the MSI's uninstall
//     action), before the scheduled tasks go.
//
// The decision rules:
//   - latest-firewall is asked only when config.json install_on_device_firewall
//     is on or the firewall is present (exe or service), so MSI hosts without
//     the firewall make no extra request.
//   - action "uninstall" (the console's removal feature) removes a present
//     firewall whatever the setting, and is never gated by the MSI version.
//   - action "install" installs or upgrades only when the setting is on and
//     the installed MSI (HKLM\Software\StepSecurity AgentVersion, written only
//     by the MSI) is at least FirstFirewallMSIVersion: an older MSI's uninstall
//     action runs an agent that cannot remove the firewall, which would leave
//     it orphaned on `msiexec /x`.
//   - Every release is verified before anything on the system changes, in
//     every environment: the signed checksum (releasesig, the release key;
//     a missing one is a failure), the download's sha256, a zip holding only
//     the exe, its Authenticode publisher (the agent's own), and the version
//     and build the exe reports.
//   - Nothing here may change the caller's outcome: failures are logged and
//     reported (at most once a day per failure) and the next tick retries.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/fwpath"
	"github.com/step-security/dev-machine-guard/internal/releasesig"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// FirstFirewallMSIVersion is the first MSI whose agent removes the firewall on
// `msiexec /x` (its seed agent has Uninstall). The agent installs the firewall
// only on hosts whose installed MSI is at least this version.
//
// TO BE CONFIRMED AT RELEASE: set to the version of the release that ships
// this package (the next minor after 1.19.1 at the time of writing).
const FirstFirewallMSIVersion = "1.20.0"

const (
	// ServiceName is the firewall's Windows service.
	ServiceName = "StepSecurityOnDeviceFirewall"
	// MutexName serializes install, upgrade and removal with every other
	// installer on the machine. It is the loader's mutex
	// (Global\StepSecurityOnDeviceFirewall); the lock package adds Global\.
	MutexName = "StepSecurityOnDeviceFirewall"
	// InvocationMethod tags this package's run-status failures.
	InvocationMethod = "firewall"
)

// Budgets. The SYSTEM tick gives the whole step ReconcileTimeout.
const (
	ReconcileTimeout  = 6 * time.Minute
	UninstallTimeout  = 3 * time.Minute // lock wait + its uninstall + the stop wait
	apiTimeout        = 30 * time.Second
	apiAttempts       = 3
	apiMaxBytes       = 64 << 10
	downloadTimeout   = 3 * time.Minute
	maxPackageBytes   = 64 << 20
	exeVersionTimeout = 15 * time.Second
	exeCommandTimeout = 60 * time.Second
	stopTimeout       = 45 * time.Second
	// swapBudget covers the swap's worst case: a stop wait and an install,
	// then the rollback's stop wait and install.
	swapBudget         = 2*stopTimeout + 2*exeCommandTimeout
	uninstallLockWait  = 60 * time.Second
	lifecycleAttempts  = 2
	lifecycleTimeout   = 3 * time.Second
	residueChecks      = 5
	residueCheckPeriod = 500 * time.Millisecond
	reportWindow       = 24 * time.Hour
)

// Run-status error types, the loader's names (Send-RunStatusFailed).
const (
	CodeAPIFailed             = "on_device_firewall_api_failed"
	CodeResponseInvalid       = "on_device_firewall_response_invalid"
	CodeSignatureDecodeFailed = "on_device_firewall_signature_decode_failed"
	CodeSignatureInvalid      = "on_device_firewall_signature_verification_failed"
	CodeMktempFailed          = "on_device_firewall_mktemp_failed"
	CodeDownloadFailed        = "on_device_firewall_download_failed"
	CodeChecksumMismatch      = "on_device_firewall_checksum_mismatch"
	CodeUnpackFailed          = "on_device_firewall_unpack_failed"
	CodeAuthenticodeFailed    = "on_device_firewall_authenticode_failed"
	CodeBuildMismatch         = "on_device_firewall_build_mismatch"
	CodeAppInstallFailed      = "on_device_firewall_app_install_failed"
	CodeStopFailed            = "on_device_firewall_stop_failed"
	CodeServiceInstallFailed  = "on_device_firewall_service_install_failed"
	CodeUninstallFailed       = "on_device_firewall_uninstall_failed"
	CodeUnhandledError        = "on_device_firewall_unhandled_error"
	// CodeMSITooOld is new (no loader counterpart): installing was asked
	// for, but the installed MSI predates FirstFirewallMSIVersion.
	CodeMSITooOld = "on_device_firewall_msi_too_old"
)

// Outcome is what one Reconcile did.
type Outcome string

const (
	OutcomeNothing      Outcome = "nothing"       // not asked for, not present
	OutcomeBusy         Outcome = "busy"          // msiexec running or another run holds the lock
	OutcomeNotAvailable Outcome = "not_available" // latest-firewall 404/501
	OutcomeUpToDate     Outcome = "up_to_date"
	OutcomeInstalled    Outcome = "installed"
	OutcomeRemoved      Outcome = "removed"
	OutcomeFailed       Outcome = "failed"
)

// ServiceStatus is the firewall service as SCM reports it.
type ServiceStatus struct {
	Exists, Running, Stopped bool
	// BinaryPath is the service's command line.
	BinaryPath string
}

// ServiceControl is SCM for the firewall service.
type ServiceControl interface {
	Status() (ServiceStatus, error)
	Stop() error // ask it to stop; does not wait
	Start() error
	Delete() error
}

// System is the OS seam (NewSystem builds the real one).
type System struct {
	// Run runs a command with its console hidden (executor.Executor).
	Run func(ctx context.Context, timeout time.Duration, name string, args ...string) (stdout, stderr string, code int, err error)
	// Service controls the firewall service.
	Service ServiceControl
	// ImageRunning reports a process running the image at path.
	ImageRunning func(path string) bool
	// MSIVersion is HKLM\Software\StepSecurity AgentVersion.
	MSIVersion func() (string, error)
	// VerifyPublisher checks candidate's Authenticode signature against
	// self's publisher (authenticode.SamePublisher).
	VerifyPublisher func(candidate, self string) error
	// InstallerBusy reports a Windows Installer transaction in progress.
	InstallerBusy func() bool
	// Elevated reports an administrator or SYSTEM process.
	Elevated func() bool
	// Lock takes MutexName without blocking; held wraps lock.ErrHeld.
	Lock func() (release func(), err error)
}

// ErrLockHeld is what a System.Lock returns (wrapped) while another process
// holds the firewall mutex.
var ErrLockHeld = errors.New("the on-device firewall lock is held")

// Manager manages the firewall on one machine. The zero values of the
// optional fields take the defaults in normalize.
type Manager struct {
	APIEndpoint, CustomerID, APIKey string
	// AgentVersion is this agent's version (headers).
	AgentVersion string
	HTTP         *http.Client
	DeviceID     func() string
	// Arch is the machine's native arch (selfupdate.NativeArch).
	Arch string
	// LagBehind and CooldownHours are the update-policy override, sent like
	// latest-binary's.
	LagBehind, CooldownHours int
	// WantInstall is config.json install_on_device_firewall.
	WantInstall bool
	// ConfigPath is the config.json the service reads (`install --config`).
	ConfigPath string
	// Dir and DataDir are the install and data dirs (fwpath).
	Dir, DataDir string
	// StateDir is a SYSTEM/Administrators-only dir for staging and the
	// report state (the MSI layout's state\).
	StateDir string
	// SelfExe is this agent's exe, the Authenticode reference.
	SelfExe string

	Sys System
	// Report posts a run-status failure (message "<code>: <detail>").
	Report func(ctx context.Context, msg string) error
	Logf   func(format string, args ...any)
	Now    func() time.Time
	Sleep  func(ctx context.Context, d time.Duration) error

	// verifyChecksum is releasesig.VerifyChecksum; tests replace it (the
	// release key's private half is not in this repository).
	verifyChecksum func(checksum string, sigFile []byte) error
}

func (m *Manager) normalize() {
	if m.Dir == "" {
		m.Dir = fwpath.Dir()
	}
	if m.DataDir == "" {
		m.DataDir = fwpath.DataDir()
	}
	if m.HTTP == nil {
		m.HTTP = http.DefaultClient
	}
	if m.DeviceID == nil {
		m.DeviceID = func() string { return "" }
	}
	if m.Logf == nil {
		m.Logf = func(string, ...any) {}
	}
	if m.Report == nil {
		m.Report = func(context.Context, string) error { return nil }
	}
	if m.Now == nil {
		m.Now = time.Now
	}
	if m.Sleep == nil {
		m.Sleep = sleepCtx
	}
	if m.verifyChecksum == nil {
		m.verifyChecksum = releasesig.VerifyChecksum
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (m *Manager) exe() string { return filepath.Join(m.Dir, fwpath.ExeName) }

// present reports the firewall's exe or service on this machine.
func (m *Manager) present() bool {
	if fileExists(m.exe()) {
		return true
	}
	st, err := m.Sys.Service.Status()
	return err == nil && st.Exists
}

func fileExists(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// msiAllowsInstall reports whether the installed MSI is new enough to remove
// the firewall again on uninstall, and why not.
func (m *Manager) msiAllowsInstall() (bool, string) {
	min, err := updatestate.ParseVersion(FirstFirewallMSIVersion)
	if err != nil {
		return false, fmt.Sprintf("FirstFirewallMSIVersion %q: %v", FirstFirewallMSIVersion, err)
	}
	raw, err := m.Sys.MSIVersion()
	if err != nil {
		return false, fmt.Sprintf("the installed MSI version (HKLM\\Software\\StepSecurity AgentVersion) cannot be read: %v", err)
	}
	v, err := updatestate.ParseVersion(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Sprintf("the installed MSI version %q is not x.y.z", raw)
	}
	if updatestate.Compare(v, min) < 0 {
		return false, fmt.Sprintf("the installed MSI is %s; installing the on-device firewall needs MSI %s or later (its uninstall removes the firewall); redeploy the current MSI", v, min)
	}
	return true, ""
}

// Reconcile is the firewall step of the SYSTEM update tick: install, upgrade
// or remove the firewall as latest-firewall says. ctx bounds it
// (ReconcileTimeout). It never panics past its caller: a panic is reported as
// on_device_firewall_unhandled_error, so the update tick's exit code, which
// the bootstrap counts, is never affected.
func (m *Manager) Reconcile(ctx context.Context) (out Outcome) {
	m.normalize()
	defer func() {
		if r := recover(); r != nil {
			m.Logf("firewall: unhandled error: %v", r)
			m.fail(ctx, CodeUnhandledError, "", fmt.Sprint(r))
			out = OutcomeFailed
		}
	}()
	present := m.present()
	if !m.WantInstall && !present {
		return OutcomeNothing
	}
	if m.Sys.InstallerBusy() {
		m.Logf("firewall: a Windows Installer transaction is running; skipping the on-device firewall on this tick")
		return OutcomeBusy
	}
	release, err := m.Sys.Lock()
	if err != nil {
		m.Logf("firewall: another run is installing or removing the on-device firewall (%v); skipping it on this tick", err)
		return OutcomeBusy
	}
	defer release()

	msiOK, msiWhy := m.msiAllowsInstall()
	if m.WantInstall && !present && !msiOK {
		// Nothing to remove and nothing we may install: no request.
		m.Logf("firewall: not installing the on-device firewall: %s", msiWhy)
		m.fail(ctx, CodeMSITooOld, "", msiWhy)
		return OutcomeFailed
	}

	resp, out := m.fetchLatest(ctx)
	if resp == nil {
		return out
	}
	if resp.Action == actionUninstall {
		m.Logf("firewall: the on-device firewall is set to be removed from this device")
		return m.removeOnRequest(ctx)
	}
	// Asked only because the firewall is present: install answers are left
	// alone, as the loader does.
	if !m.WantInstall {
		return OutcomeNothing
	}
	if !msiOK {
		m.Logf("firewall: not upgrading the on-device firewall: %s", msiWhy)
		m.fail(ctx, CodeMSITooOld, "", msiWhy)
		return OutcomeFailed
	}
	rel, ok := m.validate(ctx, resp)
	if !ok {
		return OutcomeFailed
	}
	if !m.verifySignature(ctx, rel) {
		return OutcomeFailed
	}
	return m.installRelease(ctx, rel)
}

// Uninstall removes a present firewall for the agent's `uninstall`: its own
// `uninstall`, then the service, the install dir and the data dir. It returns
// what is left (empty when all is gone, or when nothing was installed) and
// reports residue as on_device_firewall_uninstall_failed. It never fails the
// caller's uninstall.
func (m *Manager) Uninstall(ctx context.Context) (left []string) {
	m.normalize()
	defer func() {
		if r := recover(); r != nil {
			m.Logf("firewall: unhandled error: %v", r)
			m.fail(ctx, CodeUnhandledError, "", fmt.Sprint(r))
			left = []string{fmt.Sprintf("on-device firewall (%s, service %s)", m.Dir, ServiceName)}
		}
	}()
	if !m.present() {
		return nil
	}
	m.Logf("firewall: removing the on-device firewall...")
	release, err := m.acquireWait(ctx, uninstallLockWait)
	if err != nil {
		left = []string{"on-device firewall (another run held its lock)"}
	} else {
		left = m.remove(ctx)
		release()
	}
	if len(left) > 0 {
		what := strings.Join(left, ", ")
		m.Logf("firewall: on-device firewall removal incomplete; still present: %s", what)
		m.fail(ctx, CodeUninstallFailed, "", "Still present after removing the on-device firewall: "+what)
	}
	return left
}

// acquireWait retries Sys.Lock until wait passes.
func (m *Manager) acquireWait(ctx context.Context, wait time.Duration) (func(), error) {
	deadline := m.Now().Add(wait)
	for {
		release, err := m.Sys.Lock()
		if err == nil {
			return release, nil
		}
		if !errors.Is(err, ErrLockHeld) || !m.Now().Before(deadline) {
			return nil, err
		}
		if serr := m.Sleep(ctx, time.Second); serr != nil {
			return nil, err
		}
	}
}
