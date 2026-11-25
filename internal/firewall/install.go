package firewall

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

// installRelease applies an install answer: nothing when the installed exe
// is rel and the service runs it with this ConfigPath; otherwise stage and
// verify, copy the new exe beside the old one (.next), stop the service
// (at most stopTimeout), keep the old exe (.old), move the new one in and run
// its `install --config <ConfigPath>`, which registers (or updates) and
// starts the service. When that fails the old exe comes back and is
// installed again. The loader's Install-OnDeviceFirewall.
func (m *Manager) installRelease(ctx context.Context, rel release) Outcome {
	exe := m.exe()
	installed := m.exeVersionOf(ctx, exe)
	if installed.matches(rel) && m.serviceCurrent() {
		m.Logf("firewall: on-device firewall %s is up to date and running", rel)
		m.clearReports()
		return OutcomeUpToDate
	}

	// Staging gets what is left of ctx minus swapBudget; the swap, once
	// started, runs to its end on its own budget: an install cancelled
	// half-way would leave the service stopped.
	stageCtx := ctx
	if dl, has := ctx.Deadline(); has {
		var cancel context.CancelFunc
		stageCtx, cancel = context.WithDeadline(ctx, dl.Add(-swapBudget))
		defer cancel()
	}
	staged, dir, ok := m.stage(stageCtx, rel)
	if dir != "" {
		defer func() { _ = os.RemoveAll(dir) }()
	}
	if !ok {
		return OutcomeFailed
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), swapBudget)
	defer cancel()

	// Copy the new exe next to the old one while the old one still runs, so
	// a failed copy leaves the installed firewall untouched.
	next, old := exe+".next", exe+".old"
	if err := os.MkdirAll(m.Dir, 0o755); err != nil { // #nosec G301 -- Program Files: SYSTEM/Admins write, Users read
		m.appInstallFailed(ctx, rel, fmt.Sprintf("Failed to create %s: %v", m.Dir, err))
		return OutcomeFailed
	}
	_ = os.Remove(next)
	if err := copyFile(staged, next); err != nil {
		_ = os.Remove(next)
		m.appInstallFailed(ctx, rel, fmt.Sprintf("Failed to copy the on-device firewall to %s: %v", m.Dir, err))
		return OutcomeFailed
	}

	st, _ := m.Sys.Service.Status()
	hadService := st.Exists
	if hadService {
		m.Logf("firewall: stopping the installed on-device firewall %s...", installed)
		if !m.stopAndWait(ctx) {
			_ = os.Remove(next)
			msg := fmt.Sprintf("Service %s still running %s after stop", ServiceName, stopTimeout)
			m.Logf("firewall: the on-device firewall service did not stop, not replacing it")
			m.fail(ctx, CodeStopFailed, rel.key(), msg)
			// Leave it running as it was.
			_ = m.Sys.Service.Start()
			return OutcomeFailed
		}
	}

	// Renames in one dir, so the exe is never left half copied.
	hasOld := false
	_ = os.Remove(old)
	err := func() error {
		if fileExists(exe) {
			if err := os.Rename(exe, old); err != nil {
				return err
			}
			hasOld = true
		}
		return os.Rename(next, exe)
	}()
	if err != nil {
		if hasOld && !fileExists(exe) {
			_ = os.Rename(old, exe)
		}
		_ = os.Remove(next)
		if hadService {
			_ = m.Sys.Service.Start()
		}
		m.appInstallFailed(ctx, rel, fmt.Sprintf("Failed to install %s: %v", exe, err))
		return OutcomeFailed
	}

	if out, code, ierr := m.runExe(ctx, exe, "install", "--config", m.ConfigPath); ierr != nil || code != 0 {
		rolledBack := "no previous version"
		if hasOld {
			m.Logf("firewall: the on-device firewall's install failed (exit %d); restoring the previous version", code)
			rolledBack = m.rollback(ctx, exe, old)
		}
		msg := fmt.Sprintf("%s install failed for %s (exit %d): %s (%s)", exe, rel.Version, code, out, rolledBack)
		m.Logf("firewall: failed to install the on-device firewall service: %s", msg)
		m.fail(ctx, CodeServiceInstallFailed, rel.key(), msg)
		return OutcomeFailed
	}
	// Best effort: a leftover is removed by the next upgrade.
	if hasOld {
		_ = os.Remove(old)
	}
	m.Logf("firewall: on-device firewall %s installed and started", rel)
	m.clearReports()
	return OutcomeInstalled
}

func (m *Manager) appInstallFailed(ctx context.Context, rel release, msg string) {
	m.Logf("firewall: failed to install the on-device firewall: %s", msg)
	m.fail(ctx, CodeAppInstallFailed, rel.key(), msg)
}

// rollback puts the previous exe back and installs it again; it returns
// what happened, for the failure report.
func (m *Manager) rollback(ctx context.Context, exe, old string) string {
	_ = m.stopAndWait(ctx)
	if err := os.Remove(exe); err != nil && !os.IsNotExist(err) {
		return fmt.Sprintf("previous version restore failed: %v", err)
	}
	if err := os.Rename(old, exe); err != nil {
		return fmt.Sprintf("previous version restore failed: %v", err)
	}
	if out, code, err := m.runExe(ctx, exe, "install", "--config", m.ConfigPath); err != nil || code != 0 {
		return "previous version restored, its install failed: " + out
	}
	return "previous version restored"
}

// runExe runs the firewall exe with exeCommandTimeout; out is its combined
// output, trimmed.
func (m *Manager) runExe(ctx context.Context, exe string, args ...string) (out string, code int, err error) {
	stdout, stderr, code, err := m.Sys.Run(ctx, exeCommandTimeout, exe, args...)
	out = strings.TrimSpace(strings.TrimSpace(stdout) + " " + strings.TrimSpace(stderr))
	if err != nil && out == "" {
		out = err.Error()
	}
	return out, code, err
}

// serviceCurrent reports the service running the installed exe with
// --config ConfigPath. A config path that moved needs `install` again.
func (m *Manager) serviceCurrent() bool {
	st, err := m.Sys.Service.Status()
	if err != nil || !st.Exists || !st.Running {
		return false
	}
	cmd := strings.ToLower(st.BinaryPath)
	return strings.Contains(cmd, strings.ToLower(m.exe())) &&
		strings.Contains(cmd, "--config") &&
		strings.Contains(cmd, strings.ToLower(m.ConfigPath))
}

// stopAndWait stops the service and waits until it has stopped and no
// process runs the installed exe, at most stopTimeout. True when nothing
// runs any more (or there is no service). Stopping runs the firewall's
// teardown, which removes its NRPT rule, so DNS falls back to normal.
func (m *Manager) stopAndWait(ctx context.Context) bool {
	st, err := m.Sys.Service.Status()
	if err == nil && !st.Exists {
		return !m.Sys.ImageRunning(m.exe())
	}
	if err == nil && !st.Stopped {
		if serr := m.Sys.Service.Stop(); serr != nil {
			m.Logf("firewall: stopping %s: %v", ServiceName, serr)
		}
	}
	deadline := m.Now().Add(stopTimeout)
	for {
		st, err := m.Sys.Service.Status()
		stopped := err == nil && (!st.Exists || st.Stopped)
		if stopped && !m.Sys.ImageRunning(m.exe()) {
			return true
		}
		if !m.Now().Before(deadline) {
			return false
		}
		if m.Sleep(ctx, residueCheckPeriod*2) != nil {
			return false
		}
	}
}

// removeOnRequest is latest-firewall's "uninstall": nothing to do (and
// nothing reported) when the firewall is absent; otherwise remove it, report
// residue as on_device_firewall_uninstall_failed, or, when all is gone, tell
// the API so the console shows the device as removed at once.
func (m *Manager) removeOnRequest(ctx context.Context) Outcome {
	if !m.present() {
		m.Logf("firewall: the on-device firewall is set to be removed and is not installed")
		return OutcomeNothing
	}
	m.Logf("firewall: removing the on-device firewall as requested by the console...")
	if left := m.remove(ctx); len(left) > 0 {
		what := strings.Join(left, ", ")
		m.Logf("firewall: on-device firewall removal incomplete; still present: %s", what)
		m.fail(ctx, CodeUninstallFailed, "", "Still present after removing the on-device firewall: "+what)
		return OutcomeFailed
	}
	m.Logf("firewall: the on-device firewall was removed as requested by the console")
	m.clearReports()
	m.sendRemoved(ctx)
	return OutcomeRemoved
}

// remove is the loader's Uninstall-OnDeviceFirewall: the firewall's own
// `uninstall` first, while the exe is intact (it stops and deletes the
// service and removes the NRPT rule), then the service as a fallback, then
// the install dir and the data dir. It returns what is left.
func (m *Manager) remove(ctx context.Context) []string {
	if !m.Sys.Elevated() {
		m.Logf("firewall: removing the on-device firewall needs an elevated run (administrator or SYSTEM)")
		return []string{fmt.Sprintf("on-device firewall (%s, service %s)", m.Dir, ServiceName)}
	}
	exe := m.exe()
	if fileExists(exe) {
		if out, code, err := m.runExe(ctx, exe, "uninstall"); err != nil || code != 0 {
			m.Logf("firewall: the on-device firewall's uninstall did not complete (exit %d): %s; continuing", code, out)
		}
	}
	if st, err := m.Sys.Service.Status(); err == nil && st.Exists {
		// Removing the exe under a running service would break its
		// teardown: keep both and report them as left behind.
		if !m.stopAndWait(ctx) {
			m.Logf("firewall: the on-device firewall service did not stop, leaving it installed")
			return []string{"service " + ServiceName, m.Dir}
		}
		if err := m.Sys.Service.Delete(); err != nil {
			m.Logf("firewall: deleting %s: %v", ServiceName, err)
		}
	}
	_ = os.RemoveAll(m.Dir)
	if m.DataDir != "" {
		_ = os.RemoveAll(m.DataDir)
	}
	var left []string
	// A deleted service disappears once its last handle closes.
	for i := 0; i < residueChecks; i++ {
		left = nil
		if st, err := m.Sys.Service.Status(); err != nil || st.Exists {
			left = append(left, "service "+ServiceName)
		}
		if _, err := os.Lstat(m.Dir); err == nil {
			left = append(left, m.Dir)
		}
		if m.DataDir != "" {
			if _, err := os.Lstat(m.DataDir); err == nil {
				left = append(left, m.DataDir)
			}
		}
		if len(left) == 0 || i == residueChecks-1 {
			break
		}
		if m.Sleep(ctx, residueCheckPeriod) != nil {
			break
		}
	}
	if len(left) == 0 {
		m.Logf("firewall: removed the on-device firewall")
	}
	return left
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- our staged exe
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) // #nosec G302 G304 -- an exe beside the installed one
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
