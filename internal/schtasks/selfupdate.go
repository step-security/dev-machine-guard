package schtasks

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"os"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// updateTaskName is the SYSTEM self-update task of MSI bootstrap installs.
// It has its own name so the loader's same-name task handling (M-2) never
// touches it.
const updateTaskName = taskName + " (Update)"

// UpdateTaskName is exported for diagnostics (schedinfo-style queries).
const UpdateTaskName = updateTaskName

// Update task settings (spec §2).
const (
	updateInterval       = "PT1H"
	updateRandomDelay    = "PT10M"
	updateBootDelay      = "PT15M"
	updateExecutionLimit = "PT30M"
)

// stopProcessesWait bounds how long uninstall waits for a running scan to
// release the instance mutex before terminating DMG processes.
const stopProcessesWait = 60 * time.Second

// executablePath is swapped by tests.
var executablePath = os.Executable

// resolveBootstrapRoot returns the install root of an MSI bootstrap install
// that agentPath belongs to: the agent's own directory (legacy top-level
// layout) or, for an agent under seed\<v>\ or versions\<v>\, two levels
// up. ok is false when no bootstrap sits in that root.
func resolveBootstrapRoot(exec executor.Executor, agentPath string) (string, bool) {
	return updatestate.BootstrapRoot(agentPath, exec.FileExists)
}

// updateTaskXML renders the full task definition. Only a full XML import can
// express the SYSTEM principal with two triggers, the random and boot delays
// and IgnoreNew in one registration.
func updateTaskXML(bootstrapPath string, start time.Time) string {
	var cmd strings.Builder
	_ = xml.EscapeText(&cmd, []byte(bootstrapPath))
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>StepSecurity</Author>
    <Description>StepSecurity Dev Machine Guard self-update (SYSTEM).</Description>
    <URI>\` + updateTaskName + `</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>` + updateInterval + `</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>` + start.Format("2006-01-02T15:04:05") + `</StartBoundary>
      <Enabled>true</Enabled>
      <RandomDelay>` + updateRandomDelay + `</RandomDelay>
    </TimeTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>` + updateBootDelay + `</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>` + updateExecutionLimit + `</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + cmd.String() + `</Command>
      <Arguments>update</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// updateTaskMismatches lists the required update-task settings xml lacks.
func updateTaskMismatches(taskXML, bootstrapPath string) []string {
	var bad []string
	for _, kv := range [][2]string{
		{"UserId", "S-1-5-18"},
		{"MultipleInstancesPolicy", "IgnoreNew"},
		{"DisallowStartIfOnBatteries", "false"},
		{"StopIfGoingOnBatteries", "false"},
		{"StartWhenAvailable", "true"},
		{"ExecutionTimeLimit", updateExecutionLimit},
		{"Arguments", "update"},
	} {
		if got, ok := xmlElementValue(taskXML, kv[0]); !ok || got != kv[1] {
			// Task Scheduler may render the SYSTEM principal by name.
			if kv[0] == "UserId" && strings.EqualFold(got, "SYSTEM") {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s=%q (want %q)", kv[0], got, kv[1]))
		}
	}
	if got, _ := xmlElementValue(taskXML, "Command"); !strings.EqualFold(strings.Trim(html.UnescapeString(got), `"`), bootstrapPath) {
		bad = append(bad, fmt.Sprintf("Command=%q (want %q)", got, bootstrapPath))
	}
	return bad
}

// installUpdateTask (re)creates the SYSTEM update task from full XML and
// verifies the registration.
func installUpdateTask(ctx context.Context, exec executor.Executor, log *progress.Logger, bootstrapPath string, now time.Time) error {
	if err := importTaskXML(ctx, exec, updateTaskName, updateTaskXML(bootstrapPath, now)); err != nil {
		return err
	}
	out, stderr, code, err := exec.Run(ctx, "schtasks", "/query", "/tn", updateTaskName, "/xml")
	if err != nil || code != 0 {
		return fmt.Errorf("verifying task (exit %d, %v): %s", code, err, strings.TrimSpace(stderr))
	}
	if bad := updateTaskMismatches(decodeTaskXML(out), bootstrapPath); len(bad) > 0 {
		return fmt.Errorf("task registered with wrong settings: %s", strings.Join(bad, ", "))
	}
	log.Progress("  Task: %s", updateTaskName)
	return nil
}

// importTaskXML registers name from a full task XML (UTF-16LE + BOM temp
// file, `schtasks /create /xml … /f`).
func importTaskXML(ctx context.Context, exec executor.Executor, name, taskXML string) error {
	tmp, err := os.CreateTemp("", "stepsec-task-*.xml")
	if err != nil {
		return fmt.Errorf("creating temp task XML: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	_, werr := tmp.Write(encodeTaskXMLUTF16(taskXML))
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("writing temp task XML: %w", werr)
	}
	_, stderr, code, err := exec.Run(ctx, "schtasks", "/create", "/tn", name, "/xml", tmpPath, "/f")
	if err != nil {
		return fmt.Errorf("schtasks /create /xml: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("schtasks /create /xml (exit code %d): %s", code, strings.TrimSpace(stderr))
	}
	return nil
}

// deleteTaskIfPresent deletes name when it is registered. A missing task is
// not an error; a failed delete of a present task is.
func deleteTaskIfPresent(ctx context.Context, exec executor.Executor, log *progress.Logger, name string) error {
	if _, _, code, _ := exec.Run(ctx, "schtasks", "/query", "/tn", name); code != 0 {
		log.Debug("task %q not registered; nothing to delete", name)
		return nil
	}
	_, stderr, code, err := exec.Run(ctx, "schtasks", "/delete", "/tn", name, "/f")
	if err != nil {
		return fmt.Errorf("deleting task %q: %w", name, err)
	}
	if code != 0 {
		return fmt.Errorf("deleting task %q (exit code %d): %s", name, code, strings.TrimSpace(stderr))
	}
	log.Progress("Removed scheduled task: %s", name)
	return nil
}

// Platform hooks, swapped by tests: stop DMG processes under root (waiting
// for the instance mutex first) and delete the RunningVersion value.
var (
	stopDMGProcesses    = stopDMGProcessesPlatform
	deleteRunningVerReg = deleteRunningVersionPlatform
)

// removeAllRetry retries RemoveAll briefly: an image whose process was just
// terminated (or an AV scanner's handle) can keep a file locked for a moment.
func removeAllRetry(dir string) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = os.RemoveAll(dir); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}

// uninstallBootstrap is the MSI bootstrap uninstall (spec §5): delete all 3
// tasks, stop running DMG processes, then remove versions\, state\ and the
// RunningVersion value. ProgramData is left alone (M-8 is out of scope).
// Every step runs even if an earlier one failed; the errors are joined.
func uninstallBootstrap(ctx context.Context, exec executor.Executor, log *progress.Logger, root string) error {
	var errs []error
	for _, name := range []string{taskName, logonTaskName, updateTaskName} {
		if err := deleteTaskIfPresent(ctx, exec, log, name); err != nil {
			errs = append(errs, err)
		}
	}
	if err := stopDMGProcesses(root, stopProcessesWait, log); err != nil {
		log.Warn("stopping running DMG processes: %v", err)
	}
	layout := updatestate.Layout{InstallRoot: root}
	for _, dir := range []string{layout.VersionsDir(), layout.StateDir()} {
		if err := removeAllRetry(dir); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w", dir, err))
		} else {
			log.Debug("removed %s", dir)
		}
	}
	if err := deleteRunningVerReg(); err != nil {
		errs = append(errs, fmt.Errorf("deleting RunningVersion: %w", err))
	}
	if len(errs) == 0 {
		log.Progress("Windows Task Scheduler configuration and self-update state removed successfully")
	}
	return errors.Join(errs...)
}
