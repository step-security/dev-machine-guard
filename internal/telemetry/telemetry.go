package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/detector"
	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// s3UploadBackoffUnit is multiplied by attempt-number to compute the
// inter-attempt sleep on S3 PUT retries. Lifted to a package var so tests
// can shrink it; production code never mutates it.
var s3UploadBackoffUnit = 2 * time.Second

// Payload is the enterprise telemetry JSON structure.
type Payload struct {
	CustomerID     string                 `json:"customer_id"`
	DeviceID       string                 `json:"device_id"`
	SerialNumber   string                 `json:"serial_number"`
	UserIdentity   string                 `json:"user_identity"`
	Hostname       string                 `json:"hostname"`
	Platform       string                 `json:"platform"`
	OSVersion      string                 `json:"os_version"`
	Resources      model.MachineResources `json:"resources"`
	AgentVersion   string                 `json:"agent_version"`
	CollectedAt    int64                  `json:"collected_at"`
	NoUserLoggedIn bool                   `json:"no_user_logged_in"`

	// InvocationMethod is "install" when the agent ran from an installed
	// launchd/systemd/schtasks unit, "one_time" for a manual CLI run.
	// Duplicated on this struct (also lives on the run-status row) so the
	// stored telemetry record is self-describing for backfills.
	InvocationMethod string `json:"invocation_method,omitempty"`

	// StatusInfo carries the final phase completion list and total elapsed
	// time the agent saw at upload time. Snapshot of the same RunStatusInfo
	// streamed via the run-status endpoint during the run.
	StatusInfo *RunStatusInfo `json:"status_info,omitempty"`

	IDEExtensions        []model.Extension               `json:"ide_extensions"`
	IDEInstallations     []model.IDE                     `json:"ide_installations"`
	NodePkgManagers      []model.PkgManager              `json:"node_package_managers"`
	NodeGlobalPackages   []model.NodeScanResult          `json:"node_global_packages"`
	NodeProjects         []model.NodeScanResult          `json:"node_projects"`
	BrewPkgManager       *model.PkgManager               `json:"brew_package_manager,omitempty"`
	BrewScans            []model.BrewScanResult          `json:"brew_scans"`
	BrewFormulae         []model.BrewPackage             `json:"brew_formulae,omitempty"`
	BrewCasks            []model.BrewPackage             `json:"brew_casks,omitempty"`
	PythonPkgManagers    []model.PkgManager              `json:"python_package_managers"`
	PythonGlobalPackages []model.PythonScanResult        `json:"python_global_packages"`
	PythonProjects       []model.ProjectInfo             `json:"python_projects"`
	SystemPackageScans   []model.SystemPackageScanResult `json:"system_package_scans"`
	AIAgents             []model.AITool                  `json:"ai_agents"`
	MCPConfigs           []model.MCPConfigEnterprise     `json:"mcp_configs"`
	NPMRCAudit           *model.NPMRCAudit               `json:"npmrc_audit,omitempty"`
	PipAudit             *model.PipAudit                 `json:"pip_audit,omitempty"`
	PnpmAudit            *model.PnpmAudit                `json:"pnpm_audit,omitempty"`
	BunAudit             *model.BunAudit                 `json:"bun_audit,omitempty"`
	YarnAudit            *model.YarnAudit                `json:"yarn_audit,omitempty"`

	ExecutionLogs      *ExecutionLogs      `json:"execution_logs,omitempty"`
	PerformanceMetrics *PerformanceMetrics `json:"performance_metrics,omitempty"`
}

type ExecutionLogs struct {
	OutputBase64 string `json:"output_base64"`
	StartTime    int64  `json:"start_time"`
	EndTime      int64  `json:"end_time"`
	ExitCode     int    `json:"exit_code"`
	AgentVersion string `json:"agent_version"`
}

type PerformanceMetrics struct {
	ExtensionsCount       int   `json:"extensions_count"`
	NodePackagesScanMs    int64 `json:"node_packages_scan_ms"`
	NodeGlobalPkgsCount   int   `json:"node_global_packages_count"`
	NodeProjectsCount     int   `json:"node_projects_count"`
	BrewFormulaeCount     int   `json:"brew_formulae_count"`
	BrewCasksCount        int   `json:"brew_casks_count"`
	PythonGlobalPkgsCount int   `json:"python_global_packages_count"`
	PythonProjectsCount   int   `json:"python_projects_count"`
	SystemPackagesCount   int   `json:"system_packages_count"`
}

// Run executes enterprise telemetry: scan, build payload, upload to S3.
// Output format matches the shell script's sample_log:
//
//	==========================================
//	StepSecurity Device Agent v1.9.1
//	==========================================
//	[scanning] Lock acquired (PID: 32560)
//	[scanning] Device ID (Serial): ...
//	...
func Run(exec executor.Executor, log *progress.Logger, cfg *cli.Config) (err error) {
	// runCtx is the cancel-only outer context used by the heartbeat
	// goroutine, the phase-post worker, and the final telemetry upload —
	// none of which should be subject to the optional scan deadline below.
	// The deferred cancelRun() is a safety net for early returns (lock
	// failure, etc.) that bail before the goroutines are even spawned;
	// double-cancel on the normal path is a no-op.
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()

	// ctx is the scan body's working context. It carries the optional
	// global scan deadline so a single hung subprocess (Electron
	// --version, npm ls on a runaway monorepo) cannot hold the agent
	// open for the full 24h TTL window. Override via STEPSEC_MAX_SCAN_DURATION
	// (Go duration syntax: "45m", "2h"). Set to "0" to disable. The
	// telemetry upload below uses runCtx so partial data still ships when
	// the deadline trips mid-scan.
	ctx := runCtx
	if d := scanDeadlineFromEnv(defaultScanDeadline); d > 0 {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithTimeout(runCtx, d)
		defer cancelDeadline()
		log.Debug("scan deadline armed: %s", d)
	}

	startTime := time.Now()

	// Detect invocation method once at run start: "install" if the platform's
	// scheduler footprint is on disk, else "one_time". Threaded into every
	// run-status post and stamped on the final payload.
	invocationMethod := DetectInvocationMethod()

	// Phase tracker accumulates per-analysis-section completions so the
	// backend can surface in-flight progress on the console. Reads from the
	// heartbeat goroutine are mutex-guarded inside Snapshot.
	tracker := NewPhaseTracker()

	// Generate a per-run execution ID up front so failures before device.Gather
	// can still be attributed. Fall back to a timestamp-derived ID if crypto/rand
	// errors (vanishingly unlikely) — reporting is best-effort and must never
	// block the scan itself.
	executionID, idErr := newExecutionID()
	if idErr != nil {
		executionID = fmt.Sprintf("nouuid-%d", time.Now().UnixNano())
		fmt.Fprintf(os.Stderr, "[warn] failed to generate execution id, using fallback: %v\n", idErr)
	}

	// deviceID is populated once device.Gather completes; the closure below
	// captures it by reference so the deferred failure report uses whatever is
	// known at the point of failure (empty is tolerated by the backend).
	var deviceID string

	// Ensures exactly one "failed" report lands per run. The signal handler
	// goroutine and the deferred recovery can both fire in quick succession
	// during cancellation — only the first one through should post.
	var reportedFailed atomic.Bool
	reportFailedOnce := func(errMsg string) {
		if reportedFailed.CompareAndSwap(false, true) {
			reportRunStatus(context.Background(), log, executionID, deviceID, runStatusFailed, errMsg, invocationMethod)
		}
	}

	// Phase-boundary progress posts run on a dedicated worker so the scan
	// never blocks on HTTP at a call site. Buffer=1 + drop-oldest send
	// gives us two properties together:
	//   - Strict ordering: a single consumer means the backend can never
	//     see an older snapshot land after a newer one (which would cause
	//     the console UI to briefly regress on degraded networks).
	//   - Bounded resources: at most one pending snapshot is queued; a
	//     slow-network backlog can't grow across the 11+ inline call
	//     sites. The latest snapshot always wins, which matches what an
	//     operator watching progress actually cares about.
	//
	// Without this, blocking phase posts could add the per-call retry
	// budget (~6s: 2 attempts × 3s HTTP timeout + 500ms backoff) to each
	// call site, compounding to over a minute of added scan latency on a
	// degraded link for purely best-effort progress data.
	phaseCh := make(chan RunStatusInfo, 1)
	phaseDone := make(chan struct{})
	var phaseSendMu sync.Mutex // serialises drain+send so concurrent producers (main scan + heartbeat) don't race
	go func() {
		defer close(phaseDone)
		// process posts one snapshot using a Background-derived ctx with
		// a bounded per-post timeout. We deliberately do NOT chain off the
		// scan ctx here: the final phase-boundary post (which is the only
		// snapshot that includes "telemetry_upload" in phases_completed)
		// arrives at the worker *after* the function body returns and the
		// deferred cancelRun() fires. If we shared the scan ctx, that post
		// would always be cancelled mid-flight and the backend would never
		// learn the upload completed. The 10s budget covers postProgress's
		// own internal retry window (2×3s + 500ms backoff) with slack.
		process := func(snap RunStatusInfo) {
			postCtx, postCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer postCancel()
			postProgress(postCtx, log, executionID, deviceID, invocationMethod, snap)
		}
		for {
			select {
			case snap := <-phaseCh:
				process(snap)
			case <-runCtx.Done():
				// Drain any queued snapshot before exiting. Without this,
				// a naïve select on the next iteration would 50/50 between
				// the ready ctx.Done() and the ready phaseCh — dropping
				// the final post is exactly what the user reports as
				// "telemetry_upload missing from phases_completed".
				for {
					select {
					case snap := <-phaseCh:
						process(snap)
					default:
						return
					}
				}
			}
		}
	}()

	// tailEmitter is bound to the LogCapture initialized further down in
	// this function. It's declared as a nil pointer here so postPhase can
	// close over it; logTailEmitter.MaybeAttach is nil-safe, so the brief
	// window before StartCapture runs (lock acquisition, banner) just
	// produces snapshots without a log tail.
	var tailEmitter *logTailEmitter

	// sendSnapshot builds a progress snapshot, lets attach() decide the log
	// tail, and hands it to the phase-post worker (drop-oldest so the freshest
	// snapshot always lands).
	sendSnapshot := func(attach func(*RunStatusInfo)) {
		snap := tracker.Snapshot()
		attach(&snap)
		phaseSendMu.Lock()
		defer phaseSendMu.Unlock()
		// Drop any queued (older) snapshot so the freshest one always lands.
		select {
		case <-phaseCh:
		default:
		}
		// Always succeeds: buffer=1, just drained, single sender under the mutex.
		phaseCh <- snap
	}

	// postPhase is the convergence point for phase-boundary and heartbeat
	// progress updates. Captured here so the heartbeat goroutine and the
	// inline phase wrappers share a single call site. The log tail is
	// throttle-gated (MaybeAttach) so rapid phase boundaries don't each ship one.
	postPhase := func() { sendSnapshot(tailEmitter.MaybeAttach) }

	// postPhaseFinal is the single post emitted after the telemetry upload
	// completes. It FORCES a fresh tail (ForceAttach, bypassing the throttle)
	// so the run-status row's log tail includes the upload's own output and the
	// completion line — the final lines a throttled MaybeAttach would drop on a
	// short run.
	postPhaseFinal := func() { sendSnapshot(tailEmitter.ForceAttach) }

	// Catch SIGINT / SIGTERM so cancellation (Ctrl+C, launchd stop, kill)
	// still records a failure row and fires the Slack alert before exit.
	// Go's default signal disposition terminates the process without running
	// defers, which would silently drop the signal — we intercept it here.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sigHandlerDone := make(chan struct{})
	go func() {
		select {
		case sig := <-sigCh:
			fmt.Fprintf(os.Stderr, "\n[cancel] received %s, reporting failure before exit\n", sig)
			reportFailedOnce(fmt.Sprintf("%s: %s", runStatusCancelled, sig))
			// Best-effort lock cleanup. A new run can recover from a stale
			// lock file on its own via lock.Acquire; this is just polite.
			os.Exit(130) // conventional exit code for SIGINT
		case <-sigHandlerDone:
			return
		}
	}()

	// Global recovery + failure report. Runs on panic and on any non-nil error
	// return. Uses context.Background() because the original ctx may be the
	// source of the failure (e.g., context deadline exceeded). Success is
	// reported by the backend worker after it finishes processing the uploaded
	// telemetry — not here.
	defer func() {
		// Stop the signal goroutine so it doesn't leak between test runs /
		// subsequent invocations in long-running processes.
		signal.Stop(sigCh)
		close(sigHandlerDone)

		if r := recover(); r != nil {
			err = fmt.Errorf("panic in telemetry.Run: %v", r)
			reportFailedOnce(err.Error())
			return
		}
		if err != nil {
			reportFailedOnce(err.Error())
		}
	}()

	// Start capturing all stderr output for execution_logs.
	// Defer Finalize immediately to ensure stderr is always restored,
	// even on early returns (e.g., lock failure).
	capture := StartCapture()
	defer capture.Finalize()

	// Bind the throttled log-tail emitter to the live capture so every
	// subsequent postPhase() can ship a recent stderr slice attached to
	// status_info on the throttle's cadence. See log_tail_emitter.go.
	tailEmitter = newLogTailEmitter(capture, logTailHeartbeatInterval)

	// Banner (matches shell script format)
	fmt.Fprintf(os.Stderr, "==========================================\n")
	fmt.Fprintf(os.Stderr, "StepSecurity Device Agent v%s\n", buildinfo.Version)
	fmt.Fprintf(os.Stderr, "==========================================\n\n")

	// Acquire lock
	lk, err := lock.Acquire(exec)
	if err != nil {
		log.Debug("lock acquisition failed: %v", err)
		return fmt.Errorf("acquiring lock: %w", err)
	}
	log.Debug("lock acquired (pid=%d)", os.Getpid())
	defer func() {
		lk.Release()
		log.Progress("Lock released (PID: %d)", os.Getpid())
	}()
	log.Progress("Lock acquired (PID: %d)", os.Getpid())

	// Device info — first tracked phase. Completes before the "started"
	// post so the first heartbeat already includes it in phases_completed.
	phaseCtx, phaseCancel := startPhase(ctx, tracker, "device_info")
	log.Progress("Gathering device information...")
	dev := device.Gather(phaseCtx, exec)
	deviceID = dev.SerialNumber
	// Single source of truth for "is this a real developer or a daemon
	// context?" — same predicate the payload uses below, so the warning,
	// the Developer: line, and the telemetry field always agree.
	noUserLoggedIn := dev.UserIdentity == "" ||
		dev.UserIdentity == "unknown" ||
		(dev.UserIdentity == "root" && exec.IsRoot())
	log.Progress("Device ID (Serial): %s", dev.SerialNumber)
	log.Progress("OS Version: %s", dev.OSVersion)
	if noUserLoggedIn {
		log.Progress("Developer: (no user logged in)")
	} else {
		log.Progress("Developer: %s", dev.UserIdentity)
	}
	log.Debug("device gathered: hostname=%q platform=%q serial=%q user_identity=%q no_user=%v", dev.Hostname, dev.Platform, dev.SerialNumber, dev.UserIdentity, noUserLoggedIn)
	if dev.SerialNumber == "" {
		log.Warn("device serial number could not be determined — telemetry will upload with empty device_id")
	}
	if noUserLoggedIn {
		log.Warn("no real developer identity (UserIdentity=%q, root=%v) — telemetry will be marked no_user_logged_in", dev.UserIdentity, exec.IsRoot())
	}
	endPhase(phaseCtx, phaseCancel, tracker, log, "device_info")

	// Report "started" now that we have a device_id. Fire-and-forget.
	reportRunStatus(ctx, log, executionID, deviceID, runStatusStarted, "", invocationMethod)

	// First progress upsert: surfaces device_info completion immediately
	// without waiting for the 5-minute heartbeat. Safe to call after the
	// "started" post because the backend now has a row to upsert into.
	postPhase()

	// Heartbeat goroutine: pushes status_info on a ticker so a long-running
	// phase (brew on a 200k-package macbook, syspkg on a fat dpkg machine)
	// still surfaces progress to the console between phase boundaries.
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(runStatusHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				postPhase()
			}
		}
	}()
	// Shut down both the heartbeat goroutine and the phase-post worker
	// cleanly on return. Order matters: cancel first so both goroutines
	// see ctx.Done() and exit, THEN wait for each to close its done
	// channel. Splitting these into separate `defer` statements would
	// deadlock — LIFO would block on the waits before cancel fires.
	defer func() {
		cancelRun()
		<-heartbeatDone
		<-phaseDone
	}()

	// Detect the logged-in user so package-manager commands run with that
	// user's PATH/env in both deployment modes: as root (LaunchDaemon / MDM
	// "Run Script") we sudo to them; as the user (LaunchAgent's periodic fire)
	// we already are them but still go through their login shell because
	// launchd hands a stripped PATH either way. Skip "root" — if LoggedInUser()
	// fell back to CurrentUser() and that is root, there's no user context to
	// adopt and delegating is pointless.
	loggedInUsername := ""
	if u, err := exec.LoggedInUser(); err == nil && u.Username != "root" {
		loggedInUsername = u.Username
		log.Debug("logged-in user detected: username=%q home=%q — commands will run through the user's login shell", u.Username, u.HomeDir)
	} else if err != nil {
		log.Warn("could not detect logged-in user (%v) — package manager commands will run as current user and may return different results", err)
	} else {
		log.Debug("LoggedInUser() returned root — not delegating")
	}

	// Create a user-aware executor that runs commands through the logged-in
	// user's login shell (rc files sourced for a full PATH). This ensures tools
	// like brew, pip3, npm etc. execute in the correct user context — launchd
	// strips PATH whether the agent runs as root or as the user, and many tools
	// refuse to run as root or return different results. File-based detectors
	// (IDE, extensions, MCP) use the original exec since file operations don't
	// need user delegation.
	userExec := executor.NewUserAwareExecutor(exec, loggedInUsername)

	// Resolve search dirs
	searchDirs := resolveSearchDirs(exec, cfg.SearchDirs)
	log.Debug("search directories resolved: %v", searchDirs)
	fmt.Fprintln(os.Stderr)

	// Build a TCC skipper so directory walks avoid macOS-protected dirs and
	// don't trigger system permission prompts when the agent runs without
	// Full Disk Access. Nil when --include-tcc-protected is set; ShouldSkip
	// is nil-safe.
	var tccSkipper *tcc.Skipper
	if tcc.Enabled(cfg.IncludeTCCProtected) {
		tccSkipper = tcc.New(executor.ResolveHome(exec))
		if cands := tccSkipper.Candidates(); len(cands) > 0 {
			log.Debug("tcc skip list (%d): %v", len(cands), cands)
		}
	}

	// Detect IDEs
	phaseCtx, phaseCancel = startPhase(ctx, tracker, "ide_scan")
	log.Progress("Detecting IDE and AI desktop app installations...")
	ideDetector := detector.NewIDEDetector(exec)
	ides := ideDetector.Detect(phaseCtx)
	for _, ide := range ides {
		log.Progress("  Found: %s (%s) v%s at %s", ideDisplayName(ide.IDEType), ide.Vendor, ide.Version, ide.InstallPath)
	}
	if len(ides) == 0 {
		log.Progress("  No IDEs or AI desktop apps found")
	}
	fmt.Fprintln(os.Stderr)
	endPhase(phaseCtx, phaseCancel, tracker, log, "ide_scan")
	postPhase()

	// Collect extensions
	phaseCtx, phaseCancel = startPhase(ctx, tracker, "extension_scan")
	log.Progress("Scanning extensions...")
	extDetector := detector.NewExtensionDetector(exec)
	extensions := extDetector.Detect(phaseCtx, searchDirs, ides)

	// Collect JetBrains plugins
	jbDetector := detector.NewJetBrainsPluginDetector(exec)
	jbPlugins := jbDetector.Detect(phaseCtx, ides)
	extensions = append(extensions, jbPlugins...)

	// On Windows, filter out bundled/platform plugins (e.g., Eclipse's 500+ OSGi
	// bundles) unless explicitly requested. macOS is unaffected.
	if exec.GOOS() == model.PlatformWindows && !cfg.IncludeBundledPlugins {
		extensions = model.FilterUserInstalledExtensions(extensions)
	}
	log.Progress("Found total of %d IDE extensions", len(extensions))
	fmt.Fprintln(os.Stderr)
	endPhase(phaseCtx, phaseCancel, tracker, log, "extension_scan")
	postPhase()

	// Detect AI tools — CLI + general agents + frameworks roll up into one
	// phase since they're all quick discovery passes against the same user
	// home and exec PATH.
	phaseCtx, phaseCancel = startPhase(ctx, tracker, "ai_tools_scan")
	log.Progress("Detecting AI agents and tools...")
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting AI CLI tools...")
	cliTools := detector.NewAICLIDetector(userExec).Detect(phaseCtx)
	for _, t := range cliTools {
		log.Progress("  Found: %s (%s) v%s at %s", t.Name, t.Vendor, t.Version, t.BinaryPath)
	}
	if len(cliTools) == 0 {
		log.Progress("  No AI CLI tools found")
	}
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting general-purpose AI agents...")
	agents := detector.NewAgentDetector(userExec).Detect(phaseCtx, searchDirs)
	for _, a := range agents {
		log.Progress("  Found: %s (%s) at %s", a.Name, a.Vendor, a.InstallPath)
	}
	if len(agents) == 0 {
		log.Progress("  No general-purpose AI agents found")
	}
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting AI frameworks and runtimes...")
	frameworks := detector.NewFrameworkDetector(userExec).Detect(phaseCtx)
	for _, f := range frameworks {
		running := "false"
		if f.IsRunning != nil && *f.IsRunning {
			running = "true"
		}
		log.Progress("  Found: %s v%s at %s (running: %s)", f.Name, f.Version, f.BinaryPath, running)
	}
	if len(frameworks) == 0 {
		log.Progress("  No AI frameworks found")
	}
	fmt.Fprintln(os.Stderr)

	allAI := append(append(cliTools, agents...), frameworks...)
	endPhase(phaseCtx, phaseCancel, tracker, log, "ai_tools_scan")
	postPhase()

	// MCP configs
	phaseCtx, phaseCancel = startPhase(ctx, tracker, "mcp_config_scan")
	log.Progress("Collecting MCP configuration files...")
	mcpDetector := detector.NewMCPDetector(exec)
	mcpConfigs := mcpDetector.DetectEnterprise(phaseCtx)
	for _, c := range mcpConfigs {
		log.Progress("  Found: %s config (%s)", c.ConfigSource, c.Vendor)
	}
	if len(mcpConfigs) == 0 {
		log.Progress("  No MCP config files found")
	}
	log.Debug("scan totals: ides=%d extensions=%d ai_cli=%d agents=%d frameworks=%d mcp_configs=%d",
		len(ides), len(extensions), len(cliTools), len(agents), len(frameworks), len(mcpConfigs))
	fmt.Fprintln(os.Stderr)
	endPhase(phaseCtx, phaseCancel, tracker, log, "mcp_config_scan")
	postPhase()

	// Homebrew scanning
	brewEnabled := true
	if cfg.EnableBrewScan != nil {
		brewEnabled = *cfg.EnableBrewScan
	}

	var brewPkgMgr *model.PkgManager
	var brewScans []model.BrewScanResult
	var brewFormulae, brewCasks []model.BrewPackage

	if brewEnabled {
		phaseCtx, phaseCancel = startPhase(ctx, tracker, "brew_scan")
		log.Progress("Detecting Homebrew...")
		brewDetector := detector.NewBrewDetector(userExec)
		brewPkgMgr = brewDetector.DetectBrew(phaseCtx)
		log.Debug("brew detection: found=%v", brewPkgMgr != nil)
		if brewPkgMgr != nil {
			log.Progress("  Found: Homebrew v%s at %s", brewPkgMgr.Version, brewPkgMgr.Path)

			// Collect rich metadata (pre-parsed packages with desc/license/homepage)
			brewFormulae = brewDetector.ListFormulaeRich(phaseCtx)
			brewCasks = brewDetector.ListCasksRich(phaseCtx)
			log.Progress("  Formulae: %d, Casks: %d (pre-parsed with metadata)", len(brewFormulae), len(brewCasks))

			// Also collect raw scans for backward compatibility with older backends
			brewScanner := detector.NewBrewScanner(userExec, log)
			if r, ok := brewScanner.ScanFormulae(phaseCtx); ok {
				brewScans = append(brewScans, r)
			}
			if r, ok := brewScanner.ScanCasks(phaseCtx); ok {
				brewScans = append(brewScans, r)
			}
			log.Progress("  Raw scans: %d", len(brewScans))
		} else {
			log.Progress("  Homebrew not found")
		}
		fmt.Fprintln(os.Stderr)
		endPhase(phaseCtx, phaseCancel, tracker, log, "brew_scan")
		postPhase()
	} else {
		log.Progress("Homebrew scanning is DISABLED")
		fmt.Fprintln(os.Stderr)
	}

	// Python scanning
	pythonEnabled := true
	if cfg.EnablePythonScan != nil {
		pythonEnabled = *cfg.EnablePythonScan
	}

	var pythonPkgManagers []model.PkgManager
	var pythonGlobalPkgs []model.PythonScanResult
	var pythonProjects []model.ProjectInfo

	if pythonEnabled {
		phaseCtx, phaseCancel = startPhase(ctx, tracker, "python_scan")
		log.Progress("Detecting Python package managers...")
		pyDetector := detector.NewPythonPMDetector(userExec)
		pythonPkgManagers = pyDetector.DetectManagers(phaseCtx)
		for _, pm := range pythonPkgManagers {
			log.Progress("  Found: %s v%s at %s", pm.Name, pm.Version, pm.Path)
		}
		if len(pythonPkgManagers) == 0 {
			log.Progress("  No Python package managers found")
		}

		log.Progress("Scanning Python global packages...")
		pyScanner := detector.NewPythonScanner(userExec, log)
		// Stream per-PM sub-progress ("scanning pip3" / "scanning conda" /
		// "scanning uv") into the phase tracker so heartbeats surface where
		// inside the python phase a slow pip3 list is stuck.
		pyScanner.ProgressHook = func(detail string) { tracker.UpdateDetail(detail) }
		pythonGlobalPkgs = pyScanner.ScanGlobalPackages(phaseCtx)
		log.Progress("  Found %d Python global package source(s)", len(pythonGlobalPkgs))

		log.Progress("Searching for Python projects...")
		pyProjectDetector := detector.NewPythonProjectDetector(exec).WithSkipper(tccSkipper)
		pythonProjects = pyProjectDetector.ListProjects(searchDirs)
		log.Progress("  Found %d Python projects", len(pythonProjects))
		fmt.Fprintln(os.Stderr)
		endPhase(phaseCtx, phaseCancel, tracker, log, "python_scan")
		postPhase()
	} else {
		log.Progress("Python scanning is DISABLED")
		fmt.Fprintln(os.Stderr)
	}

	// System package scanning (Linux only — rpm, dpkg, pacman, apk, snap, flatpak)
	var systemPackageScans []model.SystemPackageScanResult

	if exec.GOOS() == model.PlatformLinux {
		phaseCtx, phaseCancel = startPhase(ctx, tracker, "syspkg_scan")
		log.Progress("Detecting system packages...")
		sysPkgDetector := detector.NewSystemPkgDetector(userExec)

		// Primary system PM (rpm, dpkg, pacman, or apk)
		if pm := sysPkgDetector.Detect(phaseCtx); pm != nil {
			log.Progress("  Found: %s v%s at %s", pm.Name, pm.Version, pm.Path)
			start := time.Now()
			packages := sysPkgDetector.ListPackages(phaseCtx)
			duration := time.Since(start).Milliseconds()
			if packages == nil {
				packages = []model.SystemPackage{}
			}
			systemPackageScans = append(systemPackageScans, model.SystemPackageScanResult{
				ScanType:       pm.Name,
				PackageManager: pm,
				Packages:       packages,
				PackagesCount:  len(packages),
				ScanDurationMs: duration,
			})
			log.Progress("  %s: %d packages in %dms", pm.Name, len(packages), duration)
		}

		// Additional PMs (snap, flatpak) — coexist with system PM
		for _, mgr := range sysPkgDetector.DetectAdditionalManagers(phaseCtx) {
			mgr := mgr
			log.Progress("  Found: %s v%s at %s", mgr.Name, mgr.Version, mgr.Path)
			start := time.Now()
			var packages []model.SystemPackage
			switch mgr.Name {
			case "snap":
				packages = sysPkgDetector.ListSnapPackages(phaseCtx)
			case "flatpak":
				packages = sysPkgDetector.ListFlatpakPackages(phaseCtx)
			}
			duration := time.Since(start).Milliseconds()
			if packages == nil {
				packages = []model.SystemPackage{}
			}
			systemPackageScans = append(systemPackageScans, model.SystemPackageScanResult{
				ScanType:       mgr.Name,
				PackageManager: &mgr,
				Packages:       packages,
				PackagesCount:  len(packages),
				ScanDurationMs: duration,
			})
			log.Progress("  %s: %d packages in %dms", mgr.Name, len(packages), duration)
		}

		if len(systemPackageScans) == 0 {
			log.Progress("  No system package managers found")
		}
		fmt.Fprintln(os.Stderr)
		endPhase(phaseCtx, phaseCancel, tracker, log, "syspkg_scan")
		postPhase()
	} else {
		log.Progress("System package scanning: skipped (non-Linux)")
		fmt.Fprintln(os.Stderr)
	}

	// Node.js scanning
	npmEnabled := true
	if cfg.EnableNPMScan != nil {
		npmEnabled = *cfg.EnableNPMScan
	}

	var pkgManagers []model.PkgManager
	var globalPkgs []model.NodeScanResult
	var nodeProjects []model.NodeScanResult
	var nodeScanMs int64

	if npmEnabled {
		phaseCtx, phaseCancel = startPhase(ctx, tracker, "node_scan")
		log.Progress("Node.js package scanning is ENABLED")

		log.Progress("Detecting Node.js package managers...")
		npmDetector := detector.NewNodePMDetector(userExec)
		pkgManagers = npmDetector.DetectManagers(phaseCtx)
		for _, pm := range pkgManagers {
			log.Progress("  Found: %s v%s at %s", pm.Name, pm.Version, pm.Path)
		}
		// Surface the empty-detector case explicitly. Previously this
		// printed nothing — a long blank between "Detecting Node.js
		// package managers..." and the next section, hiding the fact that
		// the per-project scans about to run would all ENOENT and produce
		// empty stdout records. The warning makes the root cause visible
		// at the agent level rather than requiring a diff of output.log
		// against a known-working device.
		if len(pkgManagers) == 0 {
			log.Warn("No Node.js package managers found on PATH — project discovery will still run but per-project package listing will be skipped")
		}
		fmt.Fprintln(os.Stderr)

		log.Progress("Scanning globally installed packages...")
		nodeScanner := detector.NewNodeScanner(exec, log, loggedInUsername).WithSkipper(tccSkipper)
		// Stream sub-progress so heartbeats show "project 12 of 47" /
		// "global: yarn" during the long-running node phase. Both
		// ScanGlobalPackages and ScanProjects share this hook.
		nodeScanner.ProgressHook = func(detail string) { tracker.UpdateDetail(detail) }
		globalPkgs = nodeScanner.ScanGlobalPackages(phaseCtx)
		log.Progress("  Found %d global package location(s)", len(globalPkgs))
		fmt.Fprintln(os.Stderr)

		log.Progress("Searching for Node.js projects...")
		scanStart := time.Now()
		nodeProjects = nodeScanner.ScanProjects(phaseCtx, searchDirs)
		nodeScanMs = time.Since(scanStart).Milliseconds()
		log.Progress("  Found %d Node.js projects", len(nodeProjects))
		log.Progress("  Scan duration: %dms", nodeScanMs)
		fmt.Fprintln(os.Stderr)
		endPhase(phaseCtx, phaseCancel, tracker, log, "node_scan")
		postPhase()
	} else {
		log.Progress("Node.js package scanning is DISABLED")
		fmt.Fprintln(os.Stderr)
	}

	if globalPkgs == nil {
		globalPkgs = []model.NodeScanResult{}
	}
	if nodeProjects == nil {
		nodeProjects = []model.NodeScanResult{}
	}
	if brewScans == nil {
		brewScans = []model.BrewScanResult{}
	}
	if pythonPkgManagers == nil {
		pythonPkgManagers = []model.PkgManager{}
	}
	if pythonGlobalPkgs == nil {
		pythonGlobalPkgs = []model.PythonScanResult{}
	}
	if pythonProjects == nil {
		pythonProjects = []model.ProjectInfo{}
	}
	if systemPackageScans == nil {
		systemPackageScans = []model.SystemPackageScanResult{}
	}

	// npm + pip configuration audits — surface-only inventory of every
	// .npmrc and pip.conf on the host, plus the merged effective views
	// each tool would resolve. We use the user-aware executor so npm and
	// pip resolve through the logged-in user's PATH (catches nvm / fnm /
	// pyenv / asdf / brew installs that root's PATH wouldn't see).
	log.Progress("Auditing npm configuration...")
	npmrcLoggedIn, _ := exec.LoggedInUser()
	npmrcAudit := configaudit.NewNPMRCDetector(userExec).WithSkipper(tccSkipper).Detect(ctx, searchDirs, npmrcLoggedIn)
	log.Progress("  npm available: %v, files discovered: %d", npmrcAudit.Available, len(npmrcAudit.Files))
	fmt.Fprintln(os.Stderr)

	log.Progress("Auditing pip configuration...")
	pipAudit := configaudit.NewPipConfigDetector(userExec).Detect(ctx, npmrcLoggedIn)
	log.Progress("  pip available: %v, files discovered: %d, findings: %d", pipAudit.Available, len(pipAudit.Files), len(pipAudit.Findings))
	fmt.Fprintln(os.Stderr)

	log.Progress("Auditing pnpm configuration...")
	pnpmAudit := configaudit.NewPnpmDetector(userExec).WithSkipper(tccSkipper).Detect(ctx, searchDirs, npmrcLoggedIn)
	log.Progress("  pnpm available: %v, files discovered: %d", pnpmAudit.Available, len(pnpmAudit.Files))
	fmt.Fprintln(os.Stderr)

	log.Progress("Auditing bun configuration...")
	bunAudit := configaudit.NewBunDetector(userExec).WithSkipper(tccSkipper).Detect(ctx, searchDirs, npmrcLoggedIn)
	log.Progress("  bun available: %v, files discovered: %d", bunAudit.Available, len(bunAudit.Files))
	fmt.Fprintln(os.Stderr)

	log.Progress("Auditing yarn configuration...")
	yarnAudit := configaudit.NewYarnDetector(userExec).WithSkipper(tccSkipper).Detect(ctx, searchDirs, npmrcLoggedIn)
	log.Progress("  yarn available: %v (flavor=%s), files discovered: %d", yarnAudit.Available, yarnAudit.Flavor, len(yarnAudit.Files))
	fmt.Fprintln(os.Stderr)

	// Snapshot execution logs for the payload WITHOUT stopping capture, so the
	// upload that follows (and the completion lines) keep being recorded and
	// can ship in the final run-status log tail via postPhaseFinal below. The
	// payload itself can't contain the log of its own upload, so this snapshot
	// is "session so far" by design. The deferred capture.Finalize() does the
	// real teardown (restores os.Stderr) on return.
	execLogsBase64 := capture.SnapshotBase64()
	endTime := time.Now()

	// Snapshot the final progress state right before we serialize. By this
	// point every analysis phase has been Finish()-ed so PhasesCompleted
	// holds the full list and CurrentPhase is empty — the upload itself
	// runs after this snapshot and is intentionally not tracked as a phase.
	finalStatusInfo := tracker.Snapshot()

	// Build payload
	payload := &Payload{
		CustomerID:     config.CustomerID,
		DeviceID:       dev.SerialNumber,
		SerialNumber:   dev.SerialNumber,
		UserIdentity:   dev.UserIdentity,
		Hostname:       dev.Hostname,
		Platform:       dev.Platform,
		OSVersion:      dev.OSVersion,
		Resources:      dev.Resources,
		AgentVersion:   buildinfo.Version,
		CollectedAt:    endTime.Unix(),
		NoUserLoggedIn: noUserLoggedIn,

		InvocationMethod: invocationMethod,
		StatusInfo:       &finalStatusInfo,

		IDEExtensions:        extensions,
		IDEInstallations:     ides,
		NodePkgManagers:      pkgManagers,
		NodeGlobalPackages:   globalPkgs,
		NodeProjects:         nodeProjects,
		BrewPkgManager:       brewPkgMgr,
		BrewScans:            brewScans,
		BrewFormulae:         brewFormulae,
		BrewCasks:            brewCasks,
		PythonPkgManagers:    pythonPkgManagers,
		PythonGlobalPackages: pythonGlobalPkgs,
		PythonProjects:       pythonProjects,
		SystemPackageScans:   systemPackageScans,
		AIAgents:             allAI,
		MCPConfigs:           mcpConfigs,
		NPMRCAudit:           &npmrcAudit,
		PipAudit:             &pipAudit,
		PnpmAudit:            &pnpmAudit,
		BunAudit:             &bunAudit,
		YarnAudit:            &yarnAudit,

		ExecutionLogs: &ExecutionLogs{
			OutputBase64: execLogsBase64,
			StartTime:    startTime.Unix(),
			EndTime:      endTime.Unix(),
			ExitCode:     0,
			AgentVersion: buildinfo.Version,
		},

		PerformanceMetrics: &PerformanceMetrics{
			ExtensionsCount:       len(extensions),
			NodePackagesScanMs:    nodeScanMs,
			NodeGlobalPkgsCount:   len(globalPkgs),
			NodeProjectsCount:     len(nodeProjects),
			BrewFormulaeCount:     brewFormulaeCount(brewScans),
			BrewCasksCount:        brewCasksCount(brewScans),
			PythonGlobalPkgsCount: len(pythonGlobalPkgs),
			PythonProjectsCount:   len(pythonProjects),
			SystemPackagesCount:   totalSystemPackagesCount(systemPackageScans),
		},
	}

	// Upload to S3 — tracked as the final phase. The Payload's StatusInfo
	// above is intentionally snapshotted *before* this phase starts (the
	// payload can't describe its own upload), so this phase only appears
	// on the run-status row via heartbeats and the post-upload progress
	// post below.
	// Upload deliberately roots on runCtx (no scan deadline) so partial
	// data still ships when the scan deadline trips earlier. We still
	// apply the per-phase telemetry_upload budget on top so the upload
	// itself cannot wedge the agent indefinitely.
	phaseCtx, phaseCancel = startPhase(runCtx, tracker, "telemetry_upload")
	log.Progress("Requesting upload URL from backend...")
	if err := uploadToS3(phaseCtx, log, payload, executionID, tracker); err != nil {
		endPhase(phaseCtx, phaseCancel, tracker, log, "telemetry_upload")
		// Force-attach a final tail capturing the upload-failure output before
		// returning. The deferred failure report carries no status_info (and so
		// can't ship a tail itself); this progress upsert lands the tail on the
		// row, which the subsequent "failed" transition preserves.
		postPhaseFinal()
		return fmt.Errorf("uploading telemetry: %w", err)
	}
	endPhase(phaseCtx, phaseCancel, tracker, log, "telemetry_upload")

	fmt.Fprintln(os.Stderr)
	log.Progress("Telemetry collection completed successfully")
	tccSkipper.LogHits(log.Debug)

	// Final progress post — AFTER the upload and the completion lines above —
	// with a forced fresh tail (bypassing the throttle) so the run-status row's
	// log tail includes them. Without this the last lines after the upload are
	// skipped. Capture is still live; the deferred capture.Finalize() restores
	// os.Stderr on return, after the phase-post worker has drained this snapshot.
	postPhaseFinal()
	return nil
}

func brewFormulaeCount(scans []model.BrewScanResult) int {
	for _, s := range scans {
		if s.ScanType == "formulae" {
			return s.LineCount
		}
	}
	return 0
}

func brewCasksCount(scans []model.BrewScanResult) int {
	for _, s := range scans {
		if s.ScanType == "casks" {
			return s.LineCount
		}
	}
	return 0
}

func totalSystemPackagesCount(scans []model.SystemPackageScanResult) int {
	total := 0
	for _, s := range scans {
		total += s.PackagesCount
	}
	return total
}

func uploadToS3(ctx context.Context, log *progress.Logger, payload *Payload, executionID string, tracker *PhaseTracker) error {
	// updateDetail forwards sub-progress to the heartbeat goroutine via the
	// tracker. Tolerates nil so the function stays callable from tests that
	// don't supply a tracker.
	updateDetail := func(detail string) {
		if tracker != nil {
			tracker.UpdateDetail(detail)
		}
	}

	updateDetail("compressing payload")
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	// Gzip-compress the payload before upload. The backend signals support by
	// honoring is_compressed=true on the upload-URL request and appending .gz
	// to the S3 key, which tells GetTelemetryFromS3 to decompress on read.
	compressedPayload, err := gzipBytes(payloadJSON)
	if err != nil {
		return fmt.Errorf("compressing payload: %w", err)
	}
	updateDetail("requesting upload URL")

	// Request upload URL
	reqBody, _ := json.Marshal(map[string]any{
		"device_id":     payload.DeviceID,
		"is_compressed": true,
	})

	uploadURLEndpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/telemetry/upload-url",
		config.APIEndpoint, config.CustomerID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURLEndpoint, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("creating upload URL request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.APIKey)
	req.Header.Set("X-Agent-Version", buildinfo.Version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("requesting upload URL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var urlResp struct {
		UploadURL string `json:"upload_url"`
		S3Key     string `json:"s3_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&urlResp); err != nil {
		return fmt.Errorf("decoding upload URL response: %w", err)
	}

	log.Debug("upload URL response: status=%d s3_key=%q url_len=%d", resp.StatusCode, urlResp.S3Key, len(urlResp.UploadURL))

	if urlResp.UploadURL == "" {
		return fmt.Errorf("empty upload URL in response")
	}

	// Upload payload to S3 with retry. Content-Type stays application/json to
	// match the presigned URL's signed headers — the body is gzipped JSON bytes.
	log.Progress("Uploading telemetry to S3 (%d bytes)...", len(compressedPayload))
	s3Client := &http.Client{Timeout: 10 * time.Minute}
	const maxRetries = 3
	backoffUnit := s3UploadBackoffUnit
	uploaded := false
	var lastFailure string
	for attempt := 1; attempt <= maxRetries; attempt++ {
		updateDetail(fmt.Sprintf("uploading to S3 (attempt %d/%d, %d KiB)", attempt, maxRetries, len(compressedPayload)/1024))
		uploadStart := time.Now()
		putReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPut, urlResp.UploadURL, bytes.NewReader(compressedPayload))
		if reqErr != nil {
			return fmt.Errorf("creating S3 PUT request: %w", reqErr)
		}
		putReq.Header.Set("Content-Type", "application/json")

		putResp, putErr := s3Client.Do(putReq)
		elapsed := time.Since(uploadStart)
		if putErr != nil {
			log.Debug("s3 PUT attempt %d/%d: error=%v elapsed=%s", attempt, maxRetries, putErr, elapsed)
			lastFailure = fmt.Sprintf("S3 PUT error: %v", putErr)
		} else {
			log.Debug("s3 PUT attempt %d/%d: status=%d elapsed=%s payload_bytes=%d", attempt, maxRetries, putResp.StatusCode, elapsed, len(payloadJSON))
		}

		if putErr == nil && putResp.StatusCode == http.StatusOK {
			// A real S3 PUT response always carries x-amz-request-id and
			// x-amz-id-2. If both are missing, the response did not
			// originate from AWS — typically a TLS-inspecting proxy or
			// outbound-filtering firewall has terminated the connection
			// and synthesized a success without forwarding the body. Ask
			// the backend whether the object actually landed in S3 before
			// trusting this 200.
			reqID := putResp.Header.Get("x-amz-request-id")
			id2 := putResp.Header.Get("x-amz-id-2")
			proxyHint := putResp.Header.Get("Server")
			_, _ = io.Copy(io.Discard, putResp.Body)
			_ = putResp.Body.Close()

			if reqID != "" || id2 != "" {
				log.Progress("Uploaded to S3 in %s", elapsed)
				uploaded = true
				break
			}

			log.Warn("S3 PUT returned 200 without AWS request id headers (Server=%q) — verifying with backend", proxyHint)
			result, reason := checkUploadInS3(ctx, log, client, urlResp.S3Key, payload.DeviceID)
			switch result {
			case uploadCheckConfirmed:
				log.Progress("Uploaded to S3 in %s (verified by backend)", elapsed)
				uploaded = true
			case uploadCheckUnsupported:
				// Backend predates confirm-upload — we can't verify, so
				// trust the 200 for compatibility. The notify endpoint's
				// own precheck is the remaining safety net.
				log.Debug("backend does not support confirm-upload; proceeding on the 200 alone")
				log.Progress("Uploaded to S3 in %s", elapsed)
				uploaded = true
			case uploadCheckMissing:
				lastFailure = fmt.Sprintf("backend confirmed the object is not in S3 (reason=%s)", reason)
			case uploadCheckIndeterminate:
				lastFailure = "backend could not verify the upload"
			}
			if uploaded {
				break
			}
		} else if putResp != nil {
			_, _ = io.Copy(io.Discard, putResp.Body)
			_ = putResp.Body.Close()
			lastFailure = fmt.Sprintf("S3 PUT returned status %d", putResp.StatusCode)
		}

		if attempt == maxRetries {
			break
		}

		backoff := time.Duration(attempt) * backoffUnit
		log.Warn("S3 upload attempt %d/%d failed (%s); retrying in %s...", attempt, maxRetries, lastFailure, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if !uploaded {
		return fmt.Errorf("telemetry upload failed after %d attempts: %s (payload: %d bytes) — the network may be intercepting outbound traffic to S3 (TLS-inspecting proxy, DLP appliance, or outbound firewall)",
			maxRetries, lastFailure, len(compressedPayload))
	}

	// Notify backend
	updateDetail("notifying backend")
	log.Progress("Notifying backend of upload...")
	notifyBody, _ := json.Marshal(map[string]string{
		"s3_key":       urlResp.S3Key,
		"device_id":    payload.DeviceID,
		"execution_id": executionID,
	})

	notifyEndpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/telemetry/process-uploaded",
		config.APIEndpoint, config.CustomerID)

	notifyReq, err := http.NewRequestWithContext(ctx, http.MethodPost, notifyEndpoint, bytes.NewReader(notifyBody))
	if err != nil {
		return fmt.Errorf("creating notify request: %w", err)
	}
	notifyReq.Header.Set("Content-Type", "application/json")
	notifyReq.Header.Set("Authorization", "Bearer "+config.APIKey)
	notifyReq.Header.Set("X-Agent-Version", buildinfo.Version)

	notifyResp, err := client.Do(notifyReq)
	if err != nil {
		return fmt.Errorf("notifying backend: %w", err)
	}
	defer func() { _ = notifyResp.Body.Close() }()
	_, _ = io.Copy(io.Discard, notifyResp.Body)
	log.Debug("notify backend: status=%d s3_key=%q", notifyResp.StatusCode, urlResp.S3Key)

	if notifyResp.StatusCode != http.StatusOK && notifyResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("backend notification failed with status %d", notifyResp.StatusCode)
	}
	log.Progress("Backend processing initiated (HTTP %d)", notifyResp.StatusCode)

	return nil
}

// uploadCheckResult is the four-valued answer the agent gets back when it
// asks the backend whether a PUT'd s3_key actually landed in S3.
type uploadCheckResult int

const (
	// uploadCheckConfirmed = backend HEAD'd the object and it exists.
	uploadCheckConfirmed uploadCheckResult = iota
	// uploadCheckMissing = backend HEAD'd the object and it does not exist.
	uploadCheckMissing
	// uploadCheckUnsupported = backend predates the confirm-upload route
	// (HTTP 404). We can't verify; for compatibility callers should trust
	// the original PUT response.
	uploadCheckUnsupported
	// uploadCheckIndeterminate = transient failure (5xx, transport error,
	// parse error). The answer is unknown; callers should retry.
	uploadCheckIndeterminate
)

// checkUploadInS3 calls the backend's /telemetry/confirm-upload endpoint
// and translates the response into a uploadCheckResult. On
// uploadCheckMissing the second return value carries the backend's
// reason string (e.g. "object_not_found").
func checkUploadInS3(ctx context.Context, log *progress.Logger, client *http.Client, s3Key, deviceID string) (uploadCheckResult, string) {
	log.Progress("Confirming upload reached S3...")

	body, _ := json.Marshal(map[string]string{
		"s3_key":    s3Key,
		"device_id": deviceID,
	})
	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/telemetry/confirm-upload",
		config.APIEndpoint, config.CustomerID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Warn("confirm-upload: request build failed: %v", err)
		return uploadCheckIndeterminate, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.APIKey)
	req.Header.Set("X-Agent-Version", buildinfo.Version)

	resp, err := client.Do(req)
	if err != nil {
		log.Warn("confirm-upload: request failed: %v", err)
		return uploadCheckIndeterminate, ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return uploadCheckUnsupported, ""
	}
	if resp.StatusCode != http.StatusOK {
		log.Warn("confirm-upload: HTTP %d", resp.StatusCode)
		_, _ = io.Copy(io.Discard, resp.Body)
		return uploadCheckIndeterminate, ""
	}

	var result struct {
		Uploaded  bool   `json:"uploaded"`
		SizeBytes int64  `json:"size_bytes"`
		Reason    string `json:"reason"`
		S3Key     string `json:"s3_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Warn("confirm-upload: malformed response: %v", err)
		return uploadCheckIndeterminate, ""
	}

	if result.Uploaded {
		log.Debug("confirm-upload: backend reports object present (%d bytes)", result.SizeBytes)
		return uploadCheckConfirmed, ""
	}
	reason := result.Reason
	if reason == "" {
		reason = "unknown"
	}
	return uploadCheckMissing, reason
}

// gzipBytes returns a gzip-compressed copy of the input bytes.
func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func resolveSearchDirs(exec executor.Executor, dirs []string) []string {
	resolved := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "$HOME" {
			if u, err := exec.LoggedInUser(); err == nil {
				d = u.HomeDir
			} else if u, err := exec.CurrentUser(); err == nil {
				// No console user (issue #63): still expand to *some* home
				// or the literal "$HOME" would propagate downstream.
				d = u.HomeDir
			}
		}
		resolved = append(resolved, d)
	}
	return resolved
}

func ideDisplayName(ideType string) string {
	switch ideType {
	case "vscode":
		return "Visual Studio Code"
	case "cursor":
		return "Cursor"
	case "windsurf":
		return "Windsurf"
	case "antigravity":
		return "Antigravity"
	case "zed":
		return "Zed"
	case "claude_desktop":
		return "Claude"
	case "microsoft_copilot_desktop":
		return "Microsoft Copilot"
	case "intellij_idea":
		return "IntelliJ IDEA"
	case "intellij_idea_ce":
		return "IntelliJ IDEA CE"
	case "pycharm":
		return "PyCharm"
	case "pycharm_ce":
		return "PyCharm CE"
	case "webstorm":
		return "WebStorm"
	case "goland":
		return "GoLand"
	case "rider":
		return "Rider"
	case "phpstorm":
		return "PhpStorm"
	case "rubymine":
		return "RubyMine"
	case "clion":
		return "CLion"
	case "datagrip":
		return "DataGrip"
	case "fleet":
		return "Fleet"
	case "android_studio":
		return "Android Studio"
	case "eclipse":
		return "Eclipse"
	case "xcode":
		return "Xcode"
	default:
		return ideType
	}
}
