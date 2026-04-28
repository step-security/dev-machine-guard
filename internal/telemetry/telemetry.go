package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/detector"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Payload is the enterprise telemetry JSON structure.
type Payload struct {
	CustomerID     string `json:"customer_id"`
	DeviceID       string `json:"device_id"`
	SerialNumber   string `json:"serial_number"`
	UserIdentity   string `json:"user_identity"`
	Hostname       string `json:"hostname"`
	Platform       string `json:"platform"`
	OSVersion      string `json:"os_version"`
	AgentVersion   string `json:"agent_version"`
	CollectedAt    int64  `json:"collected_at"`
	NoUserLoggedIn bool   `json:"no_user_logged_in"`

	IDEExtensions        []model.Extension           `json:"ide_extensions"`
	IDEInstallations     []model.IDE                 `json:"ide_installations"`
	NodePkgManagers      []model.PkgManager          `json:"node_package_managers"`
	NodeGlobalPackages   []model.NodeScanResult      `json:"node_global_packages"`
	NodeProjects         []model.NodeScanResult      `json:"node_projects"`
	BrewPkgManager       *model.PkgManager           `json:"brew_package_manager,omitempty"`
	BrewScans            []model.BrewScanResult      `json:"brew_scans"`
	PythonPkgManagers    []model.PkgManager                `json:"python_package_managers"`
	PythonGlobalPackages []model.PythonScanResult          `json:"python_global_packages"`
	PythonProjects       []model.ProjectInfo               `json:"python_projects"`
	SystemPackageScans   []model.SystemPackageScanResult   `json:"system_package_scans"`
	AIAgents             []model.AITool                    `json:"ai_agents"`
	MCPConfigs           []model.MCPConfigEnterprise `json:"mcp_configs"`

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
func Run(exec executor.Executor, log *progress.Logger, cfg *cli.Config) error {
	ctx := context.Background()
	startTime := time.Now()

	// Start capturing all stderr output for execution_logs.
	// Defer Finalize immediately to ensure stderr is always restored,
	// even on early returns (e.g., lock failure).
	capture := StartCapture()
	defer capture.Finalize()

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

	// Device info
	log.Progress("Gathering device information...")
	dev := device.Gather(ctx, exec)
	log.Progress("Device ID (Serial): %s", dev.SerialNumber)
	log.Progress("OS Version: %s", dev.OSVersion)
	log.Progress("Developer: %s", dev.UserIdentity)
	log.Debug("device gathered: hostname=%q platform=%q serial=%q user_identity=%q", dev.Hostname, dev.Platform, dev.SerialNumber, dev.UserIdentity)
	if dev.SerialNumber == "" {
		log.Warn("device serial number could not be determined — telemetry will upload with empty device_id")
	}
	if dev.UserIdentity == "" || dev.UserIdentity == "unknown" {
		log.Warn("user identity could not be determined — telemetry will be marked no_user_logged_in")
	}

	// Detect logged-in user for running commands as the real user when root.
	// Skip "root" — if LoggedInUser() fell back to CurrentUser(), delegating
	// via sudo -H -u root is pointless and changes PATH/env behavior.
	loggedInUsername := ""
	if u, err := exec.LoggedInUser(); err == nil && u.Username != "root" {
		loggedInUsername = u.Username
		log.Debug("logged-in user detected: username=%q home=%q — commands will delegate via sudo", u.Username, u.HomeDir)
	} else if err != nil {
		log.Warn("could not detect logged-in user (%v) — package manager commands will run as current user and may return different results", err)
	} else {
		log.Debug("LoggedInUser() returned root — not delegating")
	}

	// Create a user-aware executor that delegates commands to the logged-in user
	// when running as root. This ensures tools like brew, pip3, npm etc. execute
	// in the correct user context (many refuse to run as root or return different
	// results). File-based detectors (IDE, extensions, MCP) use the original exec
	// since file operations don't need user delegation.
	userExec := executor.NewUserAwareExecutor(exec, loggedInUsername)

	// Resolve search dirs
	searchDirs := resolveSearchDirs(exec, cfg.SearchDirs)
	log.Debug("search directories resolved: %v", searchDirs)
	fmt.Fprintln(os.Stderr)

	// Detect IDEs
	log.Progress("Detecting IDE and AI desktop app installations...")
	ideDetector := detector.NewIDEDetector(exec)
	ides := ideDetector.Detect(ctx)
	for _, ide := range ides {
		log.Progress("  Found: %s (%s) v%s at %s", ideDisplayName(ide.IDEType), ide.Vendor, ide.Version, ide.InstallPath)
	}
	if len(ides) == 0 {
		log.Progress("  No IDEs or AI desktop apps found")
	}
	fmt.Fprintln(os.Stderr)

	// Collect extensions
	log.Progress("Scanning extensions...")
	extDetector := detector.NewExtensionDetector(exec)
	extensions := extDetector.Detect(ctx, searchDirs, ides)

	// Collect JetBrains plugins
	jbDetector := detector.NewJetBrainsPluginDetector(exec)
	jbPlugins := jbDetector.Detect(ctx, ides)
	extensions = append(extensions, jbPlugins...)

	// On Windows, filter out bundled/platform plugins (e.g., Eclipse's 500+ OSGi
	// bundles) unless explicitly requested. macOS is unaffected.
	if exec.GOOS() == model.PlatformWindows && !cfg.IncludeBundledPlugins {
		extensions = model.FilterUserInstalledExtensions(extensions)
	}
	log.Progress("Found total of %d IDE extensions", len(extensions))
	fmt.Fprintln(os.Stderr)

	// Detect AI tools
	log.Progress("Detecting AI agents and tools...")
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting AI CLI tools...")
	cliTools := detector.NewAICLIDetector(userExec).Detect(ctx)
	for _, t := range cliTools {
		log.Progress("  Found: %s (%s) v%s at %s", t.Name, t.Vendor, t.Version, t.BinaryPath)
	}
	if len(cliTools) == 0 {
		log.Progress("  No AI CLI tools found")
	}
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting general-purpose AI agents...")
	agents := detector.NewAgentDetector(userExec).Detect(ctx, searchDirs)
	for _, a := range agents {
		log.Progress("  Found: %s (%s) at %s", a.Name, a.Vendor, a.InstallPath)
	}
	if len(agents) == 0 {
		log.Progress("  No general-purpose AI agents found")
	}
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting AI frameworks and runtimes...")
	frameworks := detector.NewFrameworkDetector(userExec).Detect(ctx)
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

	// MCP configs
	log.Progress("Collecting MCP configuration files...")
	mcpDetector := detector.NewMCPDetector(exec)
	mcpConfigs := mcpDetector.DetectEnterprise(ctx)
	for _, c := range mcpConfigs {
		log.Progress("  Found: %s config (%s)", c.ConfigSource, c.Vendor)
	}
	if len(mcpConfigs) == 0 {
		log.Progress("  No MCP config files found")
	}
	log.Debug("scan totals: ides=%d extensions=%d ai_cli=%d agents=%d frameworks=%d mcp_configs=%d",
		len(ides), len(extensions), len(cliTools), len(agents), len(frameworks), len(mcpConfigs))
	fmt.Fprintln(os.Stderr)

	// Homebrew scanning
	brewEnabled := true
	if cfg.EnableBrewScan != nil {
		brewEnabled = *cfg.EnableBrewScan
	}

	var brewPkgMgr *model.PkgManager
	var brewScans []model.BrewScanResult

	if brewEnabled {
		log.Progress("Detecting Homebrew...")
		brewDetector := detector.NewBrewDetector(userExec)
		brewPkgMgr = brewDetector.DetectBrew(ctx)
		log.Debug("brew detection: found=%v", brewPkgMgr != nil)
		if brewPkgMgr != nil {
			log.Progress("  Found: Homebrew v%s at %s", brewPkgMgr.Version, brewPkgMgr.Path)
			brewScanner := detector.NewBrewScanner(userExec, log)
			if r, ok := brewScanner.ScanFormulae(ctx); ok {
				brewScans = append(brewScans, r)
				log.Progress("  Formulae scan: exit_code=%d, error=%q, raw_len=%d", r.ExitCode, r.Error, len(r.RawStdoutBase64))
			} else {
				log.Progress("  Formulae scan: skipped (brew not in PATH)")
			}
			if r, ok := brewScanner.ScanCasks(ctx); ok {
				brewScans = append(brewScans, r)
				log.Progress("  Casks scan: exit_code=%d, error=%q, raw_len=%d", r.ExitCode, r.Error, len(r.RawStdoutBase64))
			} else {
				log.Progress("  Casks scan: skipped (brew not in PATH)")
			}
			log.Progress("  Total brew scans: %d", len(brewScans))
		} else {
			log.Progress("  Homebrew not found")
		}
		fmt.Fprintln(os.Stderr)
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
		log.Progress("Detecting Python package managers...")
		pyDetector := detector.NewPythonPMDetector(userExec)
		pythonPkgManagers = pyDetector.DetectManagers(ctx)
		for _, pm := range pythonPkgManagers {
			log.Progress("  Found: %s v%s at %s", pm.Name, pm.Version, pm.Path)
		}
		if len(pythonPkgManagers) == 0 {
			log.Progress("  No Python package managers found")
		}

		log.Progress("Scanning Python global packages...")
		pyScanner := detector.NewPythonScanner(userExec, log)
		pythonGlobalPkgs = pyScanner.ScanGlobalPackages(ctx)
		log.Progress("  Found %d Python global package source(s)", len(pythonGlobalPkgs))

		log.Progress("Searching for Python projects...")
		pyProjectDetector := detector.NewPythonProjectDetector(exec)
		pythonProjects = pyProjectDetector.ListProjects(searchDirs)
		log.Progress("  Found %d Python projects", len(pythonProjects))
		fmt.Fprintln(os.Stderr)
	} else {
		log.Progress("Python scanning is DISABLED")
		fmt.Fprintln(os.Stderr)
	}

	// System package scanning (Linux only — rpm, dpkg, pacman, apk, snap, flatpak)
	var systemPackageScans []model.SystemPackageScanResult

	if exec.GOOS() == model.PlatformLinux {
		log.Progress("Detecting system packages...")
		sysPkgDetector := detector.NewSystemPkgDetector(userExec)

		// Primary system PM (rpm, dpkg, pacman, or apk)
		if pm := sysPkgDetector.Detect(ctx); pm != nil {
			log.Progress("  Found: %s v%s at %s", pm.Name, pm.Version, pm.Path)
			start := time.Now()
			packages := sysPkgDetector.ListPackages(ctx)
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
		for _, mgr := range sysPkgDetector.DetectAdditionalManagers(ctx) {
			mgr := mgr
			log.Progress("  Found: %s v%s at %s", mgr.Name, mgr.Version, mgr.Path)
			start := time.Now()
			var packages []model.SystemPackage
			switch mgr.Name {
			case "snap":
				packages = sysPkgDetector.ListSnapPackages(ctx)
			case "flatpak":
				packages = sysPkgDetector.ListFlatpakPackages(ctx)
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
		log.Progress("Node.js package scanning is ENABLED")

		log.Progress("Detecting Node.js package managers...")
		npmDetector := detector.NewNodePMDetector(userExec)
		pkgManagers = npmDetector.DetectManagers(ctx)
		for _, pm := range pkgManagers {
			log.Progress("  Found: %s v%s at %s", pm.Name, pm.Version, pm.Path)
		}
		fmt.Fprintln(os.Stderr)

		log.Progress("Scanning globally installed packages...")
		nodeScanner := detector.NewNodeScanner(exec, log, loggedInUsername)
		globalPkgs = nodeScanner.ScanGlobalPackages(ctx)
		log.Progress("  Found %d global package location(s)", len(globalPkgs))
		fmt.Fprintln(os.Stderr)

		log.Progress("Searching for Node.js projects...")
		scanStart := time.Now()
		nodeProjects = nodeScanner.ScanProjects(ctx, searchDirs)
		nodeScanMs = time.Since(scanStart).Milliseconds()
		log.Progress("  Found %d Node.js projects", len(nodeProjects))
		log.Progress("  Scan duration: %dms", nodeScanMs)
		fmt.Fprintln(os.Stderr)
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

	// Finalize execution logs before building payload
	execLogsBase64 := capture.Finalize()
	endTime := time.Now()

	// Build payload
	payload := &Payload{
		CustomerID:     config.CustomerID,
		DeviceID:       dev.SerialNumber,
		SerialNumber:   dev.SerialNumber,
		UserIdentity:   dev.UserIdentity,
		Hostname:       dev.Hostname,
		Platform:       dev.Platform,
		OSVersion:      dev.OSVersion,
		AgentVersion:   buildinfo.Version,
		CollectedAt:    endTime.Unix(),
		NoUserLoggedIn: dev.UserIdentity == "" || dev.UserIdentity == "unknown",

		IDEExtensions:        extensions,
		IDEInstallations:     ides,
		NodePkgManagers:      pkgManagers,
		NodeGlobalPackages:   globalPkgs,
		NodeProjects:         nodeProjects,
		BrewPkgManager:       brewPkgMgr,
		BrewScans:            brewScans,
		PythonPkgManagers:    pythonPkgManagers,
		PythonGlobalPackages: pythonGlobalPkgs,
		PythonProjects:       pythonProjects,
		SystemPackageScans:   systemPackageScans,
		AIAgents:             allAI,
		MCPConfigs:           mcpConfigs,

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

	// Upload to S3
	log.Progress("Requesting upload URL from backend...")
	if err := uploadToS3(ctx, log, payload); err != nil {
		return fmt.Errorf("uploading telemetry: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	log.Progress("Telemetry collection completed successfully")
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

func uploadToS3(ctx context.Context, log *progress.Logger, payload *Payload) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	// Request upload URL
	reqBody, _ := json.Marshal(map[string]string{
		"device_id": payload.DeviceID,
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

	// Upload payload to S3 with retry — use a longer timeout since payloads
	// with npm scan data and execution logs can be several MB.
	log.Progress("Uploading telemetry to S3 (%d bytes)...", len(payloadJSON))
	s3Client := &http.Client{Timeout: 10 * time.Minute}
	const maxRetries = 3
	var putResp *http.Response
	for attempt := 1; attempt <= maxRetries; attempt++ {
		uploadStart := time.Now()
		putReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPut, urlResp.UploadURL, bytes.NewReader(payloadJSON))
		if reqErr != nil {
			return fmt.Errorf("creating S3 PUT request: %w", reqErr)
		}
		putReq.Header.Set("Content-Type", "application/json")

		putResp, err = s3Client.Do(putReq)
		elapsed := time.Since(uploadStart)
		if err != nil {
			log.Debug("s3 PUT attempt %d/%d: error=%v elapsed=%s", attempt, maxRetries, err, elapsed)
		} else {
			log.Debug("s3 PUT attempt %d/%d: status=%d elapsed=%s payload_bytes=%d", attempt, maxRetries, putResp.StatusCode, elapsed, len(payloadJSON))
		}

		if err == nil && putResp.StatusCode == http.StatusOK {
			log.Progress("Uploaded to S3 in %s", elapsed)
			break
		}

		// Clean up response body before retry
		if putResp != nil {
			_, _ = io.Copy(io.Discard, putResp.Body)
			_ = putResp.Body.Close()
		}

		if attempt == maxRetries {
			if err != nil {
				return fmt.Errorf("uploading to S3 (payload: %d bytes, elapsed: %s, attempts: %d): %w",
					len(payloadJSON), elapsed, maxRetries, err)
			}
			return fmt.Errorf("S3 upload failed with status %d (payload: %d bytes, attempts: %d)",
				putResp.StatusCode, len(payloadJSON), maxRetries)
		}

		// Log retry and backoff
		backoff := time.Duration(attempt) * 2 * time.Second
		if err != nil {
			log.Warn("S3 upload attempt %d/%d failed after %s: %v; retrying in %s...", attempt, maxRetries, elapsed, err, backoff)
		} else {
			log.Warn("S3 upload attempt %d/%d got status %d, retrying in %s...", attempt, maxRetries, putResp.StatusCode, backoff)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	defer func() { _ = putResp.Body.Close() }()
	_, _ = io.Copy(io.Discard, putResp.Body)

	// Notify backend
	log.Progress("Notifying backend of upload...")
	notifyBody, _ := json.Marshal(map[string]string{
		"s3_key":    urlResp.S3Key,
		"device_id": payload.DeviceID,
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

func resolveSearchDirs(exec executor.Executor, dirs []string) []string {
	resolved := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "$HOME" {
			u, err := exec.LoggedInUser()
			if err == nil {
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
