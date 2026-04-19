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

	IDEExtensions      []model.Extension           `json:"ide_extensions"`
	IDEInstallations   []model.IDE                 `json:"ide_installations"`
	NodePkgManagers    []model.PkgManager          `json:"node_package_managers"`
	NodeGlobalPackages []model.NodeScanResult      `json:"node_global_packages"`
	NodeProjects       []model.NodeScanResult      `json:"node_projects"`
	AIAgents           []model.AITool              `json:"ai_agents"`
	MCPConfigs         []model.MCPConfigEnterprise `json:"mcp_configs"`

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
	ExtensionsCount     int   `json:"extensions_count"`
	NodePackagesScanMs  int64 `json:"node_packages_scan_ms"`
	NodeGlobalPkgsCount int   `json:"node_global_packages_count"`
	NodeProjectsCount   int   `json:"node_projects_count"`
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
		return fmt.Errorf("acquiring lock: %w", err)
	}
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

	// Detect logged-in user for running commands as the real user when root.
	// Skip "root" — if LoggedInUser() fell back to CurrentUser(), delegating
	// via sudo -H -u root is pointless and changes PATH/env behavior.
	loggedInUsername := ""
	if u, err := exec.LoggedInUser(); err == nil && u.Username != "root" {
		loggedInUsername = u.Username
	}

	// Resolve search dirs
	searchDirs := resolveSearchDirs(exec, cfg.SearchDirs)
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
	extensions := extDetector.Detect(ctx, searchDirs)
	log.Progress("Found total of %d IDE extensions", len(extensions))
	fmt.Fprintln(os.Stderr)

	// Detect AI tools
	log.Progress("Detecting AI agents and tools...")
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting AI CLI tools...")
	cliTools := detector.NewAICLIDetector(exec).Detect(ctx)
	for _, t := range cliTools {
		log.Progress("  Found: %s (%s) v%s at %s", t.Name, t.Vendor, t.Version, t.BinaryPath)
	}
	if len(cliTools) == 0 {
		log.Progress("  No AI CLI tools found")
	}
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting general-purpose AI agents...")
	agents := detector.NewAgentDetector(exec).Detect(ctx, searchDirs)
	for _, a := range agents {
		log.Progress("  Found: %s (%s) at %s", a.Name, a.Vendor, a.InstallPath)
	}
	if len(agents) == 0 {
		log.Progress("  No general-purpose AI agents found")
	}
	fmt.Fprintln(os.Stderr)

	log.Progress("Detecting AI frameworks and runtimes...")
	frameworks := detector.NewFrameworkDetector(exec).Detect(ctx)
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
	fmt.Fprintln(os.Stderr)

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
		npmDetector := detector.NewNodePMDetector(exec)
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

		IDEExtensions:      extensions,
		IDEInstallations:   ides,
		NodePkgManagers:    pkgManagers,
		NodeGlobalPackages: globalPkgs,
		NodeProjects:       nodeProjects,
		AIAgents:           allAI,
		MCPConfigs:         mcpConfigs,

		ExecutionLogs: &ExecutionLogs{
			OutputBase64: execLogsBase64,
			StartTime:    startTime.Unix(),
			EndTime:      endTime.Unix(),
			ExitCode:     0,
			AgentVersion: buildinfo.Version,
		},

		PerformanceMetrics: &PerformanceMetrics{
			ExtensionsCount:     len(extensions),
			NodePackagesScanMs:  nodeScanMs,
			NodeGlobalPkgsCount: len(globalPkgs),
			NodeProjectsCount:   len(nodeProjects),
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

	if urlResp.UploadURL == "" {
		return fmt.Errorf("empty upload URL in response")
	}

	// Upload payload to S3
	log.Progress("Uploading telemetry to S3...")
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, urlResp.UploadURL, bytes.NewReader(payloadJSON))
	if err != nil {
		return fmt.Errorf("creating S3 PUT request: %w", err)
	}
	putReq.Header.Set("Content-Type", "application/json")

	putResp, err := client.Do(putReq)
	if err != nil {
		return fmt.Errorf("uploading to S3: %w", err)
	}
	defer func() { _ = putResp.Body.Close() }()
	_, _ = io.Copy(io.Discard, putResp.Body)

	if putResp.StatusCode != http.StatusOK {
		return fmt.Errorf("S3 upload failed with status %d", putResp.StatusCode)
	}
	log.Progress("Uploaded to S3")

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
