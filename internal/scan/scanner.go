package scan

import (
	"context"
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/detector"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/output"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Run executes a community-mode scan and outputs results.
func Run(exec executor.Executor, log *progress.Logger, cfg *cli.Config) error {
	ctx := context.Background()

	// Resolve search directories
	searchDirs := resolveSearchDirs(exec, cfg.SearchDirs)

	// Gather device info
	log.StepStart("Gathering device information")
	start := time.Now()
	dev := device.Gather(ctx, exec)
	log.StepDone(time.Since(start))

	// Detect IDE installations
	log.StepStart("Detecting IDE installations")
	start = time.Now()
	ideDetector := detector.NewIDEDetector(exec)
	ides := ideDetector.Detect(ctx)
	log.StepDone(time.Since(start))

	// Detect AI agents and tools
	log.StepStart("Detecting AI agents and tools")
	start = time.Now()
	cliDetector := detector.NewAICLIDetector(exec)
	cliTools := cliDetector.Detect(ctx)
	agentDetector := detector.NewAgentDetector(exec)
	agents := agentDetector.Detect(ctx, searchDirs)
	fwDetector := detector.NewFrameworkDetector(exec)
	frameworks := fwDetector.Detect(ctx)
	aiTools := mergeAITools(cliTools, agents, frameworks)
	log.StepDone(time.Since(start))

	// Collect MCP configurations
	log.StepStart("Collecting MCP configurations")
	start = time.Now()
	mcpDetector := detector.NewMCPDetector(exec)
	mcpConfigs := mcpDetector.Detect(ctx, dev.UserIdentity, false)
	log.StepDone(time.Since(start))

	// Collect IDE extensions
	log.StepStart("Collecting IDE extensions")
	start = time.Now()
	extDetector := detector.NewExtensionDetector(exec)
	extensions := extDetector.Detect(ctx, searchDirs)

	// Collect JetBrains plugins
	jbDetector := detector.NewJetBrainsPluginDetector(exec)
	jbPlugins := jbDetector.Detect(ctx, ides)
	extensions = append(extensions, jbPlugins...)
	log.StepDone(time.Since(start))

	// Node.js scanning (community mode defaults to off, explicit flag overrides)
	npmEnabled := false
	if cfg.EnableNPMScan != nil {
		npmEnabled = *cfg.EnableNPMScan
	}
	// auto: disabled in community mode

	var pkgManagers []model.PkgManager
	var nodeProjects []model.ProjectInfo

	if npmEnabled {
		log.StepStart("Detecting package managers")
		start = time.Now()
		npmDetector := detector.NewNodePMDetector(exec)
		pkgManagers = npmDetector.DetectManagers(ctx)
		log.StepDone(time.Since(start))

		log.StepStart("Scanning Node.js projects")
		start = time.Now()
		projectDetector := detector.NewNodeProjectDetector(exec)
		nodeProjects = projectDetector.ListProjects(searchDirs)
		log.StepDone(time.Since(start))
	} else {
		log.StepStart("Node.js package scanning")
		log.StepSkip("disabled (use --enable-npm-scan to enable)")
	}

	// Homebrew scanning (community mode defaults to off, explicit flag overrides)
	brewEnabled := false
	if cfg.EnableBrewScan != nil {
		brewEnabled = *cfg.EnableBrewScan
	}

	var brewPkgManager *model.PkgManager
	var brewFormulae []model.BrewPackage
	var brewCasks []model.BrewPackage

	if brewEnabled {
		log.StepStart("Detecting Homebrew packages")
		start = time.Now()
		brewDetector := detector.NewBrewDetector(exec)
		brewPkgManager = brewDetector.DetectBrew(ctx)
		if brewPkgManager != nil {
			brewFormulae = brewDetector.ListFormulae(ctx)
			brewCasks = brewDetector.ListCasks(ctx)
		}
		log.StepDone(time.Since(start))
	} else {
		log.StepStart("Homebrew package scanning")
		log.StepSkip("disabled (use --enable-brew-scan to enable)")
	}

	// Python scanning (community mode defaults to off, explicit flag overrides)
	pythonEnabled := false
	if cfg.EnablePythonScan != nil {
		pythonEnabled = *cfg.EnablePythonScan
	}

	var pythonPkgManagers []model.PkgManager
	var pythonPackages []model.PythonPackage
	var pythonProjects []model.ProjectInfo

	if pythonEnabled {
		log.StepStart("Detecting Python package managers")
		start = time.Now()
		pyDetector := detector.NewPythonPMDetector(exec)
		pythonPkgManagers = pyDetector.DetectManagers(ctx)
		log.StepDone(time.Since(start))

		log.StepStart("Listing Python packages")
		start = time.Now()
		pythonPackages = pyDetector.ListPackages(ctx)
		log.StepDone(time.Since(start))

		log.StepStart("Scanning Python projects")
		start = time.Now()
		pyProjectDetector := detector.NewPythonProjectDetector(exec)
		pythonProjects = pyProjectDetector.ListProjects(searchDirs)
		log.StepDone(time.Since(start))
	} else {
		log.StepStart("Python package scanning")
		log.StepSkip("disabled (use --enable-python-scan to enable)")
	}

	// Ensure no nil slices (JSON must emit [] not null)
	if aiTools == nil {
		aiTools = []model.AITool{}
	}
	if ides == nil {
		ides = []model.IDE{}
	}
	if extensions == nil {
		extensions = []model.Extension{}
	}
	if pkgManagers == nil {
		pkgManagers = []model.PkgManager{}
	}
	if nodeProjects == nil {
		nodeProjects = []model.ProjectInfo{}
	}
	if pythonPkgManagers == nil {
		pythonPkgManagers = []model.PkgManager{}
	}
	if pythonProjects == nil {
		pythonProjects = []model.ProjectInfo{}
	}
	if brewFormulae == nil {
		brewFormulae = []model.BrewPackage{}
	}
	if brewCasks == nil {
		brewCasks = []model.BrewPackage{}
	}
	if pythonPackages == nil {
		pythonPackages = []model.PythonPackage{}
	}

	// Build result
	now := time.Now()
	result := &model.ScanResult{
		AgentVersion:      buildinfo.Version,
		AgentURL:          buildinfo.AgentURL,
		ScanTimestamp:     now.Unix(),
		ScanTimestampISO:  now.UTC().Format(time.RFC3339),
		Device:            dev,
		AIAgentsAndTools:  aiTools,
		IDEInstallations:  ides,
		IDEExtensions:     extensions,
		MCPConfigs:        mcpConfigsToCommunity(mcpConfigs),
		NodePkgManagers:   pkgManagers,
		NodePackages:      []any{},
		NodeProjects:      nodeProjects,
		BrewPkgManager:    brewPkgManager,
		BrewFormulae:      brewFormulae,
		BrewCasks:         brewCasks,
		PythonPkgManagers: pythonPkgManagers,
		PythonPackages:    pythonPackages,
		PythonProjects:    pythonProjects,
		Summary: model.Summary{
			AIAgentsAndToolsCount: len(aiTools),
			IDEInstallationsCount: len(ides),
			IDEExtensionsCount:    len(extensions),
			MCPConfigsCount:       len(mcpConfigs),
			NodeProjectsCount:     len(nodeProjects),
			BrewFormulaeCount:     len(brewFormulae),
			BrewCasksCount:        len(brewCasks),
			PythonProjectsCount:   len(pythonProjects),
		},
	}

	// Output
	switch cfg.OutputFormat {
	case "json":
		return output.JSON(os.Stdout, result)
	case "html":
		return output.HTML(cfg.HTMLOutputFile, result)
	default:
		return output.Pretty(os.Stdout, result, cfg.ColorMode)
	}
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

func mergeAITools(cli, agents, frameworks []model.AITool) []model.AITool {
	result := make([]model.AITool, 0, len(cli)+len(agents)+len(frameworks))
	result = append(result, cli...)
	result = append(result, agents...)
	result = append(result, frameworks...)
	return result
}

func mcpConfigsToCommunity(configs []model.MCPConfig) []model.MCPConfig {
	if configs == nil {
		return []model.MCPConfig{}
	}
	return configs
}
