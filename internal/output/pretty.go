package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Pretty writes human-readable formatted output.
//
//nolint:errcheck // fmt.Fprint* to io.Writer; errors surface through the writer
func Pretty(w io.Writer, result *model.ScanResult, colorMode string) error {
	result = communityInventory(result)
	c := setupColors(colorMode)

	scanTime := time.Unix(result.ScanTimestamp, 0).Format("2006-01-02 15:04:05")

	title := fmt.Sprintf("StepSecurity Dev Machine Guard v%s", buildinfo.Version)
	url := buildinfo.AgentURL
	boxWidth := 58
	titlePad := boxWidth - 2 - len(title)
	urlPad := boxWidth - 2 - len(url)

	// Banner
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s┌%s┐%s\n", c.purple, strings.Repeat("─", boxWidth), c.reset)
	fmt.Fprintf(w, "  %s│%s  %s%s%s%*s%s│%s\n", c.purple, c.reset, c.bold, title, c.reset, titlePad, "", c.purple, c.reset)
	fmt.Fprintf(w, "  %s│%s  %s%s%s%*s%s│%s\n", c.purple, c.reset, c.dim, url, c.reset, urlPad, "", c.purple, c.reset)
	fmt.Fprintf(w, "  %s└%s┘%s\n", c.purple, strings.Repeat("─", boxWidth), c.reset)
	fmt.Fprintf(w, "  %sScanned at %s%s\n", c.dim, scanTime, c.reset)
	fmt.Fprintln(w)

	// DEVICE
	fmt.Fprintf(w, "  %s%sDEVICE%s\n", c.purple, c.bold, c.reset)
	fmt.Fprintf(w, "    %-16s %s\n", "Hostname", result.Device.Hostname)
	fmt.Fprintf(w, "    %-16s %s\n", "Serial", result.Device.SerialNumber)
	osLabel := model.PlatformDisplayName(result.Device.Platform)
	fmt.Fprintf(w, "    %-16s %s\n", osLabel, result.Device.OSVersion)
	fmt.Fprintf(w, "    %-16s %s\n", "User", result.Device.UserIdentity)
	if cpu := formatCPU(result.Device.Resources); cpu != "" {
		fmt.Fprintf(w, "    %-16s %s\n", "CPU", cpu)
	}
	if result.Device.Resources.MemoryBytes > 0 {
		fmt.Fprintf(w, "    %-16s %s\n", "Memory", formatBytes(result.Device.Resources.MemoryBytes))
	}
	if result.Device.Resources.DiskTotalBytes > 0 {
		fmt.Fprintf(w, "    %-16s %s\n", "Disk", formatBytes(result.Device.Resources.DiskTotalBytes))
	}
	if wsl := result.Device.WSL; wsl != nil {
		fmt.Fprintf(w, "    %-16s %s\n", "WSL", formatWSL(wsl))
	}
	fmt.Fprintln(w)

	// SUMMARY
	fmt.Fprintf(w, "  %s%sSUMMARY%s\n", c.purple, c.bold, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "AI Agents and Tools", c.green, result.Summary.AIAgentsAndToolsCount, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "IDEs & Desktop Apps", c.green, result.Summary.IDEInstallationsCount, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "IDE Extensions", c.green, result.Summary.IDEExtensionsCount, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "MCP Servers", c.green, result.Summary.MCPConfigsCount, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "Agent Skills", c.green, result.Summary.AgentSkillsCount, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "Agent Plugins", c.green, result.Summary.AgentPluginsCount, c.reset)
	if len(result.NodePkgManagers) > 0 {
		fmt.Fprintf(w, "    %-24s %s%d%s\n", "Node.js Projects", c.green, result.Summary.NodeProjectsCount, c.reset)
	}
	if result.BrewPkgManager != nil {
		fmt.Fprintf(w, "    %-24s %s%d%s\n", "Homebrew Formulae", c.green, result.Summary.BrewFormulaeCount, c.reset)
		fmt.Fprintf(w, "    %-24s %s%d%s\n", "Homebrew Casks", c.green, result.Summary.BrewCasksCount, c.reset)
	}
	if len(result.PythonPkgManagers) > 0 {
		fmt.Fprintf(w, "    %-24s %s%d%s\n", "Python Projects", c.green, result.Summary.PythonProjectsCount, c.reset)
	}
	if result.SystemPkgManager != nil {
		fmt.Fprintf(w, "    %-24s %s%d%s\n", "System Packages", c.green, result.Summary.SystemPackagesCount, c.reset)
	}
	if result.SnapPkgManager != nil {
		fmt.Fprintf(w, "    %-24s %s%d%s\n", "Snap Packages", c.green, result.Summary.SnapPackagesCount, c.reset)
	}
	if result.FlatpakPkgManager != nil {
		fmt.Fprintf(w, "    %-24s %s%d%s\n", "Flatpak Apps", c.green, result.Summary.FlatpakPackagesCount, c.reset)
	}
	fmt.Fprintln(w)

	// AI AGENTS AND TOOLS
	printSectionHeader(w, c, "AI AGENTS AND TOOLS", result.Summary.AIAgentsAndToolsCount)
	if len(result.AIAgentsAndTools) > 0 {
		for _, t := range result.AIAgentsAndTools {
			typeLabel := t.Type
			switch t.Type {
			case "cli_tool":
				typeLabel = "cli"
			case "general_agent":
				typeLabel = "agent"
			case "framework":
				typeLabel = "framework"
			}
			fmt.Fprintf(w, "    %-24s %sv%-20s %-12s %s%s\n",
				truncate(t.Name, 24), c.dim, truncate(t.Version, 20), "["+typeLabel+"]", t.Vendor, c.reset)
		}
	} else {
		fmt.Fprintf(w, "    %sNone detected%s\n", c.dim, c.reset)
	}
	fmt.Fprintln(w)

	// IDE & AI DESKTOP APPS
	printSectionHeader(w, c, "IDE & AI DESKTOP APPS", result.Summary.IDEInstallationsCount)
	if len(result.IDEInstallations) > 0 {
		for _, ide := range result.IDEInstallations {
			displayName := ideDisplayName(ide.IDEType)
			fmt.Fprintf(w, "    %-24s %sv%-20s %s%s\n",
				truncate(displayName, 24), c.dim, truncate(ide.Version, 20), ide.Vendor, c.reset)
		}
	} else {
		fmt.Fprintf(w, "    %sNone detected%s\n", c.dim, c.reset)
	}
	fmt.Fprintln(w)

	// MCP SERVERS
	printSectionHeader(w, c, "MCP SERVERS", result.Summary.MCPConfigsCount)
	if len(result.MCPConfigs) > 0 {
		for _, cfg := range result.MCPConfigs {
			fmt.Fprintf(w, "    %-24s %s%s%s\n", cfg.ConfigSource, c.dim, cfg.Vendor, c.reset)
		}
	} else {
		fmt.Fprintf(w, "    %sNone detected%s\n", c.dim, c.reset)
	}
	fmt.Fprintln(w)

	// AGENT SKILLS
	printSectionHeader(w, c, "AGENT SKILLS", result.Summary.AgentSkillsCount)
	if result.AgentSkillScan == nil {
		// Missing coverage is distinct from an empty scan.
		fmt.Fprintf(w, "    %sNot scanned%s\n", c.dim, c.reset)
	} else if len(result.AgentSkills) > 0 {
		for _, s := range result.AgentSkills {
			tag := ""
			if s.ManagedBy != "" {
				tag = " [" + s.ManagedBy + "]"
			}
			if s.DefinitionKind == model.AgentDefinitionCommand {
				tag += " [command]"
			}
			if n := len(s.SymlinkSources); n > 0 {
				tag += fmt.Sprintf(" [+%d linked]", n)
			}
			fmt.Fprintf(w, "    %-24s %s%-18s %-11s %s%s%s\n",
				truncate(s.SkillName, 24), c.dim, truncate(s.Source, 18), truncate(s.Agent, 11), s.Scope, tag, c.reset)
		}
	} else {
		fmt.Fprintf(w, "    %sNone detected%s\n", c.dim, c.reset)
	}
	fmt.Fprintln(w)

	// IDE EXTENSIONS
	printSectionHeader(w, c, "IDE EXTENSIONS", result.Summary.IDEExtensionsCount)
	if len(result.IDEExtensions) > 0 {
		// Group by IDE type
		groups := make(map[string][]model.Extension)
		for _, ext := range result.IDEExtensions {
			groups[ext.IDEType] = append(groups[ext.IDEType], ext)
		}
		for ideType, exts := range groups {
			displayType := ideDisplayName(ideType)
			fmt.Fprintf(w, "    %s%s%s%s%*s%s%d found%s\n",
				c.purple, c.bold, displayType, c.reset, 33-len(displayType), "", c.green, len(exts), c.reset)
			for _, ext := range exts {
				sourceTag := ""
				if ext.Source == "bundled" {
					sourceTag = " [bundled]"
				}
				fmt.Fprintf(w, "      %-42s %sv%-14s %s%s%s\n",
					truncate(ext.ID, 42), c.dim, truncate(ext.Version, 14), ext.Publisher, sourceTag, c.reset)
			}
		}
	} else {
		fmt.Fprintf(w, "    %sNone detected%s\n", c.dim, c.reset)
	}
	fmt.Fprintln(w)

	// AGENT PLUGINS
	printAgentPlugins(w, c, result)

	// BROWSER EXTENSIONS
	printBrowserExtensions(w, c, result)

	// NODE.JS PACKAGE MANAGERS (only if npm scan was enabled)
	if len(result.NodePkgManagers) > 0 {
		printSectionHeader(w, c, "NODE.JS PACKAGE MANAGERS", len(result.NodePkgManagers))
		for _, pm := range result.NodePkgManagers {
			fmt.Fprintf(w, "    %-24s %sv%s%s\n", pm.Name, c.dim, pm.Version, c.reset)
		}
		fmt.Fprintln(w)

		printSectionHeader(w, c, "NODE.JS PROJECTS", result.Summary.NodeProjectsCount)
		for _, proj := range result.NodeProjects {
			fmt.Fprintf(w, "    %s%s%s  %s[%s]%s\n", c.bold, proj.Path, c.reset, c.dim, proj.PackageManager, c.reset)
			for _, pkg := range proj.Packages {
				fmt.Fprintf(w, "      %-36s %s%s%s\n", pkg.Name, c.dim, pkg.Version, c.reset)
			}
		}
		fmt.Fprintln(w)
	}

	// HOMEBREW (only if brew scan was enabled and brew found)
	if result.BrewPkgManager != nil {
		fmt.Fprintf(w, "  %s%sHOMEBREW%s%*s%sv%s%s\n",
			c.purple, c.bold, c.reset, 27, "", c.dim, result.BrewPkgManager.Version, c.reset)
		fmt.Fprintln(w)

		if len(result.BrewFormulae) > 0 {
			fmt.Fprintf(w, "    %s%sFormulae%s%*s%s%d found%s\n",
				c.purple, c.bold, c.reset, 25, "", c.green, len(result.BrewFormulae), c.reset)
			for _, pkg := range result.BrewFormulae {
				fmt.Fprintf(w, "      %-36s %s%s%s\n", pkg.Name, c.dim, pkg.Version, c.reset)
			}
		} else {
			fmt.Fprintf(w, "    %s%sFormulae%s%*s%s0 found%s\n",
				c.purple, c.bold, c.reset, 25, "", c.green, c.reset)
		}
		fmt.Fprintln(w)

		if len(result.BrewCasks) > 0 {
			fmt.Fprintf(w, "    %s%sCasks%s%*s%s%d found%s\n",
				c.purple, c.bold, c.reset, 28, "", c.green, len(result.BrewCasks), c.reset)
			for _, pkg := range result.BrewCasks {
				fmt.Fprintf(w, "      %-36s %s%s%s\n", pkg.Name, c.dim, pkg.Version, c.reset)
			}
		} else {
			fmt.Fprintf(w, "    %s%sCasks%s%*s%s0 found%s\n",
				c.purple, c.bold, c.reset, 28, "", c.green, c.reset)
		}
		fmt.Fprintln(w)
	}

	// PYTHON (only if python scan was enabled)
	if len(result.PythonPkgManagers) > 0 {
		printSectionHeader(w, c, "PYTHON PACKAGE MANAGERS", len(result.PythonPkgManagers))
		for _, pm := range result.PythonPkgManagers {
			fmt.Fprintf(w, "    %-24s %sv%s%s\n", pm.Name, c.dim, pm.Version, c.reset)
		}
		fmt.Fprintln(w)

		printSectionHeader(w, c, "PYTHON GLOBAL PACKAGES", len(result.PythonPackages))
		for _, pkg := range result.PythonPackages {
			fmt.Fprintf(w, "    %-36s %s%s%s\n", pkg.Name, c.dim, pkg.Version, c.reset)
		}
		fmt.Fprintln(w)

		printSectionHeader(w, c, "PYTHON VENV PROJECTS", result.Summary.PythonProjectsCount)
		for _, proj := range result.PythonProjects {
			fmt.Fprintf(w, "    %s%s%s  %s[%s]%s\n", c.bold, proj.Path, c.reset, c.dim, proj.PackageManager, c.reset)
			for _, pkg := range proj.Packages {
				fmt.Fprintf(w, "      %-36s %s%s%s\n", pkg.Name, c.dim, pkg.Version, c.reset)
			}
		}
		fmt.Fprintln(w)
	}

	// SYSTEM PACKAGES (Linux only)
	if result.SystemPkgManager != nil {
		fmt.Fprintf(w, "  %s%sSYSTEM PACKAGES (%s)%s%*s%sv%s%s\n",
			c.purple, c.bold, strings.ToUpper(result.SystemPkgManager.Name), c.reset,
			18-len(result.SystemPkgManager.Name), "", c.dim, result.SystemPkgManager.Version, c.reset)
		fmt.Fprintln(w)

		if len(result.SystemPackages) > 0 {
			printSectionHeader(w, c, "Installed Packages", len(result.SystemPackages))
			for _, pkg := range result.SystemPackages {
				fmt.Fprintf(w, "      %-36s %s%s%s\n", pkg.Name, c.dim, pkg.Version, c.reset)
			}
		} else {
			fmt.Fprintf(w, "    %sNo packages found%s\n", c.dim, c.reset)
		}
		fmt.Fprintln(w)
	}

	// SNAP PACKAGES (Linux only)
	if result.SnapPkgManager != nil {
		fmt.Fprintf(w, "  %s%sSNAP PACKAGES%s\n", c.purple, c.bold, c.reset)
		fmt.Fprintln(w)
		if len(result.SnapPackages) > 0 {
			printSectionHeader(w, c, "Installed Snaps", len(result.SnapPackages))
			for _, pkg := range result.SnapPackages {
				fmt.Fprintf(w, "      %-36s %s%s%s\n", pkg.Name, c.dim, pkg.Version, c.reset)
			}
		} else {
			fmt.Fprintf(w, "    %sNo snap packages found%s\n", c.dim, c.reset)
		}
		fmt.Fprintln(w)
	}

	// FLATPAK APPS (Linux only)
	if result.FlatpakPkgManager != nil {
		fmt.Fprintf(w, "  %s%sFLATPAK APPS%s\n", c.purple, c.bold, c.reset)
		fmt.Fprintln(w)
		if len(result.FlatpakPackages) > 0 {
			printSectionHeader(w, c, "Installed Apps", len(result.FlatpakPackages))
			for _, pkg := range result.FlatpakPackages {
				fmt.Fprintf(w, "      %-36s %s%s%s\n", pkg.Name, c.dim, pkg.Version, c.reset)
			}
		} else {
			fmt.Fprintf(w, "    %sNo flatpak apps found%s\n", c.dim, c.reset)
		}
		fmt.Fprintln(w)
	}

	// NPM CONFIG AUDIT (compact summary; deep view via --npmrc)
	if result.NPMRCAudit != nil {
		printNPMRCAuditSummary(w, c, result.NPMRCAudit)
	}

	// PIP CONFIG AUDIT (compact summary; deep view via --pipconfig)
	if result.PipAudit != nil {
		printPipAuditSummary(w, c, result.PipAudit)
	}

	// PNPM CONFIG AUDIT (compact summary; deep view via --pnpmrc)
	if result.PnpmAudit != nil {
		printPnpmAuditSummary(w, c, result.PnpmAudit)
	}

	// BUN CONFIG AUDIT (compact summary; deep view via --bunfig)
	if result.BunAudit != nil {
		printBunAuditSummary(w, c, result.BunAudit)
	}

	// YARN CONFIG AUDIT (compact summary; deep view via --yarnrc)
	if result.YarnAudit != nil {
		printYarnAuditSummary(w, c, result.YarnAudit)
	}

	return nil
}

//nolint:errcheck // terminal output
func printYarnAuditSummary(w io.Writer, c *colors, a *model.YarnAudit) {
	fmt.Fprintf(w, "  %s%sYARN CONFIG AUDIT%s\n", c.purple, c.bold, c.reset)
	if a.Available {
		flavor := a.Flavor
		if flavor == "" {
			flavor = "unknown"
		}
		fmt.Fprintf(w, "    %syarn:%s %s (%s) @ %s\n", c.dim, c.reset, a.YarnVersion, flavor, a.YarnPath)
	} else {
		fmt.Fprintf(w, "    %syarn:%s not found in PATH\n", c.dim, c.reset)
	}
	existing := 0
	classic, berry := 0, 0
	for _, f := range a.Files {
		if f.Exists {
			existing++
		}
		switch f.Flavor {
		case "berry":
			berry++
		case "classic":
			classic++
		}
	}
	fmt.Fprintf(w, "    %sfiles:%s %d discovered (%d classic / %d berry), %d present  (+%d .npmrc side-channel)\n",
		c.dim, c.reset, len(a.Files), classic, berry, existing, len(a.NPMRCFiles))
	fmt.Fprintf(w, "    %srun --yarnrc for the deep view%s\n", c.dim, c.reset)
	fmt.Fprintln(w)
}

//nolint:errcheck // terminal output
func printBunAuditSummary(w io.Writer, c *colors, a *model.BunAudit) {
	fmt.Fprintf(w, "  %s%sBUN CONFIG AUDIT%s\n", c.purple, c.bold, c.reset)
	if a.Available {
		fmt.Fprintf(w, "    %sbun:%s %s @ %s\n", c.dim, c.reset, a.BunVersion, a.BunPath)
	} else {
		fmt.Fprintf(w, "    %sbun:%s not found in PATH\n", c.dim, c.reset)
	}
	existing := 0
	for _, f := range a.Files {
		if f.Exists {
			existing++
		}
	}
	fmt.Fprintf(w, "    %sfiles:%s %d bunfig.toml discovered, %d present  (+%d .npmrc side-channel)\n",
		c.dim, c.reset, len(a.Files), existing, len(a.NPMRCFiles))
	fmt.Fprintf(w, "    %srun --bunfig for the deep view%s\n", c.dim, c.reset)
	fmt.Fprintln(w)
}

//nolint:errcheck // terminal output
func printPnpmAuditSummary(w io.Writer, c *colors, a *model.PnpmAudit) {
	fmt.Fprintf(w, "  %s%sPNPM CONFIG AUDIT%s\n", c.purple, c.bold, c.reset)
	if a.Available {
		fmt.Fprintf(w, "    %spnpm:%s %s @ %s\n", c.dim, c.reset, a.PnpmVersion, a.PnpmPath)
	} else {
		fmt.Fprintf(w, "    %spnpm:%s not found in PATH\n", c.dim, c.reset)
	}
	existing := 0
	for _, f := range a.Files {
		if f.Exists {
			existing++
		}
	}
	fmt.Fprintf(w, "    %sfiles:%s %d discovered, %d present\n", c.dim, c.reset, len(a.Files), existing)
	fmt.Fprintf(w, "    %srun --pnpmrc for the deep view%s\n", c.dim, c.reset)
	fmt.Fprintln(w)
}

//nolint:errcheck // terminal output
func printNPMRCAuditSummary(w io.Writer, c *colors, a *model.NPMRCAudit) {
	fmt.Fprintf(w, "  %s%sNPM CONFIG AUDIT%s\n", c.purple, c.bold, c.reset)
	if a.Available {
		fmt.Fprintf(w, "    %snpm:%s %s @ %s\n", c.dim, c.reset, a.NPMVersion, a.NPMPath)
	} else {
		fmt.Fprintf(w, "    %snpm:%s not found in PATH (file-only audit)\n", c.dim, c.reset)
	}
	existing := 0
	for _, f := range a.Files {
		if f.Exists {
			existing++
		}
	}
	fmt.Fprintf(w, "    %sfiles:%s %d discovered, %d present\n", c.dim, c.reset, len(a.Files), existing)
	fmt.Fprintf(w, "    %srun --npmrc for the deep view%s\n", c.dim, c.reset)
	fmt.Fprintln(w)
}

//nolint:errcheck // terminal output
func printPipAuditSummary(w io.Writer, c *colors, a *model.PipAudit) {
	fmt.Fprintf(w, "  %s%sPIP CONFIG AUDIT%s\n", c.purple, c.bold, c.reset)
	if a.Available {
		fmt.Fprintf(w, "    %spip:%s %s @ %s\n", c.dim, c.reset, a.Version, a.Path)
	} else {
		fmt.Fprintf(w, "    %spip:%s not found in PATH\n", c.dim, c.reset)
	}
	counts := map[string]int{}
	for _, f := range a.Findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "    %sfiles:%s %d   %sfindings:%s %sCRITICAL %d  HIGH %d  MEDIUM %d  LOW %d  INFO %d%s\n",
		c.dim, c.reset, len(a.Files),
		c.dim, c.reset,
		c.bold, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"], c.reset)
	if len(a.Findings) > 0 {
		fmt.Fprintf(w, "    %srun --pipconfig for the deep view%s\n", c.dim, c.reset)
	}
	fmt.Fprintln(w)
}

// printBrowserExtensions renders the inventory in three states: the phase not having
// run, the phase having run and found nothing, and a list. The first two mean opposite
// things and are easy to confuse.
//
//nolint:errcheck // terminal output
func printBrowserExtensions(w io.Writer, c *colors, result *model.ScanResult) {
	scan := result.BrowserExtensionScan
	count := 0
	if scan != nil {
		count = len(scan.Findings)
	}
	printSectionHeader(w, c, "BROWSER EXTENSIONS", count)

	switch {
	case scan == nil:
		fmt.Fprintf(w, "    %sNot scanned%s\n", c.dim, c.reset)
	case count == 0:
		fmt.Fprintf(w, "    %sNone detected%s\n", c.dim, c.reset)
	default:
		for _, f := range scan.Findings {
			tag := ""
			if f.EnabledState != model.BrowserExtEnabled {
				tag = " [" + f.EnabledState
				if f.DisabledBy != "" {
					tag += " by " + f.DisabledBy
				}
				tag += "]"
			}
			if f.StoreListing == model.BrowserExtStoreListingDelisted {
				tag += " [delisted]"
			}
			name := f.Name
			if name == "" {
				// A finding whose metadata could not be recovered still has an
				// identity to look it up by.
				name = f.ExtensionID
			}
			fmt.Fprintf(w, "    %-30s %s%-10s %-12s %s%s%s\n",
				truncate(name, 30), c.dim, truncate(f.BrowserID, 10),
				truncate(f.InstallSource, 12), truncate(f.Version, 12), tag, c.reset)
		}
	}
	// A browser that could not be read is why a list is shorter than expected.
	if scan != nil {
		for _, b := range scan.Browsers {
			if b.Status == model.BrowserCoverageFailed || b.Status == model.BrowserCoveragePartial {
				fmt.Fprintf(w, "    %s%s: %s (%s)%s\n", c.dim, b.BrowserID, b.Status, b.ReasonCode, c.reset)
			}
		}
	}
	fmt.Fprintln(w)
}

func printSectionHeader(w io.Writer, c *colors, title string, count int) {
	padding := 35 - len(title)
	if padding < 1 {
		padding = 1
	}
	fmt.Fprintf(w, "  %s%s%s%s%*s%s%d found%s\n", c.purple, c.bold, title, c.reset, padding, "", c.green, count, c.reset)
}

type colors struct {
	purple string
	green  string
	bold   string
	dim    string
	reset  string
}

func setupColors(mode string) *colors {
	useColors := false
	switch mode {
	case "always":
		useColors = true
	case "never":
		useColors = false
	default: // auto
		fi, err := os.Stdout.Stat()
		if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			useColors = true
		}
	}

	if !useColors {
		return &colors{}
	}

	return &colors{
		purple: "\033[0;35m",
		green:  "\033[0;32m",
		bold:   "\033[1m",
		dim:    "\033[2m",
		reset:  "\033[0m",
	}
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

// formatWSL renders the WSL summary line for the DEVICE block, e.g.
// "present — 2 distros, 1 running (WSL 2.7.11.0)". Presence is tri-state:
// "unknown" (probe couldn't read the registry) is shown as-is rather than
// collapsed to "not present".
func formatWSL(w *model.WSLInfo) string {
	switch w.Presence {
	case model.WSLPresenceNo:
		return "not present"
	case model.WSLPresenceUnknown:
		return "unknown"
	}
	running := 0
	for _, d := range w.Distros {
		if d.Running {
			running++
		}
	}
	s := fmt.Sprintf("present — %d distro", len(w.Distros))
	if len(w.Distros) != 1 {
		s += "s"
	}
	if w.Active {
		s += fmt.Sprintf(", %d running", running)
	} else {
		s += ", none running"
	}
	if w.Version != "" && w.Version != "unknown" {
		s += " (WSL " + w.Version + ")"
	}
	return s
}

// formatCPU renders the CPU summary as
//
//	"Apple M3 Pro (12c / 16t, arm64)"
//
// Each piece is omitted gracefully when the underlying field is missing
// (e.g. ARM Linux where /proc/cpuinfo has no "model name"). Returns "" when
// nothing is known.
func formatCPU(res model.MachineResources) string {
	parts := []string{}
	if res.CPUModel != "" {
		parts = append(parts, res.CPUModel)
	}
	var detail []string
	if res.PhysicalCores > 0 {
		detail = append(detail, fmt.Sprintf("%dc", res.PhysicalCores))
	}
	if res.LogicalCores > 0 {
		detail = append(detail, fmt.Sprintf("%dt", res.LogicalCores))
	}
	if res.CPUArchitecture != "" {
		detail = append(detail, res.CPUArchitecture)
	}
	if len(detail) == 0 {
		if len(parts) == 0 {
			return ""
		}
		return parts[0]
	}
	if len(parts) == 0 {
		return "(" + joinCPUDetail(detail) + ")"
	}
	return parts[0] + " (" + joinCPUDetail(detail) + ")"
}

func joinCPUDetail(detail []string) string {
	// Cores joined with " / "; arch separated by ", " for readability.
	switch len(detail) {
	case 1:
		return detail[0]
	case 2:
		return detail[0] + " / " + detail[1]
	default:
		return detail[0] + " / " + detail[1] + ", " + strings.Join(detail[2:], ", ")
	}
}

// formatBytes renders a byte count as a human-readable size using binary
// units (GiB), but labels them in the more familiar "GB" form. Examples:
//
//	17179869184 -> "16 GB"
//	494384795648 -> "460 GB"
func formatBytes(b uint64) string {
	if b == 0 {
		return "0 B"
	}
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
		tib = 1024 * gib
	)
	switch {
	case b >= tib:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(tib))
	case b >= gib:
		return fmt.Sprintf("%d GB", b/gib)
	case b >= mib:
		return fmt.Sprintf("%d MB", b/mib)
	case b >= kib:
		return fmt.Sprintf("%d KB", b/kib)
	default:
		return fmt.Sprintf("%d B", b)
	}
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

func pluginState(value *bool) string {
	if value == nil {
		return "unknown"
	}
	if *value {
		return "yes"
	}
	return "no"
}

//nolint:errcheck // terminal output
func printAgentPlugins(w io.Writer, c *colors, result *model.ScanResult) {
	scan := result.AgentPlugins
	printSectionHeader(w, c, "AGENT PLUGINS", scan.PluginCount())
	if scan == nil {
		fmt.Fprintln(w, "    Not scanned")
	} else {
		if len(scan.Contexts) == 0 {
			fmt.Fprintln(w, "    No agent contexts detected")
		}
		for _, context := range scan.Contexts {
			fmt.Fprintf(w, "    %s — marketplaces: %s; installations: %s\n", context.Agent, context.MarketplaceStatus, context.InstallationStatus)
			if len(context.Plugins) == 0 && context.InstallationStatus == model.AgentScanStatusComplete {
				fmt.Fprintln(w, "      None detected")
			}
			for _, market := range context.Marketplaces {
				fmt.Fprintf(w, "      marketplace: %s; registered: %t; auto-update: %s\n", market.Name, market.Registered, pluginState(market.AutoUpdateEnabled))
				if market.Source != nil {
					fmt.Fprintf(w, "        source: %s %s\n", market.Source.Kind, market.Source.Location)
				}
			}
			for _, p := range context.Plugins {
				fmt.Fprintf(w, "      %s (%s, %s)\n", p.NativeID, p.Scope, p.InstallationKind)
				fmt.Fprintf(w, "        installed: %s; files present: %s; configured enabled: %s; effective enabled: %s\n", pluginState(p.Installed), pluginState(p.FilesPresent), pluginState(p.ConfiguredEnabled), pluginState(p.EffectiveEnabled))
				if p.ManifestVersion != "" || p.CacheVersion != "" {
					fmt.Fprintf(w, "        manifest version: %s; cache version: %s\n", p.ManifestVersion, p.CacheVersion)
				}
				if p.InstallPath != "" {
					fmt.Fprintf(w, "        path: %s\n", p.InstallPath)
				}
				if p.Source != nil {
					fmt.Fprintf(w, "        payload source: %s %s %s\n", p.Source.Kind, p.Source.Location, p.Source.PackageName)
				}
				if p.SourcePath != "" {
					fmt.Fprintf(w, "        source path: %s\n", p.SourcePath)
				}
				fmt.Fprintf(w, "        declared components: %d; coverage: %s\n", len(p.Components), p.ComponentStatus)
				for _, component := range p.Components {
					fmt.Fprintf(w, "          %s: %s (%s)\n", component.Kind, component.Name, component.Status)
				}
			}
		}
	}
	fmt.Fprintln(w)
	for _, skill := range result.AgentSkills {
		if skill.Usage == nil {
			continue
		}
		if skill.Usage.RecordedUses != nil {
			fmt.Fprintf(w, "    %s: %d recorded uses\n", skill.SkillName, *skill.Usage.RecordedUses)
		} else {
			fmt.Fprintf(w, "    %s: usage %s\n", skill.SkillName, skill.Usage.Availability)
		}
	}
	fmt.Fprintln(w)
}

// communityInventory combines display rows without duplicating the wire inventory.
// MCP counts remain configuration-file counts, not server or component counts.
func communityInventory(result *model.ScanResult) *model.ScanResult {
	if result.AgentPlugins == nil {
		return result
	}
	view := *result
	view.AgentSkills = append([]model.AgentSkill(nil), result.AgentSkills...)
	view.MCPConfigs = append([]model.MCPConfig(nil), result.MCPConfigs...)
	skillPaths, mcpPaths := map[string]bool{}, map[string]bool{}
	skillPath := func(skill model.AgentSkill) string {
		if skill.SkillDirPath != "" {
			return skill.SkillDirPath
		}
		if skill.DefinitionPath != "" {
			return skill.DefinitionPath
		}
		return skill.SkillMDPath
	}
	for _, skill := range result.AgentSkills {
		if key := skillPath(skill); key != "" {
			skillPaths[key] = true
		}
	}
	for _, mcp := range result.MCPConfigs {
		if mcp.ConfigPath != "" {
			mcpPaths[mcp.ConfigPath] = true
		}
	}
	for _, context := range result.AgentPlugins.Contexts {
		for _, plugin := range context.Plugins {
			for _, component := range plugin.Components {
				var skill *model.AgentSkill
				if component.Skill != nil {
					skill = component.Skill
				} else if command := component.Command; command != nil {
					skill = &model.AgentSkill{SkillName: command.Name, Agent: context.Agent, Source: "plugin", Scope: plugin.Scope, ProjectPath: plugin.ProjectPath,
						DefinitionKind: model.AgentDefinitionCommand, DefinitionPath: command.DefinitionPath, Usage: command.Usage}
				}
				if skill != nil {
					key := skillPath(*skill)
					if component.Kind == model.PluginComponentCommand && component.ResolvedDefinitionPath != "" {
						key = component.ResolvedDefinitionPath
					}
					if key == "" || !skillPaths[key] {
						view.AgentSkills = append(view.AgentSkills, *skill)
						if key != "" {
							skillPaths[key] = true
						}
					}
				}
				if mcp := component.MCPConfig; mcp != nil {
					key := mcp.ConfigPath
					if component.ResolvedDefinitionPath != "" {
						key = component.ResolvedDefinitionPath
					}
					if key == "" || !mcpPaths[key] {
						view.MCPConfigs = append(view.MCPConfigs, model.MCPConfig{ConfigSource: mcp.ConfigSource, ConfigPath: mcp.ConfigPath, Vendor: mcp.Vendor})
						if key != "" {
							mcpPaths[key] = true
						}
					}
				}
			}
		}
	}
	view.Summary.AgentSkillsCount = len(view.AgentSkills)
	view.Summary.MCPConfigsCount = len(view.MCPConfigs)
	return &view
}
