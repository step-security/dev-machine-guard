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
	fmt.Fprintln(w)

	// SUMMARY
	fmt.Fprintf(w, "  %s%sSUMMARY%s\n", c.purple, c.bold, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "AI Agents and Tools", c.green, result.Summary.AIAgentsAndToolsCount, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "IDEs & Desktop Apps", c.green, result.Summary.IDEInstallationsCount, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "IDE Extensions", c.green, result.Summary.IDEExtensionsCount, c.reset)
	fmt.Fprintf(w, "    %-24s %s%d%s\n", "MCP Servers", c.green, result.Summary.MCPConfigsCount, c.reset)
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

//nolint:errcheck // terminal output
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
