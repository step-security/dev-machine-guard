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
	osLabel := "macOS"
	if result.Device.Platform == "windows" {
		osLabel = "Windows"
	}
	fmt.Fprintf(w, "    %-16s %s\n", osLabel, result.Device.OSVersion)
	fmt.Fprintf(w, "    %-16s %s\n", "User", result.Device.UserIdentity)
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
		fmt.Fprintln(w)
	}

	return nil
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
