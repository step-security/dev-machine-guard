package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Default placeholders (replaced by backend for enterprise installation scripts).
var (
	CustomerID         = "{{CUSTOMER_ID}}"
	APIEndpoint        = "{{API_ENDPOINT}}"
	APIKey             = "{{API_KEY}}"
	ScanFrequencyHours = "{{SCAN_FREQUENCY_HOURS}}"
	SearchDirs         []string
	EnableNPMScan      *bool  // nil=auto
	EnableBrewScan     *bool  // nil=auto
	EnablePythonScan   *bool  // nil=auto
	ColorMode          string // "" means auto
	OutputFormat       string // "" means default (pretty)
	HTMLOutputFile     string // "" means not set
	Quiet              *bool  // nil=default behavior
)

// ConfigFile is the JSON structure persisted to ~/.stepsecurity/config.json.
type ConfigFile struct {
	CustomerID         string   `json:"customer_id,omitempty"`
	APIEndpoint        string   `json:"api_endpoint,omitempty"`
	APIKey             string   `json:"api_key,omitempty"`
	ScanFrequencyHours string   `json:"scan_frequency_hours,omitempty"`
	SearchDirs         []string `json:"search_dirs,omitempty"`
	EnableNPMScan      *bool    `json:"enable_npm_scan,omitempty"`
	EnableBrewScan     *bool    `json:"enable_brew_scan,omitempty"`
	EnablePythonScan   *bool    `json:"enable_python_scan,omitempty"`
	ColorMode          string   `json:"color_mode,omitempty"`
	OutputFormat       string   `json:"output_format,omitempty"`
	HTMLOutputFile     string   `json:"html_output_file,omitempty"`
	Quiet              *bool    `json:"quiet,omitempty"`
}

// configDir returns ~/.stepsecurity.
func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".stepsecurity")
}

// ConfigFilePath returns the path to the config file.
func ConfigFilePath() string {
	return filepath.Join(configDir(), "config.json")
}

// Load reads the config file and applies values to the package-level variables.
// Values already set (not placeholders) are not overridden — build-time values take precedence.
func Load() {
	data, err := os.ReadFile(ConfigFilePath())
	if err != nil {
		return // no config file, use defaults
	}

	var cfg ConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}

	if cfg.CustomerID != "" && isPlaceholder(CustomerID) {
		CustomerID = cfg.CustomerID
	}
	if cfg.APIEndpoint != "" && isPlaceholder(APIEndpoint) {
		APIEndpoint = cfg.APIEndpoint
	}
	if cfg.APIKey != "" && isPlaceholder(APIKey) {
		APIKey = cfg.APIKey
	}
	if cfg.ScanFrequencyHours != "" && isPlaceholder(ScanFrequencyHours) {
		ScanFrequencyHours = cfg.ScanFrequencyHours
	}
	if len(cfg.SearchDirs) > 0 {
		SearchDirs = cfg.SearchDirs
	}
	if cfg.EnableNPMScan != nil && EnableNPMScan == nil {
		EnableNPMScan = cfg.EnableNPMScan
	}
	if cfg.EnableBrewScan != nil && EnableBrewScan == nil {
		EnableBrewScan = cfg.EnableBrewScan
	}
	if cfg.EnablePythonScan != nil && EnablePythonScan == nil {
		EnablePythonScan = cfg.EnablePythonScan
	}
	if cfg.ColorMode != "" && ColorMode == "" {
		ColorMode = cfg.ColorMode
	}
	if cfg.OutputFormat != "" && OutputFormat == "" {
		OutputFormat = cfg.OutputFormat
	}
	if cfg.HTMLOutputFile != "" && HTMLOutputFile == "" {
		HTMLOutputFile = cfg.HTMLOutputFile
	}
	if cfg.Quiet != nil && Quiet == nil {
		Quiet = cfg.Quiet
	}
}

// IsEnterpriseMode returns true if valid enterprise credentials are configured.
func IsEnterpriseMode() bool {
	return APIKey != "" && !strings.Contains(APIKey, "{{")
}

// RunConfigure interactively prompts for config values and saves to the config file.
func RunConfigure() error {
	reader := bufio.NewReader(os.Stdin)

	// Load existing config to show current values
	existing := loadExisting()

	fmt.Println("StepSecurity Dev Machine Guard — Configuration")
	fmt.Println()
	fmt.Println("Enter new values or press Enter to keep the current value.")
	fmt.Println("To clear a value, enter a single dash (-).")
	fmt.Println()

	existing.CustomerID = promptValue(reader, "Customer ID", existing.CustomerID)
	existing.APIEndpoint = promptValue(reader, "API Endpoint", existing.APIEndpoint)
	existing.APIKey = promptSecret(reader, "API Key", existing.APIKey)
	existing.ScanFrequencyHours = promptValue(reader, "Scan Frequency (hours)", existing.ScanFrequencyHours)

	// Search dirs
	currentDirs := ""
	if len(existing.SearchDirs) > 0 {
		currentDirs = strings.Join(existing.SearchDirs, ", ")
	}
	dirsInput := promptValue(reader, "Search Directories (comma-separated)", currentDirs)
	if dirsInput != "" {
		dirs := strings.Split(dirsInput, ",")
		existing.SearchDirs = nil
		for _, d := range dirs {
			d = strings.TrimSpace(d)
			if d != "" {
				existing.SearchDirs = append(existing.SearchDirs, d)
			}
		}
	} else {
		existing.SearchDirs = nil
	}

	// Enable npm scan
	currentNPM := "auto"
	if existing.EnableNPMScan != nil {
		if *existing.EnableNPMScan {
			currentNPM = "true"
		} else {
			currentNPM = "false"
		}
	}
	npmInput := promptValue(reader, "Enable NPM Scan (auto/true/false)", currentNPM)
	switch strings.ToLower(npmInput) {
	case "true":
		v := true
		existing.EnableNPMScan = &v
	case "false":
		v := false
		existing.EnableNPMScan = &v
	default:
		existing.EnableNPMScan = nil // auto
	}

	// Enable brew scan
	currentBrew := "auto"
	if existing.EnableBrewScan != nil {
		if *existing.EnableBrewScan {
			currentBrew = "true"
		} else {
			currentBrew = "false"
		}
	}
	brewInput := promptValue(reader, "Enable Homebrew Scan (auto/true/false)", currentBrew)
	switch strings.ToLower(brewInput) {
	case "true":
		v := true
		existing.EnableBrewScan = &v
	case "false":
		v := false
		existing.EnableBrewScan = &v
	default:
		existing.EnableBrewScan = nil
	}

	// Enable python scan
	currentPython := "auto"
	if existing.EnablePythonScan != nil {
		if *existing.EnablePythonScan {
			currentPython = "true"
		} else {
			currentPython = "false"
		}
	}
	pythonInput := promptValue(reader, "Enable Python Scan (auto/true/false)", currentPython)
	switch strings.ToLower(pythonInput) {
	case "true":
		v := true
		existing.EnablePythonScan = &v
	case "false":
		v := false
		existing.EnablePythonScan = &v
	default:
		existing.EnablePythonScan = nil
	}

	// Color mode
	currentColor := existing.ColorMode
	if currentColor == "" {
		currentColor = "auto"
	}
	colorInput := promptValue(reader, "Color Mode (auto/always/never)", currentColor)
	switch strings.ToLower(colorInput) {
	case "always", "never":
		existing.ColorMode = strings.ToLower(colorInput)
	default:
		existing.ColorMode = "" // auto (omit from config)
	}

	// Output format
	currentFormat := existing.OutputFormat
	if currentFormat == "" {
		currentFormat = "pretty"
	}
	formatInput := promptValue(reader, "Output Format (pretty/json/html)", currentFormat)
	switch strings.ToLower(formatInput) {
	case "json", "html":
		existing.OutputFormat = strings.ToLower(formatInput)
	default:
		existing.OutputFormat = "" // pretty is the default (omit from config)
	}

	// HTML output file (only relevant when output_format is html)
	if existing.OutputFormat == "html" {
		existing.HTMLOutputFile = promptValue(reader, "HTML Output File", existing.HTMLOutputFile)
	}

	// Quiet mode
	currentQuiet := "false"
	if existing.Quiet != nil && *existing.Quiet {
		currentQuiet = "true"
	}
	quietInput := promptValue(reader, "Quiet Mode (true/false)", currentQuiet)
	switch strings.ToLower(quietInput) {
	case "true":
		v := true
		existing.Quiet = &v
	default:
		v := false
		existing.Quiet = &v
	}

	// Save
	if err := save(existing); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	fmt.Println()
	fmt.Printf("Configuration saved to %s\n", ConfigFilePath())
	return nil
}

// promptSecret shows a masked current value but keeps the real value on Enter.
func promptSecret(reader *bufio.Reader, label, current string) string {
	masked := maskSecret(current)
	if masked != "(not set)" {
		fmt.Printf("  %s [%s]: ", label, masked)
	} else {
		fmt.Printf("  %s: ", label)
	}

	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if line == "-" {
		return "" // clear value
	}
	if line == "" {
		return current // keep real value
	}
	return line
}

func promptValue(reader *bufio.Reader, label, current string) string {
	if current != "" {
		fmt.Printf("  %s [%s]: ", label, current)
	} else {
		fmt.Printf("  %s: ", label)
	}

	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)

	if line == "-" {
		return "" // clear value
	}
	if line == "" {
		return current // keep existing
	}
	return line
}

func loadExisting() *ConfigFile {
	data, err := os.ReadFile(ConfigFilePath())
	if err != nil {
		return &ConfigFile{}
	}
	var cfg ConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return &ConfigFile{}
	}
	return &cfg
}

func save(cfg *ConfigFile) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigFilePath(), data, 0o600)
}

// ShowConfigure prints the current configuration to stdout.
func ShowConfigure() {
	cfg := loadExisting()

	fmt.Printf("Configuration (%s):\n\n", ConfigFilePath())
	fmt.Printf("  %-24s %s\n", "Customer ID:", displayValue(cfg.CustomerID))
	fmt.Printf("  %-24s %s\n", "API Endpoint:", displayValue(cfg.APIEndpoint))
	fmt.Printf("  %-24s %s\n", "API Key:", maskSecret(cfg.APIKey))
	fmt.Printf("  %-24s %s\n", "Scan Frequency:", displayFrequency(cfg.ScanFrequencyHours))
	fmt.Printf("  %-24s %s\n", "Search Directories:", displayDirs(cfg.SearchDirs))
	fmt.Printf("  %-24s %s\n", "Enable NPM Scan:", displayBoolScan(cfg.EnableNPMScan))
	fmt.Printf("  %-24s %s\n", "Enable Brew Scan:", displayBoolScan(cfg.EnableBrewScan))
	fmt.Printf("  %-24s %s\n", "Enable Python Scan:", displayBoolScan(cfg.EnablePythonScan))
	fmt.Printf("  %-24s %s\n", "Color Mode:", displayColorMode(cfg.ColorMode))
	fmt.Printf("  %-24s %s\n", "Output Format:", displayOutputFormat(cfg.OutputFormat))
	if cfg.OutputFormat == "html" {
		fmt.Printf("  %-24s %s\n", "HTML Output File:", displayValue(cfg.HTMLOutputFile))
	}
	fmt.Printf("  %-24s %s\n", "Quiet Mode:", displayQuiet(cfg.Quiet))
}

func displayValue(v string) string {
	if v == "" {
		return "(not set)"
	}
	return v
}

func maskSecret(v string) string {
	if v == "" {
		return "(not set)"
	}
	if len(v) <= 6 {
		return "***"
	}
	return "***" + v[len(v)-4:]
}

func displayFrequency(v string) string {
	if v == "" {
		return "(not set)"
	}
	if v == "1" {
		return v + " hour"
	}
	return v + " hours"
}

func displayDirs(dirs []string) string {
	if len(dirs) == 0 {
		return "(not set — defaults to $HOME)"
	}
	return strings.Join(dirs, ", ")
}

func displayBoolScan(v *bool) string {
	if v == nil {
		return "auto"
	}
	if *v {
		return "true"
	}
	return "false"
}

func displayColorMode(v string) string {
	if v == "" {
		return "auto"
	}
	return v
}

func displayOutputFormat(v string) string {
	if v == "" {
		return "pretty"
	}
	return v
}

func displayQuiet(v *bool) string {
	if v != nil && *v {
		return "true"
	}
	return "false"
}

func isPlaceholder(v string) bool {
	return strings.Contains(v, "{{")
}
