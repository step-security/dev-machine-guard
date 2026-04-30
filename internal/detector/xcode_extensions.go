package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// DetectXcodeExtensions uses macOS pluginkit to find installed
// Xcode Source Editor extensions.
func (d *ExtensionDetector) DetectXcodeExtensions(ctx context.Context) []model.Extension {
	if d.exec.GOOS() != model.PlatformDarwin {
		return nil
	}
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second,
		"pluginkit", "-mAvD", "-p", "com.apple.dt.Xcode.extension.source-editor")
	if err != nil {
		return nil
	}

	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}

	var results []model.Extension
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		ext := parsePluginkitLine(line)
		if ext != nil {
			results = append(results, *ext)
		}
	}

	return results
}

// parsePluginkitLine parses a verbose pluginkit line.
// Non-verbose form (legacy): "+    com.charcoaldesign.SwiftFormat-for-Xcode.SourceEditorExtension(0.60.1)"
// Verbose form (-v): "<status indent>bundleID(version)\tUUID\ttimestamp\t/path/to/Bundle.appex"
func parsePluginkitLine(line string) *model.Extension {
	// Verbose output is tab-separated. The first field still carries the
	// leading status indicator and indent ("+", "-", " "), which we strip.
	fields := strings.Split(line, "\t")
	header := strings.TrimLeft(fields[0], "+-. \t")
	if header == "" {
		return nil
	}

	// Split "bundleID(version)" — find first "(" since bundle IDs never contain parens
	openIdx := strings.Index(header, "(")
	if openIdx < 1 || !strings.HasSuffix(header, ")") {
		return nil
	}

	bundleID := header[:openIdx]
	version := header[openIdx+1 : len(header)-1]
	if version == "(null)" || version == "" {
		version = "unknown"
	}

	// Verbose output: last tab-separated field is the bundle path.
	var installPath string
	if len(fields) >= 4 {
		installPath = strings.TrimSpace(fields[len(fields)-1])
	}

	// Derive publisher from first two segments of bundle ID
	// e.g., "com.charcoaldesign.SwiftFormat-for-Xcode.SourceEditorExtension" → "com.charcoaldesign"
	publisher := "unknown"
	parts := strings.SplitN(bundleID, ".", 3)
	if len(parts) >= 2 {
		publisher = parts[0] + "." + parts[1]
	}

	// Derive a readable name: strip the publisher prefix and common suffixes
	name := bundleID
	if len(parts) >= 3 {
		name = parts[2]
	}
	name = strings.TrimSuffix(name, ".SourceEditorExtension")
	name = strings.TrimSuffix(name, ".Extension")

	return &model.Extension{
		ID:          bundleID,
		Name:        name,
		Version:     version,
		Publisher:   publisher,
		InstallPath: installPath,
		IDEType:     "xcode",
		Source:      "user_installed",
	}
}
