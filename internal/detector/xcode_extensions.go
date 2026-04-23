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
		"pluginkit", "-mAD", "-p", "com.apple.dt.Xcode.extension.source-editor")
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

// parsePluginkitLine parses a line like:
// "+    com.charcoaldesign.SwiftFormat-for-Xcode.SourceEditorExtension(0.60.1)"
func parsePluginkitLine(line string) *model.Extension {
	// Strip leading +/- and whitespace
	enabled := strings.HasPrefix(line, "+")
	line = strings.TrimLeft(line, "+- \t")

	if line == "" {
		return nil
	}

	// Split "bundleID(version)" — find first "(" since bundle IDs never contain parens
	openIdx := strings.Index(line, "(")
	if openIdx < 1 || !strings.HasSuffix(line, ")") {
		return nil
	}

	bundleID := line[:openIdx]
	version := line[openIdx+1 : len(line)-1]
	if version == "(null)" || version == "" {
		version = "unknown"
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

	source := "user_installed"
	_ = enabled // all Xcode extensions are user-installed

	return &model.Extension{
		ID:        bundleID,
		Name:      name,
		Version:   version,
		Publisher: publisher,
		IDEType:   "xcode",
		Source:    source,
	}
}
