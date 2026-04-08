package detector

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

type ideExtensionSpec struct {
	IDEName string
	IDEType string
	ExtDir  string // relative to home (~/.vscode/extensions)
}

var extensionDirs = []ideExtensionSpec{
	{"VS Code", "vscode", "~/.vscode/extensions"},
	{"Cursor", "openvsx", "~/.cursor/extensions"},
}

// ExtensionDetector collects IDE extensions.
type ExtensionDetector struct {
	exec executor.Executor
}

func NewExtensionDetector(exec executor.Executor) *ExtensionDetector {
	return &ExtensionDetector{exec: exec}
}

func (d *ExtensionDetector) Detect(_ context.Context, searchDirs []string) []model.Extension {
	homeDir := getHomeDir(d.exec)
	var results []model.Extension

	for _, spec := range extensionDirs {
		extDir := expandTilde(spec.ExtDir, homeDir)
		exts := d.collectFromDir(extDir, spec.IDEType)
		results = append(results, exts...)
	}

	return results
}

func (d *ExtensionDetector) collectFromDir(extDir, ideType string) []model.Extension {
	if !d.exec.DirExists(extDir) {
		return nil
	}

	// Load obsolete extensions
	obsolete := d.loadObsolete(extDir)

	entries, err := d.exec.ReadDir(extDir)
	if err != nil {
		return nil
	}

	var results []model.Extension
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirname := entry.Name()

		// Skip special entries
		if dirname == "extensions.json" || dirname == ".obsolete" {
			continue
		}

		// Skip obsolete extensions
		if obsolete[dirname] {
			continue
		}

		ext := parseExtensionDir(dirname, ideType)
		if ext == nil {
			continue
		}

		// Get install date from directory modification time
		info, err := d.exec.Stat(filepath.Join(extDir, dirname))
		if err == nil {
			ext.InstallDate = info.ModTime().Unix()
		}

		results = append(results, *ext)
	}

	return results
}

// parseExtensionDir parses "publisher.name-version[-platform]" directory name.
func parseExtensionDir(dirname, ideType string) *model.Extension {
	// Find publisher (everything before first dot)
	dotIdx := strings.Index(dirname, ".")
	if dotIdx < 1 {
		return nil
	}
	publisher := dirname[:dotIdx]
	rest := dirname[dotIdx+1:]

	// Remove platform suffixes
	for _, suffix := range []string{"-darwin-arm64", "-darwin-x64", "-universal", "-linux-x64", "-linux-arm64", "-win32-x64", "-win32-arm64"} {
		if strings.HasSuffix(rest, suffix) {
			rest = strings.TrimSuffix(rest, suffix)
			break
		}
	}

	// Split name-version at last hyphen
	lastHyphen := strings.LastIndex(rest, "-")
	if lastHyphen < 1 {
		return nil
	}
	name := rest[:lastHyphen]
	version := rest[lastHyphen+1:]

	if publisher == "" || name == "" || version == "" {
		return nil
	}

	return &model.Extension{
		ID:        publisher + "." + name,
		Name:      name,
		Version:   version,
		Publisher: publisher,
		IDEType:   ideType,
	}
}

// loadObsolete reads the .obsolete file and returns a set of dirname -> true.
func (d *ExtensionDetector) loadObsolete(extDir string) map[string]bool {
	obsoleteFile := filepath.Join(extDir, ".obsolete")
	data, err := d.exec.ReadFile(obsoleteFile)
	if err != nil {
		return nil
	}

	var obsoleteMap map[string]bool
	if err := json.Unmarshal(data, &obsoleteMap); err != nil {
		return nil
	}
	return obsoleteMap
}
