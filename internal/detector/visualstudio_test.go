package detector

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestDetectVisualStudio_IDE(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	programData := `C:\ProgramData`
	mock.SetEnv("PROGRAMDATA", programData)

	stateFile := filepath.Join(programData, "Microsoft", "VisualStudio", "Packages", "_Instances", "abc123", "state.json")
	mock.SetGlob(
		filepath.Join(programData, "Microsoft", "VisualStudio", "Packages", "_Instances", "*", "state.json"),
		[]string{stateFile},
	)
	installPath := `C:\Program Files\Microsoft Visual Studio\2022\Community`
	stateJSON, _ := json.Marshal(map[string]string{
		"installationPath":    installPath,
		"installationVersion": "17.14.36310.24",
	})
	mock.SetFile(stateFile, stateJSON)

	ides := NewIDEDetector(mock).detectVisualStudio()
	if len(ides) != 1 {
		t.Fatalf("expected 1 VS IDE, got %d", len(ides))
	}
	ide := ides[0]
	if ide.IDEType != "visual_studio" {
		t.Errorf("IDEType: got %q", ide.IDEType)
	}
	if ide.Version != "17.14.36310.24" {
		t.Errorf("Version: got %q", ide.Version)
	}
	if ide.InstallPath != installPath {
		t.Errorf("InstallPath: got %q", ide.InstallPath)
	}
	if ide.Vendor != "Microsoft" {
		t.Errorf("Vendor: got %q", ide.Vendor)
	}
	if !ide.IsInstalled {
		t.Error("expected IsInstalled true")
	}
}

func TestDetectVisualStudio_NonWindows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("darwin")
	if ides := NewIDEDetector(mock).detectVisualStudio(); ides != nil {
		t.Errorf("expected nil on non-Windows, got %v", ides)
	}
}

func TestDiscoverVisualStudioInstances_FallbackAndDedup(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	programData := `C:\ProgramData`
	programFiles := `C:\Program Files`
	mock.SetEnv("PROGRAMDATA", programData)
	mock.SetEnv("PROGRAMFILES", programFiles)

	installPath := filepath.Join(programFiles, "Microsoft Visual Studio", "2022", "Community")

	// Setup instance data points at installPath (with version).
	stateFile := filepath.Join(programData, "Microsoft", "VisualStudio", "Packages", "_Instances", "abc", "state.json")
	mock.SetGlob(
		filepath.Join(programData, "Microsoft", "VisualStudio", "Packages", "_Instances", "*", "state.json"),
		[]string{stateFile},
	)
	stateJSON, _ := json.Marshal(map[string]string{"installationPath": installPath, "installationVersion": "17.14.0"})
	mock.SetFile(stateFile, stateJSON)

	// Program Files fallback also finds the same install — must dedup.
	mock.SetGlob(filepath.Join(programFiles, "Microsoft Visual Studio", "*", "*"), []string{installPath})
	mock.SetDir(installPath)

	instances := discoverVisualStudioInstances(mock)
	if len(instances) != 1 {
		t.Fatalf("expected 1 deduped instance, got %d: %+v", len(instances), instances)
	}
	// The setup-instance entry (added first, carries the version) wins the dedup.
	if instances[0].Version != "17.14.0" {
		t.Errorf("expected version from state.json, got %q", instances[0].Version)
	}
}
