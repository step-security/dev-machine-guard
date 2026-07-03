package detector

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Classic Visual Studio is discovered very differently from the editor IDEs in
// ideDefinitions: there is no single fixed install path or app bundle. The
// authoritative source is the VS setup instance data under
// %PROGRAMDATA%\Microsoft\VisualStudio\Packages\_Instances\<id>\state.json,
// which records the install path and version for each installed instance
// (multiple editions/years can coexist). This file holds the shared instance
// discovery used by both IDE detection and extension scanning.

// vsInstance is a discovered classic Visual Studio installation.
type vsInstance struct {
	InstallPath string
	Version     string
}

// discoverVisualStudioInstances finds installed classic Visual Studio instances
// (Windows). The authoritative source is the VS setup instance data, with a
// Program Files glob as a fallback. Returns nil on non-Windows hosts (the
// Windows env vars it reads are empty there).
func discoverVisualStudioInstances(exec executor.Executor) []vsInstance {
	var instances []vsInstance
	seen := make(map[string]bool)
	add := func(inst vsInstance) {
		if inst.InstallPath == "" {
			return
		}
		key := strings.ToLower(filepath.Clean(inst.InstallPath))
		if seen[key] {
			return
		}
		seen[key] = true
		instances = append(instances, inst)
	}

	// Primary: VS setup instance data — %PROGRAMDATA%\Microsoft\VisualStudio\Packages\_Instances\<id>\state.json
	if programData := exec.Getenv("PROGRAMDATA"); programData != "" {
		pattern := filepath.Join(programData, "Microsoft", "VisualStudio", "Packages", "_Instances", "*", "state.json")
		matches, _ := exec.Glob(pattern)
		for _, stateFile := range matches {
			add(readVSInstanceState(exec, stateFile))
		}
	}

	// Fallback: well-known install locations. VS 2017/2019 are 32-bit (x86).
	for _, base := range []string{exec.Getenv("PROGRAMFILES"), exec.Getenv("PROGRAMFILES(X86)")} {
		if base == "" {
			continue
		}
		// e.g. C:\Program Files\Microsoft Visual Studio\2022\Community
		pattern := filepath.Join(base, "Microsoft Visual Studio", "*", "*")
		matches, _ := exec.Glob(pattern)
		for _, m := range matches {
			// Only real product installs — the glob also matches the sibling
			// "Installer\<lang>" and "Shared\<component>" trees under
			// "Microsoft Visual Studio", which are not VS installations. A
			// product install has Common7\IDE\devenv.exe.
			if exec.FileExists(filepath.Join(m, "Common7", "IDE", "devenv.exe")) {
				add(vsInstance{InstallPath: m})
			}
		}
	}

	return instances
}

// readVSInstanceState reads installationPath and installationVersion from a VS
// setup state.json.
func readVSInstanceState(exec executor.Executor, stateFile string) vsInstance {
	data, err := exec.ReadFile(stateFile)
	if err != nil {
		return vsInstance{}
	}
	var state struct {
		InstallationPath    string `json:"installationPath"`
		InstallationVersion string `json:"installationVersion"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return vsInstance{}
	}
	return vsInstance{InstallPath: state.InstallationPath, Version: state.InstallationVersion}
}

// detectVisualStudio reports installed classic Visual Studio instances as IDEs.
// Windows-only. VS is discovered via setup instance data rather than a fixed
// install path, so it isn't part of ideDefinitions. Each installed instance
// (e.g. different editions or years) is reported separately.
func (d *IDEDetector) detectVisualStudio() []model.IDE {
	if d.exec.GOOS() != model.PlatformWindows {
		return nil
	}

	var results []model.IDE
	for _, inst := range discoverVisualStudioInstances(d.exec) {
		version := inst.Version
		if version == "" {
			version = "unknown"
		}
		results = append(results, model.IDE{
			IDEType:     "visual_studio",
			Version:     version,
			InstallPath: inst.InstallPath,
			Vendor:      "Microsoft",
			IsInstalled: true,
		})
	}
	return results
}
