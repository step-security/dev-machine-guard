package runtimeinv

import (
	"path/filepath"
	"strings"
)

// homeBudget is the entry budget of the generic home walk.
const homeBudget = 1_000_000

// appsBudget covers app install trees (/Applications, Program Files), which
// on developer machines routinely exceed the default per-root budget.
const appsBudget = 400_000

// roots lists what to walk on this OS: a depth-capped walk of the user's
// home and the machine install locations, plus deeper walks of known
// version-manager / installer roots whose runtimes sit below the generic cap.
// Env-var overrides (NVM_DIR, VOLTA_HOME, …) add roots; they never replace
// the defaults, since the agent's env may not be the user's shell env.
func (s *Scanner) roots() []walkRoot {
	switch s.goos {
	case "windows":
		return s.windowsRoots()
	case "darwin":
		return s.unixRoots(true)
	default:
		return s.unixRoots(false)
	}
}

func (s *Scanner) env(key string) string { return strings.TrimSpace(s.exec.Getenv(key)) }

func (s *Scanner) homeJoin(parts ...string) string {
	if s.home == "" {
		return ""
	}
	return filepath.Join(append([]string{s.home}, parts...)...)
}

func (s *Scanner) unixRoots(darwin bool) []walkRoot {
	h := s.homeJoin
	roots := []walkRoot{
		// Known user roots, deeper than the generic home walk reaches.
		{h(".nvm", "versions"), 4, nil, 0},
		{h(".volta", "tools", "image"), 5, nil, 0},
		{h(".local", "share", "fnm"), 6, nil, 0},
		{h(".fnm"), 6, nil, 0},
		{h(".local", "share", "mise", "installs"), 5, nil, 0},
		{h(".local", "share", "pnpm", "nodejs"), 3, nil, 0}, // `pnpm env` installs; the store beside it is a dependency store
		{h(".local", "share", "uv", "python"), 4, nil, 0},
		{h(".asdf", "installs"), 5, nil, 0},
		{h(".pyenv", "versions"), 3, nil, 0},
		{h(".sdkman", "candidates"), 4, nil, 0},
		{h(".rbenv", "versions"), 3, nil, 0},
		{h(".rvm", "rubies"), 3, nil, 0},
		{h(".goenv", "versions"), 3, nil, 0},
		{h(".dotnet"), 1, nil, 0},
		{h("sdk"), 3, nil, 0},                            // golang.org/dl downloads
		{h("go", "pkg", "mod", "golang.org"), 3, nil, 0}, // GOTOOLCHAIN downloads
		{h(".jdks"), 4, nil, 0},
		{h(".local", "share", "JetBrains"), 6, nil, 0},
		{h(".vscode-server"), 4, nil, 0},
		{h(".cursor-server"), 4, nil, 0},

		// Machine locations.
		{"/usr/bin", 0, nil, 0},
		{"/usr/local", 5, nil, 0},
		{"/opt", 6, nil, 0},
		{"/usr/lib/jvm", 4, nil, 0},
		{"/usr/lib/dotnet", 1, nil, 0},
		{"/usr/share/dotnet", 1, nil, 0},
		{"/usr/lib/go", 2, nil, 0},
		{"/snap", 4, nil, 0},
	}
	if darwin {
		roots = append(roots,
			walkRoot{h("Library", "Application Support", "fnm"), 6, nil, 0},
			walkRoot{h("Library", "pnpm", "nodejs"), 3, nil, 0},
			walkRoot{h("Library", "Java", "JavaVirtualMachines"), 5, nil, 0},
			walkRoot{h("Library", "Application Support", "JetBrains", "Toolbox", "apps"), 8, nil, 0},
			walkRoot{"/Library/Java/JavaVirtualMachines", 5, nil, 0},
			walkRoot{"/Library/Frameworks/Python.framework/Versions", 3, nil, 0},
			walkRoot{"/Library/Developer/CommandLineTools/usr/bin", 0, nil, 0},
			walkRoot{"/Applications", 7, nil, appsBudget},
		)
	}
	for _, kv := range []struct {
		env   string
		depth int
	}{
		{"NVM_DIR", 5}, {"FNM_DIR", 6}, {"VOLTA_HOME", 6}, {"N_PREFIX", 5}, {"ASDF_DATA_DIR", 6},
		{"PYENV_ROOT", 4}, {"SDKMAN_DIR", 5}, {"JAVA_HOME", 2}, {"GOROOT", 2}, {"DOTNET_ROOT", 1},
	} {
		if v := s.env(kv.env); v != "" {
			roots = append(roots, walkRoot{v, kv.depth, nil, 0})
		}
	}
	// Generic walk of home last, with the largest budget: it is the most
	// likely to be huge and must not starve the known roots. ~/Library
	// (macOS) runtime locations are listed explicitly above.
	return append(roots, walkRoot{s.home, 5, []string{"library"}, homeBudget})
}

func (s *Scanner) windowsRoots() []walkRoot {
	h := s.homeJoin
	appData := s.env("APPDATA")
	if appData == "" {
		appData = h("AppData", "Roaming")
	}
	localAppData := s.env("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = h("AppData", "Local")
	}
	sysDrive := s.env("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	sysRoot := sysDrive + `\`
	programFiles := firstNonEmpty(s.env("ProgramFiles"), sysRoot+"Program Files")
	programFilesX86 := firstNonEmpty(s.env("ProgramFiles(x86)"), sysRoot+"Program Files (x86)")
	programData := firstNonEmpty(s.env("ProgramData"), sysRoot+"ProgramData")

	join := filepath.Join
	roots := []walkRoot{
		// Known user roots.
		{join(appData, "nvm"), 2, nil, 0},
		{join(appData, "uv", "python"), 4, nil, 0}, // `uv python install` (AppData is skipped by the profile walk)
		{join(appData, "fnm"), 5, nil, 0},
		{join(localAppData, "fnm"), 5, nil, 0},
		{join(localAppData, "Volta"), 7, nil, 0},
		{join(localAppData, "pnpm", "nodejs"), 3, nil, 0},
		{join(localAppData, "Programs"), 5, nil, 0},
		{join(localAppData, "Microsoft", "WinGet", "Packages"), 9, nil, 0}, // portable apps nest bundled runtimes deep (Eclipse justj JRE)
		{join(localAppData, "JetBrains", "Toolbox", "apps"), 6, nil, 0},
		{h("go", "pkg", "mod", "golang.org"), 3, nil, 0}, // GOTOOLCHAIN downloads

		// Machine locations.
		{programFiles, 5, []string{"windowsapps"}, appsBudget},
		{programFilesX86, 5, nil, appsBudget},
		{join(programFiles, "Microsoft Visual Studio"), 9, nil, 0},
		{join(programFilesX86, "Microsoft Visual Studio"), 9, nil, 0},
		{programData, 5, nil, 0},
		// Top-level dirs on the system drive (C:\xampp, C:\wamp64,
		// C:\laragon, C:\Python312, C:\Ruby33-x64, C:\tools, …).
		{sysRoot, 4, []string{
			"windows", "program files", "program files (x86)", "programdata", "users",
			"recovery", "perflogs", "$winreagent", "config.msi", "msocache",
		}, 0},
	}
	for _, kv := range []struct {
		env   string
		depth int
	}{
		{"NVM_HOME", 2}, {"UV_PYTHON_INSTALL_DIR", 4}, {"VOLTA_HOME", 6}, {"FNM_DIR", 5}, {"SCOOP", 5}, {"SCOOP_GLOBAL", 5},
		{"ChocolateyInstall", 5}, {"JAVA_HOME", 2}, {"GOROOT", 2}, {"DOTNET_ROOT", 1}, {"PYENV", 4},
	} {
		if v := s.env(kv.env); v != "" {
			roots = append(roots, walkRoot{v, kv.depth, nil, 0})
		}
	}
	// Generic profile walk last; AppData is covered by the known roots above.
	return append(roots, walkRoot{s.home, 5, []string{"appdata"}, homeBudget})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
