package detector

import (
	"strings"
)

// isIDEInternalPath returns true if the given path is inside an IDE's bundled
// application directory. These directories contain hundreds of package.json
// files that are NOT user projects and should be skipped during scanning.
//
// Known IDE application paths that contain bundled Node.js extensions:
//
//   Windows:
//     %LOCALAPPDATA%\Programs\Antigravity\resources\app\extensions\*
//     %LOCALAPPDATA%\Programs\cursor\resources\app\extensions\*
//     %LOCALAPPDATA%\Programs\Microsoft VS Code\resources\app\extensions\*
//     C:\Program Files\Microsoft VS Code\resources\app\extensions\*
//
//   macOS:
//     /Applications/Visual Studio Code.app/Contents/Resources/app/extensions/*
//     /Applications/Cursor.app/Contents/Resources/app/extensions/*
//     /Applications/Windsurf.app/Contents/Resources/app/extensions/*
//     /Applications/Antigravity.app/Contents/Resources/app/extensions/*
//
//   Linux:
//     /usr/share/code/resources/app/extensions/*
//     /opt/Windsurf/resources/app/extensions/*
//     /usr/share/cursor/resources/app/extensions/*
//
// Rather than hardcoding every IDE path, we detect the pattern:
// any path containing "resources/app/extensions" (or the Windows equivalent).
func isIDEInternalPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))

	// IDE bundled extensions: resources/app/extensions is the universal marker
	if strings.Contains(normalized, "/resources/app/extensions/") {
		return true
	}
	// Also check for the path ending at this dir (when walking into it)
	if strings.HasSuffix(normalized, "/resources/app/extensions") {
		return true
	}

	// Eclipse internal plugins directory
	if strings.Contains(normalized, "/eclipse/plugins/") {
		return true
	}

	// JetBrains IDE internals (lib/*, plugins/*)
	if strings.Contains(normalized, "/jetbrains/") {
		// Only skip the internal lib/plugins dirs, not the user config
		if strings.Contains(normalized, "/lib/") || strings.Contains(normalized, "/plugins/") {
			return true
		}
	}

	return false
}

// shouldSkipDir returns true if the directory should be skipped during
// filesystem walks for Node.js project discovery. This combines the standard
// skip list with IDE internal path detection.
func shouldSkipDir(dirName string, fullPath string) bool {
	// Standard skip list (unchanged from original)
	if dirName == "node_modules" || dirName == ".git" || dirName == ".cache" ||
		strings.HasPrefix(dirName, ".") {
		return true
	}

	// IDE application directories contain bundled extensions, not user projects
	if isIDEInternalPath(fullPath) {
		return true
	}

	return false
}
