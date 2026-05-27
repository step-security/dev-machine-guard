//go:build darwin

package tcc

import "path/filepath"

// protectedSuffixes are paths relative to the user's home directory that
// macOS gates behind TCC permission prompts. Categories collapsed for
// maintainability:
//
//   - User data folders (Files & Folders since Catalina, hardened in
//     Sequoia): Desktop, Documents, Downloads, Pictures, Movies, Music,
//     Public, .Trash.
//
//   - The entire ~/Library tree. Apple gates many subdirs behind
//     distinct TCC services (Photos for com.apple.photos.*, Media
//     Library for com.apple.Music / iTunes / Apple/AssetCache,
//     Calendars, Contacts, the Sonoma App Management service for
//     ~/Library/Containers/<app>/Data, Sonoma+ cloud-sync services for
//     Mobile Documents / CloudStorage, etc.). Enumerating each gated
//     subdir is whack-a-mole — Apple adds new services per major
//     release. Nothing inside ~/Library is useful inventory data for
//     dev-machine-guard (code projects live under ~/, ~/code, ~/work,
//     etc.), so a whole-tree skip silences every per-service popup in
//     one shot. Sibling detectors that need specific Library subpaths
//     (JetBrains plugins at ~/Library/Application Support/JetBrains,
//     Android Studio plugins at ~/Library/Application Support/Google)
//     use direct ReadDir on known paths, not WalkDir, and are not
//     affected by this skip.
var protectedSuffixes = []string{
	"Desktop",
	"Documents",
	"Downloads",
	"Pictures",
	"Movies",
	"Music",
	"Public",
	".Trash",
	"Library",
}

// protectedAbsolutePrefixes are matched with strings.HasPrefix. Time
// Machine local-snapshot mounts use names like
// /Volumes/.timemachine.donottouch.<uuid> which vary by macOS version, so
// a prefix is more robust than an exact path.
var protectedAbsolutePrefixes = []string{
	"/Volumes/.timemachine",
}

func buildProtectedPaths(home string) map[string]struct{} {
	if home == "" {
		return nil
	}
	cleanedHome := filepath.Clean(home)
	paths := make(map[string]struct{}, len(protectedSuffixes))
	for _, suffix := range protectedSuffixes {
		paths[filepath.Join(cleanedHome, suffix)] = struct{}{}
	}
	return paths
}

func protectedPrefixes() []string {
	return protectedAbsolutePrefixes
}
