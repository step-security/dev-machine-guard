//go:build darwin

package tcc

import "path/filepath"

// protectedSuffixes are paths relative to the user's home directory that
// macOS gates behind TCC permission prompts. Categories:
//   - Files & Folders (Catalina+): Desktop, Documents, Downloads
//   - Removable / Network (Catalina+): handled via opt-in search dirs
//   - Photos / Music / Movies (Sequoia hardened): Pictures, Movies, Music
//   - Everything under ~/Library: Mail, Messages, Safari, Mobile Documents,
//     CloudStorage, Containers, plus the long tail of Apple-private
//     subtrees that gain new TCC services with each macOS release.
//
// ~/Library is skipped wholesale rather than per-subpath. Every macOS
// release adds new Apple-managed subtrees behind new TCC services
// (Sonoma's App Management, Sequoia's hardened Pictures/Music/Movies,
// Tahoe's expanded Media Library scope into
// ~/Library/Application Support/com.apple.avfoundation/, and so on),
// so a curated allowlist of "Library/X" entries goes stale on every
// upgrade — at which point a previously-silent walk into one of those
// subtrees starts firing a prompt at end users. ~/Library is the wrong
// place for developer projects / lockfiles / npmrc files anyway; the
// detectors that DO need to read specific paths under ~/Library
// (JetBrains plugins, Claude desktop MCP config, pip global config)
// use targeted ReadDir/ReadFile calls that don't consult this skipper,
// so they're unaffected.
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
