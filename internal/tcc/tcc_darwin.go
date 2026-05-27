//go:build darwin

package tcc

import "path/filepath"

// protectedSuffixes are paths relative to the user's home directory that
// macOS gates behind TCC permission prompts. Categories:
//   - Files & Folders (Catalina+): Desktop, Documents, Downloads
//   - Removable / Network (Catalina+): handled via opt-in search dirs
//   - Photos / Music / Movies (Sequoia hardened): Pictures, Movies, Music
//   - Full Disk Access subtrees: ~/Library/Mail, Messages, Safari, etc.
//   - Cloud sync (Sonoma+): Mobile Documents, CloudStorage
var protectedSuffixes = []string{
	"Desktop",
	"Documents",
	"Downloads",
	"Pictures",
	"Movies",
	"Music",
	"Public",
	".Trash",

	"Library/Mail",
	"Library/Messages",
	"Library/Safari",
	"Library/Calendars",
	"Library/Reminders",
	"Library/HomeKit",
	"Library/Suggestions",
	"Library/Application Support/AddressBook",
	"Library/Application Support/CallHistoryDB",
	"Library/Application Support/CallHistoryTransactions",
	"Library/IdentityServices",
	"Library/Metadata/CoreSpotlight",
	"Library/PersonalizationPortrait",
	"Library/Containers/com.apple.mail",
	"Library/Group Containers/group.com.apple.calendar",
	"Library/Group Containers/group.com.apple.notes",

	"Library/Mobile Documents",
	"Library/CloudStorage",
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
