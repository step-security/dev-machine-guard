//go:build windows

package credentials

import (
	"os/user"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// userEnvironmentKey is where a Windows account's own environment variables are
// stored. Reading the registry beats the shell approach the other platforms need:
// the values are in a file the agent can open, not a session it cannot enter.
const userEnvironmentKey = `Environment`

// readUserEnvironment reads the developer's environment variables out of their
// registry hive. The agent runs as a system account, so the current-user hive is the
// service account's; the developer's is reached by account identifier, which needs
// that hive loaded — true while they have a session, false once they log off. A hive
// that cannot be opened is a failed read, not an empty one.
func readUserEnvironment(username string, names []string) (userEnv, bool) {
	if username == "" {
		return userEnv{}, false
	}
	// The same lookup that resolves the account's profile directory, so the
	// identity this reads and the identity the paths are built from match.
	u, err := user.Lookup(username)
	if err != nil || u.Uid == "" {
		return userEnv{}, false
	}

	key, err := registry.OpenKey(registry.USERS, u.Uid+`\`+userEnvironmentKey, registry.QUERY_VALUE)
	if err != nil {
		return userEnv{}, false
	}
	defer key.Close()

	env := userEnv{
		Values:     make(map[string]string, len(names)),
		Unresolved: map[string]bool{},
	}
	for _, name := range names {
		value, _, err := key.GetStringValue(name)
		if err != nil || value == "" {
			continue
		}
		// The stored form may reference other variables, and expansion would
		// resolve them against this process — the system account. Recorded as
		// unresolved rather than skipped: the variable is set, so the location it
		// names has moved, and treating it as unset would fake an absence.
		if containsExpansion(value) {
			env.Unresolved[name] = true
			continue
		}
		env.Values[name] = value
	}
	return env, true
}

// containsExpansion reports whether a stored value defers to another variable.
func containsExpansion(value string) bool {
	first := -1
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if first < 0 {
			first = i
			continue
		}
		if i > first+1 {
			return true
		}
		first = i
	}
	return false
}

// broadReadAllowACE reports whether the file's own access-control list grants read
// access to a broad principal. Three-valued, and named for what was observed rather
// than a conclusion it cannot reach: effective access also depends on inherited
// entries, deny ordering, nested and domain group membership, and conditional
// entries. A nil result means the list could not be read, which stays
// distinguishable from a list that was read and grants nothing.
func broadReadAllowACE(path string) *bool {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || sd == nil {
		return nil
	}
	present := descriptorGrantsBroadRead(sd.String())
	return &present
}
