// Package identity defines configured ID validation and automatic user detection.
// It never uses an attribution ID as an OS account or home directory.
package identity

import (
	"fmt"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Normalize validates an explicitly configured user or device ID. Automatically
// detected identities are not subject to this input allowlist.
func Normalize(value, kind string) (string, error) {
	invalid := func() (string, error) {
		return "", fmt.Errorf("Invalid %s ID. Use 1–256 characters: letters, digits, @, ., _, +, or -. Values 'unknown' and 'root' are reserved.", kind) //nolint:staticcheck // ST1005: preserve the approved CLI diagnostic.
	}
	for _, c := range []byte(value) {
		if c < 32 || c == 127 {
			return invalid()
		}
	}
	value = strings.TrimSpace(value)
	if len(value) < 1 || len(value) > 256 || MissingUser(value) {
		return invalid()
	}
	for _, c := range []byte(value) {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("@._+-", rune(c))) {
			return invalid()
		}
	}
	return value, nil
}

func MissingDevice(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.EqualFold(value, "unknown")
}

func MissingUser(value string) bool {
	return MissingDevice(value) || strings.EqualFold(strings.TrimSpace(value), "root")
}

// DetectUser preserves usable automatic identities, including values outside
// the configured-ID allowlist. Absent/sentinel env values do not mask OS users.
func DetectUser(exec executor.Executor) string {
	value, _ := DetectUserSession(exec)
	return value
}

// DetectUserSession takes one OS-user snapshot, keeping session state separate
// from email attribution and any configured identity applied by the caller.
func DetectUserSession(exec executor.Executor) (string, bool) {
	u, err := exec.LoggedInUser()
	noUser := err != nil || u == nil || MissingUser(u.Username)
	for _, key := range []string{"USER_EMAIL", "DEVELOPER_EMAIL", "STEPSEC_DEVELOPER_EMAIL"} {
		if v := exec.Getenv(key); !MissingUser(v) {
			return v, noUser
		}
	}
	if !noUser {
		return u.Username, false
	}
	return "unknown", true
}
