package model

// Platform constants used by detectors, device info, and output formatters.
// These match the values returned by runtime.GOOS / executor.GOOS().
const (
	PlatformDarwin  = "darwin"
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
)

// PlatformDisplayName returns the human-readable name for a platform identifier.
func PlatformDisplayName(platform string) string {
	switch platform {
	case PlatformWindows:
		return "Windows"
	case PlatformLinux:
		return "Linux"
	default:
		return "macOS"
	}
}
