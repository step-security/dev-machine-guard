//go:build !windows && !linux && !darwin

package devicepolicy

// ProbeManagedPolicy: no known VS Code policy location on this OS. The
// platform also has no settings writer (settingsPath returns ok=false), so
// enforcement never runs here — this exists only to keep the package
// compiling on every GOOS.
func ProbeManagedPolicy() (bool, string) { return false, "" }
