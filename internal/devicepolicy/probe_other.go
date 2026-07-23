//go:build !windows && !linux && !darwin

package devicepolicy

import "encoding/json"

// ProbeManagedPolicy and ProbeManagedContent have no VS Code policy location to
// read on this OS. The platform also has no settings writer (settingsPath
// returns ok=false), so enforcement never runs here — these exist only to keep
// the package compiling on every GOOS.
func ProbeManagedPolicy() (bool, string) { return false, "" }

func ProbeManagedContent() (bool, map[string]json.RawMessage, error) { return false, nil, nil }
