//go:build !darwin && !linux && !windows

package tcc

const skipRemoteByDefault = false

func networkVolumeMounts() []string { return nil }

func CloudPlaceholder(string) bool { return false }
