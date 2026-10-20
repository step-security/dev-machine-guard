//go:build !darwin && !linux && !windows

package tcc

const skipRemoteByDefault = false

func networkVolumeMounts() []string { return nil }

func cloudPlaceholder(string) bool { return false }
