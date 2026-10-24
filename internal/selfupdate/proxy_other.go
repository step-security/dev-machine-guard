//go:build !windows

package selfupdate

func loadMachineProxy() *machineProxy { return nil }
