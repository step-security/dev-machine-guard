//go:build !darwin && !linux && !windows

package proctest

func children() ([]int, error) { return nil, nil }
