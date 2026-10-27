package proctest

import (
	"os"

	"golang.org/x/sys/unix"
)

const sZomb = 5 // SZOMB, sys/proc.h

func children() ([]int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	self := int32(os.Getpid()) // #nosec G115 -- pid
	var out []int
	for _, p := range procs {
		if p.Eproc.Ppid == self && p.Proc.P_stat != sZomb {
			out = append(out, int(p.Proc.P_pid))
		}
	}
	return out, nil
}
