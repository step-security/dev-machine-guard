package proctest

import (
	"os"
	"strconv"
	"strings"
)

func children() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	self := os.Getpid()
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...; comm may contain spaces and parens.
		f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
		if len(f) < 2 || f[0] == "Z" {
			continue
		}
		if ppid, _ := strconv.Atoi(f[1]); ppid == self {
			out = append(out, pid)
		}
	}
	return out, nil
}
