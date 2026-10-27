package updatestate

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a strict x.y.z release version. Prereleases and build metadata
// are refused (spec §6).
type Version struct{ Major, Minor, Patch uint32 }

// ParseVersion accepts only x.y.z with decimal components, no sign, no "v"
// prefix and no leading zeros.
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q: want x.y.z", s)
	}
	var n [3]uint32
	for i, p := range parts {
		if p == "" || len(p) > 10 || (len(p) > 1 && p[0] == '0') || strings.TrimLeft(p, "0123456789") != "" {
			return Version{}, fmt.Errorf("version %q: invalid component %q", s, p)
		}
		u, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: %w", s, err)
		}
		n[i] = uint32(u)
	}
	return Version{n[0], n[1], n[2]}, nil
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Compare returns -1, 0 or +1 as a is older than, equal to or newer than b.
func Compare(a, b Version) int {
	for _, d := range [3][2]uint32{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func validVersion(s string) bool {
	_, err := ParseVersion(s)
	return err == nil
}
