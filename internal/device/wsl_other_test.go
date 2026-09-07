//go:build !windows

package device

import "testing"

// parseRegDWORDOpt lives in the reg.exe-based (non-Windows) probe, so its test
// carries the same build tag — on Windows the symbol does not exist.
func TestParseRegDWORDOpt(t *testing.T) {
	cases := []struct {
		in   string
		want *uint32
	}{
		{"", nil},
		{"   ", nil},
		{"not-a-number", nil},
		{"0x0", ptrU32(0)},
		{"0x3e8", ptrU32(1000)},
		{"0X3E8", ptrU32(1000)},
		{"1000", ptrU32(1000)},
		{"0xffffffffff", nil}, // wider than 32 bits
	}
	for _, c := range cases {
		got := parseRegDWORDOpt(c.in)
		switch {
		case c.want == nil && got != nil:
			t.Errorf("parseRegDWORDOpt(%q) = %d, want nil", c.in, *got)
		case c.want != nil && got == nil:
			t.Errorf("parseRegDWORDOpt(%q) = nil, want %d", c.in, *c.want)
		case c.want != nil && *got != *c.want:
			t.Errorf("parseRegDWORDOpt(%q) = %d, want %d", c.in, *got, *c.want)
		}
	}
}
