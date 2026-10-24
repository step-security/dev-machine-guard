package updatestate

import "testing"

func TestParseVersion(t *testing.T) {
	good := map[string]Version{
		"0.0.0":          {},
		"1.19.0":         {1, 19, 0},
		"10.200.3000":    {10, 200, 3000},
		"4294967295.0.1": {4294967295, 0, 1},
		"1.0.4294967295": {1, 0, 4294967295},
	}
	for s, want := range good {
		got, err := ParseVersion(s)
		if err != nil || got != want || got.String() != s {
			t.Errorf("ParseVersion(%q) = %v, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "1", "1.2", "1.2.3.4", "v1.2.3", "1.2.3-rc.1", "1.2.3+b", "01.2.3",
		"1.02.3", "1.2.03", "-1.2.3", "+1.2.3", "1..3", "1.2.", " 1.2.3", "1.2.3 ", "1.2.x",
		"4294967296.0.0", "99999999999.0.0", "1.2.3\n", "１.2.3", "1/2.3"} {
		if v, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q) = %v, want error", s, v)
		}
	}
}

func TestCompare(t *testing.T) {
	order := []string{"0.0.0", "0.0.1", "0.1.0", "0.10.0", "1.0.0", "1.9.9", "1.10.0", "1.18.2", "1.19.0", "2.0.0"}
	for i, a := range order {
		for j, b := range order {
			va, _ := ParseVersion(a)
			vb, _ := ParseVersion(b)
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := Compare(va, vb); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
}
