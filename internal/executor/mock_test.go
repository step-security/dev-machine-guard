package executor

import (
	"context"
	"os"
	"testing"
)

func TestMock_IsAppleCLTStub(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name     string
		goos     string
		clt      bool
		path     string
		expected bool
	}{
		{"darwin /usr/bin/python3 without CLT → stub", "darwin", false, "/usr/bin/python3", true},
		{"darwin /usr/bin/pip3 without CLT → stub", "darwin", false, "/usr/bin/pip3", true},
		{"darwin /usr/bin/python3 with CLT → not stub", "darwin", true, "/usr/bin/python3", false},
		{"darwin /usr/bin/ssh without CLT → not stub (base system binary)", "darwin", false, "/usr/bin/ssh", false},
		{"darwin /usr/bin/ls without CLT → not stub (base system binary)", "darwin", false, "/usr/bin/ls", false},
		{"darwin /usr/local/bin → never a stub", "darwin", false, "/usr/local/bin/python3", false},
		{"darwin /opt/homebrew → never a stub", "darwin", false, "/opt/homebrew/bin/python3", false},
		{"linux /usr/bin/python3 without CLT flag → not a stub", "linux", false, "/usr/bin/python3", false},
		{"windows path → not a stub", "windows", false, `C:\Python\python.exe`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMock()
			m.SetGOOS(tc.goos)
			m.SetAppleCLTInstalled(tc.clt)
			if got := m.IsAppleCLTStub(ctx, tc.path); got != tc.expected {
				t.Errorf("IsAppleCLTStub(%q) on goos=%s clt=%v: got %v, want %v",
					tc.path, tc.goos, tc.clt, got, tc.expected)
			}
		})
	}
}

func TestMock_Readlink(t *testing.T) {
	m := NewMock()
	m.SetSymlink("/only-symlink", "/resolved")
	m.SetSymlink("/both", "/resolved-both")
	m.SetReadlink("/both", "../raw-both")
	m.SetReadlink("/only-readlink", `\??\C:\raw`)

	cases := []struct {
		path, want string
		wantErr    bool
	}{
		{"/only-symlink", "/resolved", false}, // falls back to the SetSymlink target
		{"/both", "../raw-both", false},       // SetReadlink wins over SetSymlink
		{"/only-readlink", `\??\C:\raw`, false},
		{"/plain", "", true},
	}
	for _, c := range cases {
		got, err := m.Readlink(c.path)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("Readlink(%q) = (%q, %v), want (%q, err=%v)", c.path, got, err, c.want, c.wantErr)
		}
	}
	if got, err := m.EvalSymlinks("/both"); err != nil || got != "/resolved-both" {
		t.Errorf("SetReadlink must not change EvalSymlinks: got (%q, %v)", got, err)
	}
}

func TestMockIrregularDirEntry(t *testing.T) {
	e := MockIrregularDirEntry("junction")
	if e.Name() != "junction" || e.IsDir() || e.Type()&os.ModeIrregular == 0 || e.Type()&os.ModeSymlink != 0 {
		t.Errorf("irregular entry: name=%q dir=%v type=%v", e.Name(), e.IsDir(), e.Type())
	}
	if s := MockSymlinkDirEntry("s"); s.Type()&os.ModeIrregular != 0 {
		t.Errorf("symlink entry must not be irregular: %v", s.Type())
	}
}
