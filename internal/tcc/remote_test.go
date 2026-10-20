package tcc

import (
	"reflect"
	"runtime"
	"testing"
)

func TestParseRemoteMounts(t *testing.T) {
	mountinfo := `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw - proc proc rw
40 22 0:35 / /home/alice/nfs rw shared:20 - nfs4 srv:/export rw
41 22 0:36 / /mnt/share rw - cifs //srv/share rw
42 22 0:37 / /home/alice/remote\040box rw - fuse.sshfs alice@box: rw
43 22 0:38 / /net rw - autofs systemd-1 rw
44 22 0:39 / /home/alice/drive rw - fuse.rclone gdrive: rw
45 22 0:40 / /srv/root rw - nfs srv:/ rw
46 1 0:41 / / rw - nfs srv:/root rw
47 22 0:42 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw
garbage line
`
	got := parseRemoteMounts(mountinfo)
	want := []string{"/home/alice/nfs", "/home/alice/remote box", "/mnt/share", "/net", "/srv/root"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseRemoteMounts = %v, want %v", got, want)
	}
}

func TestIsCloudPlaceholderAttrs(t *testing.T) {
	tests := []struct {
		attrs uint32
		want  bool
	}{
		{0x10, false},                     // plain directory
		{0x10 | 0x400, false},             // reparse point alone
		{0x10 | 0x00400000, true},         // RECALL_ON_DATA_ACCESS
		{0x10 | 0x00040000, true},         // RECALL_ON_OPEN
		{0x10 | 0x400 | 0x00400000, true}, // OneDrive online-only folder
	}
	for _, tc := range tests {
		if got := isCloudPlaceholderAttrs(tc.attrs); got != tc.want {
			t.Errorf("isCloudPlaceholderAttrs(%#x) = %v, want %v", tc.attrs, got, tc.want)
		}
	}
}

func TestSkipper_LinuxRemoteMountUnderHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("slash paths")
	}
	s := build("/home/alice", true, []string{"/home/alice/nfs"})
	if !s.ShouldSkip("/home/alice/nfs", "/home/alice") {
		t.Error("remote mount under the walk root must be skipped")
	}
	if !s.ShouldSkip("/home/alice/nfs/proj", "/home/alice") {
		t.Error("dir under remote mount must be skipped")
	}
	if s.ShouldSkip("/home/alice/code", "/home/alice") {
		t.Error("local dir must not be skipped")
	}
	if s.ShouldSkip("/home/alice/nfs/proj", "/home/alice/nfs") {
		t.Error("explicit remote walk root opts in")
	}
}
