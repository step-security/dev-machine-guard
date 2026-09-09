//go:build linux

package procusage

import "testing"

// TestMaxRSSToBytesLinux locks the kilobyte scaling. Darwin reports the
// same field in bytes, so a shared implementation would be silently off
// by 1024x on one of the two.
func TestMaxRSSToBytesLinux(t *testing.T) {
	tests := []struct {
		name   string
		maxrss int64
		want   uint64
	}{
		{"kilobytes are scaled", 48 * 1024, 48 << 20},
		{"one kilobyte", 1, 1024},
		{"zero", 0, 0},
		{"negative reading is discarded", -1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maxRSSToBytes(tt.maxrss); got != tt.want {
				t.Errorf("maxRSSToBytes(%d) = %d, want %d", tt.maxrss, got, tt.want)
			}
		})
	}
}
