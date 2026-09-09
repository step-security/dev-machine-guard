//go:build darwin

package procusage

import "testing"

// TestMaxRSSToBytesDarwin locks the byte-for-byte passthrough. Linux
// reports the same field in kilobytes — see maxrss_linux_test.go.
func TestMaxRSSToBytesDarwin(t *testing.T) {
	tests := []struct {
		name   string
		maxrss int64
		want   uint64
	}{
		{"bytes pass through unscaled", 48 << 20, 48 << 20},
		{"one byte", 1, 1},
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
