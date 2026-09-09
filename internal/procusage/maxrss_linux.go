//go:build linux

package procusage

// maxRSSToBytes scales getrusage's ru_maxrss, which Linux reports in
// kilobytes. Darwin reports the same field in bytes — see
// maxrss_darwin.go. Getting this wrong is a silent 1024x error, which is
// why the scale lives in its own per-OS file rather than a shared const.
func maxRSSToBytes(maxrss int64) uint64 {
	if maxrss <= 0 {
		return 0
	}
	return uint64(maxrss) * 1024
}
