//go:build darwin

package procusage

// maxRSSToBytes scales getrusage's ru_maxrss, which Darwin reports in
// bytes already (Linux uses kilobytes — see maxrss_linux.go).
func maxRSSToBytes(maxrss int64) uint64 {
	if maxrss <= 0 {
		return 0
	}
	return uint64(maxrss)
}
