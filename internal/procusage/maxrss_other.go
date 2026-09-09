//go:build !linux && !darwin && !windows

package procusage

// maxRSSToBytes scales getrusage's ru_maxrss on the remaining unix
// platforms. The BSDs follow Linux in reporting kilobytes.
func maxRSSToBytes(maxrss int64) uint64 {
	if maxrss <= 0 {
		return 0
	}
	return uint64(maxrss) * 1024
}
