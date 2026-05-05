package hook

import (
	"errors"
	"fmt"
	"io"
)

var errInputTooLarge = errors.New("input exceeds maximum allowed size")

// readBounded reads up to max+1 bytes from r. If max is exceeded, returns
// errInputTooLarge along with whatever was read so far.
func readBounded(r io.Reader, max int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	limited := io.LimitReader(r, max+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return buf, fmt.Errorf("readBounded: %w", err)
	}
	if int64(len(buf)) > max {
		return buf[:max], errInputTooLarge
	}
	return buf, nil
}
