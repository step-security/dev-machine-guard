//go:build linux

package containerlife

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const runtimeLogLimit = 1024 * 1024

// The detached worker has no inherited stderr destination. Keep at most two
// bounded private files, rotating on writes (not merely on worker startup).
func (r *runtime) logError(format string, args ...any) {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	message := fmt.Sprintf(format, args...)
	if r.cfg.APIKey != "" {
		message = strings.ReplaceAll(message, r.cfg.APIKey, "[redacted]")
	}
	line := []byte(time.Now().UTC().Format(time.RFC3339) + " " + message + "\n")
	_, _ = os.Stderr.Write(line)
	if len(line) > runtimeLogLimit {
		line = line[len(line)-runtimeLogLimit:]
	}
	root, err := os.OpenRoot(r.dir)
	if err != nil {
		return
	}
	defer root.Close()
	if info, err := root.Stat("runtime.log"); err == nil && info.Size()+int64(len(line)) > runtimeLogLimit {
		if err = root.Rename("runtime.log", "runtime.log.prev"); err != nil {
			return
		}
	}
	f, err := root.OpenFile("runtime.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}
