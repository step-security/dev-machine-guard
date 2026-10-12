package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Absolute globs are evaluated rule-first to preserve global-budget ordering.
// Bound their FIFO cache by both bytes and entries (including empty files).
const maxAbsoluteCacheEntries = 128

type cachedFile struct {
	info       os.FileInfo
	statErr    error
	statLoaded bool
	data       []byte
	hash       string
	ok         bool
	loaded     bool
}

type fileCache struct {
	path     string
	current  *cachedFile
	entries  map[string]*cachedFile // nil for the file-first relative walk
	order    []string
	bytes    int64
	maxBytes int64
}

func newFileCache() *fileCache { return &fileCache{} }

func newAbsoluteFileCache(maxBytes int64) *fileCache {
	return &fileCache{entries: make(map[string]*cachedFile), maxBytes: maxBytes}
}

func (fc *fileCache) file(path string) *cachedFile {
	if fc.current != nil && fc.path == path {
		return fc.current
	}
	fc.path = path
	fc.current = fc.entries[path]
	if fc.current == nil {
		fc.current = &cachedFile{}
	}
	return fc.current
}

func (fc *fileCache) stat(exec executor.Executor, path string) (os.FileInfo, error) {
	f := fc.file(path)
	if !f.statLoaded {
		f.info, f.statErr = exec.Stat(path)
		f.statLoaded = true
	}
	return f.info, f.statErr
}

func (fc *fileCache) read(exec executor.Executor, path string) ([]byte, string, bool) {
	f := fc.file(path)
	if f.loaded {
		return f.data, f.hash, f.ok
	}
	f.loaded = true
	b, err := exec.ReadFile(path)
	if err == nil {
		sum := sha256.Sum256(b)
		f.data, f.hash, f.ok = b, hex.EncodeToString(sum[:]), true
	}
	fc.remember(path, f)
	return f.data, f.hash, f.ok
}

func (fc *fileCache) remember(path string, f *cachedFile) {
	size := int64(cap(f.data))
	if fc.entries == nil || size > fc.maxBytes {
		return
	}
	for len(fc.order) > 0 && (fc.bytes+size > fc.maxBytes || len(fc.order) >= maxAbsoluteCacheEntries) {
		oldest := fc.order[0]
		fc.bytes -= int64(cap(fc.entries[oldest].data))
		delete(fc.entries, oldest)
		fc.order = fc.order[1:]
	}
	fc.entries[path] = f
	fc.order = append(fc.order, path)
	fc.bytes += size
}
