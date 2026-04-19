package executor

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"
)

// Mock implements Executor for unit testing.
type Mock struct {
	mu sync.RWMutex

	// Command results: key is "name arg1 arg2 ..."
	commands map[string]cmdResult

	// File system stubs
	files     map[string][]byte
	dirs      map[string]bool
	dirEnts   map[string][]os.DirEntry
	fileInfos map[string]os.FileInfo

	// Path lookup stubs
	paths map[string]string

	// Environment
	env      map[string]string
	hostname string
	isRoot   bool
	username string
	homeDir  string
	goos     string

	// Glob stubs
	globs map[string][]string
}

type cmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

func NewMock() *Mock {
	return &Mock{
		commands:  make(map[string]cmdResult),
		files:     make(map[string][]byte),
		dirs:      make(map[string]bool),
		dirEnts:   make(map[string][]os.DirEntry),
		fileInfos: make(map[string]os.FileInfo),
		paths:     make(map[string]string),
		env:       make(map[string]string),
		globs:     make(map[string][]string),
		hostname:  "test-host",
		username:  "testuser",
		homeDir:   "/Users/testuser",
		goos:      "darwin",
	}
}

// --- Stub setters ---

func (m *Mock) SetCommand(stdout, stderr string, exitCode int, name string, args ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := cmdKey(name, args...)
	m.commands[key] = cmdResult{Stdout: stdout, Stderr: stderr, ExitCode: exitCode}
}

func (m *Mock) SetCommandError(err error, name string, args ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := cmdKey(name, args...)
	m.commands[key] = cmdResult{Err: err}
}

func (m *Mock) SetFile(path string, content []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = content
}

func (m *Mock) SetDir(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirs[path] = true
}

func (m *Mock) SetDirEntries(path string, entries []os.DirEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirEnts[path] = entries
	m.dirs[path] = true
}

func (m *Mock) SetFileInfo(path string, info os.FileInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fileInfos[path] = info
}

func (m *Mock) SetPath(name, path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paths[name] = path
}

func (m *Mock) SetEnv(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.env[key] = value
}

func (m *Mock) SetHostname(h string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hostname = h
}

func (m *Mock) SetIsRoot(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isRoot = v
}

func (m *Mock) SetUsername(u string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.username = u
}

func (m *Mock) SetHomeDir(h string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.homeDir = h
}

func (m *Mock) SetGlob(pattern string, matches []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globs[pattern] = matches
}

func (m *Mock) SetGOOS(goos string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.goos = goos
}

// --- Executor interface ---

func (m *Mock) Run(_ context.Context, name string, args ...string) (string, string, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := cmdKey(name, args...)
	if r, ok := m.commands[key]; ok {
		return r.Stdout, r.Stderr, r.ExitCode, r.Err
	}
	return "", "", -1, fmt.Errorf("mock: no command stub for %q", key)
}

func (m *Mock) RunWithTimeout(ctx context.Context, _ time.Duration, name string, args ...string) (string, string, int, error) {
	return m.Run(ctx, name, args...)
}

func (m *Mock) RunAsUser(ctx context.Context, _ string, command string) (string, error) {
	stdout, _, _, err := m.Run(ctx, "bash", "-c", command)
	return stdout, err
}

func (m *Mock) LookPath(name string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if p, ok := m.paths[name]; ok {
		return p, nil
	}
	return "", fmt.Errorf("mock: %q not found in PATH", name)
}

func (m *Mock) FileExists(path string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.files[path]
	return ok
}

func (m *Mock) DirExists(path string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dirs[path]
}

func (m *Mock) ReadFile(path string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if data, ok := m.files[path]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("mock: file not found: %s", path)
}

func (m *Mock) ReadDir(path string) ([]os.DirEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ents, ok := m.dirEnts[path]; ok {
		return ents, nil
	}
	return nil, fmt.Errorf("mock: directory not found: %s", path)
}

func (m *Mock) Stat(path string) (os.FileInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if info, ok := m.fileInfos[path]; ok {
		return info, nil
	}
	// Fall back: check files map
	if _, ok := m.files[path]; ok {
		return &mockFileInfo{name: filepath.Base(path), size: int64(len(m.files[path]))}, nil
	}
	return nil, fmt.Errorf("mock: stat: %s not found", path)
}

func (m *Mock) Hostname() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hostname, nil
}

func (m *Mock) Getenv(key string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.env[key]
}

func (m *Mock) IsRoot() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isRoot
}

func (m *Mock) CurrentUser() (*user.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &user.User{
		Username: m.username,
		HomeDir:  m.homeDir,
	}, nil
}

func (m *Mock) HomeDir(_ string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.homeDir, nil
}

func (m *Mock) Glob(pattern string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if matches, ok := m.globs[pattern]; ok {
		return matches, nil
	}
	return nil, nil
}

func (m *Mock) LoggedInUser() (*user.User, error) {
	return m.CurrentUser()
}

func (m *Mock) GOOS() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.goos
}

// --- helpers ---

func cmdKey(name string, args ...string) string {
	parts := append([]string{name}, args...)
	return fmt.Sprintf("%v", parts)
}

type mockFileInfo struct {
	name string
	size int64
	dir  bool
}

func (fi *mockFileInfo) Name() string       { return fi.name }
func (fi *mockFileInfo) Size() int64        { return fi.size }
func (fi *mockFileInfo) IsDir() bool        { return fi.dir }
func (fi *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (fi *mockFileInfo) Mode() os.FileMode  { return 0o644 }
func (fi *mockFileInfo) Sys() any           { return nil }

// MockDirEntry creates an os.DirEntry for use with SetDirEntries.
func MockDirEntry(name string, isDir bool) os.DirEntry {
	return &mockDirEntry{name: name, dir: isDir}
}

type mockDirEntry struct {
	name string
	dir  bool
}

func (e *mockDirEntry) Name() string               { return e.name }
func (e *mockDirEntry) IsDir() bool                { return e.dir }
func (e *mockDirEntry) Type() os.FileMode          { if e.dir { return os.ModeDir }; return 0 }
func (e *mockDirEntry) Info() (os.FileInfo, error)  { return &mockFileInfo{name: e.name, dir: e.dir}, nil }
