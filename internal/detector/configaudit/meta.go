package configaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// ownerInfo carries the resolved owning user / group for a file. OK=false
// on Windows (we don't resolve SIDs) or when the file doesn't exist.
type ownerInfo struct {
	UID       int
	GID       int
	OwnerName string
	GroupName string
	OK        bool
}

// defaultInGitRepo walks parents looking for a `.git` entry (dir or worktree
// file). Stops at the filesystem root.
func defaultInGitRepo(path string) bool {
	dir := filepath.Dir(path)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// gitTrackedViaExec shells out to git ls-files. Returns false on any error
// (not installed, not in a repo, untracked). Callers gate on defaultInGitRepo.
func gitTrackedViaExec(ctx context.Context, exec executor.Executor, path string) bool {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	_, _, exit, err := exec.RunWithTimeout(ctx, 5*time.Second, "git", "-C", dir, "ls-files", "--error-unmatch", base)
	return err == nil && exit == 0
}

// sha256Hex returns hex SHA-256 of s, or "" if s is empty.
func sha256Hex(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
