package configaudit

import (
	"os"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

const maxConfigFileSize = 32 << 20
const protectedCommandReason = "not collected: protected-directory scanning is disabled"

func auditLstat(exec executor.Executor, s *tcc.Skipper, path string) (os.FileInfo, error) {
	if tcc.ProtectedReadsDisabled(exec, s) {
		return exec.Stat(path)
	}
	return os.Lstat(path)
}

func auditStat(exec executor.Executor, s *tcc.Skipper, path string) (os.FileInfo, error) {
	if tcc.ProtectedReadsDisabled(exec, s) {
		return exec.Stat(path)
	}
	return os.Stat(path)
}

func auditReadFile(exec executor.Executor, s *tcc.Skipper, path string) ([]byte, error) {
	if tcc.ProtectedReadsDisabled(exec, s) {
		return exec.ReadFile(path)
	}
	// #nosec G304 -- Existing unguarded mode reads scanner-selected config files.
	return os.ReadFile(path)
}

func guardedOwner(exec executor.Executor) func(string) ownerInfo {
	return func(path string) ownerInfo {
		info, err := exec.Stat(path)
		if err != nil {
			return ownerInfo{}
		}
		return ownerFromInfo(info)
	}
}

func guardedInGitRepo(exec executor.Executor) func(string) bool {
	return func(path string) bool {
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			if _, err := exec.Stat(filepath.Join(dir, ".git")); err == nil {
				return true
			}
			if filepath.Dir(dir) == dir {
				return false
			}
		}
	}
}
