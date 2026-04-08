package detector

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

const maxNodeProjects = 1000

// NodeProjectDetector scans for Node.js projects.
type NodeProjectDetector struct {
	exec executor.Executor
}

func NewNodeProjectDetector(exec executor.Executor) *NodeProjectDetector {
	return &NodeProjectDetector{exec: exec}
}

// CountProjects counts the number of Node.js projects found under the given directories.
// It finds package.json files (excluding node_modules) up to a limit.
func (d *NodeProjectDetector) CountProjects(_ context.Context, searchDirs []string) int {
	count := 0
	for _, dir := range searchDirs {
		count += d.countInDir(dir)
		if count >= maxNodeProjects {
			return maxNodeProjects
		}
	}
	return count
}

func (d *NodeProjectDetector) countInDir(dir string) int {
	count := 0
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible dirs
		}
		if entry.IsDir() {
			name := entry.Name()
			// Skip node_modules, hidden dirs, and other irrelevant dirs
			if name == "node_modules" || name == ".git" || name == ".cache" ||
				strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == "package.json" {
			count++
			if count >= maxNodeProjects {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return count
}

// DetectProjectPM detects which package manager a project uses based on lock files.
func DetectProjectPM(exec executor.Executor, projectDir string) string {
	if strings.Contains(filepath.ToSlash(projectDir), "/.bun/install/") {
		return "bun"
	}
	if exec.FileExists(filepath.Join(projectDir, "bun.lock")) || exec.FileExists(filepath.Join(projectDir, "bun.lockb")) {
		return "bun"
	}
	if exec.FileExists(filepath.Join(projectDir, "pnpm-lock.yaml")) {
		return "pnpm"
	}
	if exec.FileExists(filepath.Join(projectDir, "yarn.lock")) {
		// Distinguish Yarn Classic from Yarn Berry
		if exec.FileExists(filepath.Join(projectDir, ".yarnrc.yml")) || exec.DirExists(filepath.Join(projectDir, ".yarn", "releases")) {
			return "yarn-berry"
		}
		return "yarn"
	}
	if exec.FileExists(filepath.Join(projectDir, "package-lock.json")) {
		return "npm"
	}
	return "npm" // default
}
