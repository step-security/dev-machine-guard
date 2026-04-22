package detector

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const defaultMaxProjectScanBytes = 500 * 1024 * 1024 // 500MB total limit

// getMaxProjectScanBytes returns the size limit, overridable via
// STEPSEC_MAX_NODE_SCAN_BYTES environment variable.
func getMaxProjectScanBytes() int64 {
	if v := os.Getenv("STEPSEC_MAX_NODE_SCAN_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxProjectScanBytes
}

// NodeScanner performs enterprise-mode node scanning (raw output, base64 encoded).
type NodeScanner struct {
	exec         executor.Executor
	log          *progress.Logger
	loggedInUser string // when non-empty and running as root, commands run as this user
}

func NewNodeScanner(exec executor.Executor, log *progress.Logger, loggedInUser string) *NodeScanner {
	return &NodeScanner{exec: exec, log: log, loggedInUser: loggedInUser}
}

// shouldRunAsUser returns true when commands should be delegated to the logged-in user.
// Only applies on Unix — RunAsUser uses sudo which is not available on Windows.
func (s *NodeScanner) shouldRunAsUser() bool {
	return s.exec.GOOS() != "windows" && s.exec.IsRoot() && s.loggedInUser != ""
}

// runCmd runs a command, delegating to the logged-in user when running as root.
// This ensures package manager commands use the real user's PATH and config.
func (s *NodeScanner) runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, string, int, error) {
	if s.shouldRunAsUser() {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := name
		for _, a := range args {
			cmd += " " + a
		}
		stdout, err := s.exec.RunAsUser(ctx, s.loggedInUser, cmd)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return stdout, "", 124, fmt.Errorf("command timed out after %s", timeout)
			}
			return stdout, "", 1, err
		}
		return stdout, "", 0, nil
	}
	return s.exec.RunWithTimeout(ctx, timeout, name, args...)
}

// runShellCmd runs a shell command string, delegating to the logged-in user when running as root.
// Falls through to the platform-aware free function for the normal (non-delegation) path.
func (s *NodeScanner) runInDir(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) (string, string, int, error) {
	if s.shouldRunAsUser() {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := "cd " + platformShellQuote(s.exec, dir) + " && " + platformShellQuote(s.exec, name)
		for _, a := range args {
			cmd += " " + platformShellQuote(s.exec, a)
		}
		stdout, err := s.exec.RunAsUser(ctx, s.loggedInUser, cmd)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return stdout, "", 124, fmt.Errorf("command timed out after %s", timeout)
			}
			return stdout, "", 1, err
		}
		return stdout, "", 0, nil
	}
	return s.exec.RunInDir(ctx, dir, timeout, name, args...)
}

// checkPath checks if a binary is available, using the logged-in user's PATH when running as root.
func (s *NodeScanner) checkPath(ctx context.Context, name string) error {
	if s.shouldRunAsUser() {
		path, err := s.exec.RunAsUser(ctx, s.loggedInUser, "which "+name)
		if err != nil || path == "" {
			return fmt.Errorf("%s not found in user PATH", name)
		}
		return nil
	}
	_, err := s.exec.LookPath(name)
	return err
}

// ScanGlobalPackages runs npm/yarn/pnpm list -g and returns raw base64-encoded results.
func (s *NodeScanner) ScanGlobalPackages(ctx context.Context) []model.NodeScanResult {
	var results []model.NodeScanResult

	s.log.Progress("  Checking npm global packages...")
	if r, ok := s.scanNPMGlobal(ctx); ok {
		results = append(results, r)
	}

	s.log.Progress("  Checking yarn global packages...")
	if r, ok := s.scanYarnGlobal(ctx); ok {
		results = append(results, r)
	}

	s.log.Progress("  Checking pnpm global packages...")
	if r, ok := s.scanPnpmGlobal(ctx); ok {
		results = append(results, r)
	}

	return results
}

func (s *NodeScanner) scanNPMGlobal(ctx context.Context) (model.NodeScanResult, bool) {
	if err := s.checkPath(ctx, "npm"); err != nil {
		return model.NodeScanResult{}, false
	}

	version := s.getVersion(ctx, "npm", "--version")
	prefix := s.getOutput(ctx, "npm", "config", "get", "prefix")
	if prefix == "" {
		return model.NodeScanResult{}, false
	}

	start := time.Now()
	stdout, stderr, exitCode, _ := s.runCmd(ctx, 60*time.Second, "npm", "list", "-g", "--json", "--depth=3")
	duration := time.Since(start).Milliseconds()

	errMsg := ""
	if exitCode != 0 {
		errMsg = "npm list -g command failed with exit code"
	}

	return model.NodeScanResult{
		ProjectPath:      prefix,
		PackageManager:   "npm",
		PMVersion:        version,
		WorkingDirectory: prefix,
		RawStdoutBase64:  base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64:  base64.StdEncoding.EncodeToString([]byte(stderr)),
		Error:            errMsg,
		ExitCode:         exitCode,
		ScanDurationMs:   duration,
	}, true
}

func (s *NodeScanner) scanYarnGlobal(ctx context.Context) (model.NodeScanResult, bool) {
	if err := s.checkPath(ctx, "yarn"); err != nil {
		return model.NodeScanResult{}, false
	}

	version := s.getVersion(ctx, "yarn", "--version")
	globalDir := s.getOutput(ctx, "yarn", "global", "dir")
	if globalDir == "" {
		return model.NodeScanResult{}, false
	}

	start := time.Now()
	// Run directly in the global dir instead of shell cd (avoids Windows quoting issues).
	stdout, stderr, exitCode, _ := s.runInDir(ctx, globalDir, 60*time.Second, "yarn", "list", "--json", "--depth=0")
	duration := time.Since(start).Milliseconds()

	errMsg := ""
	if exitCode != 0 {
		errMsg = "yarn global list command failed"
	}

	return model.NodeScanResult{
		ProjectPath:      globalDir,
		PackageManager:   "yarn",
		PMVersion:        version,
		WorkingDirectory: globalDir,
		RawStdoutBase64:  base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64:  base64.StdEncoding.EncodeToString([]byte(stderr)),
		Error:            errMsg,
		ExitCode:         exitCode,
		ScanDurationMs:   duration,
	}, true
}

func (s *NodeScanner) scanPnpmGlobal(ctx context.Context) (model.NodeScanResult, bool) {
	if err := s.checkPath(ctx, "pnpm"); err != nil {
		return model.NodeScanResult{}, false
	}

	version := s.getVersion(ctx, "pnpm", "--version")
	globalDir := s.getOutput(ctx, "pnpm", "root", "-g")
	if globalDir == "" {
		return model.NodeScanResult{}, false
	}
	globalDir = filepath.Dir(globalDir)

	start := time.Now()
	stdout, stderr, exitCode, _ := s.runCmd(ctx, 60*time.Second, "pnpm", "list", "-g", "--json", "--depth=3")
	duration := time.Since(start).Milliseconds()

	errMsg := ""
	if exitCode != 0 {
		errMsg = "pnpm list -g command failed"
	}

	return model.NodeScanResult{
		ProjectPath:      globalDir,
		PackageManager:   "pnpm",
		PMVersion:        version,
		WorkingDirectory: globalDir,
		RawStdoutBase64:  base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64:  base64.StdEncoding.EncodeToString([]byte(stderr)),
		Error:            errMsg,
		ExitCode:         exitCode,
		ScanDurationMs:   duration,
	}, true
}

// projectEntry holds a discovered package.json with its modification time for sorting.
type projectEntry struct {
	dir     string
	modTime int64
}

// ScanProjects finds package.json files, sorts by most recently modified, then scans.
// Respects the size limit (default 500MB, override via STEPSEC_MAX_NODE_SCAN_BYTES).
func (s *NodeScanner) ScanProjects(ctx context.Context, searchDirs []string) []model.NodeScanResult {
	// Phase 1: Discover all package.json files
	var projects []projectEntry
	for _, dir := range searchDirs {
		s.log.Progress("  Searching in: %s", dir)
		_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				name := entry.Name()
				if name == "node_modules" || name == ".git" || name == ".cache" ||
					strings.HasPrefix(name, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Name() != "package.json" {
				return nil
			}
			projectDir := filepath.Dir(path)
			if isInsideNodeModules(projectDir) {
				return nil
			}
			// Get modification time for sorting
			modTime := int64(0)
			if info, err := entry.Info(); err == nil {
				modTime = info.ModTime().Unix()
			}
			projects = append(projects, projectEntry{dir: projectDir, modTime: modTime})
			return nil
		})
	}

	// Phase 2: Sort by modification time descending (most recent first)
	sort.Slice(projects, func(i, j int) bool {
		return projects[i].modTime > projects[j].modTime
	})

	// Phase 3: Scan in order, respecting limits
	maxBytes := getMaxProjectScanBytes()
	var results []model.NodeScanResult
	totalSize := int64(0)

	for i, p := range projects {
		if i >= maxNodeProjects {
			s.log.Progress("  Reached maximum of %d projects, stopping search", maxNodeProjects)
			break
		}
		if totalSize > maxBytes {
			s.log.Warn("Reached data size limit (%d bytes collected, limit: %d bytes)", totalSize, maxBytes)
			s.log.Warn("Skipping remaining projects (prioritized by most recently modified)")
			break
		}

		s.log.Progress("  Found project: %s", p.dir)
		pm := DetectProjectPM(s.exec, p.dir)
		s.log.Progress("    Package manager: %s", pm)

		r := s.scanProject(ctx, p.dir)
		resultSize := int64(len(r.RawStdoutBase64)) + int64(len(r.RawStderrBase64))

		if totalSize+resultSize > maxBytes {
			s.log.Warn("Reached data size limit (%d bytes collected, limit: %d bytes)", totalSize, maxBytes)
			s.log.Warn("Skipping remaining projects (prioritized by most recently modified)")
			break
		}

		totalSize += resultSize
		results = append(results, r)
	}

	return results
}

func (s *NodeScanner) scanProject(ctx context.Context, projectDir string) model.NodeScanResult {
	pm := DetectProjectPM(s.exec, projectDir)
	version := ""

	var cmd string
	var args []string

	switch pm {
	case "npm":
		version = s.getVersion(ctx, "npm", "--version")
		cmd = "npm"
		args = []string{"ls", "--json", "--depth=3"}
	case "yarn":
		version = s.getVersion(ctx, "yarn", "--version")
		cmd = "yarn"
		args = []string{"list", "--json"}
	case "yarn-berry":
		version = s.getVersion(ctx, "yarn", "--version")
		cmd = "yarn"
		args = []string{"info", "--all", "--json"}
	case "pnpm":
		version = s.getVersion(ctx, "pnpm", "--version")
		cmd = "pnpm"
		args = []string{"ls", "--json", "--depth=3"}
	case "bun":
		version = s.getVersion(ctx, "bun", "--version")
		cmd = "bun"
		args = []string{"pm", "ls", "--all"}
	default:
		return model.NodeScanResult{
			ProjectPath:    projectDir,
			PackageManager: pm,
			Error:          "unsupported package manager",
			ExitCode:       1,
		}
	}

	start := time.Now()
	// Run the package manager command directly in the project directory.
	// Avoids shell cd + quoting issues on Windows where cmd.exe misinterprets
	// Go's backslash-escaped quotes in paths.
	stdout, stderr, exitCode, _ := s.runInDir(ctx, projectDir, 30*time.Second, cmd, args...)
	duration := time.Since(start).Milliseconds()

	errMsg := ""
	if exitCode != 0 {
		errMsg = cmd + " command failed with exit code"
	}

	return model.NodeScanResult{
		ProjectPath:      projectDir,
		PackageManager:   pm,
		PMVersion:        version,
		WorkingDirectory: projectDir,
		RawStdoutBase64:  base64.StdEncoding.EncodeToString([]byte(stdout)),
		RawStderrBase64:  base64.StdEncoding.EncodeToString([]byte(stderr)),
		Error:            errMsg,
		ExitCode:         exitCode,
		ScanDurationMs:   duration,
	}
}

func (s *NodeScanner) getVersion(ctx context.Context, binary, flag string) string {
	stdout, _, _, err := s.runCmd(ctx, 10*time.Second, binary, flag)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(stdout)
}

func (s *NodeScanner) getOutput(ctx context.Context, binary string, args ...string) string {
	stdout, _, _, err := s.runCmd(ctx, 10*time.Second, binary, args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(stdout)
}

// isInsideNodeModules returns true if the path contains a node_modules component.
// Uses strings.ReplaceAll instead of filepath.ToSlash so the check works
// regardless of the host OS (important for cross-platform mock tests).
func isInsideNodeModules(projectDir string) bool {
	normalized := strings.ReplaceAll(projectDir, "\\", "/")
	return strings.Contains(normalized, "/node_modules/")
}
