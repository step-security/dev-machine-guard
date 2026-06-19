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
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
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
	skipper      *tcc.Skipper
	// ProgressHook, when non-nil, is invoked from inside ScanProjects /
	// ScanGlobalPackages with a short human-readable detail string ("project
	// 12 of 47", "scanning yarn", ...). Telemetry plumbs this into
	// PhaseTracker.UpdateDetail so heartbeats surface mid-phase progress.
	ProgressHook func(detail string)
	// pmAvailability caches checkPath results per package-manager binary
	// for the lifetime of the NodeScanner instance. On a device with 700+
	// lockfiles, the per-project scan path previously paid a PATH lookup
	// per project; this cache collapses that to one lookup per distinct
	// PM. A scanner is created once per telemetry run (see
	// internal/telemetry/telemetry.go), so the cache's effective scope
	// matches a single scan even though the map isn't reset. Mutex-guarded
	// because the worker pool in scanProjectsConcurrent reads/writes this
	// map from multiple goroutines.
	pmAvailability   map[string]error
	pmAvailabilityMu sync.Mutex
}

func NewNodeScanner(exec executor.Executor, log *progress.Logger, loggedInUser string) *NodeScanner {
	return &NodeScanner{
		exec:           exec,
		log:            log,
		loggedInUser:   loggedInUser,
		pmAvailability: make(map[string]error),
	}
}

// binaryAvailable returns the cached checkPath result for a package-manager
// binary, populating the cache on first call. Wraps checkPath so callers in
// the per-project loop don't pay a LookPath per project on devices that
// have hundreds of lockfiles for a PM that isn't installed.
func (s *NodeScanner) binaryAvailable(ctx context.Context, name string) error {
	s.pmAvailabilityMu.Lock()
	if err, ok := s.pmAvailability[name]; ok {
		s.pmAvailabilityMu.Unlock()
		return err
	}
	s.pmAvailabilityMu.Unlock()

	err := s.checkPath(ctx, name)
	if err != nil {
		// Logged once per PM (cache miss). "Not on PATH" is a normal
		// "PM not installed" state — projects using it are silently skipped —
		// but recording it at Debug makes "device emits no npm data" diagnosable
		// (send the Debug header) instead of an unexplained absence.
		s.log.Debug("%s not found in PATH (delegated=%v) — projects using it will be skipped: %v", name, s.shouldRunAsUser(), err)
	}
	s.pmAvailabilityMu.Lock()
	s.pmAvailability[name] = err
	s.pmAvailabilityMu.Unlock()
	return err
}

// WithSkipper attaches a TCC skipper so the discovery walk skips
// macOS-protected directories. A nil skipper is a no-op.
func (s *NodeScanner) WithSkipper(skipper *tcc.Skipper) *NodeScanner {
	s.skipper = skipper
	return s
}

func (s *NodeScanner) emitProgress(detail string) {
	if s.ProgressHook != nil {
		s.ProgressHook(detail)
	}
}

// shouldRunAsUser returns true when package-manager commands should run through
// the logged-in user's login shell (with rc files sourced for a full PATH)
// instead of a bare exec. Applies on Unix whenever we have a target user, in
// both deployment modes:
//   - root (LaunchDaemon / MDM "Run Script"): RunAsUser sudo's to the console user.
//   - non-root (LaunchAgent's periodic fire): RunAsUser runs as the current user.
//
// launchd hands both a stripped PATH (/usr/bin:/bin:/usr/sbin:/sbin), so a bare
// exec can't find npm/yarn/pnpm installed via nvm/fnm/homebrew/npm-global —
// producing exit_code -1, empty output, and version "unknown". Windows is
// excluded (no sudo / rc-sourcing model).
func (s *NodeScanner) shouldRunAsUser() bool {
	return s.exec.GOOS() != model.PlatformWindows && s.loggedInUser != ""
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

	s.emitProgress("global: npm")
	s.log.Progress("  Checking npm global packages...")
	if r, ok := s.scanNPMGlobal(ctx); ok {
		results = append(results, r)
	}

	s.emitProgress("global: yarn")
	s.log.Progress("  Checking yarn global packages...")
	if r, ok := s.scanYarnGlobal(ctx); ok {
		results = append(results, r)
	}

	s.emitProgress("global: pnpm")
	s.log.Progress("  Checking pnpm global packages...")
	if r, ok := s.scanPnpmGlobal(ctx); ok {
		results = append(results, r)
	}

	return results
}

// pmRunError returns a self-explanatory error string for a failed package-
// manager run, or "" on success. When runErr is non-nil it carries the user
// shell's stderr (see executor.RunAsUser), so the message names the real cause
// — "command not found", an npm ELSPROBLEMS line — rather than a bare exit
// code. The previous static strings ("npm list -g command failed with exit
// code") discarded both the code and the reason, which is what made the
// production failures opaque in telemetry.
func pmRunError(label string, exitCode int, runErr error) string {
	switch {
	case runErr != nil:
		return fmt.Sprintf("%s exec failed: %v", label, runErr)
	case exitCode != 0:
		return fmt.Sprintf("%s exited with code %d", label, exitCode)
	}
	return ""
}

func (s *NodeScanner) scanNPMGlobal(ctx context.Context) (model.NodeScanResult, bool) {
	if err := s.checkPath(ctx, "npm"); err != nil {
		s.log.Debug("npm not found on PATH — skipping npm global scan: %v", err)
		return model.NodeScanResult{}, false
	}

	version := s.getVersion(ctx, "npm", "--version")
	prefix := s.getOutput(ctx, "npm", "config", "get", "prefix")
	if prefix == "" {
		s.log.Warn("npm found but `npm config get prefix` returned empty — skipping npm global scan")
		return model.NodeScanResult{}, false
	}

	start := time.Now()
	stdout, stderr, exitCode, runErr := s.runCmd(ctx, 60*time.Second, "npm", "list", "-g", "--json", "--depth=3")
	duration := time.Since(start).Milliseconds()

	errMsg := pmRunError("npm list -g", exitCode, runErr)
	if errMsg != "" {
		s.log.Warn("npm global scan failed (%dms): %s — results may be incomplete", duration, errMsg)
	}
	s.log.Debug("npm global scan: version=%s prefix=%s exit_code=%d stdout_bytes=%d duration=%dms", version, prefix, exitCode, len(stdout), duration)

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
		s.log.Debug("yarn not found on PATH — skipping yarn global scan: %v", err)
		return model.NodeScanResult{}, false
	}

	version := s.getVersion(ctx, "yarn", "--version")
	globalDir := s.getOutput(ctx, "yarn", "global", "dir")
	if globalDir == "" {
		s.log.Debug("yarn found but `yarn global dir` returned empty — skipping yarn global scan")
		return model.NodeScanResult{}, false
	}

	start := time.Now()
	// Run directly in the global dir instead of shell cd (avoids Windows quoting issues).
	stdout, stderr, exitCode, runErr := s.runInDir(ctx, globalDir, 60*time.Second, "yarn", "list", "--json", "--depth=0")
	duration := time.Since(start).Milliseconds()

	errMsg := pmRunError("yarn global list", exitCode, runErr)
	if errMsg != "" {
		s.log.Warn("yarn global scan failed (%dms): %s — results may be incomplete", duration, errMsg)
	}
	s.log.Debug("yarn global scan: version=%s global_dir=%s exit_code=%d stdout_bytes=%d duration=%dms", version, globalDir, exitCode, len(stdout), duration)

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
		s.log.Warn("pnpm not found on PATH — skipping pnpm global scan: %v", err)
		return model.NodeScanResult{}, false
	}

	pnpmCmd := "pnpm"

	versionOut, _, _, verErr := s.runCmd(ctx, 10*time.Second, pnpmCmd, "--version")
	version := strings.TrimSpace(versionOut)
	if verErr != nil || version == "" {
		version = "unknown"
	}

	rootOut, _, rootExit, _ := s.runCmd(ctx, 10*time.Second, pnpmCmd, "root", "-g")
	globalDir := strings.TrimSpace(rootOut)

	// fallback logic in case `pnpm root -g` returns empty
	var extra string
	if rootExit != 0 || globalDir == "" {
		extra = defaultPnpmBinDir(s.exec)
		if extra != "" {
			oldPath := os.Getenv("PATH")
			_ = os.Setenv("PATH", extra+string(os.PathListSeparator)+oldPath)
			defer os.Setenv("PATH", oldPath)

			// For the delegation path, embed `PATH='extra':$PATH` in the command name.
			// runCmd's delegation branch space-joins name+args into the shell command
			// string, so the env-prefix flows through to the user's shell intact.
			if s.shouldRunAsUser() {
				pnpmCmd = "PATH=" + platformShellQuote(s.exec, extra) + ":$PATH pnpm"
			}

			s.log.Debug("pnpm root -g returned empty; retrying with bin dir %q prepended to PATH", extra)
			rootOut, _, _, _ = s.runCmd(ctx, 10*time.Second, pnpmCmd, "root", "-g")
			globalDir = strings.TrimSpace(rootOut)
		}
	}

	if globalDir != "" {
		globalDir = filepath.Dir(globalDir)
	} else if extra != "" {
		// Both attempts failed; use the bin dir itself as last-resort
		// ProjectPath so we still produce a result rather than dropping the
		// scan entirely.
		s.log.Debug("pnpm root -g still empty after PATH workaround; using defaultPnpmBinDir=%q", extra)
		globalDir = extra
	} else {
		s.log.Warn("pnpm found but `pnpm root -g` returned empty and no fallback available — skipping pnpm global scan")
		return model.NodeScanResult{}, false
	}

	// Try with --depth=3 first for transitive coverage (works on pnpm v10).
	// Fall back to no --depth on non-zero exit — pnpm v11 hard-fails any
	// --depth>=1 on -g and pnpm itself recommends omitting --depth.
	start := time.Now()
	stdout, stderr, exitCode, err := s.runCmd(ctx, 60*time.Second, pnpmCmd, "list", "-g", "--json", "--depth=3")
	if exitCode != 0 {
		s.log.Debug("pnpm list -g --depth=3 failed (exit=%d) — retrying without --depth (v11 path)", exitCode)
		stdout, stderr, exitCode, err = s.runCmd(ctx, 60*time.Second, pnpmCmd, "list", "-g", "--json")
	}
	duration := time.Since(start).Milliseconds()

	errMsg := pmRunError("pnpm list -g", exitCode, err)
	if errMsg != "" {
		s.log.Warn("pnpm global scan failed (%dms): %s — results may be incomplete", duration, errMsg)
	}
	s.log.Debug("pnpm global scan: version=%s global_dir=%s exit_code=%d stdout_bytes=%d duration=%dms err=%v", version, globalDir, exitCode, len(stdout), duration, err)

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

// defaultPnpmBinDir returns the default pnpm global bin directory for the current OS
// based on environment variables.
func defaultPnpmBinDir(exec executor.Executor) string {
	switch exec.GOOS() {
	case model.PlatformDarwin:
		if home := exec.Getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "pnpm", "bin")
		}
	case model.PlatformLinux:
		if home := exec.Getenv("HOME"); home != "" {
			return filepath.Join(home, ".local", "share", "pnpm", "bin")
		}
	case model.PlatformWindows:
		if localAppData := exec.Getenv("LOCALAPPDATA"); localAppData != "" {
			return filepath.Join(localAppData, "pnpm", "bin")
		}
	}
	return ""
}

// projectEntry holds a discovered package.json with its modification time for sorting.
type projectEntry struct {
	dir     string
	modTime int64
}

// ScanProjects finds package.json files and scans them within the size cap.
//
// Ordering: never-before-seen projects (paths absent from knownLastVerified)
// come first, sorted by mtime descending. Already-known projects follow,
// sorted by their LastVerifiedAt ascending so the stalest are re-checked
// first. Pass a nil map for plain mtime-descending order.
//
// The second return is every project directory discovered on disk (before
// the cap), so callers can distinguish "missing from disk" from "dropped by
// the cap" when comparing against prior state.
func (s *NodeScanner) ScanProjects(ctx context.Context, searchDirs []string, knownLastVerified map[string]time.Time) (results []model.NodeScanResult, discovered []string) {
	var projects []projectEntry
	for _, dir := range searchDirs {
		s.log.Progress("  Searching in: %s", dir)
		_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				if s.skipper.ShouldSkip(path, dir) {
					return filepath.SkipDir
				}
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
			modTime := int64(0)
			if info, err := entry.Info(); err == nil {
				modTime = info.ModTime().Unix()
			}
			projects = append(projects, projectEntry{dir: projectDir, modTime: modTime})
			return nil
		})
	}

	s.log.Debug("node project discovery: found %d package.json files across %d search dir(s)", len(projects), len(searchDirs))

	discovered = make([]string, 0, len(projects))
	for _, p := range projects {
		discovered = append(discovered, p.dir)
	}

	projects = orderScanProjects(projects, knownLastVerified)

	if len(projects) > maxNodeProjects {
		s.log.Warn("Node project scan truncated at %d projects (total discovered: %d) — lowest-priority projects were skipped", maxNodeProjects, len(projects))
		projects = projects[:maxNodeProjects]
	}

	results = s.scanProjectsConcurrent(ctx, projects)

	maxBytes := getMaxProjectScanBytes()
	totalSize := int64(0)
	capped := make([]model.NodeScanResult, 0, len(results))
	for _, r := range results {
		resultSize := int64(len(r.RawStdoutBase64)) + int64(len(r.RawStderrBase64))
		if totalSize+resultSize > maxBytes {
			s.log.Warn("Reached data size limit (%d bytes collected, limit: %d bytes)", totalSize, maxBytes)
			s.log.Warn("Skipping remaining projects (prioritized by most recently modified)")
			break
		}
		totalSize += resultSize
		capped = append(capped, r)
	}

	return capped, discovered
}

// scanProjectsConcurrent returns one NodeScanResult per project in the input
// order. Cache hits skip the PM CLI entirely; cache misses run through a
// bounded worker pool. Successful fresh scans are written back to the cache.
// Projects whose PM isn't installed on the device produce no result (skipped
// in the returned slice to match the legacy contract).
func (s *NodeScanner) scanProjectsConcurrent(ctx context.Context, projects []projectEntry) []model.NodeScanResult {
	cachePath := scanCacheFile(s.exec)
	cache := loadScanCache(cachePath)
	bypassCache := s.exec.Getenv("STEPSEC_NODE_SCAN_CACHE_BYPASS") == "1"
	nowUnix := time.Now().Unix()

	type slot struct {
		result    model.NodeScanResult
		pm        string
		populated bool
		fromCache bool
	}
	slots := make([]slot, len(projects))
	missIdx := make([]int, 0, len(projects))

	for i, p := range projects {
		s.emitProgress(fmt.Sprintf("project %d of %d", i+1, len(projects)))
		pm := DetectProjectPM(s.exec, p.dir)
		slots[i].pm = pm

		entry, ok := cache.Projects[p.dir]
		if ok && cacheValidFor(s.exec, entry, p.dir, pm, s.agentVersion(), bypassCache) {
			s.log.Progress("  Cached: %s (%s)", p.dir, pm)
			slots[i].result = entry.CachedResult
			slots[i].populated = true
			slots[i].fromCache = true
			continue
		}
		missIdx = append(missIdx, i)
	}

	if len(missIdx) > 0 {
		jobs := make(chan int, len(missIdx))
		var wg sync.WaitGroup
		workers := scanWorkerCount(s.exec)
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range jobs {
					p := projects[idx]
					pm := slots[idx].pm
					s.log.Progress("  Scanning: %s (%s)", p.dir, pm)
					r, ok := s.scanProject(ctx, p.dir, pm)
					if !ok {
						continue
					}
					slots[idx].result = r
					slots[idx].populated = true
				}
			}()
		}
		for _, i := range missIdx {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
	}

	results := make([]model.NodeScanResult, 0, len(slots))
	for i, sl := range slots {
		if !sl.populated {
			continue
		}
		results = append(results, sl.result)
		if !sl.fromCache && sl.result.ExitCode == 0 {
			cache.Projects[projects[i].dir] = scanCacheEntry{
				PackageManager:   sl.pm,
				LastScanUnix:     nowUnix,
				PackageJSONMtime: mtimeOr0(s.exec, filepath.Join(projects[i].dir, "package.json")),
				LockfileMtime:    mtimeOr0(s.exec, lockfileFor(s.exec, projects[i].dir, sl.pm)),
				NodeModulesMtime: mtimeOr0(s.exec, filepath.Join(projects[i].dir, "node_modules")),
				AgentVersion:     s.agentVersion(),
				CachedResult:     sl.result,
			}
		}
	}

	pruneCacheToDiscovered(cache, projects)
	if err := cache.save(cachePath); err != nil {
		s.log.Debug("node-scan-cache: save failed (%v) — next run will re-scan everything", err)
	}

	s.log.Progress("  Scanned %d projects (%d cache hits)", len(missIdx), len(slots)-len(missIdx))
	return results
}

// pruneCacheToDiscovered drops cache entries for projects not present in the
// current discovery pass. Bounds the cache file at the device's current
// project set rather than growing unboundedly across runs.
func pruneCacheToDiscovered(cache *scanCache, projects []projectEntry) {
	keep := make(map[string]struct{}, len(projects))
	for _, p := range projects {
		keep[p.dir] = struct{}{}
	}
	for dir := range cache.Projects {
		if _, ok := keep[dir]; !ok {
			delete(cache.Projects, dir)
		}
	}
}

// agentVersion returns the running agent's version, used as a cache key
// guard so post-upgrade runs always re-scan.
func (s *NodeScanner) agentVersion() string {
	return buildinfo.Version
}

// orderScanProjects sorts discovered projects so that paths absent from
// knownLastVerified (never-seen projects) come first by mtime descending,
// then known paths by LastVerifiedAt ascending (stalest first). A nil map
// degrades to the legacy mtime-descending order.
func orderScanProjects(projects []projectEntry, knownLastVerified map[string]time.Time) []projectEntry {
	if len(knownLastVerified) == 0 {
		sort.Slice(projects, func(i, j int) bool {
			return projects[i].modTime > projects[j].modTime
		})
		return projects
	}

	unknown := make([]projectEntry, 0, len(projects))
	known := make([]projectEntry, 0, len(projects))
	for _, p := range projects {
		if _, ok := knownLastVerified[p.dir]; ok {
			known = append(known, p)
		} else {
			unknown = append(unknown, p)
		}
	}
	sort.Slice(unknown, func(i, j int) bool {
		return unknown[i].modTime > unknown[j].modTime
	})
	sort.Slice(known, func(i, j int) bool {
		return knownLastVerified[known[i].dir].Before(knownLastVerified[known[j].dir])
	})
	return append(unknown, known...)
}

// scanProject runs the project's detected package manager in the project
// directory and returns the raw stdout/stderr as a NodeScanResult. The
// second return is false when no record should be emitted — currently only
// the case when the PM binary isn't on PATH, which is a normal "Node not
// installed on this device" state, not a scan failure. Mirrors the
// (result, ok) shape of scanNPMGlobal / scanYarnGlobal / scanPnpmGlobal.
//
// pm is passed in by the caller (ScanProjects already detects it once for
// the per-project progress log); we accept it as an argument rather than
// re-running DetectProjectPM here to avoid duplicating the FileExists /
// DirExists checks per project and to keep the detected value consistent
// with what the caller logged.
func (s *NodeScanner) scanProject(ctx context.Context, projectDir, pm string) (model.NodeScanResult, bool) {
	var cmd string
	var args []string
	switch pm {
	case "npm":
		cmd, args = "npm", []string{"ls", "--json", "--depth=3"}
	case "yarn":
		cmd, args = "yarn", []string{"list", "--json"}
	case "yarn-berry":
		cmd, args = "yarn", []string{"info", "--all", "--json"}
	case "pnpm":
		cmd, args = "pnpm", []string{"ls", "--json", "--depth=3"}
	case "bun":
		cmd, args = "bun", []string{"pm", "ls", "--all"}
	default:
		// "unsupported package manager" is a genuine error state — the
		// lockfile detector matched something we don't have a scanner for.
		// Emit so the backend can surface it; this is distinct from the
		// "PM not installed" case handled below.
		return model.NodeScanResult{
			ProjectPath:    projectDir,
			PackageManager: pm,
			Error:          "unsupported package manager",
			ExitCode:       1,
		}, true
	}

	// "PM not installed on this device" is not a scan failure — it's a
	// normal configuration state (e.g. a Windows machine that hasn't
	// received the corporate Node.js deployment, scanning vendored
	// package.json files inside VS Code extensions). Without this guard
	// the per-project loop fell through to exec.CommandContext, hit ENOENT,
	// and shipped an empty-RawStdoutBase64 record per project to the
	// backend. The backend can't tell the difference between "agent
	// couldn't run npm" and "agent ran npm and got 0 packages", so devices
	// with hundreds of vendored package.json files dropped off the UI's
	// "Has npm_packages" view despite the backend running cleanly.
	//
	// Symmetric with scanNPMGlobal / scanYarnGlobal / scanPnpmGlobal which
	// already do this — global scans for missing PMs are dropped from
	// telemetry rather than emitted as zero-result records.
	if err := s.binaryAvailable(ctx, cmd); err != nil {
		return model.NodeScanResult{}, false
	}

	version := s.getVersion(ctx, cmd, "--version")

	start := time.Now()
	// Run the package manager command directly in the project directory.
	// Avoids shell cd + quoting issues on Windows where cmd.exe misinterprets
	// Go's backslash-escaped quotes in paths.
	stdout, stderr, exitCode, runErr := s.runInDir(ctx, projectDir, 30*time.Second, cmd, args...)
	duration := time.Since(start).Milliseconds()

	// Capture the real failure reason for the case where the PM IS
	// available but the run still fails (timeout, mid-run exec error,
	// non-zero exit). Previously runErr was discarded and errMsg was
	// derived from exitCode alone, making spawn failure mid-run,
	// context cancellation, and a genuine non-zero exit indistinguishable.
	// runErr carries the user shell's stderr (see executor.RunAsUser), so the
	// message names the real cause instead of a bare exit code.
	errMsg := pmRunError(cmd, exitCode, runErr)

	// Surface the failure in the agent log, not just the telemetry record.
	// A recurring failure (e.g. npm unreachable under the LaunchAgent's
	// stripped PATH) previously left both the log and — on the delegated
	// path, where stderr is unavailable — the telemetry stderr blank, so the
	// only signal was an opaque exit code.
	if errMsg != "" {
		s.log.Warn("node project scan failed: %s (project=%s, exit=%d)", errMsg, projectDir, exitCode)
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
	}, true
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
