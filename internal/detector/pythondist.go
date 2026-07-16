// Disk-based Python package discovery.
//
// PythonDistDetector inventories installed Python packages by reading their
// on-disk install metadata — *.dist-info/METADATA (PEP 566) and the legacy
// *.egg-info/PKG-INFO — instead of running `pip list`. This is the same set
// pip itself reports, since pip derives its listing from these dirs.
//
// Read-only: no pip/uv/conda subprocess. Per-file size is capped so a
// package shipping a giant METADATA description payload cannot blow up memory.
package detector

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// maxMetadataFileSize bounds a single METADATA / PKG-INFO read. We only need
// the RFC-822 header block (Name/Version, in the first few KB), but the whole
// file is read through the executor before parsing, so this cap only guards
// against pathological files. It was 1 MiB, which silently dropped installed
// packages whose METADATA embeds a large README/changelog in its description;
// raised to 32 MiB so realistic packages are never dropped while still
// bounding memory. (A future refinement is to stream only the header.)
const maxMetadataFileSize = 32 << 20 // 32 MiB

// PythonDistDetector discovers installed Python packages from install
// metadata on disk, with no package-manager subprocess.
type PythonDistDetector struct {
	exec        executor.Executor
	log         *progress.Logger
	skipper     *tcc.Skipper
	maxFileSize int64
}

func NewPythonDistDetector(exec executor.Executor) *PythonDistDetector {
	return &PythonDistDetector{exec: exec, log: progress.NewNoop(), maxFileSize: maxMetadataFileSize}
}

// WithSkipper attaches a TCC skipper so the walk skips macOS-protected
// directories. A nil skipper is a no-op. Returns the detector for chaining.
func (d *PythonDistDetector) WithSkipper(s *tcc.Skipper) *PythonDistDetector {
	d.skipper = s
	return d
}

// WithLogger attaches a progress logger. A nil logger falls back to the
// no-op default. Returns the detector for chaining.
func (d *PythonDistDetector) WithLogger(log *progress.Logger) *PythonDistDetector {
	if log != nil {
		d.log = log
	}
	return d
}

// ScanVenv returns the packages installed in a single virtual environment by
// reading the dist-info/egg-info metadata under it (typically
// lib/python*/site-packages or Lib/site-packages). Replaces the per-venv
// `pip list` call.
func (d *PythonDistDetector) ScanVenv(venvPath string) []model.PackageDetail {
	return d.ScanRoots(venvSitePackages(venvPath))
}

// venvSitePackages returns the site-packages directories inside a venv —
// lib/python*/site-packages (POSIX) and Lib/site-packages (Windows). Scanning
// only these avoids walking bin/include/share, which never hold install
// metadata. Falls back to the venv root if no site-packages dir is found, so
// a non-standard layout is still scanned.
func venvSitePackages(venvPath string) []string {
	var roots []string
	for _, pattern := range []string{
		filepath.Join(venvPath, "lib", "python*", "site-packages"),
		filepath.Join(venvPath, "Lib", "site-packages"),
	} {
		if matches, err := filepath.Glob(pattern); err == nil {
			roots = append(roots, matches...)
		}
	}
	if len(roots) == 0 {
		return []string{venvPath}
	}
	return roots
}

// ScanRoots walks each root and returns every distinct package discovered via
// install metadata. Packages are de-duplicated by (lowercased name, version)
// so the same install surfaced once is reported once, and the result is
// sorted by name then version for stable output.
func (d *PythonDistDetector) ScanRoots(roots []string) []model.PackageDetail {
	seen := make(map[string]struct{})
	var pkgs []model.PackageDetail

	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				if d.skipper.ShouldSkip(path, root) {
					return filepath.SkipDir
				}
				if shouldSkipMetadataDir(entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}

			name, version, ok := d.parseMetadataFile(path, entry.Name())
			if !ok {
				return nil
			}
			key := strings.ToLower(name) + "\x00" + version
			if _, dup := seen[key]; dup {
				return nil
			}
			seen[key] = struct{}{}
			pkgs = append(pkgs, model.PackageDetail{Name: name, Version: version})
			return nil
		})
	}

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})
	return pkgs
}

// ScanGlobalPackages walks the host's global / user site-packages roots and
// returns the installed packages, replacing the `pip3 list` global scan.
func (d *PythonDistDetector) ScanGlobalPackages() []model.PythonPackage {
	details := d.ScanRoots(GlobalPythonRoots(d.exec, d.log))
	out := make([]model.PythonPackage, len(details))
	for i, p := range details {
		out[i] = model.PythonPackage(p)
	}
	return out
}

// parseMetadataFile returns the package name and version if path is a
// recognised metadata file (*.dist-info/METADATA or *.egg-info/PKG-INFO).
func (d *PythonDistDetector) parseMetadataFile(path, base string) (name, version string, ok bool) {
	switch base {
	case "METADATA":
		if !isDistInfoMetadata(path) {
			return "", "", false
		}
	case "PKG-INFO":
		if !isEggInfoPKGInfo(path) {
			return "", "", false
		}
	default:
		return "", "", false
	}

	data, err := d.readBounded(path)
	if err != nil {
		return "", "", false
	}
	name, version = parseRFC822NameVersion(data)
	if name == "" || version == "" {
		d.log.Debug("python dist scan: %s missing Name/Version header — skipping", path)
		return "", "", false
	}
	return name, version, true
}

// readBounded reads path through the executor and rejects files over the size
// cap. The metadata header we parse is tiny; the cap only guards memory. The
// size is checked via Stat *before* reading so a pathological file is never
// pulled into memory, with the post-read length check kept as a race-safety
// fallback (the file can grow between Stat and ReadFile).
func (d *PythonDistDetector) readBounded(path string) ([]byte, error) {
	if d.maxFileSize > 0 {
		if info, err := d.exec.Stat(path); err == nil && info.Size() > d.maxFileSize {
			d.log.Debug("python dist scan: %s exceeds %d bytes — skipping", path, d.maxFileSize)
			return nil, fmt.Errorf("file %s exceeds max size %d", path, d.maxFileSize)
		}
	}
	data, err := d.exec.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if d.maxFileSize > 0 && int64(len(data)) > d.maxFileSize {
		d.log.Debug("python dist scan: %s exceeds %d bytes — skipping", path, d.maxFileSize)
		return nil, fmt.Errorf("file %s exceeds max size %d", path, d.maxFileSize)
	}
	return data, nil
}

// isDistInfoMetadata reports whether path is METADATA inside a *.dist-info dir.
func isDistInfoMetadata(path string) bool {
	return filepath.Base(path) == "METADATA" && strings.HasSuffix(filepath.Dir(path), ".dist-info")
}

// isEggInfoPKGInfo reports whether path is PKG-INFO inside a *.egg-info dir.
func isEggInfoPKGInfo(path string) bool {
	return filepath.Base(path) == "PKG-INFO" && strings.HasSuffix(filepath.Dir(path), ".egg-info")
}

// shouldSkipMetadataDir lists directories that never hold install metadata and
// are costly to descend. Unlike the venv-discovery skip list this does NOT
// skip site-packages or dotted dirs — installed packages live under both.
func shouldSkipMetadataDir(name string) bool {
	switch name {
	case "node_modules", ".git", ".hg", ".svn", ".cache",
		"__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache":
		return true
	}
	return false
}

// parseRFC822NameVersion reads only the RFC-822 header block of a METADATA /
// PKG-INFO file, stopping at the first blank line so the (potentially large)
// description payload is never scanned.
func parseRFC822NameVersion(data []byte) (name, version string) {
	br := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := br.ReadString('\n')
		trim := strings.TrimRight(line, "\r\n")
		if trim == "" {
			break
		}
		// Continuation lines start with whitespace; we only care about
		// Name/Version, which are single-line in practice.
		if trim[0] == ' ' || trim[0] == '\t' {
			if err == io.EOF {
				break
			}
			continue
		}
		if idx := strings.IndexByte(trim, ':'); idx > 0 {
			key := strings.TrimSpace(trim[:idx])
			val := strings.TrimSpace(trim[idx+1:])
			switch strings.ToLower(key) {
			case "name":
				if name == "" {
					name = val
				}
			case "version":
				if version == "" {
					version = val
				}
			}
		}
		if name != "" && version != "" {
			break
		}
		if err != nil {
			break
		}
	}
	return name, version
}

// PythonGlobalRoots returns the global / user site-packages locations worth
// scanning for system-wide Python packages, keeping only those present on
// this host. These are the install roots the old `pip3 list` global scan
// reported from, plus user-site and version-manager locations the
// command-based scan tended to miss.
func PythonGlobalRoots(exec executor.Executor) []string {
	var candidates []string
	add := func(paths ...string) { candidates = append(candidates, paths...) }
	addGlob := func(pattern string) {
		if matches, err := filepath.Glob(pattern); err == nil {
			add(matches...)
		}
	}

	// Anchor per-user paths on the console (GUI) user, not the process user:
	// the enterprise agent runs as root via launchd, where os.UserHomeDir
	// resolves to /var/root and would miss the logged-in user's ~/.local,
	// ~/.pyenv, pipx venvs, etc. (issue #63). Fall back to os.UserHomeDir.
	home := executor.ResolveHome(exec)
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	if home != "" {
		addGlob(filepath.Join(home, ".local", "lib", "python*", "site-packages"))
		add(filepath.Join(home, ".local", "share", "pipx", "venvs"))
		addGlob(filepath.Join(home, ".pyenv", "versions", "*", "lib", "python*", "site-packages"))
	}

	switch runtime.GOOS {
	case "darwin":
		addGlob("/opt/homebrew/lib/python*/site-packages")
		addGlob("/usr/local/lib/python*/site-packages")
		addGlob("/Library/Frameworks/Python.framework/Versions/*/lib/python*/site-packages")
		if home != "" {
			addGlob(filepath.Join(home, "Library", "Python", "*", "lib", "python", "site-packages"))
		}
	case "linux":
		addGlob("/usr/lib/python*/dist-packages")
		addGlob("/usr/lib/python*/site-packages")
		addGlob("/usr/lib/python3/dist-packages")
		addGlob("/usr/local/lib/python*/dist-packages")
		addGlob("/usr/local/lib/python*/site-packages")
	}

	// Keep only existing directories; absent candidates are normal.
	seen := make(map[string]struct{}, len(candidates))
	roots := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		if exec.FileExists(c) || isDir(c) {
			roots = append(roots, c)
		}
	}
	return roots
}

// isDir reports whether path is an existing directory. exec.FileExists rejects
// directories, so global roots (which are dirs) are confirmed here.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
