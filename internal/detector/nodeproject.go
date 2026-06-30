package detector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

const maxNodeProjects = 1000

// NodeProjectDetector scans for Node.js projects.
type NodeProjectDetector struct {
	exec    executor.Executor
	skipper *tcc.Skipper
	// dist, when non-nil, makes per-project package listing read resolved
	// versions from on-disk lockfiles instead of the declared ranges in
	// package.json. Attached by the caller based on config.UseLegacyNodeScan.
	dist *NodeDistDetector
}

func NewNodeProjectDetector(exec executor.Executor) *NodeProjectDetector {
	return &NodeProjectDetector{exec: exec}
}

// WithSkipper attaches a TCC skipper so the walk skips macOS-protected
// directories. A nil skipper is a no-op. Returns the detector for chaining.
func (d *NodeProjectDetector) WithSkipper(s *tcc.Skipper) *NodeProjectDetector {
	d.skipper = s
	return d
}

// WithDiskScan switches per-project package listing to disk parsing (resolved
// name@version from the lockfile / node_modules) via the supplied detector. A
// nil detector leaves the legacy package.json-range path in place. Returns the
// detector for chaining.
func (d *NodeProjectDetector) WithDiskScan(dist *NodeDistDetector) *NodeProjectDetector {
	d.dist = dist
	return d
}

// CountProjects counts the number of Node.js projects found under the given directories.
func (d *NodeProjectDetector) CountProjects(_ context.Context, searchDirs []string) int {
	return len(d.ListProjects(searchDirs))
}

// ListProjects returns Node.js project paths with their detected package manager
// and the dependencies listed in package.json.
func (d *NodeProjectDetector) ListProjects(searchDirs []string) []model.ProjectInfo {
	var projects []model.ProjectInfo
	for _, dir := range searchDirs {
		projects = append(projects, d.listInDir(dir)...)
		if len(projects) >= maxNodeProjects {
			return projects[:maxNodeProjects]
		}
	}
	return projects
}

func (d *NodeProjectDetector) listInDir(dir string) []model.ProjectInfo {
	var projects []model.ProjectInfo
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if d.skipper.ShouldSkip(path, dir) {
				return filepath.SkipDir
			}
			name := entry.Name()
			if name == "node_modules" || name == ".git" || name == ".cache" ||
				strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == "package.json" {
			projectDir := filepath.Dir(path)
			pm := DetectProjectPM(d.exec, projectDir)
			// Only include projects with node_modules installed.
			// yarn-berry can use PnP (no node_modules), so check for .pnp.cjs instead.
			hasNodeModules := d.exec.DirExists(filepath.Join(projectDir, "node_modules"))
			isYarnBerryPnP := pm == "yarn-berry" && d.exec.FileExists(filepath.Join(projectDir, ".pnp.cjs"))
			if !hasNodeModules && !isYarnBerryPnP {
				return nil
			}
			pkgs := d.projectPackages(projectDir, pm, path)
			projects = append(projects, model.ProjectInfo{
				Path:           projectDir,
				PackageManager: pm,
				Packages:       pkgs,
			})
			if len(projects) >= maxNodeProjects {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return projects
}

// projectPackages returns a project's packages, preferring disk parsing
// (resolved name@version, full transitive set) when a dist detector is
// attached, and falling back to the package.json declared ranges otherwise.
// is_direct is not carried in the community ProjectInfo shape, so it is dropped
// here; it survives in the enterprise path.
func (d *NodeProjectDetector) projectPackages(projectDir, pm, packageJSONPath string) []model.PackageDetail {
	if d.dist != nil {
		return nodePackagesToDetails(d.dist.ScanProject(projectDir, pm))
	}
	return d.readPackageJSONDeps(packageJSONPath)
}

// nodePackagesToDetails projects the disk-parse result down to the community
// {name, version} shape.
func nodePackagesToDetails(pkgs []model.NodePackage) []model.PackageDetail {
	if len(pkgs) == 0 {
		return nil
	}
	out := make([]model.PackageDetail, len(pkgs))
	for i, p := range pkgs {
		out[i] = model.PackageDetail{Name: p.Name, Version: p.Version}
	}
	return out
}

// readPackageJSONDeps reads dependencies + devDependencies from a package.json file.
func (d *NodeProjectDetector) readPackageJSONDeps(packageJSONPath string) []model.PackageDetail {
	data, err := d.exec.ReadFile(packageJSONPath)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	total := len(pkg.Dependencies) + len(pkg.DevDependencies)
	if total == 0 {
		return nil
	}
	pkgs := make([]model.PackageDetail, 0, total)
	for name, version := range pkg.Dependencies {
		pkgs = append(pkgs, model.PackageDetail{Name: name, Version: version})
	}
	for name, version := range pkg.DevDependencies {
		pkgs = append(pkgs, model.PackageDetail{Name: name, Version: version})
	}
	return pkgs
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
		if exec.FileExists(filepath.Join(projectDir, ".yarnrc.yml")) || exec.DirExists(filepath.Join(projectDir, ".yarn", "releases")) {
			return "yarn-berry"
		}
		return "yarn"
	}
	if exec.FileExists(filepath.Join(projectDir, "package-lock.json")) {
		return "npm"
	}
	return "npm"
}
