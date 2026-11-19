package tcc

import (
	"os"
	"path/filepath"
	"strings"
)

// All paths are folded and cleaned once at configuration time or once per query.
// Matching is lexical so probing a sync root never lists it.
type cloudRoots struct {
	home     string
	envRoots []string
	explicit []string
}

func newCloudRoots(home string, searchDirs []string) *cloudRoots {
	c := &cloudRoots{}
	if filepath.IsAbs(home) {
		c.home = strings.ToLower(filepath.Clean(home))
	}
	for _, key := range []string{"OneDrive", "OneDriveCommercial", "OneDriveConsumer"} {
		if p := os.Getenv(key); filepath.IsAbs(p) {
			c.envRoots = append(c.envRoots, strings.ToLower(filepath.Clean(p)))
		}
	}
	for _, dir := range searchDirs {
		if dir == "" {
			continue
		}
		p, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		p = strings.ToLower(p)
		if c.contains(p) {
			c.explicit = append(c.explicit, p)
		}
	}
	return c
}

func (c *cloudRoots) contains(path string) bool {
	for _, root := range c.envRoots {
		if hasDirPrefix(path, root) {
			return true
		}
	}
	if c.home == "" || !hasDirPrefix(path, c.home) {
		return false
	}
	rel := strings.TrimLeft(path[len(c.home):], string(filepath.Separator))
	first, _, _ := strings.Cut(rel, string(filepath.Separator))
	return first == "onedrive" || strings.HasPrefix(first, "onedrive - ") && len(first) > len("onedrive - ")
}

// SkipCloudPath checks a directly selected file or directory before scan I/O.
// An explicitly selected sync root permits local content, including its children.
func (s *Skipper) SkipCloudPath(path string) bool {
	if s == nil || s.cloud == nil {
		return false
	}
	return s.cloud.excludes(path) || CloudPlaceholder(path)
}

func (c *cloudRoots) excludes(path string) bool {
	if c == nil {
		return false
	}
	if !filepath.IsAbs(path) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return false
		}
		path = absolute
	}
	p := strings.ToLower(filepath.Clean(path))
	if !c.contains(p) {
		return false
	}
	for _, root := range c.explicit {
		// Component-wise readers also need the ancestors of an approved subtree.
		if hasDirPrefix(p, root) || hasDirPrefix(root, p) {
			return false
		}
	}
	return true
}
