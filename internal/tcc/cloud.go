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
	path, err := filepath.Abs(path)
	if err != nil {
		return true
	}
	// Inspect each entry from its already-checked parent. Looking up a deep
	// path directly would let Windows follow an intermediate link or recall
	// a placeholder directory before we had checked it.
	const maxLinks = 32
resolve:
	for hops := 0; hops <= maxLinks; hops++ {
		if s.cloud.excludes(path) {
			return true
		}
		volume := filepath.VolumeName(path)
		prefix := volume + string(filepath.Separator)
		remaining := strings.TrimPrefix(path[len(volume):], string(filepath.Separator))
		for remaining != "" {
			part, rest, _ := strings.Cut(remaining, string(filepath.Separator))
			prefix = filepath.Join(prefix, part)
			placeholder, link, err := cloudEntry(prefix)
			if err != nil {
				// A missing entry cannot be hydrated. For other failures we
				// could not establish that the caller can safely follow it.
				return !os.IsNotExist(err)
			}
			if placeholder {
				return true
			}
			remaining = rest
			if link {
				target, err := os.Readlink(prefix)
				if err != nil || target == "" {
					return true
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(prefix), target)
				}
				path = filepath.Join(target, rest)
				continue resolve
			}
		}
		return false
	}
	return true // Too many redirects or a link cycle.
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
