package safepath

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Reader provides guarded filesystem access across explicit caller-selected roots.
// It is opt-in; existing Resolver callers retain their original traversal behavior.
type Reader struct {
	roots []*Resolver
	guard Guard
}

// NewReader accepts scan roots chosen by the caller, never from inspected metadata.
func NewReader(roots []string, guard Guard) *Reader {
	r := &Reader{guard: guard}
	for _, root := range roots {
		if root != "" {
			r.roots = append(r.roots, New(root, guard))
		}
	}
	return r
}

func (r *Reader) contains(path string, allowAncestor bool) bool {
	for _, root := range r.roots {
		if root.Contains(path) {
			return true
		}
		if allowAncestor {
			for _, allowed := range root.containmentRoots() {
				if rel, err := filepath.Rel(path, allowed); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return true
				}
			}
		}
	}
	return false
}

func (r *Reader) Resolve(path string) (string, error) {
	resolved, _, err := r.resolveChain(path)
	return resolved, err
}

func (r *Reader) resolveChain(path string) (string, os.FileInfo, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", nil, refuse(ReasonUnresolved)
	}
	// Keep pending dot-dot components until preceding symlinks are resolved.
	current := filepath.FromSlash(path)

	for hop := 0; ; hop++ {
		if hop > maxHops {
			return "", nil, refuse(ReasonUnresolved)
		}
		if reason := r.refusedBy(current); reason != "" {
			return "", nil, refuse(reason)
		}

		volume, comps := splitPendingPath(current)
		if len(comps) > maxComponents {
			return "", nil, refuse(ReasonUnresolved)
		}

		prefix := volume + string(filepath.Separator)
		redirected := false
		var leaf os.FileInfo
		for i, comp := range comps {
			if leaf != nil && !leaf.IsDir() {
				return "", nil, refuse(ReasonUnresolved)
			}
			prefix = filepath.Join(prefix, comp)
			// Traversal may visit ancestors only to reach an explicitly allowed root.
			if !r.contains(prefix, true) {
				return "", nil, refuse(ReasonOutsideRoots)
			}
			if reason := r.refusedBy(prefix); reason != "" {
				return "", nil, refuse(reason)
			}
			info, err := os.Lstat(prefix)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return "", nil, err
				}
				return "", nil, refuse(ReasonDenied)
			}
			if !isLink(info) {
				leaf = info
				continue
			}
			target, err := os.Readlink(prefix)
			if err != nil {
				return "", nil, refuse(ReasonUnresolved)
			}
			if target == "" {
				return "", nil, refuse(ReasonUnresolved)
			}
			if !filepath.IsAbs(target) {
				target = filepath.Dir(prefix) + string(filepath.Separator) + target
			}
			target = filepath.FromSlash(target)
			if reason := r.refusedBy(target); reason != "" {
				return "", nil, refuse(reason)
			}
			current = target
			if i+1 < len(comps) {
				current += string(filepath.Separator) + strings.Join(comps[i+1:], string(filepath.Separator))
			}
			if !r.contains(current, false) {
				return "", nil, refuse(ReasonOutsideRoots)
			}
			redirected = true
			break
		}
		if redirected {
			continue
		}
		if !r.contains(prefix, false) {
			return "", nil, refuse(ReasonOutsideRoots)
		}
		return prefix, leaf, nil
	}
}

func (r *Reader) refusedBy(path string) string {
	if r.guard == nil {
		return ""
	}
	return r.guard(path)
}

func (r *Reader) Stat(path string) (os.FileInfo, error) {
	_, info, err := r.resolveChain(path)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, refuse(ReasonUnresolved)
	}
	return info, nil
}

// ReadFile refuses nonregular or oversized files without returning partial contents.
func (r *Reader) ReadFile(path string, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, refuse(ReasonDenied)
	}
	resolved, err := r.Resolve(path)
	if err != nil {
		return nil, err
	}
	f, info, err := openVerified(resolved, false, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, refuse(ReasonDenied)
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, refuse(ReasonDenied)
	}
	// Detect growth past the cap without max+1 overflowing.
	var extra [1]byte
	n, err := f.Read(extra[:])
	if n != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return nil, refuse(ReasonDenied)
	}
	return data, nil
}

func (r *Reader) ReadDir(path string) ([]os.DirEntry, error) {
	resolved, err := r.Resolve(path)
	if err != nil {
		return nil, err
	}
	f, _, err := openVerified(resolved, true, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, refuse(ReasonDenied)
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

func splitPendingPath(path string) (volume string, comps []string) {
	volume = filepath.VolumeName(path)
	rest := strings.TrimPrefix(path[len(volume):], string(filepath.Separator))
	if rest == "" {
		return volume, nil
	}
	for c := range strings.SplitSeq(rest, string(filepath.Separator)) {
		if c == "" {
			continue
		}
		comps = append(comps, c)
	}
	return volume, comps
}
