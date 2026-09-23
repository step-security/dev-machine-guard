package executor

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// guardedGlobFS lets the standard glob implementation enumerate through the
// same reader as direct accesses. Filtering matches after Glob is too late.
type guardedGlobFS struct {
	exec Executor
	root string
	err  error
}

func (g *guardedGlobFS) Open(string) (fs.File, error) { return nil, fs.ErrInvalid }

func (g *guardedGlobFS) Stat(name string) (fs.FileInfo, error) {
	info, err := g.exec.Stat(filepath.Join(g.root, filepath.FromSlash(name)))
	g.record(err)
	return info, err
}

func (g *guardedGlobFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := g.exec.ReadDir(filepath.Join(g.root, filepath.FromSlash(name)))
	g.record(err)
	return entries, err
}

func (g *guardedGlobFS) record(err error) {
	// fs.Glob ignores directory errors. Preserve refusals for callers so a
	// denied inventory cannot become a successful empty inventory.
	if err != nil && !os.IsNotExist(err) && g.err == nil {
		g.err = err
	}
}

func (g *guardedFiles) Glob(pattern string) ([]string, error) {
	abs, err := filepath.Abs(pattern)
	if err != nil {
		return nil, err
	}
	root := filepath.VolumeName(abs) + string(filepath.Separator)
	reader := &guardedGlobFS{exec: g, root: root}
	matches, err := fs.Glob(reader, filepath.ToSlash(strings.TrimPrefix(abs, root)))
	if err != nil {
		return nil, err
	}
	for i, match := range matches {
		matches[i] = filepath.Join(root, filepath.FromSlash(match))
		if !filepath.IsAbs(pattern) {
			cwd, err := os.Getwd()
			if err != nil {
				return nil, err
			}
			matches[i], err = filepath.Rel(cwd, matches[i])
			if err != nil {
				return nil, err
			}
		}
	}
	return matches, reader.err
}

func (g *guardedFiles) WalkDir(root string, fn fs.WalkDirFunc) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return fn(root, nil, err)
	}
	reader := &guardedGlobFS{exec: g, root: abs}
	return fs.WalkDir(reader, ".", func(name string, entry fs.DirEntry, err error) error {
		return fn(filepath.Join(root, filepath.FromSlash(name)), entry, err)
	})
}
