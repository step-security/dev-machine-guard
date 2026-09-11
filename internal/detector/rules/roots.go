package rules

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// errWalkStop unwinds filepath.WalkDir when a global budget is hit or the
// context is cancelled.
var errWalkStop = errors.New("rules: walk stopped")

// resolveAbsolute handles rules' absolute globs by resolving each to concrete
// paths via the executor's Glob (filepath.Glob semantics — no "**"), then
// evaluating each. Sets st.globalStop if a global file budget is exhausted.
func (e *Engine) resolveAbsolute(ctx context.Context, st *scanState) {
	for _, rstate := range st.states {
		for _, cg := range rstate.rule.globs {
			if !cg.absolute || rstate.truncated {
				continue
			}
			if ctx.Err() != nil {
				st.globalStop = true
				return
			}
			paths, err := e.exec.Glob(filepath.FromSlash(cg.raw))
			if err != nil {
				continue
			}
			for _, p := range paths {
				if rstate.truncated {
					break
				}
				if ctx.Err() != nil {
					st.globalStop = true
					return
				}
				if e.evaluate(st, rstate, p, cg.raw) {
					st.globalStop = true
					return
				}
			}
		}
	}
}

// relMatcher binds one relative glob to its rule's accumulator. Order preserves
// first-matching-glob and global-budget behavior when merging the two indexes.
type relMatcher struct {
	rstate *ruleState
	cg     compiledGlob
	order  int
}

type relativeIndex struct {
	byName       map[string][]relMatcher
	wildcards    []relMatcher
	prefixes     map[string][]*ruleState
	unrestricted []*ruleState
	activeRules  int
}

func newRelativeIndex(states []*ruleState) *relativeIndex {
	idx := &relativeIndex{byName: make(map[string][]relMatcher), prefixes: make(map[string][]*ruleState)}
	order := 0
	for _, state := range states {
		if state.truncated {
			continue
		}
		active := false
		for _, cg := range state.rule.globs {
			if cg.absolute {
				continue
			}
			active = true
			m := relMatcher{rstate: state, cg: cg, order: order}
			order++
			name := path.Base(cg.raw)
			if strings.ContainsAny(name, "*?") {
				idx.wildcards = append(idx.wildcards, m)
			} else {
				idx.byName[name] = append(idx.byName[name], m)
			}
			prefix := globDirectoryPrefix(cg.raw)
			if prefix == "" {
				idx.unrestricted = append(idx.unrestricted, state)
			} else {
				idx.prefixes[prefix] = append(idx.prefixes[prefix], state)
			}
		}
		if active {
			idx.activeRules++
		}
	}
	return idx
}

// globDirectoryPrefix returns only literal directory segments before the first
// wildcard. A leading ** leaves the walk unrestricted, including hidden dirs.
func globDirectoryPrefix(glob string) string {
	parts := strings.Split(glob, "/")
	for i, part := range parts[:len(parts)-1] {
		if strings.ContainsAny(part, "*?") {
			return strings.Join(parts[:i], "/")
		}
	}
	return strings.Join(parts[:len(parts)-1], "/")
}

func activeRule(states []*ruleState) bool {
	for _, state := range states {
		if !state.truncated {
			return true
		}
	}
	return false
}

// canDescend only rejects directories proven disjoint from all active globs.
// The candidate walk preserves lexical order, TCC checks, and refusal to
// follow symlinked directories.
func (idx *relativeIndex) canDescend(rel string) bool {
	if activeRule(idx.unrestricted) {
		return true
	}
	for prefix, states := range idx.prefixes {
		if (rel == prefix || strings.HasPrefix(prefix, rel+"/") || strings.HasPrefix(rel, prefix+"/")) && activeRule(states) {
			return true
		}
	}
	return false
}

// walkRoots performs one TCC-aware walk per root. Fixed filenames remain indexed
// even when the bundle also contains wildcard filenames.
func (e *Engine) walkRoots(ctx context.Context, st *scanState, searchDirs []string) {
	idx := newRelativeIndex(st.states)
	for _, root := range searchDirs {
		if idx.activeRules == 0 {
			return
		}
		if root == "" {
			continue
		}
		if e.walkOneRoot(ctx, st, root, idx) {
			st.globalStop = true
			return
		}
	}
}

// walkOneRoot returns true only for a global budget stop; exhausting active
// rules ends the walk without marking unrelated rules incomplete.
func (e *Engine) walkOneRoot(ctx context.Context, st *scanState, root string, idx *relativeIndex) bool {
	cleanRoot := filepath.Clean(root)
	err := e.walkCandidates(ctx, root, idx, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if idx.activeRules == 0 {
			return filepath.SkipAll
		}
		if ctx.Err() != nil {
			return errWalkStop
		}
		if d.IsDir() {
			if e.skipper.ShouldSkip(filePath, root) {
				return filepath.SkipDir
			}
			if filePath != cleanRoot && !activeRule(idx.unrestricted) {
				rel, err := filepath.Rel(root, filePath)
				if err == nil && !idx.canDescend(filepath.ToSlash(rel)) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		exact, wild := idx.byName[d.Name()], idx.wildcards
		if len(exact) == 0 && len(wild) == 0 {
			return nil
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		for len(exact) > 0 || len(wild) > 0 {
			var m relMatcher
			if len(wild) == 0 || (len(exact) > 0 && exact[0].order < wild[0].order) {
				m, exact = exact[0], exact[1:]
			} else {
				m, wild = wild[0], wild[1:]
			}
			if m.rstate.truncated {
				continue
			}
			if ctx.Err() != nil {
				return errWalkStop
			}
			if !m.cg.re.MatchString(rel) {
				continue
			}
			if e.evaluate(st, m.rstate, filePath, m.cg.raw) {
				return errWalkStop
			}
			if m.rstate.truncated {
				idx.activeRules--
			}
		}
		return nil
	})
	return errors.Is(err, errWalkStop)
}

// walkCandidates preserves WalkDir's lexical depth-first order and symlink
// behavior, but only constructs paths for directories and candidate filenames.
// ReadDir is sorted by the executor; unrelated files need no path allocation.
func (e *Engine) walkCandidates(ctx context.Context, root string, idx *relativeIndex, visit fs.WalkDirFunc) error {
	if _, err := e.exec.Readlink(root); err == nil {
		return nil
	}
	info, err := e.exec.Stat(root)
	if err != nil {
		return nil
	}
	var walk func(string, fs.DirEntry) error
	walk = func(name string, entry fs.DirEntry) error {
		if err := visit(name, entry, nil); err != nil {
			if err == fs.SkipDir && entry.IsDir() {
				return nil
			}
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		// As with WalkDir, keep any entries returned before a read error.
		entries, _ := e.exec.ReadDir(name)
		for _, child := range entries {
			if idx.activeRules == 0 {
				return fs.SkipAll
			}
			if ctx.Err() != nil {
				return errWalkStop
			}
			if !child.IsDir() && (!child.Type().IsRegular() || (len(idx.wildcards) == 0 && len(idx.byName[child.Name()]) == 0)) {
				continue
			}
			if err := walk(filepath.Join(name, child.Name()), child); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, fs.FileInfoToDirEntry(info))
}
