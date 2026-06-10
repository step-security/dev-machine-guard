package rules

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
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
			if !cg.absolute {
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
				if e.evaluate(st, rstate, p, cg.raw) {
					st.globalStop = true
					return
				}
			}
		}
	}
}

// relMatcher binds one relative glob to its rule's accumulator.
type relMatcher struct {
	rstate *ruleState
	cg     compiledGlob
}

// walkRoots performs one TCC-aware walk per search root, matching each regular
// file against every relative glob. Symlinks are never followed (the walk does
// not descend into symlinked directories, and symlinked files are not regular,
// so they are skipped) — the symlink-escape guard. Sets st.globalStop if a
// global file/time budget is hit.
func (e *Engine) walkRoots(ctx context.Context, st *scanState, searchDirs []string) {
	var matchers []relMatcher
	for _, rstate := range st.states {
		for _, cg := range rstate.rule.globs {
			if !cg.absolute {
				matchers = append(matchers, relMatcher{rstate: rstate, cg: cg})
			}
		}
	}
	if len(matchers) == 0 {
		return
	}

	for _, root := range searchDirs {
		if root == "" {
			continue
		}
		if e.walkOneRoot(ctx, st, root, matchers) {
			st.globalStop = true
			return
		}
	}
}

// walkOneRoot walks a single root. Returns true if the whole scan should stop
// (global budget or context cancellation).
func (e *Engine) walkOneRoot(ctx context.Context, st *scanState, root string, matchers []relMatcher) (stopped bool) {
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry — skip, never fail the run
		}
		if ctx.Err() != nil {
			return errWalkStop
		}
		if d.IsDir() {
			if e.skipper.ShouldSkip(path, root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks/sockets/etc.
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		relSlashed := filepath.ToSlash(rel)
		for _, m := range matchers {
			if m.cg.re.MatchString(relSlashed) {
				if e.evaluate(st, m.rstate, path, m.cg.raw) {
					return errWalkStop
				}
			}
		}
		return nil
	})
	return errors.Is(err, errWalkStop)
}
