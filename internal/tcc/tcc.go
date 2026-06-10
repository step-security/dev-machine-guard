// Package tcc identifies macOS TCC (Transparency, Consent, and Control)
// protected directories so filesystem walks can skip them and avoid
// triggering system permission prompts on a user's machine.
//
// On non-darwin builds the Skipper is a no-op: ShouldSkip always returns
// false and Candidates returns nil, so callers can wire it unconditionally.
package tcc

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Enabled reports whether the TCC skipper should be active for this run.
// The override is the resolved tri-state cfg/config value: nil or false
// to apply the default (skip TCC-protected dirs), true to include them
// in the scan.
//
// Default behavior is to skip — both community (`scan`) and enterprise
// (`send-telemetry`) runs avoid TCC-protected paths so the agent never
// triggers permission prompts. Customers who have granted the agent
// access (via a PPPC profile pushed by their MDM, or by manually
// approving "Full Disk Access" in System Settings) flip the bool to
// `true` to opt those paths back into the scan. See
// docs/macos-tcc-permissions.md for the configuration recipe.
func Enabled(override *bool) bool {
	if override != nil && *override {
		// Explicit include: skipper OFF.
		return false
	}
	// Default and explicit exclude both leave the skipper ON.
	return true
}

// Skipper matches TCC-protected directories. Build one per scan via New;
// share across detectors. Hits are tracked so callers can prove from logs
// which protected paths were actually encountered during the walks.
type Skipper struct {
	paths    map[string]struct{}
	prefixes []string

	mu   sync.Mutex
	hits map[string]int
}

// New builds a Skipper anchored at home. home == "" produces a degraded
// Skipper that only matches absolute-prefix entries (e.g. Time Machine
// snapshot mounts) — useful when the agent runs without a console user.
func New(home string) *Skipper {
	return &Skipper{
		paths:    buildProtectedPaths(home),
		prefixes: protectedPrefixes(),
	}
}

// ShouldSkip reports whether path is a TCC-protected directory whose walk
// should be short-circuited. When path equals walkRoot the result is always
// false: passing --search-dirs ~/Documents is an explicit opt-in, and the
// walk root must be entered for anything to happen.
//
// Safe to call on a nil receiver (returns false), which is what callers
// pass when --include-tcc-protected is set.
func (s *Skipper) ShouldSkip(path, walkRoot string) bool {
	if s == nil {
		return false
	}
	cleaned := filepath.Clean(path)
	if filepath.Clean(walkRoot) == cleaned {
		return false
	}
	if _, ok := s.paths[cleaned]; ok {
		s.recordHit(cleaned)
		return true
	}
	for _, p := range s.prefixes {
		if hasPathPrefix(cleaned, p) {
			s.recordHit(cleaned)
			return true
		}
	}
	return false
}

// hasPathPrefix returns true when s starts with prefix AND the character
// immediately after is a path separator, a dot, or end-of-string. This
// keeps a sentinel like "/Volumes/.timemachine" from matching unrelated
// paths such as "/Volumes/.timemachine_backup", while still matching the
// real Time Machine mount form "/Volumes/.timemachine.donottouch.<uuid>".
func hasPathPrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	if len(s) == len(prefix) {
		return true
	}
	c := s[len(prefix)]
	return c == '/' || c == '.'
}

func (s *Skipper) recordHit(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hits == nil {
		s.hits = make(map[string]int)
	}
	s.hits[path]++
}

// Hits returns the set of TCC-protected paths that were encountered during
// walks, with the count of times each was matched. Returns nil if nothing
// was skipped (or on a nil receiver). Safe to call concurrently with
// ShouldSkip, though callers typically only read after walks complete.
func (s *Skipper) Hits() map[string]int {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hits) == 0 {
		return nil
	}
	out := make(map[string]int, len(s.hits))
	for k, v := range s.hits {
		out[k] = v
	}
	return out
}

// LogHits emits a single summary line listing the protected paths that
// were actually encountered during walks. Quiet when nothing was matched
// (or on a nil receiver). The emit callback decouples this from any
// specific logger — pass log.Warn (interactive) or log.Debug (daemon) to
// pick the level. Single source of truth for both community scan and
// enterprise telemetry.
func (s *Skipper) LogHits(emit func(format string, args ...any)) {
	if s == nil || emit == nil {
		return
	}
	hits := s.Hits()
	if len(hits) == 0 {
		return
	}
	paths := make([]string, 0, len(hits))
	for p := range hits {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	emit("macOS TCC: encountered and skipped %d protected path(s) during walks: %v", len(paths), paths)
}

// Candidates returns the exact-match protected paths the Skipper would
// skip, sorted lexicographically. Useful for surfacing in logs. Returns nil
// on a nil receiver or on non-darwin builds.
func (s *Skipper) Candidates() []string {
	if s == nil || len(s.paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.paths))
	for p := range s.paths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
