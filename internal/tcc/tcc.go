// Package tcc identifies macOS TCC (Transparency, Consent, and Control)
// protected locations so filesystem walks can skip them and avoid
// triggering system permission prompts on a user's machine.
//
// Two independent skip classes, each with its own toggle and its own
// default, because the prompt/coverage trade-off differs between them:
//
//   - Protected directories (~/Documents, ~/Library, …), gated by Enabled.
//     Skipped by default — nothing developers care about lives there.
//   - Network volumes (non-local mounts, which is how macOS classifies
//     OrbStack/Docker/Colima container mounts), gated by
//     SkipNetworkVolumes. Walked by default — that walk is the only thing
//     that inventories packages inside dev containers.
//
// ForRun resolves both toggles and builds the one Skipper the scan uses.
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

// SkipNetworkVolumes reports whether the network-volume skip class should
// be active for this run. The override is the resolved tri-state
// cfg/config value: nil or true to apply the default (walk them), false to
// skip them.
//
// The polarity is the mirror image of Enabled, deliberately. Container
// runtimes expose their filesystems over virtiofs and friends, which macOS
// classifies as Network Volumes, so the first walk into an OrbStack /
// Docker / Colima mount fires a kTCCServiceSystemPolicyNetworkVolumes
// prompt. Skipping by default would suppress the prompt but also drop the
// package inventory inside dev containers — supply-chain surface nothing
// else covers — so the default keeps the coverage and admins who can't
// pre-approve the prompt via PPPC opt out per fleet with
// include_network_volumes: false. See docs/macos-tcc-permissions.md.
func SkipNetworkVolumes(override *bool) bool {
	return override != nil && !*override
}

// Skipper matches TCC-protected locations. Build one per scan via ForRun
// (or New for the protected-dirs class alone); share across detectors.
// Hits are tracked so callers can prove from logs which protected paths
// were actually encountered during the walks.
type Skipper struct {
	paths    map[string]struct{}
	prefixes []string
	volumes  []string

	mu   sync.Mutex
	hits map[string]int
}

// New builds a Skipper for the protected-directories class alone, anchored
// at home. home == "" produces a degraded Skipper that only matches
// absolute-prefix entries (e.g. Time Machine snapshot mounts) — useful when
// the agent runs without a console user.
func New(home string) *Skipper {
	return &Skipper{
		paths:    buildProtectedPaths(home),
		prefixes: protectedPrefixes(),
	}
}

// ForRun builds the Skipper for one scan from both tri-state toggles. It
// returns nil when neither class is active — every Skipper method is
// nil-safe, so callers hand the result straight to detectors without
// branching.
//
// Enumerating the mount table is a metadata read, not a volume access, so
// it never fires the prompt it exists to avoid.
func ForRun(home string, includeTCCProtected, includeNetworkVolumes *bool) *Skipper {
	var mounts []string
	if SkipNetworkVolumes(includeNetworkVolumes) {
		mounts = networkVolumeMounts()
	}
	return build(home, Enabled(includeTCCProtected), mounts)
}

// build is ForRun without the mount-table syscall, so the matching rules
// are testable on every platform.
func build(home string, protected bool, mounts []string) *Skipper {
	if !protected && len(mounts) == 0 {
		return nil
	}
	s := &Skipper{volumes: mounts}
	if protected {
		s.paths = buildProtectedPaths(home)
		s.prefixes = protectedPrefixes()
	}
	return s
}

// ShouldSkip reports whether path is a TCC-protected directory — or a
// skipped network-volume mount point — whose walk should be
// short-circuited. When path equals walkRoot the result is always false:
// passing --search-dirs ~/Documents (or --search-dirs ~/OrbStack) is an
// explicit opt-in, and the walk root must be entered for anything to
// happen.
//
// Callers must consult this BEFORE reading the directory: it is the
// mountpoint's ReadDir, not the parent's listing of it, that fires the
// network-volume prompt.
//
// Safe to call on a nil receiver (returns false), which is what callers
// pass when --include-tcc-protected is set and no volume class is skipped.
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
	return s.withinNetworkVolume(cleaned)
}

// WithinProtected reports whether path is a TCC-protected directory OR lies
// beneath one (e.g. ~/Documents/my-project). It differs from ShouldSkip, which
// matches only the protected directory itself as a walk descends into it and so
// relies on the walk passing through the protected parent. Callers that resolve
// a deep path directly — and would otherwise stat inside the protected tree,
// firing the very prompt we avoid — must use this BEFORE any filesystem access.
// Safe on a nil receiver (returns false), matching the --include-tcc-protected
// opt-in. Records a hit against the matched protected root so LogHits surfaces
// the skip. Also matches paths under a skipped network-volume mount, for the
// same reason: resolving into one is what triggers the prompt.
func (s *Skipper) WithinProtected(path string) bool {
	if s == nil {
		return false
	}
	cleaned := filepath.Clean(path)
	for p := range s.paths {
		// Home-anchored protected dirs match on equality or a "/" boundary only.
		// hasPathPrefix (used for the prefixes below) also treats "." as a
		// boundary, which is correct for Time Machine names but here would let
		// ~/Documents swallow a sibling like ~/Documents.backup.
		if hasDirPrefix(cleaned, p) {
			s.recordHit(p)
			return true
		}
	}
	for _, p := range s.prefixes {
		if hasPathPrefix(cleaned, p) {
			s.recordHit(p)
			return true
		}
	}
	return s.withinNetworkVolume(cleaned)
}

// withinNetworkVolume reports whether cleaned is a skipped network-volume
// mount point or lies beneath one, recording a hit against the mount. The
// slice is empty unless the run opted out of walking network volumes, so
// this is a no-op loop on the default path.
func (s *Skipper) withinNetworkVolume(cleaned string) bool {
	for _, v := range s.volumes {
		if hasDirPrefix(cleaned, v) {
			s.recordHit(v)
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

// hasDirPrefix reports whether s equals dir or is nested under it at a "/"
// boundary. Unlike hasPathPrefix it does NOT treat "." as a boundary: a
// protected directory such as ~/Documents must match ~/Documents/x but never a
// distinct sibling like ~/Documents.backup. (hasPathPrefix's "." boundary
// exists only for the Time Machine prefix form
// /Volumes/.timemachine.donottouch.<uuid>.)
func hasDirPrefix(s, dir string) bool {
	if !strings.HasPrefix(s, dir) {
		return false
	}
	return len(s) == len(dir) || s[len(dir)] == '/'
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

// NetworkVolumes returns the network-volume mount points the Skipper would
// skip, sorted lexicographically. Empty on the default path (network
// volumes are walked) and on non-darwin builds. Useful for surfacing in
// logs which mounts a fleet's include_network_volumes: false actually cost
// it in coverage.
func (s *Skipper) NetworkVolumes() []string {
	if s == nil || len(s.volumes) == 0 {
		return nil
	}
	out := make([]string, len(s.volumes))
	copy(out, s.volumes)
	return out
}

// Candidates returns the exact-match protected paths the Skipper would
// skip, sorted lexicographically. Useful for surfacing in logs. Returns nil
// on a nil receiver or on non-darwin builds. Network-volume mounts are not
// included — see NetworkVolumes.
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
