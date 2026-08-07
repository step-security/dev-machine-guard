// Package safepath opens a file through a chain of path components it has
// verified itself, and refuses any target that resolves outside a declared set
// of roots.
//
// Two properties motivate it, and neither is delivered by resolving a path
// string and then reading it.
//
// First, resolution must happen before the first read. On macOS the kernel
// traversal into a consent-gated directory IS the consent event: a background
// process that traverses one gets no error and no prompt it can answer — it blocks
// indefinitely, and no context deadline interrupts a blocked open. A lexical check
// on the path as written is not enough; the check has to run on the resolved target
// of every component, before the syscall that would traverse it. Resolution is
// therefore os.Lstat plus os.Readlink per component, following nothing: a resolver
// that followed links would fire the traversal it is called to decide about.
//
// Second, O_NOFOLLOW on the leaf is not sufficient. It protects the leaf only, while
// every parent was validated by an earlier syscall — a local process that swaps a
// parent for a symlink in that window still gets the kernel to traverse it. So the
// read goes through the components as descriptors: on unix an openat chain with
// O_NOFOLLOW|O_DIRECTORY per component, opening the leaf relative to the last
// verified directory. Windows has no openat, so the leaf is opened without following
// a reparse point and the kernel's own final path for the handle is compared against
// the resolved path before a byte is read; the residual risk there is reading the
// wrong file rather than a blocked traversal.
//
// Containment is a separate guarantee, and it is what makes a privileged reader safe
// to point at a user-supplied location: the resolved target must lie inside the
// roots, which come from the OS user record rather than from any variable the same
// user could set — a root set taken from the channel being bounded is no bound at
// all. It is checked at every hop, so a path that leaves the roots is refused before
// the components below it are stat'd.
package safepath

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Refusal reason codes. These are the only vocabulary a caller reports; a
// refusal never carries a path or an underlying error message, because both can
// quote the content of the file being examined.
const (
	// ReasonOutsideRoots is a target that resolves outside the declared root.
	ReasonOutsideRoots = "refused_outside_user_roots"
	// ReasonDenied is a target the process is not permitted to stat or open.
	ReasonDenied = "permission_denied"
	// ReasonUnresolved is a target whose path could not be resolved to a single
	// concrete file: a symlink cycle, more hops than the budget allows, a
	// relative path, or a component swapped between resolution and open.
	ReasonUnresolved = "location_unresolved"
)

// maxHops bounds symlink indirection. Each hop restarts resolution at the
// link's target, so a cycle burns hops rather than looping forever.
const maxHops = 16

// maxComponents bounds path depth so a pathological path cannot make the
// descriptor chain unbounded.
const maxComponents = 256

// Refusal is the error returned when a path was declined rather than missing.
// Reason is one of the codes above and is the whole error text: a refusal must
// be reportable without disclosing what was refused.
type Refusal struct{ Reason string }

func (e *Refusal) Error() string { return e.Reason }

// ReasonOf returns the refusal code carried by err, or "" when err is not a
// refusal (a missing file is not a refusal).
func ReasonOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

func refuse(reason string) error { return &Refusal{Reason: reason} }

// Guard reports a refusal reason for a path a Resolver is about to touch, or "" to
// allow it, consulted on the whole path and on every component before the first
// syscall against any of them. Its reason travels back as the refusal, so the
// vocabulary belongs to the caller: this package does not know why a path is off
// limits, only that it must not find out by touching it.
type Guard func(path string) string

// Resolver resolves and opens paths under one root, declining anything that leaves
// it or that its guard refuses. The root must come from the OS user record — the
// directory service entry, the passwd entry, or the profile path registered for the
// account's SID — never from $HOME, $XDG_CONFIG_HOME or %APPDATA%, which the same
// user can set. An empty root contains nothing, so every target is refused, the
// correct posture when no user resolved.
type Resolver struct {
	home  string
	guard Guard

	// rootsOnce resolves the containment roots once: the home as written plus its own
	// resolved form. A home behind a symlink is an ordinary layout, and containment
	// anchored only on the written form would refuse every file the user owns.
	rootsOnce sync.Once
	roots     []string
}

// New returns a Resolver contained to home, consulting guard before every
// syscall. A nil guard allows every path the containment check admits.
func New(home string, guard Guard) *Resolver {
	if home != "" {
		home = filepath.Clean(home)
	}
	return &Resolver{home: home, guard: guard}
}

// containmentRoots returns the home as written plus its resolved form, computed
// once and reused: Contains runs at the end of every resolution, so it must not
// rebuild the list or re-resolve the home each time.
func (r *Resolver) containmentRoots() []string {
	if r.home == "" {
		return nil
	}
	r.rootsOnce.Do(func() {
		r.roots = []string{r.home}
		// Resolved without a containment check, because this call is what
		// establishes what containment means. The guard still applies: a home that
		// resolves into a place the caller refuses must not be traversed.
		if resolved, _, err := r.resolveChain(r.home, false); err == nil && resolved != r.home {
			r.roots = append(r.roots, resolved)
		}
	})
	return r.roots
}

// Contains reports whether path lies within the root. Lexical, and expects an
// already-resolved path; callers get that from Resolve. The nesting test is at a
// separator boundary: a prefix test alone would let /home/bobby pass for /home/bob.
func (r *Resolver) Contains(path string) bool {
	cleaned := filepath.Clean(path)
	for _, root := range r.containmentRoots() {
		if cleaned == root {
			return true
		}
		if strings.HasPrefix(cleaned, root) && cleaned[len(root)] == filepath.Separator {
			return true
		}
	}
	return false
}

// Resolve returns the concrete path that path refers to, following symlinks
// component by component without ever letting the kernel do the following. It
// returns a *Refusal when the guard declines the target, when it escapes the root,
// when it is unreadable, or when it cannot be resolved; and an error satisfying
// errors.Is(err, os.ErrNotExist) when nothing is there. Absence is not a refusal —
// a caller stays silent about a file the machine simply does not have.
func (r *Resolver) Resolve(path string) (string, error) {
	resolved, _, err := r.resolveChain(path, true)
	return resolved, err
}

// resolveChain walks path root-to-leaf resolving each symlink it meets, and returns
// the leaf's own metadata alongside the resolved path. checkRoots is false only while
// establishing the roots themselves. The leaf metadata is a by-product: a leaf that
// was a link sent the walk around again, so what returns is never a link.
func (r *Resolver) resolveChain(path string, checkRoots bool) (string, os.FileInfo, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", nil, refuse(ReasonUnresolved)
	}
	current := filepath.Clean(path)

	for hop := 0; ; hop++ {
		if hop > maxHops {
			return "", nil, refuse(ReasonUnresolved)
		}
		// Lexical guard check on the whole path before any syscall against it. A
		// deep target under a refused directory is reached directly here, so
		// nothing else would notice it on the way down.
		if reason := r.refusedBy(current); reason != "" {
			return "", nil, refuse(reason)
		}

		volume, comps := split(current)
		if len(comps) > maxComponents {
			return "", nil, refuse(ReasonUnresolved)
		}

		prefix := volume + string(filepath.Separator)
		redirected := false
		var leaf os.FileInfo
		for i, comp := range comps {
			prefix = filepath.Join(prefix, comp)
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
				target = filepath.Join(filepath.Dir(prefix), target)
			}
			target = filepath.Clean(target)
			// Re-check the link's target before anything touches it. This is the
			// check that must not wait for the final path: traversal is itself the
			// event on the platform this exists for, so a link pointing at a
			// refused directory is refused before the next component is stat'd.
			if reason := r.refusedBy(target); reason != "" {
				return "", nil, refuse(reason)
			}
			// Restart resolution at the target with the components we had not
			// reached yet still appended.
			current = filepath.Join(append([]string{target}, comps[i+1:]...)...)
			// Containment applies to the redirected path for the same reason the
			// guard does: the components below it are about to be stat'd, and a stat
			// into a network volume or a consent-gated tree is itself the blocking
			// call. Deciding only at the end would mean walking the whole of
			// somewhere this may not be. The roots hold both the home as written and
			// its resolved form, which is what makes this safe per hop: an ancestor
			// that redirects still lands under the resolved root. What it refuses is
			// a path that leaves and comes back through a second link — contained in
			// the end, but only by way of somewhere this may not go.
			if checkRoots && !r.Contains(current) {
				return "", nil, refuse(ReasonOutsideRoots)
			}
			redirected = true
			break
		}
		if redirected {
			continue
		}
		if checkRoots && !r.Contains(current) {
			return "", nil, refuse(ReasonOutsideRoots)
		}
		return current, leaf, nil
	}
}

// refusedBy asks the guard about one path. A nil guard refuses nothing.
func (r *Resolver) refusedBy(path string) string {
	if r.guard == nil {
		return ""
	}
	return r.guard(path)
}

// Stat resolves path and returns what the resolved target is without opening it,
// which is what makes it usable for a location whose contents must not be read. The
// metadata comes from the walk, which had to lstat the leaf to know it was no link.
func (r *Resolver) Stat(path string) (resolved string, info os.FileInfo, err error) {
	resolved, info, err = r.resolveChain(path, true)
	if err != nil {
		return "", nil, err
	}
	if info == nil {
		// A resolved path with no leaf metadata is the volume root itself, which
		// is not a location this reads.
		return "", nil, refuse(ReasonUnresolved)
	}
	return resolved, info, nil
}

// Read resolves path and reads at most max bytes from the resolved target through
// the verified chain. A longer file is read to the cap with truncated set, so the
// caller can report an incomplete parse rather than a wrong one. A directory
// resolves and is described but not read: info says what the location is, data is
// nil, and nothing is refused. The path and info come from the same resolution and
// handle the bytes came from, so a separate stat would describe another moment.
func (r *Resolver) Read(path string, max int64) (data []byte, resolved string, info os.FileInfo, truncated bool, err error) {
	resolved, err = r.Resolve(path)
	if err != nil {
		return nil, "", nil, false, err
	}
	f, info, err := openVerified(resolved, false)
	if err != nil {
		return nil, "", nil, false, err
	}
	defer func() { _ = f.Close() }()

	if info.IsDir() {
		return nil, resolved, info, false, nil
	}
	// One byte past the cap distinguishes "exactly at the cap" from "longer".
	data, rerr := io.ReadAll(io.LimitReader(f, max+1))
	if rerr != nil {
		return nil, "", nil, false, refuse(ReasonDenied)
	}
	if int64(len(data)) > max {
		data = data[:max]
		truncated = true
	}
	return data, resolved, info, truncated, nil
}

// ReadDirNames resolves path and returns at most max of its immediate entries,
// reporting whether the directory held more. Non-recursive by construction: it
// returns names, not paths, so a caller cannot accidentally descend. The bound is
// applied at the read rather than to the result — the directories this opens are
// exactly the ones an attacker can fill, so a million entries has to be refused
// rather than measured.
func (r *Resolver) ReadDirNames(path string, max int) (names []string, resolved string, more bool, err error) {
	resolved, err = r.Resolve(path)
	if err != nil {
		return nil, "", false, err
	}
	f, _, err := openVerified(resolved, true)
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = f.Close() }()
	// One name past the bound distinguishes a directory that exactly fills it from
	// one that overruns it, without reading the rest of either.
	entries, rerr := f.Readdirnames(max + 1)
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		// A short read ends the listing rather than failing it: io.EOF is how a
		// directory with fewer entries than the bound reports that it is done.
		return nil, "", false, refuse(ReasonDenied)
	}
	if len(entries) > max {
		return entries[:max], resolved, true, nil
	}
	return entries, resolved, false, nil
}

// split separates a cleaned absolute path into its volume ("" on unix, "C:" on
// Windows) and its components below the volume root.
func split(path string) (volume string, comps []string) {
	volume = filepath.VolumeName(path)
	rest := strings.TrimPrefix(path[len(volume):], string(filepath.Separator))
	if rest == "" {
		return volume, nil
	}
	for c := range strings.SplitSeq(rest, string(filepath.Separator)) {
		if c == "" || c == "." {
			continue
		}
		comps = append(comps, c)
	}
	return volume, comps
}

// isLink reports whether info describes something the kernel would follow.
// ModeIrregular covers the Windows reparse points Go cannot classify as
// symlinks, which redirect just as effectively.
func isLink(info os.FileInfo) bool {
	m := info.Mode()
	return m&os.ModeSymlink != 0 || m&os.ModeIrregular != 0
}
