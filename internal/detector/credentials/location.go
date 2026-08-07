package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Tokenised path roots. A reported location is written with its root replaced by
// one of these, and the same string is both what a reader sees and what identifies
// the file across scans: two spellings of one path become two rows for one file.
const (
	tokenHome      = "$HOME"
	tokenAppData   = "$APPDATA"
	tokenXDGConfig = "$XDG_CONFIG_HOME" //#nosec G101 -- the spelling of a path root in a reported location, which is an environment variable's name.
	// The fallback for a path matching no root: the directories above the file
	// become a short identifier of themselves and only the final element is kept.
	// Such a path is not one this inventory can describe, and its full spelling
	// can name directories that have nothing to do with credentials.
	tokenAbsolute = "$ABS"
)

// userPaths is the resolved developer's trusted root set, derived from the
// operating system's record of the account rather than an inherited variable: a
// root set taken from a value the scanned session controls is no boundary at all.
type userPaths struct {
	Username string
	Home     string
	// The home as the filesystem spells it, kept only when that differs from the
	// account record's spelling. Containment admits both, so a path can arrive in
	// either, and tokenisation respells the resolved one before matching: a home
	// reached through a symlink is still the home, and labelling its resolved form
	// with the opaque root would give one file two identities and hide the only
	// root a reader can interpret.
	HomeResolved string
	// The roaming application data directory, derived from the home rather than
	// read from the environment for the same reason.
	AppData string
	// The configuration directory for the tools that honour the variable,
	// defaulted below the home when the developer has not set it.
	XDGConfig string
}

// newUserPaths derives the root set from a resolved account.
func newUserPaths(username, home, platform string) userPaths {
	p := userPaths{
		Username:  username,
		Home:      home,
		XDGConfig: filepath.Join(home, ".config"),
	}
	if platform == model.PlatformWindows {
		p.AppData = filepath.Join(home, "AppData", "Roaming")
	}
	return p
}

// withXDGConfig applies the developer's own setting, if the environment probe
// established one.
func (p userPaths) withXDGConfig(value string) userPaths {
	if value != "" {
		p.XDGConfig = value
	}
	return p
}

// withResolvedHome records the filesystem's spelling of the home. An identical
// spelling is not stored, so in the ordinary case there is nothing to respell and
// the second spelling exists only where it changes an answer.
func (p userPaths) withResolvedHome(value string) userPaths {
	if value == "" || pathsEqual(filepath.Clean(value), filepath.Clean(p.Home)) {
		return p
	}
	p.HomeResolved = value
	return p
}

// candidatesFor expands one source into the locations to try. Each is absolute and
// unresolved. Overrides are not an edge case: relocating these files is how
// monorepos, multi-account setups and CI parity are configured, so probing the
// default alone would report such a machine as holding nothing.
//
// A relocation override replaces the catalog defaults rather than merely preceding
// them, and it does so on being set rather than on naming something that exists.
// The tools stop reading their default path once the variable is set, so a default
// reported alongside an override claims a credential is in use somewhere its tool
// never looks — the same over-report the first-match policy exists to prevent,
// arriving by a different route.
func candidatesFor(s source, paths userPaths, env map[string]string, platform string) []string {
	if relocated, isSet := relocationCandidates(s, env); isSet {
		return relocated
	}
	var out []string
	for _, l := range s.Locations {
		if !l.appliesTo(platform) {
			continue
		}
		root := paths.root(l.Root)
		if root == "" {
			continue
		}
		out = append(out, filepath.Join(root, filepath.FromSlash(l.Rel)))
	}
	return out
}

// relocationCandidates expands the first override that is set, in the declaration
// order the tools themselves apply, and reports that one was. Later overrides are
// not consulted: where a tool reads one variable in preference to another, so does
// this, and probing the lower-precedence target would report a file the tool has
// stopped reading.
//
// Being set is what displaces the defaults, not naming somewhere real. A target
// that does not exist is still the answer: the developer pointed the tool somewhere
// and nothing is there, which describes a source holding no credential. So is a
// value that resolves to no path at all — a list of nothing but separators — which
// is how the tools read it, the default restored by unsetting the variable and not
// by emptying it. Neither is an error, because nothing failed.
func relocationCandidates(s source, env map[string]string) ([]string, bool) {
	for _, o := range s.Overrides {
		if o.Kind == overridePrefix {
			// A prefix override rewrites paths arriving from elsewhere, so it
			// expands to nothing here and displaces no default. Only a delegated
			// source may declare one, which a catalog invariant enforces.
			continue
		}
		value := strings.TrimSpace(env[o.Var])
		if value == "" {
			continue
		}
		out, expandable := expandOverride(o, value)
		if !expandable {
			continue
		}
		return out, true
	}
	return nil, false
}

// expandOverride turns one variable's value into candidates, and reports whether
// its kind is one that replaces defaults at all. A path list can expand to nothing
// while remaining the answer, so emptiness is carried in the slice and never in the
// second return — that is reserved for a kind with no expansion, where standing
// aside for the default is the safer way for an inventory to be wrong.
func expandOverride(o envOverride, value string) ([]string, bool) {
	switch o.Kind {
	case overrideFile:
		return []string{value}, true
	case overrideDir:
		return []string{filepath.Join(value, filepath.FromSlash(o.Rel))}, true
	case overrideList:
		// The value is every path the tool reads, not a replacement for one.
		out := make([]string, 0, 1)
		for _, element := range filepath.SplitList(value) {
			if element = strings.TrimSpace(element); element != "" {
				out = append(out, element)
			}
		}
		return out, true
	}
	return nil, false
}

// root resolves a catalog path root.
func (p userPaths) root(r pathRoot) string {
	switch r {
	case rootHome:
		return p.Home
	case rootAppData:
		return p.AppData
	case rootXDGConfig:
		return p.XDGConfig
	}
	return ""
}

// applyPrefixOverrides rewrites a path whose leading directory a variable has
// moved — how relocation variables reach locations another component declares. The
// second return says a variable moved this path, which decides how it is read: a
// declared location is one of a reviewed set, a rewritten one is not.
func applyPrefixOverrides(path string, s source, paths userPaths, env map[string]string) (string, bool) {
	for _, o := range s.Overrides {
		if o.Kind != overridePrefix {
			continue
		}
		value := strings.TrimSpace(env[o.Var])
		if value == "" {
			continue
		}
		prefix := filepath.Join(paths.Home, filepath.FromSlash(o.Rel))
		rest, ok := trimPathPrefix(path, prefix)
		if !ok {
			continue
		}
		return filepath.Join(value, rest), true
	}
	return path, false
}

// tokenise rewrites an absolute path with its root replaced by a token. Roots are
// tried longest first: the roaming and configuration directories sit below the
// home, so matching the home first would label every path with the least
// specific root it happens to be under.
//
// A path spelled with the filesystem's home rather than the account record's is
// respelled and tried again against the same roots. That is deliberately not the
// same as carrying the resolved home as a second root: as a root it would match the
// home and stop, taking every path below it away from the more specific roots that
// live there — the roaming directory, a moved configuration directory — and
// reporting one file under a different token depending on which spelling of the home
// it happened to arrive with.
func (p userPaths) tokenise(path string) string {
	if path == "" {
		return ""
	}
	roots := p.tokenRoots()
	if out, ok := tokeniseWith(roots, path); ok {
		return out
	}
	if respelled, ok := p.respellResolvedHome(path); ok {
		if out, ok := tokeniseWith(roots, respelled); ok {
			return out
		}
	}
	// An opaque root still carries an identifier segment before the remainder, so
	// it keeps the shape every other location has: a reader that has to
	// special-case one root's segment count will eventually get it wrong.
	return tokenAbsolute + "/" + opaqueParent(path) + "/" + filepath.Base(path)
}

// tokeniseWith applies one root set to one spelling of a path.
func tokeniseWith(roots []rootToken, path string) (string, bool) {
	for _, r := range roots {
		rest, ok := trimPathPrefix(path, r.dir)
		if !ok {
			continue
		}
		if rest == "" {
			return r.token, true
		}
		return r.token + "/" + filepath.ToSlash(rest), true
	}
	return "", false
}

// respellResolvedHome rewrites a path below the filesystem's home to name the
// account record's home instead. Containment admits both spellings, so a path can
// arrive in either, and the roots are all derived from the record's.
func (p userPaths) respellResolvedHome(path string) (string, bool) {
	if p.HomeResolved == "" {
		return "", false
	}
	rest, ok := trimPathPrefix(path, p.HomeResolved)
	if !ok {
		return "", false
	}
	if rest == "" {
		return p.Home, true
	}
	return filepath.Join(p.Home, rest), true
}

// opaqueParent identifies the directories above a path without naming them. Stable
// across scans, or one unchanged file would arrive under a new location every run
// and count as new. Truncated: it identifies rather than authenticates.
func opaqueParent(path string) string {
	sum := sha256.Sum256([]byte(filepath.ToSlash(filepath.Dir(path))))
	return hex.EncodeToString(sum[:6])
}

// rootToken is one trusted root and the token that stands in for it.
type rootToken struct {
	dir   string
	token string
}

// tokenRoots returns the roots to try, longest first, so the most specific one
// wins regardless of declaration order.
func (p userPaths) tokenRoots() []rootToken {
	roots := make([]rootToken, 0, 3)
	for _, r := range []rootToken{{p.AppData, tokenAppData}, {p.Home, tokenHome}} {
		if r.dir != "" {
			roots = append(roots, r)
		}
	}
	// The configuration root earns its own token only where the developer moved it.
	// At its default below the home it is not a separate place, and several tools
	// keep files there while ignoring the variable, so labelling them with its name
	// would give one unchanged file two identities.
	if p.XDGConfig != "" && !p.xdgConfigIsDefault() {
		roots = append(roots, rootToken{p.XDGConfig, tokenXDGConfig})
	}
	slices.SortStableFunc(roots, func(a, b rootToken) int { return len(b.dir) - len(a.dir) })
	return roots
}

// xdgConfigIsDefault reports whether the configuration root is the default below the
// home. Either spelling of the home counts: a shell that reports the resolved one
// has set the variable to the same directory, not moved anything, and treating that
// as a move would hand the default location a token of its own.
func (p userPaths) xdgConfigIsDefault() bool {
	clean := filepath.Clean(p.XDGConfig)
	if pathsEqual(clean, filepath.Join(p.Home, ".config")) {
		return true
	}
	return p.HomeResolved != "" && pathsEqual(clean, filepath.Join(p.HomeResolved, ".config"))
}

// trimPathPrefix reports whether path lies at or below prefix and returns the
// remainder, comparing whole elements so a sibling whose name merely starts with
// the prefix is not treated as inside it. Casing follows the platform, and the
// remainder keeps its own: folding it would produce a string that does not resolve.
func trimPathPrefix(path, prefix string) (string, bool) {
	cleanPath := filepath.Clean(path)
	cleanPrefix := filepath.Clean(prefix)
	if pathsEqual(cleanPath, cleanPrefix) {
		return "", true
	}
	if len(cleanPath) <= len(cleanPrefix) {
		return "", false
	}
	if !pathsEqual(cleanPath[:len(cleanPrefix)], cleanPrefix) {
		return "", false
	}
	if !os.IsPathSeparator(cleanPath[len(cleanPrefix)]) {
		return "", false
	}
	return cleanPath[len(cleanPrefix)+1:], true
}

// pathsEqual compares two path fragments with the case rules of the machine being
// described, always the one this runs on: the build's target is the authority, so a
// caller cannot ask for rules the filesystem would not agree with.
func pathsEqual(a, b string) bool {
	if runtime.GOOS == model.PlatformWindows {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// gitCheckTimeout bounds the tracked-file check. It only runs for a file already
// inside a repository, which is rare, but a repository on a stalled network
// mount would otherwise hold the phase open.
const gitCheckTimeout = 5 * time.Second

// permissionMode renders the permission bits a reader can act on. Empty on Windows,
// where bits are synthesised from one read-only attribute, so every file reports one
// of two values whatever its access control says — and that looks like a measurement.
func permissionMode(info os.FileInfo, platform string) string {
	if platform == model.PlatformWindows {
		return ""
	}
	return fmt.Sprintf("%04o", info.Mode().Perm())
}

// broadTrustees are the security-descriptor abbreviations for principals that
// mean "more than this account".
var broadTrustees = map[string]bool{
	"WD": true, // everyone
	"AU": true, // authenticated users
	"BU": true, // built-in users group
	"IU": true, // interactively logged-on users
	"AN": true, // anonymous
}

// readRights are the rights abbreviations that include reading contents.
var readRights = map[string]bool{
	"FA": true, // full access
	"FR": true, // file read
	"GA": true, // generic all
	"GR": true, // generic read
	"KA": true, // key all, appears on descriptors copied from registry templates
	"KR": true, // key read, same
}

// Right bits checked when an entry spells its rights as a number rather than an
// abbreviation.
const (
	fileReadData = 0x0001
	genericRead  = 0x80000000
	genericAll   = 0x10000000
)

// descriptorGrantsBroadRead classifies the discretionary section of a Windows
// security descriptor, which is where access is described on the platform with no
// permission bits to render above. Read from the descriptor's textual form rather
// than by walking entry structures: the form is platform-produced and stable, and
// reading it needs no pointer arithmetic inside a security-sensitive path. Because
// it is text, only the call that asks for the descriptor is Windows-only.
func descriptorGrantsBroadRead(sddl string) bool {
	section, ok := discretionarySection(sddl)
	if !ok {
		return false
	}
	for _, entry := range splitACEs(section) {
		if aceGrantsBroadRead(entry) {
			return true
		}
	}
	return false
}

// discretionarySection extracts the discretionary list, which runs from its own
// marker to the start of the next section.
func discretionarySection(sddl string) (string, bool) {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return "", false
	}
	rest := sddl[i+2:]
	for _, marker := range []string{"S:", "O:", "G:"} {
		if j := strings.Index(rest, marker); j >= 0 {
			rest = rest[:j]
		}
	}
	return rest, true
}

// splitACEs returns the parenthesised entries of a list.
func splitACEs(section string) []string {
	var entries []string
	for {
		open := strings.IndexByte(section, '(')
		if open < 0 {
			return entries
		}
		end := strings.IndexByte(section[open:], ')')
		if end < 0 {
			return entries
		}
		entries = append(entries, section[open+1:open+end])
		section = section[open+end+1:]
	}
}

// aceGrantsBroadRead classifies one entry. Its fields are type, flags, rights,
// two object identifiers, and the principal.
func aceGrantsBroadRead(entry string) bool {
	fields := strings.Split(entry, ";")
	if len(fields) < 6 {
		return false
	}
	// Only an allow entry grants anything. A conditional-allow entry carries
	// extra terms deciding whether it applies at all, so it is not counted:
	// reporting it as a grant would assert access that may never be in effect.
	if strings.ToUpper(strings.TrimSpace(fields[0])) != "A" {
		return false
	}
	if !broadTrustees[strings.ToUpper(strings.TrimSpace(fields[5]))] {
		return false
	}
	return rightsIncludeRead(strings.TrimSpace(fields[2]))
}

// rightsIncludeRead reports whether a rights field allows reading contents. The
// field is either a sequence of two-letter abbreviations or a hexadecimal
// number.
func rightsIncludeRead(rights string) bool {
	if after, ok := cutHexPrefix(rights); ok {
		mask, err := strconv.ParseUint(after, 16, 64)
		if err != nil {
			return false
		}
		return mask&fileReadData != 0 || mask&genericRead != 0 || mask&genericAll != 0
	}
	upper := strings.ToUpper(rights)
	for i := 0; i+2 <= len(upper); i += 2 {
		if readRights[upper[i:i+2]] {
			return true
		}
	}
	return false
}

// cutHexPrefix reports whether a rights field is spelled as a number and returns
// its digits.
func cutHexPrefix(rights string) (string, bool) {
	if len(rights) > 2 && (rights[0] == '0') && (rights[1] == 'x' || rights[1] == 'X') {
		return rights[2:], true
	}
	return "", false
}

// inGitRepo reports whether a path sits inside a repository working tree, caching
// per directory: the answer depends only on the directory, and a key directory
// holds many keys, so without the cache every key repeats the same walk.
func (s *scanState) inGitRepo(path string) bool {
	dir := filepath.Dir(path)
	if answer, known := s.gitRepos[dir]; known {
		return answer
	}
	answer := inGitRepo(path, s.paths.Home)
	s.gitRepos[dir] = answer
	return answer
}

// inGitRepo reports whether a path sits inside a repository working tree, evaluated
// against the resolved location: a symlink farm pointing a home dotfile into a
// checked-out dotfiles repository is precisely the arrangement that puts a
// credential under version control while the path the tool reads looks innocent.
// The search stops at the trusted root — a repository above a home is not it.
func inGitRepo(path, root string) bool {
	dir := filepath.Dir(path)
	for {
		// Containment is tested before the directory is looked at, so a
		// repository beside or above the home is never inspected and never
		// claims a file inside it.
		if _, ok := trimPathPrefix(dir, root); !ok {
			return false
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// gitTracked reports whether a file is under version control, only for one already
// known to be inside a repository. It asks the repository rather than reading the
// index: ignore rules, sparse checkouts and worktrees all change the answer.
func gitTracked(ctx context.Context, exec executor.Executor, path string) bool {
	dir, base := filepath.Split(path)
	if dir == "" || base == "" {
		return false
	}
	_, _, exitCode, err := exec.RunWithTimeout(ctx, gitCheckTimeout, "git", "-C", filepath.Clean(dir), "ls-files", "--error-unmatch", base)
	return err == nil && exitCode == 0
}
