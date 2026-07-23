package devicepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/step-security/dev-machine-guard/internal/atomicfile"
)

// Writer reads, upserts, and removes the `extensions.allowed` key in the
// user-scope VS Code settings.json. It is a thin primitive: it manages ONLY
// that one top-level key — every other key, comment, and formatting detail in
// the file is preserved (single-key JSONC merge), which is what makes editing
// a file the user also owns safe. Ownership and drift decisions (whether the
// agent may overwrite or remove) live in the reconciler, not here, so the
// writer stays pure and fake-testable.
//
// Values are compact JSON object strings — the backend's compiled
// extensions.allowed object, compacted. Read returns the on-disk value
// re-compacted, so equality against a recorded written value is canonical
// regardless of how the file is formatted on disk.
//
// The production implementation is settingsWriter below; the reconciler is
// exercised against fakes.
type Writer interface {
	// Read returns the current extensions.allowed value (compacted) and
	// whether it is present. (present=false, err=nil) means the file is
	// missing or readable-but-without-the-key. An unparseable settings.json
	// is an error — the writer refuses to reason about a file it cannot
	// understand.
	Read() (value string, present bool, err error)

	// Write upserts extensions.allowed to value, then reads it back and
	// returns the read-back value. The reconciler compares it to value to
	// detect a silent non-apply (policy_not_applied). An error means the
	// write itself failed or the file is unsalvageable → write_failed.
	Write(value string) (readback string, err error)

	// Clear removes the extensions.allowed key, leaving the rest of the file
	// (and the file itself) intact. A missing file or absent key is a no-op.
	Clear() error

	// Location is a human-readable description of the target, for logs.
	Location() string
}

// settingOp is a requested mutation of ONE managed settings.json key. Exactly
// one of Set / Remove is chosen by the caller; neither set (the zero value)
// means "preserve" — leave whatever is on disk, the ownership-safe default that
// never deletes a value the agent did not write. Remove is ownership-gated by
// the caller (reconcile), not here.
type settingOp struct {
	Key    string          // e.g. allowedExtensionsSettingKey, galleryServiceURLSettingKey
	Set    bool            // set Key to Value
	Value  json.RawMessage // already-encoded, compacted JSON value (when Set)
	Remove bool            // remove Key
}

// settingValue is a key's on-disk state. Present distinguishes an absent key
// from a present-but-empty one (needed for convergence + readback); Raw is the
// compacted encoded value (empty when absent).
type settingValue struct {
	Present bool
	Raw     string
}

// managedSettingsWriter is implemented by settingsWriter. The reconciler
// type-asserts for it; a Writer without it keeps the single-key Write/Read/Clear
// path. Each method acts on one atomic file write over a set of keyed ops.
type managedSettingsWriter interface {
	// ReadManaged returns each requested key's on-disk value + presence in one
	// file read. An unparseable / non-object settings.json is an error (the
	// never-clobber contract), exactly as Read.
	ReadManaged(keys []string) (map[string]settingValue, error)
	// ApplyManaged performs ONE atomic load→patch→store over the ops (Set →
	// add, Remove → remove-if-present, preserve → skipped), then reads back and
	// returns every op key's resulting value + presence. All requested mutations
	// land or none do. When no op mutates anything (all preserve, or every
	// Remove targets an absent key) it performs no write at all.
	ApplyManaged(ops []settingOp) (map[string]settingValue, error)
	// RestoreManaged restores each key in the snapshot to its recorded state
	// (Present → set to Raw, absent → remove) in one atomic write. Used by
	// enforce's post-write rollback.
	RestoreManaged(snapshot map[string]settingValue) error
}

// allowedExtensionsSettingKey is the `extensions.allowed` SETTING ID — the key
// VS Code reads from settings.json. This is deliberately NOT the registered
// policy name "AllowedExtensions" (allowedExtensionsName): policy locations
// (registry / policy.json / managed prefs) are keyed by policy name and are
// probed read-only (probe_*.go); the settings file is keyed by setting id and
// is the surface the agent writes.
const allowedExtensionsSettingKey = "extensions.allowed"

// galleryServiceURLSettingKey is the `extensions.gallery.serviceUrl` SETTING ID
// — the (hidden, application-scope) key VS Code reads from settings.json to
// repoint the extension marketplace. Like allowedExtensionsSettingKey it is
// deliberately NOT the registered policy name "ExtensionGalleryServiceUrl"
// (galleryServiceURLName), which the read-only probes look for at OS policy
// locations; this is the setting id the agent writes.
const galleryServiceURLSettingKey = "extensions.gallery.serviceUrl"

// settingsFileMode is the fallback mode for a settings.json the agent creates.
// An existing file keeps its current mode (atomicfile.PickMode); 0600 for a
// new one is safe because VS Code runs as the same user.
const settingsFileMode os.FileMode = 0o600

// settingsWriter implements Writer against the user-scope VS Code
// settings.json (JSONC). One implementation serves every OS — only the path
// differs (settingsPath).
//
// Invariants:
//   - Single-key edits: only the top-level "extensions.allowed" member is ever
//     added, replaced, or removed. Everything else in the file — other keys,
//     comments, trailing commas, whitespace — is preserved byte-for-byte
//     (hujson syntax tree + RFC 6902 patch).
//   - A file that cannot be parsed as JSONC, or whose root is not an object,
//     is NEVER rewritten: every operation fails and the file is untouched
//     (surfaces as write_failed; blind overwrite would destroy user settings).
//   - Replacement is atomic (temp + fsync + rename in the target dir) and the
//     previous file is kept as a capped sibling backup (atomicfile).
//   - The file itself is never deleted; Clear removes only the key.
//
// Known limitation: VS Code also accepts the nested spelling
// `"extensions": {"allowed": …}`. The agent reads/writes only the canonical
// flat dotted key, so a pre-existing nested value is invisible to it (VS Code
// resolves the flat key it writes; the nested duplicate is the user's to
// reconcile).
type settingsWriter struct{ path string }

// newSettingsWriterAt builds a settings writer for an arbitrary path
// (tests use a tempdir; production uses settingsPath()).
func newSettingsWriterAt(path string) *settingsWriter { return &settingsWriter{path: path} }

// NewWriter returns the user-scope settings.json writer for this OS. ok=false
// when settingsPath cannot resolve the target (unsupported OS, no home dir or
// %APPDATA%) — the reconciler treats that as not agent-enforceable and no-ops.
func NewWriter() (Writer, bool) {
	path, ok := settingsPath()
	if !ok {
		return nil, false
	}
	return newSettingsWriterAt(path), true
}

// settingsPath resolves the user-scope VS Code settings.json for this OS,
// matching VS Code's own resolution (the default profile's user settings):
//
//	windows  %APPDATA%\Code\User\settings.json
//	darwin   ~/Library/Application Support/Code/User/settings.json
//	linux    $XDG_CONFIG_HOME/Code/User/settings.json (default ~/.config)
//
// ok=false when the base directory cannot be resolved (no home, no %APPDATA%)
// or the OS is not one of the three supported platforms.
func settingsPath() (string, bool) {
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", false
		}
		return filepath.Join(appdata, "Code", "User", "settings.json"), true
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", false
		}
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json"), true
	case "linux":
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return "", false
			}
			base = filepath.Join(home, ".config")
		}
		return filepath.Join(base, "Code", "User", "settings.json"), true
	default:
		return "", false
	}
}

func (w *settingsWriter) Location() string {
	return w.path + ` [` + allowedExtensionsSettingKey + `]`
}

// load reads and parses the settings file. Returns:
//   - the syntax tree (an empty object when the file is absent or blank, so
//     callers can patch a first key into a fresh file);
//   - existed=false when the file is absent;
//   - an error when the file exists but is unreadable, is not parseable JSONC,
//     or its root is not an object — the never-clobber contract.
func (w *settingsWriter) load() (v hujson.Value, existed bool, err error) {
	// #nosec G304 -- w.path is settingsPath() (env/home + fixed segments) or a
	// test override, never external input.
	b, err := os.ReadFile(w.path)
	if errors.Is(err, os.ErrNotExist) {
		v, _ := hujson.Parse([]byte("{}"))
		return v, false, nil
	}
	if err != nil {
		return hujson.Value{}, false, fmt.Errorf("devicepolicy: read %s: %w", w.path, err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		// An empty file is how VS Code-adjacent tooling often seeds settings;
		// treat it as an empty object rather than a parse error.
		v, _ := hujson.Parse([]byte("{}"))
		return v, true, nil
	}
	v, perr := hujson.Parse(b)
	if perr != nil {
		return hujson.Value{}, true, fmt.Errorf("devicepolicy: %s is not valid JSONC, refusing to touch it: %w", w.path, perr)
	}
	if _, ok := v.Value.(*hujson.Object); !ok {
		return hujson.Value{}, true, fmt.Errorf("devicepolicy: %s root is not a JSON object, refusing to touch it", w.path)
	}
	return v, true, nil
}

// extractAllowedExtensions returns the compacted current value of the
// extensions.allowed key, or ok=false when it is absent.
func extractAllowedExtensions(v hujson.Value) (string, bool, error) {
	return extractKey(v, allowedExtensionsSettingKey)
}

// extractKey returns the compacted current value of one top-level settings key
// from a parsed tree, or ok=false when the key is absent. Compaction normalizes
// whitespace (and any comments inside the value, which Standardize strips) so
// values compare canonically regardless of on-disk formatting.
func extractKey(v hujson.Value, key string) (string, bool, error) {
	std := v.Clone()
	std.Standardize()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(std.Pack(), &m); err != nil {
		return "", false, fmt.Errorf("devicepolicy: standardize settings: %w", err)
	}
	raw, ok := m[key]
	if !ok {
		return "", false, nil
	}
	s, err := compactJSON(raw)
	if err != nil {
		return "", false, err
	}
	return s, true, nil
}

// compactJSON returns raw with insignificant whitespace removed. Member order
// is preserved, so two compactions are byte-equal iff the underlying JSON has
// identical structure and order — exactly the comparison ownership and
// readback need.
func compactJSON(raw []byte) (string, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "", fmt.Errorf("devicepolicy: compact value: %w", err)
	}
	return buf.String(), nil
}

func (w *settingsWriter) Read() (string, bool, error) {
	v, existed, err := w.load()
	if err != nil {
		return "", false, err
	}
	if !existed {
		return "", false, nil
	}
	return extractAllowedExtensions(v)
}

// Write upserts the extensions.allowed key to value (a compact JSON object
// string — the reconciler passes the backend's compiled policy compacted) and
// returns the value read back from disk.
func (w *settingsWriter) Write(value string) (string, error) {
	if !json.Valid([]byte(value)) || !isJSONObject([]byte(value)) {
		// The patch document embeds value verbatim; reject anything that is not
		// a JSON object before it can corrupt the patch (defense in depth — the
		// fetcher already enforces object shape).
		return "", fmt.Errorf("devicepolicy: refusing to write non-object policy value to %s", w.path)
	}
	v, _, err := w.load()
	if err != nil {
		return "", err
	}
	// RFC 6902 "add" on an object member is an upsert. The key contains no '/'
	// or '~', so it needs no JSON-Pointer escaping; the dot is literal.
	patch := `[{"op":"add","path":"/` + allowedExtensionsSettingKey + `","value":` + value + `}]`
	if err := v.Patch([]byte(patch)); err != nil {
		return "", fmt.Errorf("devicepolicy: patch %s: %w", w.path, err)
	}
	if err := w.store(v); err != nil {
		return "", err
	}
	rb, _, err := w.Read()
	if err != nil {
		return "", err
	}
	return rb, nil
}

// Clear removes the extensions.allowed key. The file is never deleted (it is
// the user's settings.json); a file or key already absent is a no-op that
// performs no write at all.
func (w *settingsWriter) Clear() error {
	v, existed, err := w.load()
	if err != nil {
		return err
	}
	if !existed {
		return nil
	}
	if _, present, err := extractAllowedExtensions(v); err != nil {
		return err
	} else if !present {
		return nil
	}
	patch := `[{"op":"remove","path":"/` + allowedExtensionsSettingKey + `"}]`
	if err := v.Patch([]byte(patch)); err != nil {
		return fmt.Errorf("devicepolicy: patch %s: %w", w.path, err)
	}
	return w.store(v)
}

// store atomically replaces the settings file with the packed tree, preserving
// the existing file mode and keeping a capped sibling backup of the previous
// content (atomicfile: temp in target dir → fsync → rename).
func (w *settingsWriter) store(v hujson.Value) error {
	mode := atomicfile.PickMode(w.path, settingsFileMode)
	if _, err := atomicfile.WriteAtomic(w.path, v.Pack(), mode); err != nil {
		return fmt.Errorf("devicepolicy: write %s: %w", w.path, err)
	}
	return nil
}

// ReadManaged returns each requested key's compacted value + presence in one
// file read. An absent/blank file yields all-absent; an unparseable or
// non-object file is an error (the never-clobber contract), same as Read.
func (w *settingsWriter) ReadManaged(keys []string) (map[string]settingValue, error) {
	v, existed, err := w.load()
	if err != nil {
		return nil, err
	}
	out := make(map[string]settingValue, len(keys))
	if !existed {
		for _, k := range keys {
			out[k] = settingValue{}
		}
		return out, nil
	}
	// Standardize + unmarshal once, then look up every key (cheaper than
	// extractKey per key, and identical in result).
	std := v.Clone()
	std.Standardize()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(std.Pack(), &m); err != nil {
		return nil, fmt.Errorf("devicepolicy: standardize settings: %w", err)
	}
	for _, k := range keys {
		raw, ok := m[k]
		if !ok {
			out[k] = settingValue{}
			continue
		}
		s, err := compactJSON(raw)
		if err != nil {
			return nil, err
		}
		out[k] = settingValue{Present: true, Raw: s}
	}
	return out, nil
}

// ApplyManaged builds one RFC-6902 patch from ops — Set → add (upsert), Remove
// → remove (pre-checked so an absent key is skipped, not an error), preserve →
// nothing — and applies it in a single atomic load→patch→store. An empty patch
// writes nothing, so a remove-absent or preserve-only call leaves the file
// untouched. Returns a readback of every op's key.
func (w *settingsWriter) ApplyManaged(ops []settingOp) (map[string]settingValue, error) {
	v, _, err := w.load()
	if err != nil {
		return nil, err
	}
	patchOps := make([]string, 0, len(ops))
	for _, op := range ops {
		switch {
		case op.Set:
			// The patch document embeds the value verbatim; reject anything that
			// is not valid JSON before it can corrupt the patch (defense in depth
			// — the caller passes already-compacted, validated values). Object
			// shape is NOT required: a managed value may be a JSON string (the
			// gallery URL) as well as an object (the allowlist).
			if !json.Valid(op.Value) {
				return nil, fmt.Errorf("devicepolicy: refusing to write invalid JSON value for %q to %s", op.Key, w.path)
			}
			// op.Key is a dotted setting id with no '/' or '~', so it needs no
			// JSON-Pointer escaping; the dot is literal.
			patchOps = append(patchOps, `{"op":"add","path":"/`+op.Key+`","value":`+string(op.Value)+`}`)
		case op.Remove:
			// RFC 6902 "remove" errors on an absent member; pre-check presence so
			// a Remove of a key that is not there is simply skipped.
			_, present, perr := extractKey(v, op.Key)
			if perr != nil {
				return nil, perr
			}
			if present {
				patchOps = append(patchOps, `{"op":"remove","path":"/`+op.Key+`"}`)
			}
		}
	}
	if len(patchOps) > 0 {
		patch := "[" + strings.Join(patchOps, ",") + "]"
		if err := v.Patch([]byte(patch)); err != nil {
			return nil, fmt.Errorf("devicepolicy: patch %s: %w", w.path, err)
		}
		if err := w.store(v); err != nil {
			return nil, err
		}
	}
	keys := make([]string, len(ops))
	for i, op := range ops {
		keys[i] = op.Key
	}
	return w.ReadManaged(keys)
}

// RestoreManaged restores each key in the snapshot to its recorded state in one
// atomic write: a Present key is set back to its Raw value, an absent key is
// removed. Keys are applied in sorted order so the output is deterministic.
// Used by enforce's post-write rollback to undo a multi-key write atomically.
func (w *settingsWriter) RestoreManaged(snapshot map[string]settingValue) error {
	keys := make([]string, 0, len(snapshot))
	for k := range snapshot {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ops := make([]settingOp, 0, len(keys))
	for _, k := range keys {
		sv := snapshot[k]
		if sv.Present {
			ops = append(ops, settingOp{Key: k, Set: true, Value: json.RawMessage(sv.Raw)})
		} else {
			ops = append(ops, settingOp{Key: k, Remove: true})
		}
	}
	_, err := w.ApplyManaged(ops)
	return err
}
