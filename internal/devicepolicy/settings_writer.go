package devicepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

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

// allowedExtensionsSettingKey is the `extensions.allowed` SETTING ID — the key
// VS Code reads from settings.json. This is deliberately NOT the registered
// policy name "AllowedExtensions" (allowedExtensionsName): policy locations
// (registry / policy.json / managed prefs) are keyed by policy name and are
// probed read-only (probe_*.go); the settings file is keyed by setting id and
// is the surface the agent writes.
const allowedExtensionsSettingKey = "extensions.allowed"

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

// extract returns the compacted current value of the extensions.allowed key
// from a parsed tree, or ok=false when the key is absent. Compaction
// normalizes whitespace (and any comments inside the value, which Standardize
// strips) so values compare canonically regardless of on-disk formatting.
func extractAllowedExtensions(v hujson.Value) (string, bool, error) {
	std := v.Clone()
	std.Standardize()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(std.Pack(), &m); err != nil {
		return "", false, fmt.Errorf("devicepolicy: standardize settings: %w", err)
	}
	raw, ok := m[allowedExtensionsSettingKey]
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
