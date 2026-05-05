package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/tidwall/gjson"
	"github.com/tidwall/pretty"
	"github.com/tidwall/sjson"

	"github.com/step-security/dev-machine-guard/internal/aiagents/atomicfile"
	"github.com/step-security/dev-machine-guard/internal/aiagents/configedit"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
)

const (
	hookTimeoutSeconds = 30
	matcherAll         = "*"
	matcherSession     = "startup|resume|clear"
	settingsMode       = os.FileMode(0o600)
	statusMessagePrefix = "dev-machine-guard"
)

// managedCmdRE is the uninstall match criterion. It matches an entry's
// `command` field when the executable token is the DMG binary,
// regardless of which absolute path it sits behind. The `(^|/)`
// left-side accepts both bare invocations and absolute-path
// invocations, while rejecting prefix collisions like
// `mystepsecurity-dev-machine-guard`.
//
// The regex is kept identical to the claudecode adapter's so a single
// grep covers both.
var managedCmdRE = regexp.MustCompile(`(^|/)stepsecurity-dev-machine-guard\s+_hook\s+`)

// hooksDoc holds raw bytes for ~/.codex/hooks.json. orig is the bytes
// as read from disk (nil if the file did not exist); json is the
// in-memory mutation buffer that starts equal to orig (or `{}` when
// the file is missing/empty). All edits go through tidwall/sjson so
// unrelated user formatting is preserved byte-for-byte.
type hooksDoc struct {
	orig []byte
	json []byte
}

func loadHooksDoc(path string) (*hooksDoc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &hooksDoc{json: []byte(`{}`)}, nil
		}
		return nil, fmt.Errorf("codex hooks read: %w", err)
	}
	normalized, err := configedit.NormalizeJSONObject(b)
	if err != nil {
		return nil, fmt.Errorf("codex hooks parse: %w", err)
	}
	return &hooksDoc{orig: b, json: normalized}, nil
}

func hookEventPath(hookType event.HookEvent) string {
	return configedit.Path("hooks", string(hookType))
}

func statusMessageFor(hookType event.HookEvent) string {
	switch hookType {
	case HookSessionStart:
		return statusMessagePrefix + ": recording Codex session"
	case HookPreToolUse:
		return statusMessagePrefix + ": checking tool use"
	case HookPermissionRequest:
		return statusMessagePrefix + ": checking approval request"
	case HookPostToolUse:
		return statusMessagePrefix + ": recording tool result"
	case HookUserPromptSubmit:
		return statusMessagePrefix + ": recording prompt"
	case HookStop:
		return statusMessagePrefix + ": recording turn stop"
	}
	return statusMessagePrefix
}

// matcherFor returns the matcher for a hook event, or "" when the
// matcher key should be omitted entirely from the matcher group.
// Codex is more particular than Claude Code about matchers — only
// SessionStart and the tool-use family carry one.
func matcherFor(hookType event.HookEvent) string {
	switch hookType {
	case HookSessionStart:
		return matcherSession
	case HookPreToolUse, HookPermissionRequest, HookPostToolUse:
		return matcherAll
	}
	return ""
}

// codexHookEntry is the inner record shape Codex expects. DMG entries
// are identified on uninstall by `managedCmdRE` matching the command
// field, not by a metadata marker.
type codexHookEntry struct {
	Type          string `json:"type"`
	Command       string `json:"command"`
	Timeout       int    `json:"timeout"`
	StatusMessage string `json:"statusMessage"`
}

func desiredHookEntry(hookType event.HookEvent, command string) codexHookEntry {
	return codexHookEntry{
		Type:          "command",
		Command:       command,
		Timeout:       hookTimeoutSeconds,
		StatusMessage: statusMessageFor(hookType),
	}
}

// isManagedCommand reports whether cmd is a DMG-installed hook entry.
// Hook entries from other tools are intentionally not matched.
func isManagedCommand(cmd string) bool {
	return managedCmdRE.MatchString(cmd)
}

// upsertHook ensures exactly one DMG entry exists for hookType under
// the desired matcher, preserving every unrelated user matcher and
// inner hook. DMG entries under any other matcher are dropped (and
// recreated under the desired matcher) so audit coverage always
// tracks the install desired state.
//
// command is the literal string to write into the entry's `command`
// field — the adapter computes it via a.commandFor(hookType) so the
// settings document never embeds the binary path resolution logic.
//
// Always-refresh: when a managed entry already sits under the desired
// matcher, its type/command/timeout/statusMessage fields are rewritten
// in place via sjson (preserving any extra keys the user added). This
// self-heals the binary-move case — matching the claudecode adapter's
// behavior at zero extra cost.
func (d *hooksDoc) upsertHook(hookType event.HookEvent, command string) (added bool) {
	want := desiredHookEntry(hookType, command)
	wantMatcher := matcherFor(hookType)
	wantRaw, err := configedit.MarshalRawJSON(want)
	if err != nil {
		return false
	}
	path := hookEventPath(hookType)
	list := gjson.GetBytes(d.json, path).Array()

	outGroups := make([]string, 0, len(list)+1)
	placed := false
	listChanged := false

	for _, group := range list {
		if !group.IsObject() {
			outGroups = append(outGroups, group.Raw)
			continue
		}
		matcher := group.Get("matcher").String()
		inner := group.Get("hooks").Array()

		filtered := make([]string, 0, len(inner)+1)
		groupChanged := false
		for _, h := range inner {
			if !h.IsObject() {
				filtered = append(filtered, h.Raw)
				continue
			}
			cmd := h.Get("command").String()
			if !isManagedCommand(cmd) {
				filtered = append(filtered, h.Raw)
				continue
			}
			// Managed entry. Refresh + keep ONLY when this group's
			// matcher matches the desired matcher and we have not yet
			// placed one; otherwise drop so the desired-matcher group
			// receives it.
			if matcher == wantMatcher && !placed {
				refreshed, err := refreshManagedEntry(h.Raw, want)
				if err != nil {
					return false
				}
				if refreshed != h.Raw {
					groupChanged = true
				}
				filtered = append(filtered, refreshed)
				placed = true
				continue
			}
			// drop: stale matcher or duplicate.
			groupChanged = true
		}
		// If this group has the desired matcher and we still need to
		// place the managed entry, insert it here so we don't append a
		// new group for a matcher that already exists.
		if matcher == wantMatcher && !placed {
			filtered = append(filtered, wantRaw)
			placed = true
			groupChanged = true
		}
		if len(filtered) == 0 {
			listChanged = true
			continue
		}
		if !groupChanged {
			outGroups = append(outGroups, group.Raw)
			continue
		}
		updated, err := sjson.SetRawBytes([]byte(group.Raw), "hooks", []byte(configedit.RawArray(filtered)))
		if err != nil {
			return false
		}
		outGroups = append(outGroups, string(updated))
		listChanged = true
	}

	if !placed {
		groupRaw, err := newGroupRaw(wantMatcher, wantRaw)
		if err != nil {
			return false
		}
		outGroups = append(outGroups, groupRaw)
		added = true
		listChanged = true
	}

	if !listChanged {
		return added
	}

	patched, err := configedit.SetRaw(d.json, path, configedit.RawArray(outGroups))
	if err != nil {
		return false
	}
	d.json = patched
	return added
}

// newGroupRaw builds the matcher-group JSON: with `matcher` when
// wantMatcher is non-empty, omitting it otherwise.
func newGroupRaw(wantMatcher, hookRaw string) (string, error) {
	if wantMatcher == "" {
		group := struct {
			Hooks []json.RawMessage `json:"hooks"`
		}{Hooks: []json.RawMessage{json.RawMessage(hookRaw)}}
		return configedit.MarshalRawJSON(group)
	}
	group := struct {
		Matcher string            `json:"matcher"`
		Hooks   []json.RawMessage `json:"hooks"`
	}{Matcher: wantMatcher, Hooks: []json.RawMessage{json.RawMessage(hookRaw)}}
	return configedit.MarshalRawJSON(group)
}

// refreshManagedEntry rewrites type, command, timeout, and
// statusMessage on an existing DMG hook entry while preserving every
// other key the user might have added. Used so that a `hooks install`
// re-run after the binary path changes (e.g. `brew upgrade` relocated
// it) updates the absolute path in-place rather than leaving a stale
// entry behind.
func refreshManagedEntry(rawEntry string, want codexHookEntry) (string, error) {
	out := []byte(rawEntry)
	var err error
	out, err = sjson.SetBytes(out, "type", want.Type)
	if err != nil {
		return "", err
	}
	out, err = sjson.SetBytes(out, "command", want.Command)
	if err != nil {
		return "", err
	}
	out, err = sjson.SetBytes(out, "timeout", want.Timeout)
	if err != nil {
		return "", err
	}
	out, err = sjson.SetBytes(out, "statusMessage", want.StatusMessage)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// removeManagedHooks strips every DMG-owned entry (regex match on
// managedCmdRE). Returns the hook events from which at least one entry
// was removed. binaryPath is reserved for future scoping (e.g.,
// "remove only entries pointing at this specific binary"); today we
// remove any entry whose command matches managedCmdRE, regardless of
// the path token.
func (d *hooksDoc) removeManagedHooks(binaryPath string) []event.HookEvent {
	_ = binaryPath
	var removed []event.HookEvent
	hooksRoot := gjson.GetBytes(d.json, "hooks")
	if !hooksRoot.IsObject() {
		return nil
	}

	type hookKeyEntry struct {
		key  string
		list []gjson.Result
	}
	var events []hookKeyEntry
	hooksRoot.ForEach(func(k, v gjson.Result) bool {
		if v.IsArray() {
			events = append(events, hookKeyEntry{key: k.String(), list: v.Array()})
		}
		return true
	})

	for _, ev := range events {
		outGroups := make([]string, 0, len(ev.list))
		didRemove := false
		for _, group := range ev.list {
			if !group.IsObject() {
				outGroups = append(outGroups, group.Raw)
				continue
			}
			inner := group.Get("hooks").Array()
			filtered := make([]string, 0, len(inner))
			groupChanged := false
			for _, h := range inner {
				if h.IsObject() && isManagedCommand(h.Get("command").String()) {
					didRemove = true
					groupChanged = true
					continue
				}
				filtered = append(filtered, h.Raw)
			}
			if len(filtered) == 0 {
				continue
			}
			if !groupChanged {
				outGroups = append(outGroups, group.Raw)
				continue
			}
			updated, err := sjson.SetRawBytes([]byte(group.Raw), "hooks", []byte(configedit.RawArray(filtered)))
			if err != nil {
				return nil
			}
			outGroups = append(outGroups, string(updated))
		}
		if didRemove {
			removed = append(removed, event.HookEvent(ev.key))
		}
		if !didRemove {
			continue
		}
		path := configedit.Path("hooks", ev.key)
		if len(outGroups) == 0 {
			next, err := configedit.Delete(d.json, path)
			if err != nil {
				return nil
			}
			d.json = next
			continue
		}
		next, err := configedit.SetRaw(d.json, path, configedit.RawArray(outGroups))
		if err != nil {
			return nil
		}
		d.json = next
	}

	if hooks := gjson.GetBytes(d.json, "hooks"); hooks.IsObject() {
		empty := true
		hooks.ForEach(func(k, v gjson.Result) bool {
			empty = false
			return false
		})
		if empty {
			next, err := configedit.Delete(d.json, "hooks")
			if err == nil {
				d.json = next
			}
		}
	}

	slices.SortFunc(removed, func(a, b event.HookEvent) int {
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		}
		return 0
	})
	return removed
}

// writeHooksAtomic installs doc.json through atomicfile. When the
// upsert pipeline produced no structural change, doc.json is
// byte-identical to doc.orig and the call is a complete no-op (no
// backup, no write, returns nil result). Otherwise the entire file is
// pretty-printed with 2-space indent so the result is human-readable.
func writeHooksAtomic(path string, doc *hooksDoc) (*atomicfile.WriteResult, error) {
	if !json.Valid(doc.json) {
		return nil, fmt.Errorf("codex hooks: invalid JSON after edit")
	}
	if bytes.Equal(doc.json, doc.orig) {
		return nil, nil
	}
	out := pretty.PrettyOptions(doc.json, &pretty.Options{Indent: "  ", Width: 80})
	if bytes.Equal(out, doc.orig) {
		return nil, nil
	}
	mode := atomicfile.PickMode(path, settingsMode)
	wr, err := atomicfile.WriteAtomic(path, out, mode)
	if err != nil {
		return nil, err
	}
	return &wr, nil
}

// loadConfigTOMLBytes reads ~/.codex/config.toml and returns the raw
// bytes. We do NOT round-trip through go-toml's marshaller for writes
// because that reorders keys and discards comments. Callers patch the
// bytes via configedit.EnsureCodexHooksFlag.
//
// Missing files return (nil, nil). Malformed TOML is rejected here so
// install can abort BEFORE hooks.json is touched (multi-file safety;
// see TestInstallMalformedTOMLDoesNotMutateHooks).
func loadConfigTOMLBytes(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("codex config read: %w", err)
	}
	probe := map[string]any{}
	if len(bytes.TrimSpace(b)) > 0 {
		if err := toml.Unmarshal(b, &probe); err != nil {
			return nil, fmt.Errorf("codex config parse: %w", err)
		}
	}
	return b, nil
}

// writeConfigAtomic installs encoded as the new config.toml contents
// via atomicfile. Returns nil, nil when encoded is byte-identical to
// the existing file (no-op).
func writeConfigAtomic(path string, encoded []byte) (*atomicfile.WriteResult, error) {
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, encoded) {
		return nil, nil
	}
	mode := atomicfile.PickMode(path, settingsMode)
	wr, err := atomicfile.WriteAtomic(path, encoded, mode)
	if err != nil {
		return nil, err
	}
	return &wr, nil
}

