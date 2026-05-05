package claudecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"

	"github.com/tidwall/gjson"
	"github.com/tidwall/pretty"
	"github.com/tidwall/sjson"

	"github.com/step-security/dev-machine-guard/internal/aiagents/atomicfile"
	"github.com/step-security/dev-machine-guard/internal/aiagents/configedit"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
)

// settingsDoc holds raw bytes for ~/.claude/settings.json. orig is the
// bytes as read from disk (nil if the file did not exist); json is the
// in-memory mutation buffer that starts equal to orig (or `{}` for
// missing/empty input). All edits go through tidwall/sjson so that
// unrelated user formatting is preserved byte-for-byte.
//
// Hooks have this shape per Claude Code docs:
//
//	"hooks": {
//	  "PreToolUse": [
//	    {
//	      "matcher": "*",
//	      "hooks": [
//	        {"type": "command", "command": "...", "timeout": 30}
//	      ]
//	    }
//	  ]
//	}
type settingsDoc struct {
	orig []byte
	json []byte
}

const (
	hookTimeoutSeconds = 30
	matcherAll         = "*"
)

// settingsMode is the default mode for ~/.claude/settings.json. The
// atomicfile helpers preserve a tighter existing mode if present.
const settingsMode = os.FileMode(0o600)

// managedCmdRE is the uninstall match criterion (plan §1.4). It matches
// an entry's `command` field when the executable token is the DMG
// binary, regardless of which absolute path it sits behind. The
// `(^|/)` left-side accepts both bare invocations and absolute-path
// invocations, while rejecting prefix collisions like
// `mystepsecurity-dev-machine-guard`.
var managedCmdRE = regexp.MustCompile(`(^|/)stepsecurity-dev-machine-guard\s+_hook\s+`)

func loadSettings(path string) (*settingsDoc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &settingsDoc{json: []byte(`{}`)}, nil
		}
		return nil, fmt.Errorf("claude settings read: %w", err)
	}
	normalized, err := configedit.NormalizeJSONObject(b)
	if err != nil {
		return nil, fmt.Errorf("claude settings parse: %w", err)
	}
	return &settingsDoc{orig: b, json: normalized}, nil
}

func hookEventPath(hookType event.HookEvent) string {
	return configedit.Path("hooks", string(hookType))
}

// hookEntry is the inner record we install. DMG entries are identified
// on uninstall by the regex `managedCmdRE` matching the command
// field, not by a metadata marker.
type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

func installEntry(command string) hookEntry {
	return hookEntry{
		Type:    "command",
		Command: command,
		Timeout: hookTimeoutSeconds,
	}
}

// isManagedCommand reports whether cmd is a DMG-installed hook entry,
// per the plan §1.4 matcher. It explicitly does NOT match legacy
// pre-port hook entries left by other tools (plan §7).
func isManagedCommand(cmd string) bool {
	return managedCmdRE.MatchString(cmd)
}

// upsertHook adds or refreshes the DMG matcher entry for one hook
// type while preserving every unrelated user matcher and inner hook.
// When the desired entry is already in place, the JSON document bytes
// are not touched at all so a re-install on a pretty-printed file does
// not collapse formatting.
//
// command is the literal string to write into the entry's `command`
// field — the adapter computes it via a.commandFor(hookType) so the
// settings document never embeds the binary path resolution logic.
func (s *settingsDoc) upsertHook(hookType event.HookEvent, command string) (added bool) {
	want := installEntry(command)
	wantRaw, err := configedit.MarshalRawJSON(want)
	if err != nil {
		return false
	}
	path := hookEventPath(hookType)
	list := gjson.GetBytes(s.json, path).Array()

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

		filteredInner := make([]string, 0, len(inner)+1)
		innerChanged := false
		for _, h := range inner {
			if !h.IsObject() {
				filteredInner = append(filteredInner, h.Raw)
				continue
			}
			cmd := h.Get("command").String()
			if isManagedCommand(cmd) {
				refreshed, err := refreshManagedEntry(h.Raw, want)
				if err != nil {
					return false
				}
				if refreshed != h.Raw {
					innerChanged = true
				}
				filteredInner = append(filteredInner, refreshed)
				placed = true
				continue
			}
			filteredInner = append(filteredInner, h.Raw)
		}
		if matcher == matcherAll && !placed {
			filteredInner = append(filteredInner, wantRaw)
			placed = true
			innerChanged = true
		}
		if len(filteredInner) == 0 {
			listChanged = true
			continue
		}
		if !innerChanged {
			outGroups = append(outGroups, group.Raw)
			continue
		}
		updated, err := sjson.SetRawBytes([]byte(group.Raw), "hooks", []byte(configedit.RawArray(filteredInner)))
		if err != nil {
			return false
		}
		outGroups = append(outGroups, string(updated))
		listChanged = true
	}

	if !placed {
		newGroup := struct {
			Matcher string      `json:"matcher"`
			Hooks   []hookEntry `json:"hooks"`
		}{Matcher: matcherAll, Hooks: []hookEntry{want}}
		raw, err := configedit.MarshalRawJSON(newGroup)
		if err != nil {
			return false
		}
		outGroups = append(outGroups, raw)
		added = true
		listChanged = true
	}

	if !listChanged {
		return added
	}

	patched, err := configedit.SetRaw(s.json, path, configedit.RawArray(outGroups))
	if err != nil {
		return false
	}
	s.json = patched
	return added
}

// refreshManagedEntry rewrites type, command, and timeout on an existing
// DMG hook entry while preserving every other key the user might have
// added. Used so that a `hooks install` re-run after the binary path
// changes (e.g. `brew upgrade` relocated it) updates the absolute path
// in-place rather than leaving a stale entry behind.
func refreshManagedEntry(rawEntry string, want hookEntry) (string, error) {
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
	return string(out), nil
}

// removeManagedHooks strips every DMG-owned entry (regex match per
// plan §1.4). Returns the hook events from which at least one entry
// was removed. binaryPath is reserved for future scoping (e.g.,
// "remove only entries pointing at this specific binary"); Phase 1
// removes any entry whose command matches managedCmdRE, regardless of
// the path token.
func (s *settingsDoc) removeManagedHooks(binaryPath string) []event.HookEvent {
	_ = binaryPath
	var removed []event.HookEvent
	hooksRoot := gjson.GetBytes(s.json, "hooks")
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
			filteredInner := make([]string, 0, len(inner))
			groupChanged := false
			for _, h := range inner {
				if h.IsObject() && isManagedCommand(h.Get("command").String()) {
					didRemove = true
					groupChanged = true
					continue
				}
				filteredInner = append(filteredInner, h.Raw)
			}
			if len(filteredInner) == 0 {
				continue
			}
			if !groupChanged {
				outGroups = append(outGroups, group.Raw)
				continue
			}
			updated, err := sjson.SetRawBytes([]byte(group.Raw), "hooks", []byte(configedit.RawArray(filteredInner)))
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
			next, err := configedit.Delete(s.json, path)
			if err != nil {
				return nil
			}
			s.json = next
			continue
		}
		next, err := configedit.SetRaw(s.json, path, configedit.RawArray(outGroups))
		if err != nil {
			return nil
		}
		s.json = next
	}

	if hooks := gjson.GetBytes(s.json, "hooks"); hooks.IsObject() {
		empty := true
		hooks.ForEach(func(k, v gjson.Result) bool {
			empty = false
			return false
		})
		if empty {
			next, err := configedit.Delete(s.json, "hooks")
			if err == nil {
				s.json = next
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

// writeAtomic installs doc.json through atomicfile. When the upsert
// pipeline produced no structural change, doc.json is byte-identical
// to doc.orig and the call is a complete no-op (no backup, no write,
// returns nil result). Otherwise the entire file is pretty-printed
// with 2-space indent so the result is human-readable.
//
// Returns nil, nil on no-op. Returns &WriteResult, nil on a successful
// write. The caller copies fields into adapter.InstallResult /
// adapter.UninstallResult so the install handler can chown them under
// root.
func writeAtomic(path string, doc *settingsDoc) (*atomicfile.WriteResult, error) {
	if !json.Valid(doc.json) {
		return nil, fmt.Errorf("claude settings: invalid JSON after edit")
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
