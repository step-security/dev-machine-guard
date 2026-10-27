package faultinject

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MalformedExitCode is how a fault build exits on a malformed DMG_FAULT or
// Baked spec: distinct from every fault action and from a Go panic (2), so
// it can't pass for a crash.
const MalformedExitCode = 64

// MalformedMarker starts the stderr line written before that exit; drivers
// fail the test when they see it.
const MalformedMarker = "faultinject: malformed spec:"

// Validate checks a DMG_FAULT / Baked spec. Test drivers and harnesses
// call it before launching a process with one, so a typo fails at setup.
// It is available in every build and reads no environment.
func Validate(spec string) error {
	_, err := parse(spec)
	return err
}

type rule struct {
	checkpoint string
	principal  string // "", "user" or "system"
	action     string
}

// parse splits a spec list. Every entry must be <checkpoint>[@user|@system]:<action>
// with a known action; the action is split off the last ':' because
// checkpoint names contain ':' (S4.downloaded:<asset>).
func parse(spec string) ([]rule, error) {
	var rules []rule
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		i := strings.LastIndexByte(entry, ':')
		if i <= 0 || i == len(entry)-1 {
			return nil, fmt.Errorf("entry %q: want <checkpoint>:<action>", entry)
		}
		r := rule{checkpoint: entry[:i], action: entry[i+1:]}
		if !validAction(r.action) {
			return nil, fmt.Errorf("entry %q: unknown action %q", entry, r.action)
		}
		if j := strings.LastIndexByte(r.checkpoint, '@'); j >= 0 {
			switch p := r.checkpoint[j+1:]; p {
			case "user", "system":
				r.principal, r.checkpoint = p, r.checkpoint[:j]
			default:
				return nil, fmt.Errorf("entry %q: unknown principal qualifier %q (want @user or @system)", entry, p)
			}
		}
		if r.checkpoint == "" {
			return nil, fmt.Errorf("entry %q: empty checkpoint", entry)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func validAction(a string) bool {
	switch a {
	case "kill", "err", "hang", "diskfull", "panic":
		return true
	}
	if _, ok := sleepAction(a); ok {
		return true
	}
	n, ok := strings.CutPrefix(a, "exit")
	code, err := strconv.Atoi(n)
	// MalformedExitCode is reserved: a fault may not imitate a bad spec.
	return ok && err == nil && code >= 0 && code != MalformedExitCode
}

// MaxSleep bounds the sleep<duration> action.
const MaxSleep = 10 * time.Minute

// sleepAction parses sleep<duration> (Go syntax, 0 < d <= MaxSleep).
func sleepAction(a string) (time.Duration, bool) {
	v, ok := strings.CutPrefix(a, "sleep")
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 || d > MaxSleep {
		return 0, false
	}
	return d, true
}
