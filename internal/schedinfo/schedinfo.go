// Package schedinfo gathers and logs the agent's own scheduler state —
// launchd on macOS, Task Scheduler on Windows, systemd on Linux — for
// troubleshooting. It answers "did the agent run, when, how often, and how
// is it scheduled?" from inside agent.log, so an operator no longer has to
// reproduce `launchctl print` / `schtasks /query /v` by hand (the manual
// recipes live in docs/launchd-troubleshooting.md).
//
// Every gather path is best-effort: short per-command timeouts, failures
// recorded in Info.Warnings, and Gather never returns an error — a flaky
// launchctl/schtasks/systemctl call can't fail a scan. The pure parse
// helpers live in this (untagged) file so they compile and unit-test on any
// OS; the platform files only orchestrate the subprocess calls.
package schedinfo

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// queryTimeout caps each scheduler-introspection subprocess. Kept short so
// the whole phase stays well inside its budget even if several queries hang
// (launchctl over a broken session, schtasks during a Schedule-service
// hiccup).
const queryTimeout = 3 * time.Second

// Management classifies who owns the scheduler entry, inferred from the
// program the plist/task invokes.
type Management string

const (
	ManagementUnknown Management = "unknown"
	ManagementLoader  Management = "loader" // runs stepsecurity-loader.{sh,ps1}
	ManagementBinary  Management = "binary" // runs the agent binary directly
)

// Info is a best-effort snapshot of the agent's scheduler state. Empty
// strings / zero ints mean "unknown"; pointer fields are nil when the value
// could not be determined (distinct from a real zero).
type Info struct {
	Platform        string     // runtime.GOOS
	Manager         string     // "launchd" | "schtasks" | "systemd" | ""
	Scheduled       bool       // a scheduler footprint exists on disk
	Loaded          bool       // the scheduler currently knows the job
	Management      Management // loader vs binary vs unknown
	Label           string     // launchd label / windows task name / systemd unit
	UnitPath        string     // plist / unit path ("" on windows)
	State           string     // launchd "state" / schtasks "Status"
	IntervalSeconds int        // schedule interval (0 = unknown)
	ConfiguredHours int        // config.ScanFrequencyHours (cross-check)
	RunAtLoad       *bool      // macOS only; nil elsewhere
	LastRunTime     string     // human-readable last-run
	LastExitCode    *int       // launchd "last exit code" / windows "Last Result"
	NextRunTime     string     // windows "Next Run Time"; "" where unavailable
	MissedRuns      *int       // windows "Number of Missed Runs"; nil elsewhere
	PID             *int       // running PID when in-flight
	LogMtime        time.Time  // mtime of <Home>/agent.log as a last-run proxy
	Raw             string     // raw command output, logged at Debug
	Warnings        []string   // per-query failures / drift notes, logged at Warn
}

// Gather collects scheduler state for the current platform. Best-effort;
// never returns an error.
func Gather(ctx context.Context, exec executor.Executor) Info {
	return gather(ctx, exec)
}

// Log emits info's headline fields at Progress, the raw command dump at
// Debug, and any warnings at Warn. Safe to call with a zero Info.
func Log(info Info, log *progress.Logger) {
	manager := info.Manager
	if manager == "" {
		manager = "none"
	}
	log.Progress("  Manager: %s (footprint=%v loaded=%v management=%s)", manager, info.Scheduled, info.Loaded, info.Management)

	interval := "unknown"
	if info.IntervalSeconds > 0 {
		interval = fmt.Sprintf("%ds (~%dh)", info.IntervalSeconds, info.IntervalSeconds/3600)
	}
	log.Progress("  Interval: %s (config=%dh)", interval, info.ConfiguredHours)

	switch {
	case info.LastRunTime != "":
		log.Progress("  Last run: %s", info.LastRunTime)
	case !info.LogMtime.IsZero():
		log.Progress("  Last run (agent.log mtime): %s", info.LogMtime.Format(time.RFC3339))
	}
	if info.NextRunTime != "" {
		log.Progress("  Next run: %s", info.NextRunTime)
	}
	if info.LastExitCode != nil {
		log.Progress("  Last exit code: %d", *info.LastExitCode)
	}
	if info.RunAtLoad != nil {
		log.Progress("  RunAtLoad: %v", *info.RunAtLoad)
	}
	if info.MissedRuns != nil {
		log.Progress("  Missed runs: %d", *info.MissedRuns)
	}
	if info.State != "" {
		log.Progress("  State: %s", info.State)
	}
	if info.PID != nil {
		log.Progress("  PID: %d", *info.PID)
	}
	if info.UnitPath != "" {
		log.Progress("  Unit: %s", info.UnitPath)
	}

	// Full scheduler detail, line-prefixed so it stays readable in agent.log —
	// the macOS/Linux analog of `schtasks /query /v /fo LIST`. Capped so a
	// verbose `launchctl print` can't flood the log; the parsed summary above
	// always carries the headline fields, and --verbose dumps the full text.
	if info.Raw != "" {
		log.Progress("  ----- scheduler detail (%s) -----", manager)
		lines := strings.Split(strings.TrimRight(info.Raw, "\n"), "\n")
		const maxLines = 80
		for i, line := range lines {
			if i >= maxLines {
				log.Progress("  | ... (%d more lines; run with --verbose for the full text)", len(lines)-maxLines)
				break
			}
			log.Progress("  | %s", line)
		}
		log.Progress("  ---------------------------------")
		log.Debug("scheduler raw query output:\n%s", info.Raw)
	}
	for _, w := range info.Warnings {
		log.Warn("scheduler: %s", w)
	}
}

// configuredHours returns the configured scan frequency in hours, defaulting
// to 4 when the value is unset, the build placeholder, or non-positive —
// mirroring the installers' fallback.
func configuredHours() int {
	h, _ := strconv.Atoi(config.ScanFrequencyHours)
	if h <= 0 {
		return 4
	}
	return h
}

// logMtime returns the mtime of <Home>/agent.log as a last-run proxy, or the
// zero time when it can't be resolved.
func logMtime() time.Time {
	home := paths.Home()
	if home == "" {
		return time.Time{}
	}
	fi, err := os.Stat(filepath.Join(home, "agent.log"))
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// firstLine returns the first non-empty line of s, trimmed — used to keep
// multi-line stderr out of a single Warn line.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if before, _, found := strings.Cut(s, "\n"); found {
		return strings.TrimSpace(before)
	}
	return s
}

// managementFromCmd infers loader-vs-binary management from a program/command
// string (launchd ProgramArguments joined, or a schtasks "Task To Run" line).
func managementFromCmd(cmd string) Management {
	lc := strings.ToLower(cmd)
	switch {
	case strings.Contains(lc, "stepsecurity-loader"):
		return ManagementLoader
	case strings.Contains(lc, "stepsecurity-dev-machine-guard"), strings.Contains(lc, "send-telemetry"):
		return ManagementBinary
	default:
		return ManagementUnknown
	}
}

// --- launchd plist parsing (darwin) --------------------------------------

type parsedPlist struct {
	StartInterval    int
	RunAtLoad        bool
	ProgramArguments []string
}

// parsePlist extracts StartInterval, RunAtLoad, and ProgramArguments from our
// own well-formed launchd plist via a token stream. Reading the file beats
// scraping `plutil` output and avoids a subprocess. Keys we don't care about
// (and nested dicts like EnvironmentVariables) are ignored.
func parsePlist(data []byte) (parsedPlist, error) {
	var pl parsedPlist
	dec := xml.NewDecoder(bytes.NewReader(data))
	curKey := ""
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return pl, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "key":
			var k string
			if err := dec.DecodeElement(&k, &se); err != nil {
				return pl, err
			}
			curKey = strings.TrimSpace(k)
			continue // preserve curKey for the value element that follows
		case "true":
			if curKey == "RunAtLoad" {
				pl.RunAtLoad = true
			}
		case "false":
			if curKey == "RunAtLoad" {
				pl.RunAtLoad = false
			}
		case "integer":
			var v string
			if err := dec.DecodeElement(&v, &se); err != nil {
				return pl, err
			}
			if curKey == "StartInterval" {
				pl.StartInterval, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		case "array":
			if curKey == "ProgramArguments" {
				args, err := decodeStringArray(dec, se)
				if err != nil {
					return pl, err
				}
				pl.ProgramArguments = args
			}
		}
		curKey = "" // any non-key value element ends the current key
	}
	return pl, nil
}

// decodeStringArray reads <string> children until the matching </array>.
func decodeStringArray(dec *xml.Decoder, start xml.StartElement) ([]string, error) {
	var out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return out, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "string" {
				var s string
				if err := dec.DecodeElement(&s, &t); err != nil {
					return out, err
				}
				out = append(out, s)
			}
		case xml.EndElement:
			if t.Name.Local == start.Name.Local {
				return out, nil
			}
		}
	}
}

// --- launchctl output parsing (darwin) -----------------------------------

// applyLaunchctlPrint pulls state/pid/last-exit-code from `launchctl print`
// output (lines of the form `key = value`).
func applyLaunchctlPrint(info *Info, out string) {
	if v, ok := scanField(out, "state"); ok {
		info.State = v
	}
	if v, ok := scanField(out, "pid"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			info.PID = &n
		}
	}
	if v, ok := scanField(out, "last exit code"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			info.LastExitCode = &n
		}
	}
}

// applyLaunchctlList pulls LastExitStatus/PID from `launchctl list <label>`
// output (a plist-style dict), only filling fields print didn't already set.
func applyLaunchctlList(info *Info, out string) {
	if v, ok := scanQuotedField(out, "LastExitStatus"); ok && info.LastExitCode == nil {
		if n, err := strconv.Atoi(v); err == nil {
			info.LastExitCode = &n
		}
	}
	if v, ok := scanQuotedField(out, "PID"); ok && info.PID == nil {
		if n, err := strconv.Atoi(v); err == nil {
			info.PID = &n
		}
	}
}

// scanField finds a `key = value` line (key bounded by `=`), tolerant of
// leading indentation.
func scanField(out, key string) (string, bool) {
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, key) {
			continue
		}
		rest := strings.TrimSpace(line[len(key):])
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(rest, "=")), true
	}
	return "", false
}

// scanQuotedField finds a `"Key" = value;` line from a launchctl-list dict.
func scanQuotedField(out, key string) (string, bool) {
	needle := `"` + key + `"`
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, needle) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, needle))
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(rest, "="))
		val = strings.TrimSpace(strings.TrimSuffix(val, ";"))
		return strings.Trim(val, `"`), true
	}
	return "", false
}

// --- schtasks output parsing (windows) -----------------------------------

// applySchtasksList pulls the run/result/schedule fields from
// `schtasks /query /v /fo LIST` output. Field labels are English and matched
// case-insensitively; a non-English Windows simply yields fewer fields.
func applySchtasksList(info *Info, out string) {
	if v, ok := scanColonField(out, "Last Run Time"); ok {
		info.LastRunTime = v
	}
	if v, ok := scanColonField(out, "Next Run Time"); ok {
		info.NextRunTime = v
	}
	if v, ok := scanColonField(out, "Status"); ok {
		info.State = v
	}
	if v, ok := scanColonField(out, "Last Result"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			info.LastExitCode = &n
		}
	}
	if v, ok := scanColonField(out, "Number of Missed Runs"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			info.MissedRuns = &n
		}
	}
	if v, ok := scanColonField(out, "Task To Run"); ok {
		info.Management = managementFromCmd(v)
	}
}

// scanColonField finds a `Label: value` line, matching the label
// case-insensitively and exactly (so "Last Run Time" doesn't match
// "Run Time").
func scanColonField(out, label string) (string, bool) {
	ll := strings.ToLower(label)
	for line := range strings.SplitSeq(out, "\n") {
		name, val, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		if strings.ToLower(strings.TrimSpace(name)) != ll {
			continue
		}
		return strings.TrimSpace(val), true
	}
	return "", false
}
