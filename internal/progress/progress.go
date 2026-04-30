package progress

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Level controls which messages a Logger emits. Higher values are more verbose.
type Level int

const (
	// levelOff suppresses everything, including errors. Used by NewNoop.
	levelOff Level = iota - 1
	// LevelError emits only errors.
	LevelError
	// LevelWarn emits errors and warnings.
	LevelWarn
	// LevelInfo emits errors, warnings, and progress/step messages. Default.
	LevelInfo
	// LevelDebug emits everything including detailed diagnostic logs.
	LevelDebug
)

// ParseLevel parses a case-insensitive level string ("error", "warn", "info", "debug").
// Returns false if the string is unrecognised.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return LevelError, true
	case "warn", "warning":
		return LevelWarn, true
	case "info":
		return LevelInfo, true
	case "debug":
		return LevelDebug, true
	}
	return LevelInfo, false
}

// String returns the canonical lowercase name of the level.
func (l Level) String() string {
	switch l {
	case LevelError:
		return "error"
	case LevelWarn:
		return "warn"
	case LevelInfo:
		return "info"
	case LevelDebug:
		return "debug"
	}
	return "off"
}

// Logger handles leveled output to stderr.
// Logging format:
//
//	2006-01-02 15:04:05 [scanning] message   — progress (info+)
//	2006-01-02 15:04:05 [warning] message    — warnings (warn+)
//	2006-01-02 15:04:05 [error] message      — errors (error+)
//	2006-01-02 15:04:05 [debug] message      — diagnostics (debug only)
//	⠋ label... (Xms)                         — spinner animation (info+)
//	✓ label (Xms)                            — step done (info+)
//	○ label (skipped)                        — step skipped (info+)
type Logger struct {
	level   Level
	spinner *spinner
}

// NewLogger creates a Logger that emits messages at or below the given level.
func NewLogger(level Level) *Logger {
	return &Logger{level: level}
}

// NewNoop returns a Logger that suppresses all output, including errors.
func NewNoop() *Logger {
	return &Logger{level: levelOff}
}

// Level returns the logger's current level.
func (l *Logger) Level() Level {
	return l.level
}

// Progress prints a progress message to stderr when level >= info.
// Format: [scanning] message
func (l *Logger) Progress(format string, args ...any) {
	if l.level < LevelInfo {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "\033[2m%s [scanning]\033[0m %s\n", ts, fmt.Sprintf(format, args...))
}

// Warn prints a warning to stderr when level >= warn.
func (l *Logger) Warn(format string, args ...any) {
	if l.level < LevelWarn {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "%s \033[0;33m[warning]\033[0m %s\n", ts, fmt.Sprintf(format, args...))
}

// Error prints an error to stderr when level >= error (i.e. unless noop).
// Format: [error] message
func (l *Logger) Error(format string, args ...any) {
	if l.level < LevelError {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "%s \033[0;31m[error]\033[0m %s\n", ts, fmt.Sprintf(format, args...))
}

// Debug prints a diagnostic message to stderr when level >= debug.
// Format: [debug] message
func (l *Logger) Debug(format string, args ...any) {
	if l.level < LevelDebug {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "\033[2m%s [debug] %s\033[0m\n", ts, fmt.Sprintf(format, args...))
}

// StepStart begins a labeled progress step with a spinner.
func (l *Logger) StepStart(label string) {
	if l.level < LevelInfo {
		return
	}
	l.spinner = newSpinner(label)
	l.spinner.run()
}

// StepDone completes the current step, showing elapsed time.
func (l *Logger) StepDone(elapsed time.Duration) {
	if l.level < LevelInfo || l.spinner == nil {
		return
	}
	l.spinner.stopDone(elapsed)
	l.spinner = nil
}

// StepSkip marks the current step as skipped.
func (l *Logger) StepSkip(reason string) {
	if l.level < LevelInfo || l.spinner == nil {
		return
	}
	l.spinner.stopSkip(reason)
	l.spinner = nil
}

// spinner renders an animated progress indicator on stderr.
type spinner struct {
	label     string
	startedAt time.Time
	stopCh    chan stopMsg
	wg        sync.WaitGroup
}

type stopMsg struct {
	kind    string // "done" or "skip"
	reason  string
	elapsed time.Duration
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func newSpinner(label string) *spinner {
	return &spinner{
		label:     label,
		startedAt: time.Now(),
		stopCh:    make(chan stopMsg, 1),
	}
}

func (s *spinner) run() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		i := 0
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case msg := <-s.stopCh:
				switch msg.kind {
				case "done":
					ms := msg.elapsed.Milliseconds()
					fmt.Fprintf(os.Stderr, "\r  ✓ %s (%dms)\033[K\n", s.label, ms)
				case "skip":
					fmt.Fprintf(os.Stderr, "\r  ○ %s (skipped)\033[K\n", s.label)
				}
				return
			case <-ticker.C:
				ms := time.Since(s.startedAt).Milliseconds()
				fmt.Fprintf(os.Stderr, "\r  %s %s... (%dms)\033[K", spinnerFrames[i%len(spinnerFrames)], s.label, ms)
				i++
			}
		}
	}()
}

func (s *spinner) stopDone(elapsed time.Duration) {
	s.stopCh <- stopMsg{kind: "done", elapsed: elapsed}
	s.wg.Wait()
}

func (s *spinner) stopSkip(reason string) {
	s.stopCh <- stopMsg{kind: "skip", reason: reason}
	s.wg.Wait()
}
