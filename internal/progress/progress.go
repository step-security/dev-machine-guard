package progress

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger handles progress output to stderr.
// Logging format:
//
//	2006-01-02 15:04:05 [scanning] message   — progress (suppressed in quiet mode)
//	2006-01-02 15:04:05 [error] message      — errors (never suppressed)
//	⠋ label... (Xms)                         — spinner animation
//	✓ label (Xms)                            — step done
//	○ label (skipped)                        — step skipped
type Logger struct {
	quiet   bool
	spinner *spinner
}

// NewLogger creates a Logger. If quiet is true, progress messages are suppressed.
func NewLogger(quiet bool) *Logger {
	return &Logger{quiet: quiet}
}

// NewNoop returns a Logger that suppresses all output.
func NewNoop() *Logger {
	return &Logger{quiet: true}
}

// Progress prints a progress message to stderr (suppressed in quiet mode).
// Format: [scanning] message
func (l *Logger) Progress(format string, args ...any) {
	if l.quiet {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "\033[2m%s [scanning]\033[0m %s\n", ts, fmt.Sprintf(format, args...))
}

// Warn always prints to stderr regardless of quiet mode.
// Use for important operational messages that should be visible even in enterprise (quiet) mode.
func (l *Logger) Warn(format string, args ...any) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "%s \033[0;33m[warning]\033[0m %s\n", ts, fmt.Sprintf(format, args...))
}

// Error always prints to stderr regardless of quiet mode.
// Format: [error] message
func (l *Logger) Error(format string, args ...any) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "%s \033[0;31m[error]\033[0m %s\n", ts, fmt.Sprintf(format, args...))
}

// StepStart begins a labeled progress step with a spinner.
func (l *Logger) StepStart(label string) {
	if l.quiet {
		return
	}
	l.spinner = newSpinner(label)
	l.spinner.run()
}

// StepDone completes the current step, showing elapsed time.
func (l *Logger) StepDone(elapsed time.Duration) {
	if l.quiet || l.spinner == nil {
		return
	}
	l.spinner.stopDone(elapsed)
	l.spinner = nil
}

// StepSkip marks the current step as skipped.
func (l *Logger) StepSkip(reason string) {
	if l.quiet || l.spinner == nil {
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
