package devcli

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type progressMode int

const (
	progressPlain progressMode = iota // one line per step, for a terminal without cursor control
	progressLine                      // one line, redrawn in place
	progressList                      // finished steps stay listed above the active one
)

// scanProgress shows a scan as it runs and removes itself when the report is
// ready. Stage changes render synchronously, while the ticker keeps a slow
// collector visibly alive.
type scanProgress struct {
	out      *os.File
	mode     progressMode
	color    bool
	estimate time.Duration // how long the previous scan took; zero if unknown
	stop     chan struct{}
	wg       sync.WaitGroup

	mu        sync.Mutex
	start     time.Time
	stepStart time.Time
	label     string
	done      int
	skipped   int
	lines     int // finished steps left on screen
	columns   int
}

func newScanProgress(out *os.File, mode progressMode, color bool, estimate time.Duration) *scanProgress {
	return &scanProgress{out: out, mode: mode, color: color, estimate: estimate, stop: make(chan struct{})}
}

func (p *scanProgress) paint(code, s string) string {
	if !p.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p *scanProgress) StepStart(label string) {
	if p.mode == progressPlain {
		fmt.Fprintln(p.out, label+"…")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.start.IsZero() {
		p.start = now
		p.wg.Go(p.animate)
	}
	p.label, p.stepStart = label, now
	p.draw()
}

func (p *scanProgress) StepDone(took time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done++
	p.finish(p.paint(green, "✓"), stepTime(took))
}

func (p *scanProgress) StepSkip(string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.skipped++
	p.finish(p.paint(dim, "–"), "skipped")
}

const labelWidth = 36

// finish moves the active step into the list. When the list would outgrow the
// screen it stops growing, because lines that scroll away cannot be removed.
func (p *scanProgress) finish(mark, note string) {
	label := p.label
	p.label = "Preparing inventory"
	if p.mode != progressList || label == "" {
		return
	}
	p.label = ""
	if rows := terminalRows(p.out); rows > 0 && p.lines >= rows-2 {
		return
	}
	width, _ := terminalWidth(p.out)
	if width == 0 {
		width = 80
	}
	fmt.Fprint(p.out, "\r\x1b[K  ", mark, " ", pad(clip(label, min(labelWidth, width-14), false), labelWidth), " ", p.paint(dim, note), "\n")
	p.lines++
}

func stepTime(d time.Duration) string {
	if d < 10*time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return clock(d)
}

func clock(d time.Duration) string {
	seconds := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", seconds/60, seconds%60)
}

const frameInterval = 125 * time.Millisecond

func (p *scanProgress) animate() {
	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.mu.Lock()
			p.draw()
			p.mu.Unlock()
		}
	}
}

func (p *scanProgress) draw() {
	width, _ := terminalWidth(p.out)
	if width == 0 {
		width = 80
	}
	// Leave the last column empty to avoid an automatic line wrap.
	width = max(0, width-1)
	now := time.Now()
	if p.mode == progressList {
		icon, label, tail := activeFrame(p.label, now.Sub(p.stepStart), now.Sub(p.start), p.estimate, width)
		fmt.Fprint(p.out, "\r\x1b[K  ", p.paint(cyan, icon), " ", label, p.paint(dim, tail))
		return
	}
	frame := progressFrame(p.label, now.Sub(p.start), p.done, p.skipped, width)
	padding := max(0, min(p.columns, width)-len([]rune(frame)))
	fmt.Fprint(p.out, "\r", frame, strings.Repeat(" ", padding))
	p.columns = len([]rune(frame))
}

var spinnerFrames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// activeFrame is the line under the list: the running step and its time, then
// the whole scan's time against the previous scan's when that is known.
func activeFrame(label string, step, total, estimate time.Duration, cols int) (icon, text, tail string) {
	icon = spinnerFrames[int64(total/frameInterval)%int64(len(spinnerFrames))]
	if label == "" {
		label = "Finishing"
	}
	tail = "   " + clock(total) + " so far"
	if left := estimate - total; estimate > 0 && left >= time.Second {
		tail = "   about " + clock(left) + " left"
	}
	text = pad(clip(label, labelWidth, false), labelWidth) + " " + clock(step)
	if 4+width(text)+width(tail) > cols {
		tail = ""
	}
	if room := cols - 4; width(text) > room {
		text = clip(label, max(1, room), false)
	}
	return icon, text, tail
}

func progressFrame(label string, elapsed time.Duration, done, skipped, width int) string {
	icon := spinnerFrames[int64(elapsed/frameInterval)%int64(len(spinnerFrames))]
	prefix := icon + "  "
	seconds := int(elapsed.Seconds())
	timer := fmt.Sprintf("  %d:%02d", seconds/60, seconds%60)
	counts := fmt.Sprintf("  ·  %d done", done)
	if skipped > 0 {
		counts += fmt.Sprintf("  ·  %d skipped", skipped)
	}
	if len([]rune(prefix+label+timer+counts)) > width {
		counts = ""
	}
	room := width - len([]rune(prefix+timer+counts))
	if room < 2 {
		return string([]rune(icon)[:min(1, width)])
	}
	if chars := []rune(label); len(chars) > room {
		label = string(chars[:room-1]) + "…"
	}
	return prefix + label + timer + counts
}

func (p *scanProgress) close() {
	close(p.stop)
	p.wg.Wait()
	switch {
	case p.mode == progressList && !p.start.IsZero():
		fmt.Fprint(p.out, "\r\x1b[K")
		if p.lines > 0 {
			fmt.Fprintf(p.out, "\x1b[%dA\x1b[J", p.lines)
		}
	case p.columns > 0:
		fmt.Fprint(p.out, "\r", strings.Repeat(" ", p.columns), "\r")
	}
}
