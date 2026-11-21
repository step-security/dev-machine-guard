package devcli

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestProgressFitsTerminal(t *testing.T) {
	const stage = "Scanning Node.js projects"
	for width := 0; width <= 100; width++ {
		frame := progressFrame(stage, 67*time.Second, 4, 2, width)
		if utf8.RuneCountInString(frame) > width || !utf8.ValidString(frame) {
			t.Fatalf("width %d: %q", width, frame)
		}
		if width == 80 {
			for _, want := range []string{stage, "1:07", "4 done", "2 skipped"} {
				if !strings.Contains(frame, want) {
					t.Errorf("missing %q in %q", want, frame)
				}
			}
		}
	}
}

func TestActiveFrameFitsTerminal(t *testing.T) {
	for width := 6; width <= 100; width++ {
		icon, text, tail := activeFrame("Scanning Node.js projects", 12*time.Second, 23*time.Second, 50*time.Second, width)
		if n := 4 + utf8.RuneCountInString(text+tail); n > width+utf8.RuneCountInString(icon) {
			t.Fatalf("width %d: %d columns: %q%q", width, n, text, tail)
		}
		if width == 80 && (!strings.Contains(text, "0:12") || !strings.Contains(tail, "about 0:27 left")) {
			t.Errorf("%q%q", text, tail)
		}
	}
	if _, _, tail := activeFrame("x", time.Second, 70*time.Second, 50*time.Second, 80); !strings.Contains(tail, "1:10 so far") {
		t.Errorf("overrun: %q", tail)
	}
}

func TestStepListRemovesItself(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p := newScanProgress(w, progressList, false, 0)
	p.StepStart("Detecting IDE installations")
	p.StepDone(300 * time.Millisecond)
	p.StepStart("Homebrew package scanning")
	p.StepSkip("disabled")
	p.StepStart("Scanning Node.js projects")
	p.close()
	w.Close()
	out, _ := io.ReadAll(r)
	got := string(out)
	for _, want := range []string{"✓ Detecting IDE installations", "0.3s", "– Homebrew package scanning", "skipped", "Scanning Node.js projects"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if !strings.HasSuffix(got, "\r\x1b[K\x1b[2A\x1b[J") {
		t.Errorf("finished steps were left on screen: %q", got[max(0, len(got)-40):])
	}
}
