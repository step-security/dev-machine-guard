package awakeclock

import (
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu    sync.Mutex
	awake time.Duration
	wall  time.Time
}

func (f *fakeClock) Awake() time.Duration { f.mu.Lock(); defer f.mu.Unlock(); return f.awake }
func (f *fakeClock) Wall() time.Time      { f.mu.Lock(); defer f.mu.Unlock(); return f.wall }
func (f *fakeClock) set(awake, wall time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.awake, f.wall = awake, time.Unix(0, 0).Add(wall)
}

type result struct{ fired, slept bool }

func start(c *fakeClock, limit time.Duration, done chan struct{}) <-chan result {
	out := make(chan result, 1)
	d := Begin(c)
	go func() {
		f, s := d.Wait(limit, done, time.Millisecond)
		out <- result{f, s}
	}()
	return out
}

// FR1-3: the deadline counts awake time only; a laptop asleep longer than
// the limit doesn't fire it, and a firing after a sleep says so.
func TestWaitCountsAwakeTimeAndReportsSleep(t *testing.T) {
	c := &fakeClock{}
	c.set(0, 0)
	res := start(c, 4*time.Hour, nil)
	c.set(3*time.Hour, 5*time.Hour) // 2 h asleep: 5 h of wall, 3 h awake
	select {
	case r := <-res:
		t.Fatalf("fired after 3 h awake (5 h wall): %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
	c.set(4*time.Hour, 6*time.Hour)
	select {
	case r := <-res:
		if !r.fired || !r.slept {
			t.Fatalf("got %+v, want fired after a sleep", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not fire at 4 h awake")
	}
}

func TestWaitWithoutSleep(t *testing.T) {
	c := &fakeClock{}
	c.set(0, 0)
	res := start(c, time.Hour, nil)
	c.set(time.Hour, time.Hour+time.Minute)
	if r := <-res; !r.fired || r.slept {
		t.Fatalf("got %+v, want fired, not slept", r)
	}
	done := make(chan struct{})
	res = start(c, 10*time.Hour, done)
	close(done)
	if r := <-res; r.fired {
		t.Fatalf("fired after done: %+v", r)
	}
}

func TestSystemClockAdvances(t *testing.T) {
	a := System.Awake()
	time.Sleep(20 * time.Millisecond)
	if System.Awake() <= a {
		t.Fatal("awake clock did not advance")
	}
}
