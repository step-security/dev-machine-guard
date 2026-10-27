// Package awakeclock measures time the system was awake. Watchdogs use it
// so a laptop asleep past a deadline isn't treated as a hung process.
package awakeclock

import "time"

// SleptThreshold is how far wall time may run ahead of awake time before a
// wait counts as having spanned a sleep.
const SleptThreshold = 5 * time.Minute

// Clock reads awake time (excluding system sleep) and wall time.
type Clock interface {
	Awake() time.Duration
	Wall() time.Time
}

// System is the real clock.
var System Clock = systemClock{}

type systemClock struct{}

func (systemClock) Wall() time.Time { return time.Now() }

// Deadline is a start point on a Clock.
type Deadline struct {
	clk Clock
	a0  time.Duration
	w0  time.Time
}

// Begin starts a deadline now.
func Begin(clk Clock) Deadline { return Deadline{clk: clk, a0: clk.Awake(), w0: clk.Wall()} }

// Wait blocks until limit of awake time has passed since Begin (fired) or
// done is closed, polling every step. slept reports that wall time ran
// ahead of awake time by more than SleptThreshold meanwhile.
func (d Deadline) Wait(limit time.Duration, done <-chan struct{}, step time.Duration) (fired, slept bool) {
	for {
		elapsed := d.clk.Awake() - d.a0
		if elapsed >= limit {
			return true, d.clk.Wall().Sub(d.w0)-elapsed > SleptThreshold
		}
		select {
		case <-done:
			return false, false
		case <-time.After(min(step, limit-elapsed)):
		}
	}
}
