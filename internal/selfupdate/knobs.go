package selfupdate

import "time"

// knob names a time constant that selfupdate_testkeys builds may override.
type knob int

const (
	knobProbationWindow knob = iota // smoke-only promotion / inconclusive window (72 h)
	knobSwitchWait                  // S6 wait for the scan instance mutex (10 min)
	knobDedupeWindow                // event dedupe window (24 h)
	knobCheckInterval               // minimum spacing of S3 target checks (6 h)
	knobSmokeTimeout                // S5 self-check limit (60 s)
	knobSendBackoff                 // first retry delay of an unsent event (1 h)
)

var knobDefaults = map[knob]time.Duration{
	knobProbationWindow: 72 * time.Hour,
	knobSwitchWait:      10 * time.Minute,
	knobDedupeWindow:    24 * time.Hour,
	knobCheckInterval:   6 * time.Hour,
	knobSmokeTimeout:    60 * time.Second,
	knobSendBackoff:     time.Hour,
}

// knobOverrides is set by in-package tests only.
var knobOverrides = map[knob]time.Duration{}

func duration(k knob) time.Duration {
	if d, ok := knobOverrides[k]; ok {
		return d
	}
	if d, ok := testDuration(k); ok {
		return d
	}
	return knobDefaults[k]
}
