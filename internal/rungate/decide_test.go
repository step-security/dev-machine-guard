package rungate

import (
	"testing"
	"time"
)

func TestDecidePrecedence(t *testing.T) {
	now := time.Unix(1_753_160_800, 0)
	skipDirective := &Directive{Mode: ModeSkip, Reason: "not_due", GatingEnabled: true, EffectiveIntervalMinutes: 240, NextEligibleAt: now.Unix() + 3600}
	fullDirective := &Directive{Mode: ModeFull, Reason: "interval_elapsed", GatingEnabled: true, EffectiveIntervalMinutes: 240}

	tests := []struct {
		name       string
		in         Inputs
		wantSkip   bool
		wantReason string
	}{
		{
			name:       "force wins over everything",
			in:         Inputs{ForceScan: true, FeatureEnabled: true, LockHeldByLivePID: true, Directive: skipDirective, Now: now},
			wantSkip:   false,
			wantReason: "forced",
		},
		{
			name:       "feature gate off never skips",
			in:         Inputs{FeatureEnabled: false, LockHeldByLivePID: true, Directive: skipDirective, Now: now},
			wantSkip:   false,
			wantReason: "feature_disabled",
		},
		{
			name:       "kill switch never skips",
			in:         Inputs{FeatureEnabled: true, KillSwitch: true, Directive: skipDirective, Now: now},
			wantSkip:   false,
			wantReason: "kill_switch",
		},
		{
			name:       "live lock holder backs off quietly",
			in:         Inputs{FeatureEnabled: true, LockHeldByLivePID: true, Directive: fullDirective, Now: now},
			wantSkip:   true,
			wantReason: "lock_held",
		},
		{
			name:       "skip directive obeyed",
			in:         Inputs{FeatureEnabled: true, Directive: skipDirective, Now: now},
			wantSkip:   true,
			wantReason: "directive:not_due",
		},
		{
			name:       "full directive obeyed",
			in:         Inputs{FeatureEnabled: true, Directive: fullDirective, Now: now},
			wantSkip:   false,
			wantReason: "directive:interval_elapsed",
		},
		{
			name: "unknown future mode degrades to full, never skip",
			in: Inputs{FeatureEnabled: true, Now: now,
				Directive: &Directive{Mode: "partial", Reason: "phased_rollout", GatingEnabled: true}},
			wantSkip:   false,
			wantReason: "directive:phased_rollout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := Decide(tt.in)
			if dec.Skip != tt.wantSkip || dec.Reason != tt.wantReason {
				t.Fatalf("Decide() = (skip=%v, reason=%q), want (skip=%v, reason=%q)",
					dec.Skip, dec.Reason, tt.wantSkip, tt.wantReason)
			}
		})
	}
}

func TestDecideSkipCarriesNextEligible(t *testing.T) {
	now := time.Unix(1_753_160_800, 0)
	d := &Directive{Mode: ModeSkip, Reason: "not_due", GatingEnabled: true, NextEligibleAt: now.Unix() + 1234}
	dec := Decide(Inputs{FeatureEnabled: true, Directive: d, Now: now})
	if !dec.Skip || dec.NextEligibleAt != now.Unix()+1234 {
		t.Fatalf("Decide() = %+v, want skip with NextEligibleAt=%d", dec, now.Unix()+1234)
	}
}

func TestDecideOfflineFallback(t *testing.T) {
	now := time.Unix(1_753_160_800, 0)
	nowUnix := now.Unix()
	const interval = 240 // minutes

	state := func(mutate func(*State)) *State {
		st := &State{
			GatingEnabled:            true,
			EffectiveIntervalMinutes: interval,
			LastFullRunAt:            nowUnix - 60,          // 1 min ago
			DirectiveFetchedAt:       nowUnix - 3600,        // 1h ago — fresh
		}
		if mutate != nil {
			mutate(st)
		}
		return st
	}

	tests := []struct {
		name       string
		st         *State
		wantSkip   bool
		wantReason string
	}{
		{name: "no cached state fails open", st: nil, wantSkip: false, wantReason: "offline_fail_open"},
		{name: "gating was off at last contact", st: state(func(s *State) { s.GatingEnabled = false }), wantSkip: false, wantReason: "offline_fail_open"},
		{name: "no cached interval", st: state(func(s *State) { s.EffectiveIntervalMinutes = 0 }), wantSkip: false, wantReason: "offline_fail_open"},
		{name: "never completed a run", st: state(func(s *State) { s.LastFullRunAt = 0 }), wantSkip: false, wantReason: "offline_fail_open"},
		{name: "never checked in", st: state(func(s *State) { s.DirectiveFetchedAt = 0 }), wantSkip: false, wantReason: "offline_fail_open"},
		{name: "fresh cache within interval skips", st: state(nil), wantSkip: true, wantReason: "offline_cache_skip"},
		{name: "interval elapsed locally runs", st: state(func(s *State) { s.LastFullRunAt = nowUnix - int64(interval)*60 }), wantSkip: false, wantReason: "offline_fail_open"},
		{
			name: "stale cache beyond max(floor, 2x interval) runs",
			st: state(func(s *State) {
				s.DirectiveFetchedAt = nowUnix - int64((8*24*time.Hour)/time.Second)
			}),
			wantSkip: false, wantReason: "offline_fail_open",
		},
		{
			name: "floor keeps a days-old cache usable for short intervals",
			st: state(func(s *State) {
				// 2×interval = 8h, but the 7d floor governs: a 6d-old cache
				// still skips when the last (e.g. forced) run was recent.
				s.DirectiveFetchedAt = nowUnix - int64((6*24*time.Hour)/time.Second)
			}),
			wantSkip: true, wantReason: "offline_cache_skip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := Decide(Inputs{FeatureEnabled: true, State: tt.st, Now: now})
			if dec.Skip != tt.wantSkip || dec.Reason != tt.wantReason {
				t.Fatalf("Decide() = (skip=%v, reason=%q), want (skip=%v, reason=%q)",
					dec.Skip, dec.Reason, tt.wantSkip, tt.wantReason)
			}
			if tt.wantSkip && dec.NextEligibleAt != tt.st.LastFullRunAt+int64(interval)*60 {
				t.Fatalf("NextEligibleAt = %d, want %d", dec.NextEligibleAt, tt.st.LastFullRunAt+int64(interval)*60)
			}
		})
	}
}
