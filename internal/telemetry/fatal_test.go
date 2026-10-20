package telemetry

import (
	"testing"
	"time"
)

func TestReportFatal(t *testing.T) {
	ReportFatal("no run in flight", time.Second) // must not panic

	got := make(chan string, 1)
	fake := func(reason string) { got <- reason }
	fatalReporter.Store(&fake)
	t.Cleanup(func() { fatalReporter.Store(nil) })

	ReportFatal("watchdog fired", time.Second)
	select {
	case r := <-got:
		if r != "watchdog fired" {
			t.Errorf("reason = %q", r)
		}
	default:
		t.Fatal("reporter not called before ReportFatal returned")
	}

	block := func(string) { select {} }
	fatalReporter.Store(&block)
	start := time.Now()
	ReportFatal("hung post", 100*time.Millisecond)
	if d := time.Since(start); d > time.Second {
		t.Errorf("ReportFatal ignored its timeout: %v", d)
	}
}
