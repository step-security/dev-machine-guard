package procusage

import (
	"cmp"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// topPhasesLogged caps how many phases the logged line names, so a run
// with 20 phases still emits one readable line.
const topPhasesLogged = 5

// Meta identifies the run a Sample belongs to.
//
// InvocationMethod and ExecutionID are enterprise-only: the community
// scan path has no execution ID, and detecting the invocation method
// costs a scheduler subprocess probe that isn't worth paying to label a
// local scan. Both are omitempty for that reason.
type Meta struct {
	Command          string
	InvocationMethod string
	ExecutionID      string
}

// Report logs what the run cost and appends it to the local history.
// Both dispatch paths (community scan and enterprise telemetry) call
// this so the two produce comparable records.
//
// Emitted at info, not debug: the enterprise ExecutionLogs payload
// carries whatever the run wrote to stderr at the configured level, and
// installs run at log_level=info, so a debug line would be absent from
// every log we can actually download.
//
// Wholly best-effort — a failure here is logged at debug and never
// affects the run's outcome.
func Report(log *progress.Logger, wall time.Duration, meta Meta, phases []Phase) {
	sample := Capture(wall)
	log.Progress("resource usage: %s", sample)
	if len(phases) > 0 {
		log.Progress("phase cpu: %s", formatPhaseCPU(phases))
	}

	command := meta.Command
	if command == "" {
		// The default dispatch is a community scan; cli leaves Command
		// empty for it. Name it so the history is readable.
		command = "scan"
	}

	rec := Record{
		Timestamp:        time.Now().UTC(),
		AgentVersion:     buildinfo.Version,
		Command:          command,
		InvocationMethod: meta.InvocationMethod,
		OS:               runtime.GOOS,
		ExecutionID:      meta.ExecutionID,
		Usage:            sample,
		Phases:           phases,
	}
	if err := AppendHistory(paths.RunMetricsFile(), rec); err != nil {
		log.Debug("run metrics: history write failed: %v", err)
	}
}

// formatPhaseCPU names the costliest phases, so the logged line points
// at what to optimise rather than only what the run totalled.
func formatPhaseCPU(phases []Phase) string {
	ranked := slices.Clone(phases)
	slices.SortStableFunc(ranked, func(a, b Phase) int { return cmp.Compare(b.CPUMs, a.CPUMs) })
	if len(ranked) > topPhasesLogged {
		ranked = ranked[:topPhasesLogged]
	}
	parts := make([]string, 0, len(ranked))
	for _, p := range ranked {
		parts = append(parts, fmt.Sprintf("%s=%s", p.Name, ms(p.CPUMs)))
	}
	return strings.Join(parts, " ")
}
