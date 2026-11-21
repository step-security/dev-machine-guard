package devcli

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/scan"
)

type Findings struct{}

var findingsAreas = []string{"agents", "mcp", "skills", "plugins", "extensions", "browser", "credentials", "projects", "packages", "runtimes", "alerts"}

func (Findings) Describe() Descriptor {
	return Descriptor{Name: "findings", Description: "See what is installed on this machine and what needs your attention.", Sections: findingsAreas, Search: true, ReadOnly: true}
}

func (Findings) Query(ctx context.Context, exec executor.Executor, settings ScanConfig, opts Options, log *progress.Logger) (Result, error) {
	if opts.Section == "alerts" {
		return findingsResult{section: opts.Section, report: &model.DeveloperReport{SchemaVersion: model.DeveloperReportSchemaVersion,
			Attention: []model.AttentionItem{}, Areas: []model.ReportArea{scan.AlertsArea()}}}, nil
	}
	start := time.Now()
	log.StepStart("Reading scan settings")
	cfg, err := settings()
	if cfg == nil {
		return nil, err
	}
	on, off := true, false
	if err != nil {
		// A standard user may lack access to machine bootstrap credentials.
		// Keep optional and remote-volume collectors off without those settings.
		cfg.EnableRuntimeScan = &off
		cfg.IncludeNetworkVolumes = &off
	}
	// "Do I have this package" is the point of the command, so the package
	// collectors run unless this device's configuration turned one off.
	for _, v := range []**bool{&cfg.EnableNPMScan, &cfg.EnablePythonScan, &cfg.EnableBrewScan} {
		if *v == nil {
			*v = &on
		}
	}
	if opts.IncludeProtected {
		cfg.IncludeTCCProtected = &on
	}
	log.StepDone(time.Since(start))

	key := cacheKey(cfg)
	var report *model.DeveloperReport
	if !opts.Refresh {
		report = loadCache(key, time.Now())
	}
	if report == nil {
		scanStart := time.Now()
		report = scan.Developer(ctx, exec, cfg, log)
		if err != nil {
			report.Scope.Note = "This device's scan settings could not be read. Showing the default scope with optional collectors off."
		}
		saveCache(key, report, time.Since(scanStart))
	}
	return findingsResult{report: report, section: opts.Section, search: opts.Search}, nil
}

type findingsResult struct {
	report          *model.DeveloperReport
	section, search string
}

type searchMatch struct {
	Area string           `json:"area"`
	Item model.ReportItem `json:"item"`
}

// scoped narrows the report to one area and the attention items raised from it.
func (r findingsResult) scoped() model.DeveloperReport {
	rep := *r.report
	if r.section == "" {
		return rep
	}
	rep.Areas, rep.Attention = nil, []model.AttentionItem{}
	for _, a := range r.report.Areas {
		if a.ID == r.section {
			rep.Areas = append(rep.Areas, a)
		}
	}
	for _, a := range r.report.Attention {
		if a.Area == r.section {
			rep.Attention = append(rep.Attention, a)
		}
	}
	return rep
}

// matches finds rows by name. "name@1.2" needs the exact name and a version
// starting with 1.2; a bare term also matches inside names and details, which
// is where an MCP server's package appears.
func (r findingsResult) matches() []searchMatch {
	term := strings.ToLower(strings.TrimSpace(r.search))
	name, version, exact := term, "", false
	if at := strings.LastIndex(term, "@"); at > 0 {
		name, version, exact = term[:at], term[at+1:], true
	}
	out := []searchMatch{}
	for _, a := range r.report.Areas {
		for _, it := range a.Items {
			itemName := strings.ToLower(it.Name)
			hit := strings.Contains(itemName, name) || strings.Contains(strings.ToLower(it.Detail), name)
			if exact {
				hit = itemName == name && strings.HasPrefix(strings.ToLower(it.Version), version)
			}
			if hit {
				out = append(out, searchMatch{a.ID, it})
			}
		}
	}
	return out
}

func (r findingsResult) MarshalJSON() ([]byte, error) {
	if r.search == "" {
		return json.Marshal(r.scoped())
	}
	return json.Marshal(struct {
		SchemaVersion int           `json:"schema_version"`
		ScannedAt     string        `json:"scanned_at"`
		Cached        bool          `json:"cached"`
		Query         string        `json:"query"`
		Matches       []searchMatch `json:"matches"`
	}{r.report.SchemaVersion, r.report.ScannedAt, r.report.Cached, r.search, r.matches()})
}
