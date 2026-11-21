package devcli

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/model"
)

type printer struct {
	w    *bufio.Writer
	view View
	home string
	now  time.Time
}

func (r findingsResult) RenderText(out io.Writer, view View) error {
	p := &printer{w: bufio.NewWriter(out), view: view, now: time.Now()}
	if r.report.Scope != nil {
		p.home = r.report.Scope.Home
	}
	switch {
	case r.search != "":
		p.search(r)
	case r.section != "":
		p.area(r.scoped())
	default:
		p.overview(*r.report)
	}
	return p.w.Flush()
}

// tidy makes a collected value safe and short enough to show: paths and
// package metadata can contain terminal control sequences.
func (p *printer) tidy(s string) string {
	// Credential locations arrive with the home directory already tokenised.
	s = strings.ReplaceAll(s, "$HOME/", "~/")
	if p.home != "" {
		for from := 0; ; {
			i := strings.Index(s[from:], p.home)
			if i < 0 {
				break
			}
			i += from
			end := i + len(p.home)
			// "/Users/sam" must not shorten "/Users/samantha".
			if end == len(s) || strings.ContainsRune(`/\ ,)`, rune(s[end])) {
				s = s[:i] + "~" + s[end:]
				end = i + 1
			}
			from = end
		}
	}
	return strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return '�'
		}
		return r
	}, s)
}

const (
	bold   = "1"
	dim    = "2"
	red    = "31"
	green  = "32"
	yellow = "33"
	cyan   = "36"
)

func (p *printer) paint(code, s string) string {
	if !p.view.Color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p *printer) line(s string) { fmt.Fprintln(p.w, strings.TrimRight(s, " ")) }

func width(s string) int { return utf8.RuneCountInString(s) }

func pad(s string, n int) string { return s + strings.Repeat(" ", max(0, n-width(s))) }

// clip shortens to n columns. A path keeps its end, which names the thing.
func clip(s string, n int, keepEnd bool) string {
	if n <= 0 || width(s) <= n {
		return s
	}
	r := []rune(s)
	if n == 1 {
		return "…"
	}
	if keepEnd {
		return "…" + string(r[len(r)-n+1:])
	}
	return string(r[:n-1]) + "…"
}

func wrap(s string, n int) []string {
	if n <= 0 {
		return []string{s}
	}
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && width(line)+1+width(word) > n {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	return append(lines, line)
}

func num(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func (p *printer) age(rep model.DeveloperReport) string {
	scanned, err := time.Parse(time.RFC3339, rep.ScannedAt)
	if err != nil {
		return ""
	}
	d := p.now.Sub(scanned)
	when := "just now"
	switch {
	case d >= time.Hour:
		when = fmt.Sprintf("%dh ago", int(d.Hours()))
	case d >= time.Minute:
		when = fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if rep.Cached {
		return "Scanned " + when + " · add --refresh to scan again"
	}
	return "Scanned " + when
}

func (p *printer) attention(a model.AttentionItem, maxDetailLines int) {
	label, color := "INFO", cyan
	switch a.Severity {
	case model.AttentionHigh:
		label, color = "HIGH", red
	case model.AttentionMedium:
		label, color = "MEDIUM", yellow
	}
	const indent = 10
	title := p.tidy(a.Title)
	head := "  " + p.paint(color, pad(label, indent-2)) + p.paint(bold, title)
	below := false
	if a.Action != "" && maxDetailLines > 0 {
		gap := 2
		if p.view.Width > 0 {
			gap = p.view.Width - indent - width(title) - width(a.Action)
		}
		if below = gap < 2; !below {
			head += strings.Repeat(" ", gap) + p.paint(cyan, a.Action)
		}
	}
	p.line(head)
	defer func() {
		if below {
			p.line(strings.Repeat(" ", indent) + p.paint(cyan, a.Action))
		}
	}()
	lines := wrap(p.tidy(a.Detail), p.view.Width-indent)
	if maxDetailLines > 0 && len(lines) > maxDetailLines {
		lines = lines[:maxDetailLines]
		lines[maxDetailLines-1] = clip(lines[maxDetailLines-1]+" …", p.view.Width-indent, false)
	}
	for _, l := range lines {
		p.line(strings.Repeat(" ", indent) + p.paint(dim, l))
	}
}

func (p *printer) overview(rep model.DeveloperReport) {
	p.line(p.paint(bold, "Dev Machine Guard") + " · this machine")
	p.line(p.paint(dim, p.age(rep)))
	if rep.Scope != nil && rep.Scope.Note != "" {
		p.line(p.paint(yellow, p.tidy(rep.Scope.Note)))
	}
	p.line("")
	if len(rep.Attention) == 0 {
		p.line(p.paint(bold, "NEEDS ATTENTION"))
		p.line("  " + p.paint(green, "Nothing needs attention in what was checked."))
	} else {
		p.line(p.paint(bold, fmt.Sprintf("NEEDS ATTENTION (%d)", len(rep.Attention))))
		for _, a := range rep.Attention {
			p.attention(a, 2)
		}
	}
	p.line("")
	p.line(p.paint(bold, "ON THIS MACHINE"))
	titles := 0
	for _, a := range rep.Areas {
		titles = max(titles, width(a.Title))
	}
	// The per-row command needs room; a narrow terminal gets it once, below.
	hints := p.view.Width == 0 || p.view.Width >= 110
	const countWidth, hintWidth = 7, 24
	for _, a := range rep.Areas {
		count, summary := num(len(a.Items)), p.tidy(a.Summary)
		switch a.Status {
		case model.AreaPartial:
			summary = "incomplete · " + cmpOr(summary, p.tidy(a.StatusNote))
		case model.AreaDisabled, model.AreaUnavailable, model.AreaUnsupported:
			count, summary = "–", "not checked: "+p.tidy(a.StatusNote)
		}
		room := 0
		if p.view.Width > 0 {
			room = p.view.Width - (2 + titles + countWidth + 2)
			if hints {
				room -= hintWidth + 2
			}
			room = max(room, 1)
		}
		summary = clip(summary, room, false)
		row := "  " + pad(a.Title, titles) + strings.Repeat(" ", countWidth-width(count)) + p.paint(bold, count) + "  " + p.paint(dim, summary)
		if hints {
			row += strings.Repeat(" ", 2+max(0, room-width(summary))) + p.paint(cyan, "dmg findings "+a.ID)
		}
		p.line(row)
	}
	p.line("")
	if rep.Scope != nil {
		p.notScanned("protected by macOS privacy settings", rep.Scope.ProtectedPaths)
		p.notScanned("could not be read", rep.Scope.SkippedPaths)
	}
	p.line("  Find anything   " + p.paint(cyan, "dmg findings search <name>[@version]"))
	if !hints {
		p.line("  Open an area    " + p.paint(cyan, "dmg findings <area>") + p.paint(dim, "   (--help lists the areas)"))
	}
}

func (p *printer) notScanned(why string, paths []string) {
	if len(paths) == 0 {
		return
	}
	shown := make([]string, 0, 4)
	for _, path := range paths[:min(3, len(paths))] {
		shown = append(shown, p.tidy(path))
	}
	if len(paths) > 3 {
		shown = append(shown, fmt.Sprintf("and %d more", len(paths)-3))
	}
	p.line(p.paint(dim, clip("  Not scanned ("+why+"): "+strings.Join(shown, ", "), p.view.Width, false)))
}

func (p *printer) area(rep model.DeveloperReport) {
	if len(rep.Areas) == 0 {
		return
	}
	a := rep.Areas[0]
	head := p.paint(bold, a.Title) + " · " + num(len(a.Items))
	if a.Summary != "" {
		head += " · " + p.tidy(a.Summary)
	}
	p.line(head)
	p.line(p.paint(dim, p.age(rep)))
	switch {
	case a.Status == model.AreaPartial:
		p.line(p.paint(yellow, "Incomplete: "+p.tidy(a.StatusNote)))
	case a.Status != model.AreaComplete:
		p.line(p.paint(yellow, "Not checked: "+p.tidy(a.StatusNote)))
	case a.StatusNote != "":
		p.line(p.paint(dim, p.tidy(a.StatusNote)))
	}
	if len(rep.Attention) > 0 {
		p.line("")
		for _, at := range rep.Attention {
			at.Action = ""
			p.attention(at, 0)
		}
	}
	if len(a.Items) == 0 {
		if a.Status == model.AreaComplete {
			p.line("")
			p.line("  None found.")
		}
		return
	}
	p.line("")
	collapsed := p.table(a.ID, a.Items, false)
	if collapsed {
		p.line("")
		p.line(p.paint(dim, "  A row found in several places shows a count. List them with ") + p.paint(cyan, "dmg findings search <name>"))
	}
}

func (p *printer) search(r findingsResult) {
	matches := r.matches()
	total := 0
	for _, a := range r.report.Areas {
		total += len(a.Items)
	}
	p.line(p.paint(bold, fmt.Sprintf("Search %q", p.tidy(r.search))) + " · " + plural(len(matches), "match", "matches") + " in " + num(total) + " items")
	p.line(p.paint(dim, p.age(*r.report)))
	for _, a := range r.report.Areas {
		var items []model.ReportItem
		for _, m := range matches {
			if m.Area == a.ID {
				items = append(items, m.Item)
			}
		}
		if len(items) == 0 {
			continue
		}
		p.line("")
		p.line(p.paint(bold, a.Title))
		p.table(a.ID, items, true)
	}
	for _, a := range r.report.Areas {
		if (a.ID == "packages" || a.ID == "projects") && a.Status != model.AreaComplete && a.StatusNote != "" {
			p.line("")
			p.line(p.paint(yellow, "Note: "+p.tidy(a.StatusNote)))
			break
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return num(n) + " " + many
}

// Column headings that differ by area: what Kind, Detail and Location mean there.
var areaHeads = map[string][3]string{
	"agents":      {"VENDOR", "", "PATH"},
	"mcp":         {"CLIENT", "RUNS", "CONFIG"},
	"skills":      {"AGENT", "SCOPE", "PATH"},
	"plugins":     {"AGENT", "CONTAINS", "PATH"},
	"extensions":  {"IDE", "", "PATH"},
	"browser":     {"BROWSER", "ACCESS", "PATH"},
	"credentials": {"CATEGORY", "HOLDS", "PATH"},
	"projects":    {"MANAGER", "PACKAGES", ""},
	"packages":    {"TYPE", "", "INSTALLED IN"},
	"runtimes":    {"SOURCE", "", "PATH"},
}

// table prints aligned rows and reports whether any row stands for several
// locations. expand lists those locations under the row.
func (p *printer) table(area string, items []model.ReportItem, expand bool) (collapsed bool) {
	heads := areaHeads[area]
	type column struct {
		head    string
		cells   []string
		limit   int // widest a fixed column may grow on a terminal
		flex    bool
		keepEnd bool
		color   string
		width   int
	}
	cols := []*column{
		{head: "NAME", limit: max(44, p.view.Width*45/100)},
		{head: "VERSION", limit: 18},
		{head: cmpOr(heads[0], "KIND"), limit: 18},
		{head: "NOTE", limit: 30},
		{head: cmpOr(heads[1], "DETAIL"), flex: true},
		{head: cmpOr(heads[2], "LOCATION"), flex: true, keepEnd: true, color: dim},
	}
	for _, it := range items {
		location := it.Location
		if len(it.Locations) > 1 {
			location, collapsed = "", true
		}
		if location == it.Name {
			location = ""
		}
		for i, v := range []string{it.Name, it.Version, it.Kind, strings.Join(it.Flags, ", "), it.Detail, location} {
			cols[i].cells = append(cols[i].cells, p.tidy(v))
		}
	}
	used := cols[:0]
	for _, c := range cols {
		for _, v := range c.cells {
			c.width = max(c.width, width(v))
		}
		if c.width == 0 {
			continue
		}
		c.width = max(c.width, width(c.head))
		if p.view.Width > 0 && !c.flex {
			c.width = min(c.width, c.limit)
		}
		used = append(used, c)
	}
	// When the rows do not fit, the location moves to its own line under each
	// row instead of every column being cut short.
	var under *column
	if p.view.Width > 0 {
		natural := 2 + 2*(len(used)-1)
		for _, c := range used {
			natural += c.width
		}
		// A dense list (packages, runtimes) stays one line and clips the path instead.
		detailed := slices.ContainsFunc(used, func(c *column) bool { return c.flex && !c.keepEnd && c.width > 24 })
		if last := used[len(used)-1]; natural > p.view.Width && last.keepEnd && detailed {
			under, used = last, used[:len(used)-1]
		}
		room := p.view.Width - 2 - 2*(len(used)-1)
		var flex []*column
		for _, c := range used {
			if c.flex {
				flex = append(flex, c)
			} else {
				room -= c.width
			}
		}
		// Share what is left; a column that needs less than its share gives the rest away.
		for i, c := range flex {
			c.width = min(c.width, max(12, room/(len(flex)-i)))
			room -= c.width
		}
	}
	row := func(get func(*column) string, paint bool) {
		var b strings.Builder
		b.WriteString("  ")
		for i, c := range used {
			cell := get(c)
			if p.view.Width > 0 {
				cell = clip(cell, c.width, c.keepEnd)
			}
			color := c.color
			if !paint {
				color = dim
			}
			b.WriteString(p.paint(color, cell))
			if i < len(used)-1 {
				b.WriteString(strings.Repeat(" ", c.width-width(cell)+2))
			}
		}
		p.line(b.String())
	}
	row(func(c *column) string { return c.head }, false)
	for i, it := range items {
		row(func(c *column) string { return c.cells[i] }, true)
		if under != nil && under.cells[i] != "" {
			p.line("      " + p.paint(dim, clip(under.cells[i], p.view.Width-6, true)))
		}
		if expand && len(it.Locations) > 1 {
			for _, l := range it.Locations {
				p.line("      " + p.paint(dim, p.tidy(l)))
			}
		}
	}
	return collapsed && !expand
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
