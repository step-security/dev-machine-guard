// Package devcli dispatches developer-facing data commands. JSON and command
// discovery are shared so a new terminal view also works for automation.
package devcli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

type Descriptor struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Sections    []string `json:"sections"`
	Search      bool     `json:"search"`
	ReadOnly    bool     `json:"read_only"`
}

// ScanConfig loads local collector settings only when a query needs them.
type ScanConfig func() (*cli.Config, error)

type Command interface {
	Describe() Descriptor
	Query(context.Context, executor.Executor, ScanConfig, Options, *progress.Logger) (Result, error)
}

// Results contain only public, JSON-serializable fields. RenderText presents the same data.
type Result interface {
	RenderText(io.Writer, View) error
}

// View describes the terminal the text is for. The zero value is a pipe:
// no colour, no truncation.
type View struct {
	Color bool
	Width int
}

// TerminalView reads the view from stdout.
func TerminalView() View {
	width, ok := terminalWidth(os.Stdout)
	if !ok || os.Getenv("TERM") == "dumb" {
		return View{}
	}
	return View{Color: os.Getenv("NO_COLOR") == "" && enableVT(os.Stdout), Width: width}
}

var commands = []Command{Findings{}}

func Lookup(name string) Command {
	for _, command := range commands {
		if command.Describe().Name == name {
			return command
		}
	}
	return nil
}

type Options struct {
	Section, Search              string
	JSON, Help, NoPager, Refresh bool
	// IncludeProtected also reads folders macOS guards, which can prompt for access.
	IncludeProtected bool
}

// Overview reports the one-screen view, which is never paged.
func (o Options) Overview() bool { return o.Section == "" && o.Search == "" }

func Parse(d Descriptor, args []string) (Options, error) {
	var opts Options
	unexpected := func(arg string) (Options, error) {
		return Options{}, fmt.Errorf("unexpected argument %q (run dmg %s --help)", arg, d.Name)
	}
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "--json":
			opts.JSON = true
		case arg == "--no-pager":
			opts.NoPager = true
		case arg == "--refresh":
			opts.Refresh = true
		case arg == "--include-protected":
			opts.IncludeProtected = true
		case arg == "-h" || arg == "--help":
			opts.Help = true
		case opts.Section != "" || opts.Search != "":
			return unexpected(arg)
		case arg == "search" && d.Search:
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return Options{}, fmt.Errorf("search needs a name, for example: dmg %s search lodash@4.17", d.Name)
			}
			i++
			opts.Search = args[i]
		case slices.Contains(d.Sections, arg):
			opts.Section = arg
		default:
			return unexpected(arg)
		}
	}
	return opts, nil
}

func usage(d Descriptor) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nUsage:\n  dmg %s                      one-screen overview\n", d.Description, d.Name)
	fmt.Fprintf(&b, "  dmg %s <area>               everything found in one area\n", d.Name)
	if d.Search {
		fmt.Fprintf(&b, "  dmg %s search <name>[@ver]  where a package, extension or server is installed\n", d.Name)
	}
	fmt.Fprintf(&b, "\nAreas: %s\n\nOptions:\n", strings.Join(d.Sections, ", "))
	b.WriteString("  --refresh            scan again instead of reusing a scan from the last 15 minutes\n")
	b.WriteString("  --include-protected  also read folders macOS guards, such as Documents and\n")
	b.WriteString("                       browser profiles; macOS may ask you to allow it\n")
	b.WriteString("  --json               machine-readable output (also with --help)\n")
	b.WriteString("  --no-pager           print long tables without a pager\n")
	return b.String()
}

func Run(ctx context.Context, command Command, opts Options, exec executor.Executor, settings ScanConfig, w io.Writer, view View) error {
	d := command.Describe()
	if opts.Help {
		if opts.JSON {
			return json.NewEncoder(w).Encode(struct {
				Descriptor
				SchemaVersion int      `json:"schema_version"`
				Formats       []string `json:"formats"`
			}{d, 2, []string{"text", "json"}})
		}
		_, err := io.WriteString(w, usage(d))
		return err
	}
	log := progress.NewNoop()
	var bar *scanProgress
	if !opts.JSON && terminal(os.Stdout) && terminal(os.Stderr) {
		mode := progressLine
		switch {
		case os.Getenv("TERM") == "dumb":
			mode = progressPlain
		case enableVT(os.Stderr):
			mode = progressList
		}
		bar = newScanProgress(os.Stderr, mode, os.Getenv("NO_COLOR") == "", lastScanDuration())
		log = progress.NewStageLogger(bar)
	}
	result, err := command.Query(ctx, exec, settings, opts, log)
	if bar != nil {
		bar.close()
	}
	if err != nil {
		return err
	}
	if opts.JSON {
		return json.NewEncoder(w).Encode(result)
	}
	return result.RenderText(w, view)
}
