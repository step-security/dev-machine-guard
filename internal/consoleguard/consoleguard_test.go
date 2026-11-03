package consoleguard

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// hiders hide a command's console when called on it in the same function.
var hiders = map[string]bool{
	"HideWindow":    true, // winproc.HideWindow
	"HardenCommand": true, // executor.HardenCommand
}

// attrHelpers build the SysProcAttr for a spawn in their caller. Their
// Windows bodies are checked like any SysProcAttr literal, and a probe test
// covers each at runtime (probe_windows_test.go).
var attrHelpers = map[string]bool{
	"prepareSmoke": true, // selfupdate.RunSmoke
	"detachAttrs":  true, // executor.StartDetached (the WSL relay)
}

// noWindowFlag matches the CREATE_NO_WINDOW spellings in this repo.
var noWindowFlag = regexp.MustCompile(`^(CREATE_NO_WINDOW|CreateNoWindow|createNoWindow)$`)

// consoleFlag matches flags that open a console window, or leave the child
// without one so it allocates its own (#271).
var consoleFlag = regexp.MustCompile(`(?i)^(detached_?process|create_?new_?console)$`)

// rawSpawns start a process outside os/exec, where none of the above applies.
var rawSpawns = map[string]map[string]bool{
	"os":                       {"StartProcess": true},
	"syscall":                  {"StartProcess": true, "CreateProcess": true, "CreateProcessAsUser": true},
	"golang.org/x/sys/windows": {"CreateProcess": true, "CreateProcessAsUser": true, "ShellExecute": true},
}

// skipDirs hold no agent code. internal/proctest is imported by tests only.
var skipDirs = map[string]bool{
	".git": true, "testdata": true, "vendor": true, "dist": true, "proctest": true,
}

// TestNoConsoleWindowSpawns is the codepath half of the console guard: every
// process the Windows agent can start must hide its console. A new spawn
// site that fails here should go through executor.Executor (which hides it)
// or call winproc.HideWindow on its *exec.Cmd; see AGENTS.md §7.4.
func TestNoConsoleWindowSpawns(t *testing.T) {
	root := moduleRoot(t)
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "windows", "amd64", false

	var problems, sites []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if ok, err := ctx.MatchFile(filepath.Dir(path), name); err != nil || !ok {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		p, s, err := checkFile(path, filepath.ToSlash(rel), nil)
		problems = append(problems, p...)
		sites = append(sites, s...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) == 0 {
		t.Fatal("found no exec.Command sites; the walk is broken")
	}
	t.Logf("checked %d spawn sites:\n  %s", len(sites), strings.Join(sites, "\n  "))
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// checkFile reports console problems in one file, and each exec.Command site
// it checked. src, when non-nil, is parsed instead of reading path.
func checkFile(path, rel string, src any) (problems, sites []string, err error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, nil, err
	}
	imports := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		ipath, _ := strconv.Unquote(imp.Path.Value)
		local := ipath[strings.LastIndex(ipath, "/")+1:]
		if imp.Name != nil {
			local = imp.Name.Name
		}
		imports[local] = ipath
	}
	at := func(n ast.Node) string {
		return fmt.Sprintf("%s:%d", rel, fset.Position(n.Pos()).Line)
	}

	// Flags that open a window are wrong anywhere, not just at spawn sites.
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			if consoleFlag.MatchString(n.Name) {
				problems = append(problems, fmt.Sprintf("%s: %s opens a console window; use CREATE_NO_WINDOW", at(n), n.Name))
			}
		case *ast.CompositeLit:
			if p := checkSysProcAttr(n); p != "" {
				problems = append(problems, fmt.Sprintf("%s: %s", at(n), p))
			}
		}
		return true
	})

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		hidden := false
		var spawns []*ast.CallExpr
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				pkg, name := callee(n, imports)
				switch {
				case pkg == "os/exec" && (name == "Command" || name == "CommandContext"):
					spawns = append(spawns, n)
				case rawSpawns[pkg][name]:
					problems = append(problems, fmt.Sprintf("%s: %s.%s bypasses console hiding; use os/exec + winproc.HideWindow", at(n), pkg, name))
				case hiders[name] || attrHelpers[name]:
					hidden = true
				}
			case *ast.CompositeLit:
				if isSysProcAttr(n) && hidesWindow(n) {
					hidden = true
				}
			}
			return true
		})
		for _, s := range spawns {
			sites = append(sites, fmt.Sprintf("%s (%s)", at(s), fn.Name.Name))
			if !hidden {
				problems = append(problems, fmt.Sprintf(
					"%s: exec command in %s never hides its console; call winproc.HideWindow(cmd) or use executor.Executor (AGENTS.md §7.4)",
					at(s), fn.Name.Name))
			}
		}
	}
	return problems, sites, nil
}

// callee resolves a call to (import path, function name). Unqualified calls
// return an empty path.
func callee(call *ast.CallExpr, imports map[string]string) (pkg, name string) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return "", fun.Name
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok {
			if ipath, ok := imports[x.Name]; ok {
				return ipath, fun.Sel.Name
			}
		}
		return "", fun.Sel.Name
	}
	return "", ""
}

func isSysProcAttr(lit *ast.CompositeLit) bool {
	switch typ := lit.Type.(type) {
	case *ast.SelectorExpr:
		return typ.Sel.Name == "SysProcAttr"
	case *ast.Ident:
		return typ.Name == "SysProcAttr"
	}
	return false
}

// checkSysProcAttr: a SysProcAttr literal that sets anything must hide the
// window, or assigning it replaces a HideWindow applied earlier.
func checkSysProcAttr(lit *ast.CompositeLit) string {
	if !isSysProcAttr(lit) || len(lit.Elts) == 0 || hidesWindow(lit) {
		return ""
	}
	return "SysProcAttr literal without HideWindow: true and CREATE_NO_WINDOW; set both, or call winproc.HideWindow after assigning it"
}

// hidesWindow reports whether lit sets HideWindow: true and names
// CREATE_NO_WINDOW in its CreationFlags (directly or via a local const whose
// name says so).
func hidesWindow(lit *ast.CompositeLit) bool {
	var hide, noWindow bool
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, _ := kv.Key.(*ast.Ident)
		if key == nil {
			continue
		}
		switch key.Name {
		case "HideWindow":
			v, ok := kv.Value.(*ast.Ident)
			hide = ok && v.Name == "true"
		case "CreationFlags":
			ast.Inspect(kv.Value, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && (noWindowFlag.MatchString(id.Name) || constNamesNoWindow(id)) {
					noWindow = true
				}
				return true
			})
		}
	}
	return hide && noWindow
}

// constNamesNoWindow follows a local const (`const flags = ... |
// windows.CREATE_NO_WINDOW`) to its value.
func constNamesNoWindow(id *ast.Ident) bool {
	if id.Obj == nil || id.Obj.Kind != ast.Con {
		return false
	}
	spec, ok := id.Obj.Decl.(*ast.ValueSpec)
	if !ok {
		return false
	}
	found := false
	for _, v := range spec.Values {
		ast.Inspect(v, func(n ast.Node) bool {
			if x, ok := n.(*ast.Ident); ok && noWindowFlag.MatchString(x.Name) {
				found = true
			}
			return true
		})
	}
	return found
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// The checker itself: each case is a shape it must catch or allow.
func TestCheckFile(t *testing.T) {
	cases := []struct {
		name, src string
		problem   string // substring of the expected problem; "" = clean
	}{
		{"bare exec.Command", `package p
import "os/exec"
func f() { _ = exec.Command("cmd").Run() }`, "never hides its console"},
		{"aliased os/exec", `package p
import x "os/exec"
func f() { _ = x.CommandContext(nil, "cmd").Run() }`, "never hides its console"},
		{"HideWindow", `package p
import ("os/exec"; "example/winproc")
func f() { c := exec.Command("cmd"); winproc.HideWindow(c); _ = c.Run() }`, ""},
		{"HardenCommand", `package p
import ("os/exec"; "example/executor")
func f() { c := exec.Command("cmd"); executor.HardenCommand(c); _ = c.Run() }`, ""},
		{"hiding literal", `package p
import ("os/exec"; "syscall"; "golang.org/x/sys/windows")
func f() { c := exec.Command("cmd"); c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}; _ = c.Run() }`, ""},
		{"pre-#271 detachAttrs", `package p
import "syscall"
const detachedProcess = 0x00000008
func detachAttrs() []*syscall.SysProcAttr {
	return []*syscall.SysProcAttr{{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess}}
}`, "detachedProcess opens a console window"},
		{"x/sys DETACHED_PROCESS", `package p
import "golang.org/x/sys/windows"
var f = windows.DETACHED_PROCESS`, "DETACHED_PROCESS opens a console window"},
		{"CREATE_NEW_CONSOLE", `package p
import "golang.org/x/sys/windows"
var f = windows.CREATE_NEW_CONSOLE`, "CREATE_NEW_CONSOLE opens a console window"},
		{"fixed detachAttrs via const", `package p
import ("syscall"; "golang.org/x/sys/windows")
func detachAttrs() []*syscall.SysProcAttr {
	const flags = syscall.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW
	return []*syscall.SysProcAttr{{HideWindow: true, CreationFlags: flags}}
}`, ""},
		{"literal overwrites HideWindow", `package p
import ("os/exec"; "syscall"; "example/winproc")
func f() { c := exec.Command("cmd"); winproc.HideWindow(c); c.SysProcAttr = &syscall.SysProcAttr{NoInheritHandles: true}; _ = c.Run() }`, "SysProcAttr literal without HideWindow"},
		{"HideWindow without CREATE_NO_WINDOW", `package p
import "syscall"
var a = &syscall.SysProcAttr{HideWindow: true}`, "SysProcAttr literal without HideWindow"},
		{"empty literal", `package p
import "syscall"
var a = &syscall.SysProcAttr{}`, ""},
		{"os.StartProcess", `package p
import "os"
func f() { _, _ = os.StartProcess("cmd", nil, nil) }`, "bypasses console hiding"},
		{"windows.CreateProcess", `package p
import "golang.org/x/sys/windows"
func f() { _ = windows.CreateProcess(nil, nil, nil, nil, false, 0, nil, nil, nil, nil) }`, "bypasses console hiding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems, _, err := checkFile("x.go", "x.go", tc.src)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(problems, "\n")
			switch {
			case tc.problem == "" && got != "":
				t.Errorf("want clean, got:\n%s", got)
			case tc.problem != "" && !strings.Contains(got, tc.problem):
				t.Errorf("want a problem containing %q, got:\n%s", tc.problem, got)
			}
		})
	}
}
