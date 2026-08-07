package credentials

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestUserPaths(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "home", "octocat")

	t.Run("roots derive from the account, not the environment", func(t *testing.T) {
		unix := newUserPaths("octocat", home, model.PlatformLinux)
		if unix.XDGConfig != filepath.Join(home, ".config") {
			t.Errorf("configuration root = %q, want the default below the home", unix.XDGConfig)
		}
		if unix.AppData != "" {
			t.Errorf("roaming root = %q, want empty off Windows", unix.AppData)
		}
		// Derived from the trusted home, not the environment: the agent runs as a
		// system account, so an inherited roaming value names a service profile.
		win := newUserPaths("octocat", home, model.PlatformWindows)
		if win.AppData != filepath.Join(home, "AppData", "Roaming") {
			t.Errorf("roaming root = %q, want it derived from the home", win.AppData)
		}
	})

	t.Run("the developer's own configuration root wins when set", func(t *testing.T) {
		paths := newUserPaths("octocat", home, model.PlatformLinux)
		if got := paths.withXDGConfig("").XDGConfig; got != filepath.Join(home, ".config") {
			t.Errorf("unset variable changed the root to %q", got)
		}
		custom := filepath.Join(string(filepath.Separator), "opt", "config")
		if got := paths.withXDGConfig(custom).XDGConfig; got != custom {
			t.Errorf("configuration root = %q, want %q", got, custom)
		}
	})
}

func TestTokenise(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "home", "octocat")
	winHome := filepath.Join(string(filepath.Separator), "Users", "Octocat")
	nested := filepath.Join(home, "config", "deeply", "nested")
	outside := filepath.Join(string(filepath.Separator), "opt", "config")

	defaults := userPaths{
		Username:  "octocat",
		Home:      home,
		AppData:   filepath.Join(home, "AppData", "Roaming"),
		XDGConfig: filepath.Join(home, ".config"),
	}

	tests := []struct {
		name  string
		paths userPaths
		path  string
		want  string
	}{
		{"home file", defaults, filepath.Join(home, ".netrc"), "$HOME/.netrc"},
		{"nested home file", defaults, filepath.Join(home, ".aws", "credentials"), "$HOME/.aws/credentials"},
		{"the home itself", defaults, home, "$HOME"},
		// The roaming and configuration directories sit below the home, so matching
		// the home first would label every path with the least specific root.
		{"roaming file", defaults, filepath.Join(home, "AppData", "Roaming", "GitHub CLI", "hosts.yml"), "$APPDATA/GitHub CLI/hosts.yml"},
		// The configuration directory at its default is not a separate place, and
		// several tools keep files there while ignoring the variable.
		{"configuration file at the default", defaults, filepath.Join(home, ".config", "git", "credentials"), "$HOME/.config/git/credentials"},
		// A path with no root to strip is not one this inventory can describe, and
		// its full spelling can name unrelated directories. The opaque root keeps an
		// identifier segment, so it has the shape every other location has.
		{"outside every root", defaults, filepath.Join(string(filepath.Separator), "opt", "secrets", "creds.json"), "$ABS/39722e7bf8a8/creds.json"},
		{"empty", defaults, "", ""},
		// A folded location would produce a string that does not resolve and
		// that differs from every other view of the machine.
		{
			"the tail keeps its own casing",
			userPaths{Home: winHome, AppData: filepath.Join(winHome, "AppData", "Roaming")},
			filepath.Join(winHome, "AppData", "Roaming", "GitHub CLI", "hosts.yml"),
			"$APPDATA/GitHub CLI/hosts.yml",
		},
		// Where it does earn its own token: the file genuinely is not where the
		// default puts it, and the most specific root wins however roots are declared.
		{
			"a relocated configuration root below the home",
			userPaths{Home: home, XDGConfig: nested},
			filepath.Join(nested, "git", "credentials"),
			"$XDG_CONFIG_HOME/git/credentials",
		},
		{
			"a relocated configuration root outside the home",
			userPaths{Home: home, XDGConfig: outside},
			filepath.Join(outside, "git", "credentials"),
			"$XDG_CONFIG_HOME/git/credentials",
		},
		// A home the filesystem spells differently is still the home. Containment
		// admits both spellings, so a file under the resolved one is inside the
		// account's tree, and the opaque root would give it a second identity for
		// the same file and hide the only root a reader can interpret.
		{
			"a file under the resolved spelling of the home",
			userPaths{Home: home}.withResolvedHome(filepath.Join(string(filepath.Separator), "export", "home", "octocat")),
			filepath.Join(string(filepath.Separator), "export", "home", "octocat", ".aws", "credentials"),
			"$HOME/.aws/credentials",
		},
		// The written spelling keeps working when a second one is known.
		{
			"a file under the written spelling when both are known",
			userPaths{Home: home}.withResolvedHome(filepath.Join(string(filepath.Separator), "export", "home", "octocat")),
			filepath.Join(home, ".aws", "credentials"),
			"$HOME/.aws/credentials",
		},
		// The resolved spelling is respelled and then matched against the same roots,
		// so it can still reach a more specific one. Carrying it as a root of its own
		// would match the home and stop here, reporting the roaming file under the
		// home token — a second identity for a file whose location did not change.
		{
			"a roaming file under the resolved spelling of the home",
			userPaths{Home: winHome, AppData: filepath.Join(winHome, "AppData", "Roaming")}.
				withResolvedHome(filepath.Join(string(filepath.Separator), "Volumes", "Profiles", "Octocat")),
			filepath.Join(string(filepath.Separator), "Volumes", "Profiles", "Octocat", "AppData", "Roaming", "GitHub CLI", "hosts.yml"),
			"$APPDATA/GitHub CLI/hosts.yml",
		},
		// Same for a configuration root the developer moved: the file is not where the
		// default puts it, and that stays true of a path spelled the other way.
		{
			"a moved configuration root reached through the resolved home",
			userPaths{Home: home, XDGConfig: nested}.
				withResolvedHome(filepath.Join(string(filepath.Separator), "export", "home", "octocat")),
			filepath.Join(string(filepath.Separator), "export", "home", "octocat", "config", "deeply", "nested", "git", "credentials"),
			"$XDG_CONFIG_HOME/git/credentials",
		},
		// The configuration root spelled with the resolved home is the default, not a
		// move: a shell reporting the resolved home has set the variable to the same
		// directory. Giving it a token would name, for this one machine, the place
		// every other machine reports under the home.
		{
			"the default configuration root spelled with the resolved home",
			userPaths{Home: home, XDGConfig: filepath.Join(string(filepath.Separator), "export", "home", "octocat", ".config")}.
				withResolvedHome(filepath.Join(string(filepath.Separator), "export", "home", "octocat")),
			filepath.Join(string(filepath.Separator), "export", "home", "octocat", ".config", "git", "credentials"),
			"$HOME/.config/git/credentials",
		},
		// A path under neither spelling is still opaque; the respelling is not a
		// second chance at containment.
		{
			"outside both spellings of the home",
			userPaths{Home: home}.withResolvedHome(filepath.Join(string(filepath.Separator), "export", "home", "octocat")),
			filepath.Join(string(filepath.Separator), "opt", "secrets", "creds.json"),
			"$ABS/39722e7bf8a8/creds.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.paths.tokenise(tt.path); got != tt.want {
				t.Errorf("tokenise(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestWithResolvedHome_OnlyStoresASecondSpelling keeps the ordinary machine at one
// home: the second spelling exists to recognise one the account record does not
// carry, and storing an identical one would only add a respelling pass to every
// path that failed to match — including one that should stay opaque.
func TestWithResolvedHome_OnlyStoresASecondSpelling(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "home", "octocat")
	base := userPaths{Home: home}

	if got := base.withResolvedHome(home); got.HomeResolved != "" {
		t.Errorf("an identical spelling was stored as %q", got.HomeResolved)
	}
	if got := base.withResolvedHome(home + string(filepath.Separator)); got.HomeResolved != "" {
		t.Errorf("a trailing separator was treated as a different home: %q", got.HomeResolved)
	}
	if got := base.withResolvedHome(""); got.HomeResolved != "" {
		t.Errorf("an unresolved home was stored as %q", got.HomeResolved)
	}

	elsewhere := filepath.Join(string(filepath.Separator), "export", "home", "octocat")
	if got := base.withResolvedHome(elsewhere); got.HomeResolved != elsewhere {
		t.Errorf("HomeResolved = %q, want %q", got.HomeResolved, elsewhere)
	}
}

func TestTrimPathPrefix_ComparesWholeElements(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "home", "bob")

	if _, ok := trimPathPrefix(filepath.Join(string(filepath.Separator), "home", "bobby", "file"), root); ok {
		t.Error("a sibling whose name starts with the root is not inside it")
	}
	rest, ok := trimPathPrefix(filepath.Join(root, "a", "b"), root)
	if !ok || rest != filepath.Join("a", "b") {
		t.Errorf("rest = %q/%v, want %q/true", rest, ok, filepath.Join("a", "b"))
	}
	if rest, ok := trimPathPrefix(root, root); !ok || rest != "" {
		t.Errorf("the root itself = %q/%v, want empty/true", rest, ok)
	}
	if _, ok := trimPathPrefix(filepath.Join(string(filepath.Separator), "home"), root); ok {
		t.Error("a parent of the root is not inside it")
	}
}

// TestCandidatesFor covers the precedence between an environment override and
// the catalog default, and how each override kind expands.
func TestCandidatesFor(t *testing.T) {
	unixHome := filepath.Join(string(filepath.Separator), "home", "octocat")
	winHome := filepath.Join(string(filepath.Separator), "Users", "octocat")
	awsDefault := filepath.Join(unixHome, ".aws", "credentials")
	relocated := filepath.Join(string(filepath.Separator), "opt", "aws", "creds")
	ghDir := filepath.Join(string(filepath.Separator), "opt", "gh")
	xdg := filepath.Join(string(filepath.Separator), "opt", "config")
	kubeA := filepath.Join(string(filepath.Separator), "opt", "kube", "a")
	kubeB := filepath.Join(string(filepath.Separator), "opt", "kube", "b")

	tests := []struct {
		name     string
		sourceID string
		home     string
		platform string
		env      map[string]string
		want     []string
	}{
		// The tool reads the relocated file and stops reading the default, so the
		// default is not a candidate. Offering it would report a credential in a
		// file nothing consults.
		{name: "an override replaces the default", sourceID: sourceAWSCredentials, home: unixHome, platform: model.PlatformLinux, env: map[string]string{"AWS_SHARED_CREDENTIALS_FILE": relocated}, want: []string{relocated}},
		{name: "an unset override is skipped", sourceID: sourceAWSCredentials, home: unixHome, platform: model.PlatformLinux, env: map[string]string{"AWS_SHARED_CREDENTIALS_FILE": "   "}, want: []string{awsDefault}},
		{name: "a directory override joins the file", sourceID: sourceGitHubCLIHosts, home: unixHome, platform: model.PlatformLinux, env: map[string]string{"GH_CONFIG_DIR": ghDir}, want: []string{filepath.Join(ghDir, "hosts.yml")}},
		{
			// Reverse of the usual assumption, on Windows too: unset, this tool falls
			// back to the roaming profile rather than to a directory below the home,
			// which is why the variable is an override and the default is not.
			name: "the configuration variable outranks the roaming profile", sourceID: sourceGitHubCLIHosts,
			home: winHome, platform: model.PlatformWindows,
			env:  map[string]string{"XDG_CONFIG_HOME": xdg},
			want: []string{filepath.Join(xdg, "gh", "hosts.yml")},
		},
		{
			// This tool reads the first variable in preference to the second, so the
			// second names a file it has stopped reading.
			name: "the higher-precedence override wins outright", sourceID: sourceGitHubCLIHosts,
			home: unixHome, platform: model.PlatformLinux,
			env:  map[string]string{"GH_CONFIG_DIR": ghDir, "XDG_CONFIG_HOME": xdg},
			want: []string{filepath.Join(ghDir, "hosts.yml")},
		},
		{
			// An override naming somewhere empty is still where the tool looks. The
			// answer is one candidate that will not be there, not a fallback.
			name: "a missing target does not fall through", sourceID: sourceGitHubCLIHosts,
			home: unixHome, platform: model.PlatformLinux,
			env:  map[string]string{"XDG_CONFIG_HOME": xdg},
			want: []string{filepath.Join(xdg, "gh", "hosts.yml")},
		},
		// Every element is live, so each is its own candidate; the empty
		// element is not a path. The default is displaced, as with any override.
		{name: "a list override splits on the platform separator", sourceID: sourceKubeconfig, home: unixHome, platform: model.PlatformLinux, env: map[string]string{"KUBECONFIG": strings.Join([]string{kubeA, "", kubeB}, string(os.PathListSeparator))}, want: []string{kubeA, kubeB}},
		{
			// Set is what displaces the default, not naming somewhere real. The tool
			// itself splits any non-empty value and then ignores the empty elements
			// without restoring its default, which is only restored by unsetting the
			// variable — so a value of nothing but separators names nowhere to look.
			name: "a list naming no path still displaces the default", sourceID: sourceKubeconfig,
			home: unixHome, platform: model.PlatformLinux,
			env:  map[string]string{"KUBECONFIG": strings.Repeat(string(os.PathListSeparator), 3)},
			want: []string{},
		},
		{name: "the dotted spelling on unix", sourceID: sourceNetrc, home: unixHome, platform: model.PlatformDarwin, want: []string{filepath.Join(unixHome, ".netrc")}},
		// The Windows name uses an underscore.
		{name: "the underscored spelling on windows", sourceID: sourceNetrc, home: winHome, platform: model.PlatformWindows, want: []string{filepath.Join(winHome, "_netrc")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := newUserPaths("octocat", tt.home, tt.platform)
			got := candidatesFor(sourceByID(t, tt.sourceID), paths, tt.env, tt.platform)
			if !slices.Equal(got, tt.want) {
				t.Errorf("candidates = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyPrefixOverrides(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "home", "octocat")
	paths := newUserPaths("octocat", home, model.PlatformLinux)
	s := sourceByID(t, sourceMCPConfig)
	relocated := filepath.Join(string(filepath.Separator), "opt", "claude")

	declared := filepath.Join(home, ".claude", "settings.json")
	got, rewritten := applyPrefixOverrides(declared, s, paths, map[string]string{"CLAUDE_CONFIG_DIR": relocated})
	if got != filepath.Join(relocated, "settings.json") {
		t.Errorf("path = %q, want the leading directory replaced", got)
	}
	// The caller reads a rewritten path through the guard rather than as a targeted
	// read, so saying a variable moved it is as load-bearing as where it moved to.
	if !rewritten {
		t.Error("rewritten = false for a path a variable relocated")
	}

	// A path the variable does not govern is returned untouched.
	other := filepath.Join(home, ".cursor", "mcp.json")
	if got, rewritten := applyPrefixOverrides(other, s, paths, map[string]string{"CLAUDE_CONFIG_DIR": relocated}); got != other || rewritten {
		t.Errorf("path = %q (rewritten=%v), want it unchanged", got, rewritten)
	}
	// An unset variable relocates nothing.
	if got, rewritten := applyPrefixOverrides(declared, s, paths, nil); got != declared || rewritten {
		t.Errorf("path = %q (rewritten=%v), want it unchanged", got, rewritten)
	}
}

func sourceByID(t *testing.T, id string) source {
	t.Helper()
	for _, s := range sources {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no catalog entry %q", id)
	return source{}
}

func TestPermissionMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// The bits are only real where the host filesystem carries them; a Windows host
	// synthesises them, which is why the field is omitted for that platform below.
	if runtime.GOOS != model.PlatformWindows {
		if got := permissionMode(info, model.PlatformDarwin); got != "0600" {
			t.Errorf("mode = %q, want %q", got, "0600")
		}
	}
	// Permission bits are synthesised on Windows from one read-only attribute, so
	// every file would report one of two values whatever its access control says —
	// and a number that always says the same thing looks like a measurement.
	if got := permissionMode(info, model.PlatformWindows); got != "" {
		t.Errorf("mode = %q, want it omitted on Windows", got)
	}
}

func TestInGitRepo(t *testing.T) {
	// A credential inside a checked-out working tree is the finding a customer
	// acts on immediately, so it has to be identifiable however deep it sits.
	t.Run("finds the repository above a file", func(t *testing.T) {
		root := t.TempDir()
		home := filepath.Join(root, "octocat")
		repo := filepath.Join(home, "dotfiles")
		for _, dir := range []string{filepath.Join(repo, ".git"), filepath.Join(repo, ".aws"), filepath.Join(home, ".aws")} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}

		for _, tc := range []struct {
			name string
			path string
			want bool
		}{
			{"below the repository", filepath.Join(repo, ".aws", "credentials"), true},
			{"at the repository root", filepath.Join(repo, "credentials"), true},
			{"no repository above it", filepath.Join(home, ".aws", "credentials"), false},
		} {
			if got := inGitRepo(tc.path, home); got != tc.want {
				t.Errorf("%s: inGitRepo = %v, want %v", tc.name, got, tc.want)
			}
		}
	})

	// A repository above a developer's home is not their working tree, and the
	// bound keeps the walk inside the boundary the rest of this phase respects.
	t.Run("stops at the trusted root", func(t *testing.T) {
		root := t.TempDir()
		home := filepath.Join(root, "octocat")
		for _, dir := range []string{filepath.Join(home, ".aws"), filepath.Join(root, ".git")} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}
		if inGitRepo(filepath.Join(home, ".aws", "credentials"), home) {
			t.Error("a repository above the home must not claim a file inside it")
		}
	})

	// A key directory holds many keys and they all share one answer: without
	// the cache each one repeats the walk.
	t.Run("cached per directory", func(t *testing.T) {
		root := t.TempDir()
		home := filepath.Join(root, "octocat")
		ssh := filepath.Join(home, ".ssh")
		if err := os.MkdirAll(ssh, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		scan := &scanState{paths: userPaths{Home: home}, gitRepos: map[string]bool{}}
		if scan.inGitRepo(filepath.Join(ssh, "id_ed25519")) {
			t.Error("no repository above the key directory")
		}
		// The directory is now a repository and the cached answer predates that: one
		// answer per directory per scan, so a payload cannot contradict itself.
		if err := os.MkdirAll(filepath.Join(ssh, ".git"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if scan.inGitRepo(filepath.Join(ssh, "id_rsa")) {
			t.Error("the second key in the same directory must reuse the first answer")
		}
		if fresh := (&scanState{paths: userPaths{Home: home}, gitRepos: map[string]bool{}}); !fresh.inGitRepo(filepath.Join(ssh, "id_rsa")) {
			t.Error("a later scan must see the repository")
		}
	})
}

// TestCatalog_Invariants holds the properties every table entry must satisfy,
// checked rather than trusted: adding a family is a table entry plus a parser, and
// each of these is a way that edit goes wrong silently.
func TestCatalog_Invariants(t *testing.T) {
	// The load-bearing one: the phase touches exactly the paths named in the table,
	// so a wildcard or a bare directory would turn a bounded set of reads into a
	// traversal of the home — on macOS, straight into consent-gated territory. The
	// one directory this phase lists is declared by its read mode, not its path.
	t.Run("no location is a walk", func(t *testing.T) {
		var listing []string
		for _, s := range sources {
			for _, l := range s.Locations {
				if strings.ContainsAny(l.Rel, "*?[") {
					t.Errorf("%s: location %q contains a wildcard", s.ID, l.Rel)
				}
			}
			if s.Mode == readKeyDir {
				listing = append(listing, s.ID)
			}
		}
		if len(listing) != 1 {
			t.Errorf("exactly one source may list a directory, got %v", listing)
		}
	})

	t.Run("ids are unique and distinct from the status source", func(t *testing.T) {
		seen := map[string]bool{}
		for _, s := range sources {
			if seen[s.ID] {
				t.Errorf("duplicate source id %q", s.ID)
			}
			seen[s.ID] = true
		}
		// The GitHub CLI status collector reports through the hosts finding, so
		// a table entry for it would produce a finding row that must not exist.
		if seen[sourceGitHubCLIStatus] {
			t.Errorf("%s must not be a table entry", sourceGitHubCLIStatus)
		}
	})

	t.Run("categories are model values", func(t *testing.T) {
		valid := map[string]bool{
			model.CredentialCategoryCloud:          true,
			model.CredentialCategorySourceControl:  true,
			model.CredentialCategoryPackageReg:     true,
			model.CredentialCategoryContainers:     true,
			model.CredentialCategoryAIMCP:          true,
			model.CredentialCategoryInfrastructure: true,
		}
		for _, s := range sources {
			if !valid[s.Category] {
				t.Errorf("%s: category %q is not a model value", s.ID, s.Category)
			}
		}
	})

	// A source that reads without a bound. The stat-only source is the
	// deliberate exception: it opens nothing, so it has no bytes to cap.
	t.Run("every reading source has a cap", func(t *testing.T) {
		for _, s := range sources {
			switch s.Mode {
			case readStat:
				if s.MaxBytes != 0 {
					t.Errorf("%s: stat-only source declares a byte cap", s.ID)
				}
			default:
				if s.MaxBytes <= 0 {
					t.Errorf("%s: reads bytes with no cap", s.ID)
				}
			}
		}
	})

	// Catches an entry that would silently never be probed — a row with no
	// location on any platform, or a Windows-only spelling and no unix one.
	t.Run("every source resolves somewhere", func(t *testing.T) {
		for _, s := range sources {
			if s.Mode == readDelegated {
				continue
			}
			for _, plat := range []string{model.PlatformDarwin, model.PlatformLinux, model.PlatformWindows} {
				if !s.applies(plat) {
					t.Errorf("%s: no location on %s", s.ID, plat)
				}
			}
		}
	})

	// The roaming root has no meaning elsewhere; an unscoped entry would
	// resolve to nothing on unix and read as an absent credential.
	t.Run("the roaming root is windows only", func(t *testing.T) {
		for _, s := range sources {
			for _, l := range s.Locations {
				if l.Root != rootAppData {
					continue
				}
				if len(l.Platforms) != 1 || l.Platforms[0] != model.PlatformWindows {
					t.Errorf("%s: %q uses the roaming root without scoping to Windows", s.ID, l.Rel)
				}
			}
		}
	})

	// A source with no parser is reported unreadable, which is honest but useless:
	// the agent opened the file and the record says nothing about it. Forgetting the
	// parser is the one edit this design invites, so it fails here rather than in a
	// customer's payload — and the reverse catches a parser no source declares.
	t.Run("parsers and sources match", func(t *testing.T) {
		declared := map[string]bool{}
		for _, s := range sources {
			declared[s.ID] = true
			// Two modes classify without a parser: one from metadata alone, the
			// other by the key classifier the directory listing drives.
			if s.Mode == readStat || s.Mode == readKeyDir {
				continue
			}
			if parsers[s.ID] == nil {
				t.Errorf("%s is read but has no parser", s.ID)
			}
		}
		for id := range parsers {
			if !declared[id] {
				t.Errorf("parser %q matches no catalog source", id)
			}
		}
	})

	// A prefix override applies where paths arrive from elsewhere. On a source that
	// resolves its own location it would be read from the environment and do nothing.
	t.Run("prefix overrides only on delegated sources", func(t *testing.T) {
		for _, s := range sources {
			for _, o := range s.Overrides {
				if o.Kind == overridePrefix && s.Mode != readDelegated {
					t.Errorf("%s: prefix override %q has no effect on a %s source", s.ID, o.Var, s.Mode)
				}
			}
		}
	})

	t.Run("EnvVars is deduplicated and covers every override", func(t *testing.T) {
		seen := map[string]bool{}
		for _, v := range EnvVars() {
			if seen[v] {
				t.Errorf("EnvVars returned %q twice", v)
			}
			seen[v] = true
		}
		// XDG_CONFIG_HOME is listed by one source as an override and is also a
		// path root, so it is where deduplication actually matters.
		if !seen["XDG_CONFIG_HOME"] {
			t.Error("EnvVars must include the variable the path roots depend on")
		}
		for _, s := range sources {
			for _, o := range s.Overrides {
				if !seen[o.Var] {
					t.Errorf("%s: override %q missing from EnvVars", s.ID, o.Var)
				}
			}
		}
	})

	// Why this list is a closed table rather than a pattern: several tools accept the
	// secret itself through the environment, and such a variable is never collected.
	t.Run("EnvVars never asks for a credential", func(t *testing.T) {
		for _, v := range EnvVars() {
			for _, bad := range []string{"TOKEN", "PASSWORD", "SECRET", "KEY"} {
				if strings.Contains(v, bad) {
					t.Errorf("EnvVars asks for %q, which can hold a credential", v)
				}
			}
		}
	})
}

func TestDescriptorGrantsBroadRead(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		want bool
	}{
		{name: "read granted to everyone", sddl: `O:BAG:BAD:(A;;FR;;;WD)`, want: true},
		{name: "read granted to all authenticated accounts", sddl: `O:BAG:BAD:(A;;FA;;;AU)`, want: true},
		{name: "read granted to the local users group", sddl: `D:(A;;FR;;;BU)`, want: true},
		{name: "read granted to anyone signed in interactively", sddl: `D:(A;;GR;;;IU)`, want: true},
		{name: "read granted anonymously", sddl: `D:(A;;FR;;;AN)`, want: true},
		// The layout a developer's own credential file has: the account, the
		// system, and administrators.
		{name: "read granted only to specific accounts", sddl: `O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-513D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)`, want: false},
		// Only an allow entry grants anything.
		{name: "read denied to everyone", sddl: `D:(D;;FA;;;WD)`, want: false},
		// A conditional entry carries extra terms deciding whether it applies at all,
		// so reporting it as a grant would assert access that may never be in effect.
		{name: "conditional allow is not counted", sddl: `D:(XA;;FR;;;WD)`, want: false},
		{name: "write without read", sddl: `D:(A;;FW;;;WD)`, want: false},
		{name: "numeric rights including read", sddl: `D:(A;;0x80000000;;;WD)`, want: true},
		{name: "numeric rights for content read", sddl: `D:(A;;0x00000001;;;WD)`, want: true},
		{name: "numeric rights without read", sddl: `D:(A;;0x00000002;;;WD)`, want: false},
		{name: "inheritance flags do not change the verdict", sddl: `D:PAI(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)`, want: true},
		// The audit list records access rather than granting it, so it is not part
		// of what this classifies.
		{name: "an audit entry for everyone is not a grant", sddl: `D:(A;;FA;;;SY)S:(AU;SAFA;FR;;;WD)`, want: false},
		{name: "no discretionary list at all", sddl: `O:BAG:BA`, want: false},
		{name: "empty descriptor", sddl: ``, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := descriptorGrantsBroadRead(tt.sddl); got != tt.want {
				t.Errorf("descriptorGrantsBroadRead(%q) = %v, want %v", tt.sddl, got, tt.want)
			}
		})
	}
}

func TestSplitACEs(t *testing.T) {
	got := splitACEs(`PAI(A;;FA;;;SY)(A;;FR;;;WD)`)
	want := []string{`A;;FA;;;SY`, `A;;FR;;;WD`}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
	// An unterminated entry yields what was complete rather than failing the list.
	if entries := splitACEs(`(A;;FA;;;SY)(A;;FR`); len(entries) != 1 {
		t.Errorf("entries = %v, want only the complete one", entries)
	}
	if entries := splitACEs(``); len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
}

func TestAceGrantsBroadRead_MalformedEntry(t *testing.T) {
	// An entry with fewer fields than the format defines is not classified.
	if aceGrantsBroadRead(`A;;FA`) {
		t.Error("a truncated entry must not be read as a grant")
	}
}

func TestRightsIncludeRead(t *testing.T) {
	tests := map[string]bool{
		"FA":         true,
		"FR":         true,
		"GA":         true,
		"GR":         true,
		"KA":         true,
		"KR":         true,
		"FRFW":       true,
		"fr":         true,
		"FW":         false,
		"WD":         false,
		"":           false,
		"0xdeadbeef": true,
		"0x1F01FF":   true,
		"0X80000000": true,
		"0x00000002": false,
		"0xzz":       false,
		// A number the field cannot hold is not read as a grant. Truncating it to
		// what fits would invent a rights mask the descriptor never stated.
		"0xffffffffffffffffff": false,
		// Too short to be a number, so it falls to the abbreviation reading and
		// matches none.
		"0x": false,
	}
	for rights, want := range tests {
		if got := rightsIncludeRead(rights); got != want {
			t.Errorf("rightsIncludeRead(%q) = %v, want %v", rights, got, want)
		}
	}
}
