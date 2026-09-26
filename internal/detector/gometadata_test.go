package detector

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/module"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// goTestH1 returns a canonical h1 value derived from seed.
func goTestH1(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "h1:" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestGoProjectFromModfile(t *testing.T) {
	data := []byte(`module example.com/App/v2

go 1.24
toolchain go1.24.3

require (
	github.com/BurntSushi/toml v1.3.2
	"golang.org/x/text" v0.14.0 // indirect
)
require example.com/lib/v2 v2.1.0
require	github.com/Sirupsen/logrus	v1.0.0
require "github.com/sirupsen/logrus" v1.9.3

replace example.com/old => example.com/new v1.0.0
replace example.com/lib/v2 v2.1.0 => ../lib
exclude example.com/bad v0.1.0
tool example.com/tools/cmd/gen
`)
	p, err := goProjectFromModfile("go.mod", data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.ModulePath != "example.com/App/v2" || p.GoVersion != "1.24" || p.Toolchain != "go1.24.3" {
		t.Errorf("header = %q %q %q", p.ModulePath, p.GoVersion, p.Toolchain)
	}
	wantReq := []model.GoRequirement{
		{ModulePath: "github.com/BurntSushi/toml", RequestedVersion: "v1.3.2"},
		{ModulePath: "golang.org/x/text", RequestedVersion: "v0.14.0", Indirect: true},
		{ModulePath: "example.com/lib/v2", RequestedVersion: "v2.1.0"},
		// Tab-separated and quoted forms; paths differing only by case stay distinct.
		{ModulePath: "github.com/Sirupsen/logrus", RequestedVersion: "v1.0.0"},
		{ModulePath: "github.com/sirupsen/logrus", RequestedVersion: "v1.9.3"},
	}
	if !reflect.DeepEqual(p.Requirements, wantReq) {
		t.Errorf("requirements = %+v", p.Requirements)
	}
	wantRep := []model.GoReplacement{
		{FromPath: "example.com/old", Kind: model.GoReplaceModule, ToModulePath: "example.com/new", ToVersion: "v1.0.0"},
		{FromPath: "example.com/lib/v2", FromVersion: "v2.1.0", Kind: model.GoReplaceLocal, ToLocalPath: "../lib"},
	}
	if !reflect.DeepEqual(p.Replacements, wantRep) {
		t.Errorf("replacements = %+v", p.Replacements)
	}
	if !slices.Equal(p.Exclusions, []model.GoModuleVersion{{ModulePath: "example.com/bad", Version: "v0.1.0"}}) {
		t.Errorf("exclusions = %+v", p.Exclusions)
	}
	if !slices.Equal(p.Tools, []string{"example.com/tools/cmd/gen"}) {
		t.Errorf("tools = %v", p.Tools)
	}

	bare, err := goProjectFromModfile("go.mod", []byte("go 1.22\n"))
	if err != nil || bare.ModulePath != "" || bare.Requirements == nil || bare.WorkspacePaths == nil {
		t.Errorf("module-less go.mod = %+v, %v; want empty module and non-nil lists", bare, err)
	}
	for _, bad := range []string{"module x.com/a\nrequire x.com/b master\n", "module x.com/a\nbogus directive\n", "module (\n"} {
		if _, err := goProjectFromModfile("go.mod", []byte(bad)); err == nil {
			t.Errorf("%q: expected a parse error, never a guessed version", bad)
		}
	}
}

func TestGoWorkspaceFromModfile(t *testing.T) {
	w, err := goWorkspaceFromModfile("go.work", []byte("go 1.23\ntoolchain go1.23.1\nuse (\n\t./a\n\t/abs/b\n)\nreplace x.com/a v1.0.0 => x.com/b v1.1.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if w.GoVersion != "1.23" || w.Toolchain != "go1.23.1" {
		t.Errorf("header = %q %q", w.GoVersion, w.Toolchain)
	}
	if len(w.Members) != 2 || w.Members[0].DeclaredPath != "./a" || w.Members[1].DeclaredPath != "/abs/b" {
		t.Errorf("members = %+v", w.Members)
	}
	if len(w.Replacements) != 1 || w.Replacements[0].ToModulePath != "x.com/b" {
		t.Errorf("replacements = %+v", w.Replacements)
	}
	if _, err := goWorkspaceFromModfile("go.work", []byte("use (\n")); err == nil {
		t.Error("expected parse error")
	}
}

func TestParseVendorModules(t *testing.T) {
	data := []byte(`# example.com/a v1.0.0
## explicit; go 1.20
example.com/a
example.com/a/sub
# example.com/headeronly v1.1.0
## explicit
# example.com/rep v1.2.0 => example.com/fork v1.2.1
## explicit
example.com/rep/pkg
# example.com/wild => ../wild
# example.com/local v0.1.0 => ../local
example.com/local
# example.com/bad v1.0.0
not a package
# nonsense line
orphan/pkg
`)
	l := parseVendorModules(data)
	var got []string
	for _, m := range l.modules {
		r := ""
		if m.replace != nil {
			r = " => " + m.replace.Path + " " + m.replace.Version
		}
		got = append(got, fmt.Sprintf("%s@%s%s %v", m.mod.Path, m.mod.Version, r, m.packages))
	}
	want := []string{
		"example.com/a@v1.0.0 [example.com/a example.com/a/sub]",
		"example.com/rep@v1.2.0 => example.com/fork v1.2.1 [example.com/rep/pkg]",
		"example.com/local@v0.1.0 => ../local  [example.com/local]",
	}
	if !slices.Equal(got, want) {
		t.Errorf("modules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !l.explicit[module.Version{Path: "example.com/headeronly", Version: "v1.1.0"}] {
		t.Error("header-only explicit marker lost")
	}

	req := func(pairs ...string) model.GoProject {
		p := model.GoProject{GoVersion: "1.21"}
		for i := 0; i < len(pairs); i += 2 {
			p.Requirements = append(p.Requirements, model.GoRequirement{ModulePath: pairs[i], RequestedVersion: pairs[i+1]})
		}
		return p
	}
	consistent := req("example.com/a", "v1.0.0", "example.com/headeronly", "v1.1.0", "example.com/rep", "v1.2.0")
	tests := []struct {
		name string
		p    model.GoProject
		want bool
	}{
		{"consistent", consistent, false},
		{"requirement bumped", req("example.com/a", "v1.0.1", "example.com/headeronly", "v1.1.0", "example.com/rep", "v1.2.0"), true},
		{"explicit entry dropped from go.mod", req("example.com/a", "v1.0.0", "example.com/rep", "v1.2.0"), true},
		{"pre-1.14 compares selected version only", model.GoProject{GoVersion: "1.13", Requirements: []model.GoRequirement{
			{ModulePath: "example.com/a", RequestedVersion: "v1.0.0"}, {ModulePath: "example.com/headeronly", RequestedVersion: "v1.1.0"},
			{ModulePath: "example.com/rep", RequestedVersion: "v1.2.0"}, {ModulePath: "example.com/local", RequestedVersion: "v0.1.0"},
		}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := l.mismatches(tc.p); got != tc.want {
				t.Errorf("mismatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGoCacheNames(t *testing.T) {
	dirs := []struct {
		rel     string
		want    string
		wantErr error
	}{
		{"github.com/!burnt!sushi/toml@v1.3.2", "github.com/BurntSushi/toml@v1.3.2", nil},
		{"example.com/lib/v2@v2.0.0", "example.com/lib/v2@v2.0.0", nil},
		{"example.com/old@v2.0.0+incompatible", "example.com/old@v2.0.0+incompatible", nil},
		{"golang.org/toolchain@v0.0.1-go1.22.0.darwin-arm64", "golang.org/toolchain@v0.0.1-go1.22.0.darwin-arm64", nil},
		{"example.com/a@v1.0.0.tmp-123", "", errGoTempName},
		{"example.com/a@master", "", errors.New("invalid")},
		{"example.com/Upper@v1.0.0", "", errors.New("invalid")}, // unescaped capital
		{"example.com/a", "", errors.New("invalid")},
	}
	for _, tc := range dirs {
		t.Run(tc.rel, func(t *testing.T) {
			m, err := goCacheModuleDir(tc.rel)
			switch {
			case tc.wantErr == nil && (err != nil || m.String() != tc.want):
				t.Errorf("got %v, %v; want %s", m, err, tc.want)
			case tc.wantErr == errGoTempName && !errors.Is(err, errGoTempName):
				t.Errorf("err = %v; want temp-name sentinel", err)
			case tc.wantErr != nil && err == nil:
				t.Errorf("got %v; want an error", m)
			}
		})
	}

	files := []struct {
		name, ext string
		ok        bool
	}{
		{"v1.0.0.zip", ".zip", true},
		{"v1.0.0.ziphash", ".ziphash", true},
		{"v1.0.0.partial", ".partial", true},
		{"v1.0.0-!r!c1.zip", ".zip", true},
		{"v1.0.0.mod", "", false},
		{"v1.0.0.info", "", false},
		{"v1.0.0.lock", "", false},
		{"list", "", false},
		{"v1.0.0.zip12345.tmp", "", false},
		{"master.zip", ".zip", false},
	}
	for _, tc := range files {
		t.Run(tc.name, func(t *testing.T) {
			m, ext, ok := goCacheDownloadFile("github.com/!burnt!sushi/toml", tc.name)
			if ok != tc.ok || (ok && (ext != tc.ext || m.Path != "github.com/BurntSushi/toml")) {
				t.Errorf("got %v %q %v; want ext %q ok %v", m, ext, ok, tc.ext, tc.ok)
			}
		})
	}
	if m, _, ok := goCacheDownloadFile("github.com/!burnt!sushi/toml", "v1.0.0-!r!c1.zip"); !ok || m.Version != "v1.0.0-RC1" {
		t.Errorf("escaped version = %v, %v", m, ok)
	}
}

func goTestZip(t testing.TB, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("x"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestZipArchiveStatus(t *testing.T) {
	mod := module.Version{Path: "example.com/a", Version: "v1.0.0"}
	good := goTestZip(t, "example.com/a@v1.0.0/go.mod", "example.com/a@v1.0.0/a.go")
	tests := []struct {
		name string
		data []byte
		cap  int
		want string
	}{
		{"match", good, 10, model.GoArtifactPresent},
		{"other version", goTestZip(t, "example.com/a@v1.0.1/go.mod"), 10, model.GoArtifactUnreadable},
		{"prefix without slash", goTestZip(t, "example.com/a@v1.0.0x/go.mod"), 10, model.GoArtifactUnreadable},
		{"entry cap", good, 1, model.GoArtifactPartial},
		{"corrupt", good[:len(good)/2], 10, model.GoArtifactUnreadable},
		{"not a zip", []byte("hello"), 10, model.GoArtifactUnreadable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := maxGoZipEntries
			maxGoZipEntries = tc.cap
			defer func() { maxGoZipEntries = old }()
			if got := zipArchiveStatus(tc.data, mod); got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

// BenchmarkZipArchiveStatus measures allocation for an adversarial archive
// with more entries than the cap, the spec's required memory measurement.
func BenchmarkZipArchiveStatus(b *testing.B) {
	names := make([]string, maxGoZipEntries*3)
	for i := range names {
		names[i] = fmt.Sprintf("example.com/a@v1.0.0/%0200d.go", i) // long names inflate the central directory
	}
	data := goTestZip(b, names...)
	mod := module.Version{Path: "example.com/a", Version: "v1.0.0"}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		if zipArchiveStatus(data, mod) != model.GoArtifactPartial {
			b.Fatal("expected the entry cap")
		}
	}
}

func TestGoToolFromBuildInfo(t *testing.T) {
	sumMain, sumDep, sumRep := goTestH1("main"), goTestH1("dep"), goTestH1("rep")
	bi := &debug.BuildInfo{
		Path: "example.com/tool/cmd/tool",
		Main: debug.Module{Path: "example.com/tool", Version: "v1.2.3", Sum: sumMain},
		Deps: []*debug.Module{
			{Path: "example.com/dep", Version: "v0.1.0-20240101000000-abcdefabcdef", Sum: sumDep},
			{Path: "example.com/orig", Version: "v1.0.0", Sum: goTestH1("orig"),
				Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1", Sum: sumRep}},
			{Path: "example.com/local", Version: "v1.0.0", Replace: &debug.Module{Path: "../local"}},
			{Path: "example.com/nosum", Version: "v2.0.0+incompatible"},
			{Path: "example.com/badsum", Version: "v1.0.0", Sum: "h1:short"},
			nil,
		},
		Settings: []debug.BuildSetting{{Key: "-ldflags", Value: "-X secret=hunter2"}},
	}
	tool := goToolFromBuildInfo(bi, "/home/u/go/bin/tool", "src1")
	if tool.MainPackagePath != "example.com/tool/cmd/tool" || tool.MainModulePath != "example.com/tool" ||
		tool.ObservedVersion != "v1.2.3" || tool.VersionStatus != model.GoVersionKnown || tool.SourceID != "src1" {
		t.Errorf("tool header = %+v", tool)
	}
	if tool.ChecksumStatus != model.GoChecksumRecorded || len(tool.RecordedChecksums) != 1 ||
		!reflect.DeepEqual(tool.RecordedChecksums[0], model.GoRecordedChecksum{Kind: model.GoChecksumKindModuleContent, Value: sumMain,
			Source: model.GoChecksumSourceBinaryBuildInfo, SourceID: "src1", SourcePath: "/home/u/go/bin/tool", Verification: model.GoChecksumNotVerified}) {
		t.Errorf("main checksum = %+v", tool.GoChecksumEvidence)
	}
	if len(tool.Dependencies) != 5 {
		t.Fatalf("dependencies = %d, want 5 (nil skipped)", len(tool.Dependencies))
	}
	d := tool.Dependencies
	if d[0].ObservedVersion != "v0.1.0-20240101000000-abcdefabcdef" || d[0].ChecksumStatus != model.GoChecksumRecorded || d[0].RecordedChecksums[0].Value != sumDep {
		t.Errorf("pseudo-version dep = %+v", d[0])
	}
	if d[1].ChecksumStatus != model.GoChecksumNotApplicable || d[1].RecordedChecksums != nil ||
		d[1].Replacement == nil || d[1].Replacement.ToModulePath != "example.com/fork" ||
		d[1].Replacement.ChecksumStatus != model.GoChecksumRecorded || d[1].Replacement.RecordedChecksums[0].Value != sumRep {
		t.Errorf("replaced dep: Replace.Sum must stay on the provider: %+v %+v", d[1], d[1].Replacement)
	}
	if d[2].Replacement == nil || d[2].Replacement.Kind != model.GoReplaceLocal || d[2].Replacement.ToLocalPath != "../local" ||
		d[2].Replacement.ChecksumStatus != model.GoChecksumNotApplicable {
		t.Errorf("local replacement = %+v", d[2].Replacement)
	}
	if d[3].ObservedVersion != "v2.0.0+incompatible" || d[3].ChecksumStatus != model.GoChecksumAbsent {
		t.Errorf("empty Sum dep = %+v; want verbatim version and absent", d[3])
	}
	if d[4].ChecksumStatus != model.GoChecksumInvalid || d[4].RecordedChecksums != nil {
		t.Errorf("invalid Sum dep = %+v", d[4])
	}

	devel := goToolFromBuildInfo(&debug.BuildInfo{Path: "x.com/c", Main: debug.Module{Path: "x.com/c", Version: "(devel)"}}, "/b", "s")
	if devel.ObservedVersion != "" || devel.VersionStatus != model.GoVersionUnknown || devel.ChecksumStatus != model.GoChecksumNotApplicable {
		t.Errorf("devel tool = %+v", devel)
	}
	empty := goToolFromBuildInfo(&debug.BuildInfo{Path: "command-line-arguments"}, "/b", "s")
	if empty.VersionStatus != model.GoVersionUnknown || empty.MainModulePath != "" {
		t.Errorf("no main module = %+v", empty)
	}
}

func TestGoBuildInfo(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	bi, notGo := goBuildInfo(data)
	if bi == nil || notGo {
		t.Fatalf("test binary: bi=%v notGo=%v", bi, notGo)
	}
	// Test binaries record no dependencies, so this pins the real-read path
	// and the devel main module; constructed BuildInfo covers dependencies.
	tool := goToolFromBuildInfo(bi, exe, "s")
	if tool.MainModulePath != "github.com/step-security/dev-machine-guard" || tool.VersionStatus != model.GoVersionUnknown ||
		tool.ChecksumStatus != model.GoChecksumNotApplicable {
		t.Errorf("test binary tool = %+v", tool)
	}

	tests := []struct {
		name      string
		data      []byte
		wantNotGo bool
	}{
		{"script", []byte("#!/bin/sh\necho hi\n"), true},
		{"empty", nil, true},
		{"truncated ELF", append([]byte("\x7FELF"), make([]byte, 60)...), false},
		{"truncated Go binary", data[:4096], false},
		{"truncated PE", []byte("MZ\x90\x00"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if bi, notGo := goBuildInfo(tc.data); bi != nil || notGo != tc.wantNotGo {
				t.Errorf("bi=%v notGo=%v; want nil, %v", bi, notGo, tc.wantNotGo)
			}
		})
	}
	if runtime.GOOS != "windows" {
		if ls, err := os.ReadFile("/bin/ls"); err == nil {
			if bi, notGo := goBuildInfo(ls); bi != nil || !notGo {
				t.Errorf("/bin/ls: bi=%v notGo=%v; want a non-Go executable", bi, notGo)
			}
		}
	}
}

func TestParseGoSum(t *testing.T) {
	h1, h2 := goTestH1("1"), goTestH1("2")
	nonCanonical := h1[:len(h1)-2] + "B=" // same length, trailing bits set
	tests := []struct {
		name        string
		data        string
		wantKeys    map[module.Version][]goSumEntry
		wantReasons []string
	}{
		{"both kinds", "x.com/a v1.0.0 " + h1 + "\nx.com/a v1.0.0/go.mod " + h2 + "\n",
			map[module.Version][]goSumEntry{{Path: "x.com/a", Version: "v1.0.0"}: {{model.GoChecksumKindModuleContent, h1}, {model.GoChecksumKindGoMod, h2}}}, nil},
		{"blank and CRLF lines", "\n  \nx.com/a v1.0.0 " + h1 + "\r\n",
			map[module.Version][]goSumEntry{{Path: "x.com/a", Version: "v1.0.0"}: {{model.GoChecksumKindModuleContent, h1}}}, nil},
		{"duplicates collapse, conflicts kept", "x.com/a v1 " + h1 + "\nx.com/a v1 " + h1 + "\nx.com/a v1 " + h2 + "\n",
			map[module.Version][]goSumEntry{{Path: "x.com/a", Version: "v1"}: {{model.GoChecksumKindModuleContent, h1}, {model.GoChecksumKindModuleContent, h2}}}, nil},
		{"malformed lines", "x.com/a v1.0.0\nx.com/a v1.0.0 h1:abc\nx.com/a v1.0.0 " + nonCanonical + "\nx.com/b v1 " + h1 + " extra\nx.com/c v1 nocolon\n",
			map[module.Version][]goSumEntry{}, []string{model.GoReasonMalformedChecksumLine}},
		{"other scheme", "x.com/a v1.0.0 h2:" + h1[3:] + "\nx.com/b v1 " + h1 + "\n",
			map[module.Version][]goSumEntry{{Path: "x.com/b", Version: "v1"}: {{model.GoChecksumKindModuleContent, h1}}}, []string{model.GoReasonUnsupportedChecksumScheme}},
		{"old empty go.mod hash dropped", "x.com/a v1.0.0/go.mod " + goEmptyGoModSumBug + "\n", map[module.Version][]goSumEntry{}, nil},
		{"long line keeps matches on both sides", "x.com/z v1 " + h2 + "\nx.com/a v1.0.0 " + h1 + strings.Repeat(" ", 5000) + "\nx.com/b v1 " + h1,
			map[module.Version][]goSumEntry{
				{Path: "x.com/z", Version: "v1"}: {{model.GoChecksumKindModuleContent, h2}},
				{Path: "x.com/b", Version: "v1"}: {{model.GoChecksumKindModuleContent, h1}},
			}, []string{model.GoReasonChecksumLineTooLong}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idx, reasons := parseGoSum([]byte(tc.data))
			if len(idx) != len(tc.wantKeys) {
				t.Errorf("index = %v, want %v", idx, tc.wantKeys)
			}
			for k, want := range tc.wantKeys {
				if !slices.Equal(idx[k], want) {
					t.Errorf("%v = %v, want %v", k, idx[k], want)
				}
			}
			if !slices.Equal(reasons, tc.wantReasons) {
				t.Errorf("reasons = %v, want %v", reasons, tc.wantReasons)
			}
			for _, r := range reasons {
				if strings.Contains(r, "x.com") {
					t.Errorf("reason leaks line text: %q", r)
				}
			}
		})
	}

	old := maxGoSumLines
	maxGoSumLines = 2
	defer func() { maxGoSumLines = old }()
	idx, reasons := parseGoSum([]byte("x.com/a v1 " + h1 + "\nx.com/b v1 " + h1 + "\nx.com/c v1 " + h1 + "\n"))
	if len(idx) != 2 || !slices.Equal(reasons, []string{model.GoReasonChecksumLineLimit}) {
		t.Errorf("line cap: %d keys, %v; want 2 kept and the cap reason", len(idx), reasons)
	}
}

func TestValidH1AndZiphash(t *testing.T) {
	h := goTestH1("z")
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{h, true}, {"h1:", false}, {"h2:" + h[3:], false}, {h + "=", false}, {"h1:" + base64.StdEncoding.EncodeToString(make([]byte, 31)), false},
		{h[:len(h)-2] + "B=", false}, {strings.TrimSuffix(h, "="), false},
	} {
		if got := validH1(tc.in); got != tc.want {
			t.Errorf("validH1(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if v, ok := parseZiphash([]byte(" \n" + h + "\n")); !ok || v != h {
		t.Errorf("ziphash with whitespace = %q, %v", v, ok)
	}
	if _, ok := parseZiphash([]byte("garbage")); ok {
		t.Error("garbage ziphash accepted")
	}
}

func TestGoChecksums(t *testing.T) {
	mod := module.Version{Path: "x.com/a", Version: "v1.0.0"}
	h1, h2 := goTestH1("1"), goTestH1("2")
	src := func(kind, path, failure string, entries ...goSumEntry) goSumSource {
		s := goSumSource{kind: kind, id: "id-" + path, path: path, failure: failure, index: goSumIndex{}}
		if entries != nil {
			s.index[mod] = entries
		}
		return s
	}
	proj, work := model.GoChecksumSourceProjectGoSum, model.GoChecksumSourceWorkspaceGoWorkSum
	content, gomod := goSumEntry{model.GoChecksumKindModuleContent, h1}, goSumEntry{model.GoChecksumKindGoMod, h2}
	tests := []struct {
		name    string
		sources []goSumSource
		want    string
		recs    int
	}{
		{"recorded", []goSumSource{src(proj, "/p/go.sum", "", content)}, model.GoChecksumRecorded, 1},
		{"absent", []goSumSource{src(proj, "/p/go.sum", "")}, model.GoChecksumAbsent, 0},
		{"match with gap", []goSumSource{src(proj, "/p/go.sum", "", content), src(work, "/w/go.work.sum", model.GoChecksumUnreadable)}, model.GoChecksumPartial, 1},
		{"match from partially parsed file", []goSumSource{src(proj, "/p/go.sum", model.GoChecksumInvalid, content)}, model.GoChecksumPartial, 1},
		{"unreadable beats skipped", []goSumSource{src(proj, "/p/go.sum", model.GoChecksumSkipped), src(work, "/w/go.work.sum", model.GoChecksumUnreadable)}, model.GoChecksumUnreadable, 0},
		{"skipped", []goSumSource{src(proj, "/p/go.sum", model.GoChecksumSkipped)}, model.GoChecksumSkipped, 0},
		{"partial beats invalid", []goSumSource{src(proj, "/p/go.sum", model.GoChecksumInvalid), src(work, "/w", model.GoChecksumPartial)}, model.GoChecksumPartial, 0},
		{"invalid", []goSumSource{src(proj, "/p/go.sum", model.GoChecksumInvalid)}, model.GoChecksumInvalid, 0},
		{"unsupported", []goSumSource{src(proj, "/p/go.sum", model.GoChecksumUnsupported)}, model.GoChecksumUnsupported, 0},
		{"same value from two files kept apart", []goSumSource{src(proj, "/p/go.sum", "", content), src(work, "/w/go.work.sum", "", content)}, model.GoChecksumRecorded, 2},
		{"duplicate source collapses", []goSumSource{src(proj, "/p/go.sum", "", content), src(proj, "/p/go.sum", "", content, gomod)}, model.GoChecksumRecorded, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ev model.GoChecksumEvidence
			goChecksums(&ev, mod, tc.sources...)
			if ev.ChecksumStatus != tc.want || len(ev.RecordedChecksums) != tc.recs {
				t.Errorf("got %q with %d records, want %q with %d", ev.ChecksumStatus, len(ev.RecordedChecksums), tc.want, tc.recs)
			}
			for _, r := range ev.RecordedChecksums {
				if r.Verification != model.GoChecksumNotVerified || r.SourceID == "" || r.SourcePath == "" {
					t.Errorf("record = %+v", r)
				}
			}
		})
	}

	var ev model.GoChecksumEvidence
	goChecksums(&ev, mod, src(work, "/w", "", gomod, content), src(proj, "/p", "", content))
	order := []string{}
	for _, r := range ev.RecordedChecksums {
		order = append(order, r.Kind+":"+r.Source)
	}
	if want := []string{"module_content:" + proj, "module_content:" + work, "go_mod:" + work}; !slices.Equal(order, want) {
		t.Errorf("sort order = %v, want %v", order, want)
	}

	var many []goSumEntry
	for i := range maxGoChecksums + 3 {
		many = append(many, goSumEntry{model.GoChecksumKindModuleContent, goTestH1(fmt.Sprint(i))})
	}
	ev = model.GoChecksumEvidence{}
	goChecksums(&ev, mod, src(proj, "/p", "", many...))
	if len(ev.RecordedChecksums) != maxGoChecksums || ev.ChecksumStatus != model.GoChecksumPartial {
		t.Errorf("cap: %d records, %q; want %d and partial", len(ev.RecordedChecksums), ev.ChecksumStatus, maxGoChecksums)
	}
}

func TestGoSumFailure(t *testing.T) {
	tests := []struct {
		reasons []string
		want    string
	}{
		{nil, ""},
		{[]string{model.GoReasonUnsupportedChecksumScheme}, model.GoChecksumUnsupported},
		{[]string{model.GoReasonMalformedChecksumLine, model.GoReasonUnsupportedChecksumScheme}, model.GoChecksumInvalid},
		{[]string{model.GoReasonChecksumLineTooLong, model.GoReasonMalformedChecksumLine}, model.GoChecksumPartial},
		{[]string{model.GoReasonChecksumLineLimit}, model.GoChecksumPartial},
	}
	for _, tc := range tests {
		if got := goSumFailure(tc.reasons); got != tc.want {
			t.Errorf("goSumFailure(%v) = %q, want %q", tc.reasons, got, tc.want)
		}
	}
}
