package detector

import (
	"archive/zip"
	"bytes"
	"cmp"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"errors"
	"runtime/debug"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Byte-level parsers for Go metadata. Nothing here touches the filesystem;
// goscan.go reads bounded bytes through the guarded executor and hands them in.

// Checksum and archive bounds from the spec's starting values.
// ponytail: unmeasured on fleet data; tune after lab measurements.
var (
	maxGoSumLines     = 50_000
	maxGoSumLineBytes = 4 << 10
	maxGoChecksums    = 8
	maxGoZipEntries   = 10_000
)

// goEmptyGoModSumBug is an old bad go.mod hash that cmd/go drops on read.
const goEmptyGoModSumBug = "h1:G7mAYYxgmS0lVkHyy2hEOLQCFB0DlQFTMLWggykrydY="

// goProjectFromModfile parses go.mod bytes. The caller sets the source ID and
// paths. Parse is strict: a version Go would have to resolve over the network
// is a parse error, never a guess.
func goProjectFromModfile(name string, data []byte) (model.GoProject, error) {
	f, err := modfile.Parse(name, data, nil)
	if err != nil {
		return model.GoProject{}, err
	}
	p := model.GoProject{
		Requirements:   []model.GoRequirement{},
		Replacements:   goReplacements(f.Replace),
		Exclusions:     []model.GoModuleVersion{},
		Tools:          []string{},
		WorkspacePaths: []string{},
	}
	if f.Module != nil {
		p.ModulePath = f.Module.Mod.Path
	}
	if f.Go != nil {
		p.GoVersion = f.Go.Version
	}
	if f.Toolchain != nil {
		p.Toolchain = f.Toolchain.Name
	}
	for _, r := range f.Require {
		p.Requirements = append(p.Requirements, model.GoRequirement{
			ModulePath: r.Mod.Path, RequestedVersion: r.Mod.Version, Indirect: r.Indirect,
		})
	}
	for _, x := range f.Exclude {
		p.Exclusions = append(p.Exclusions, model.GoModuleVersion{ModulePath: x.Mod.Path, Version: x.Mod.Version})
	}
	for _, t := range f.Tool {
		p.Tools = append(p.Tools, t.Path)
	}
	return p, nil
}

// goWorkspaceFromModfile parses go.work bytes; members carry only their
// declared path until the scanner resolves them.
func goWorkspaceFromModfile(name string, data []byte) (model.GoWorkspace, error) {
	f, err := modfile.ParseWork(name, data, nil)
	if err != nil {
		return model.GoWorkspace{}, err
	}
	w := model.GoWorkspace{Members: []model.GoWorkspaceMember{}, Replacements: goReplacements(f.Replace)}
	if f.Go != nil {
		w.GoVersion = f.Go.Version
	}
	if f.Toolchain != nil {
		w.Toolchain = f.Toolchain.Name
	}
	for _, u := range f.Use {
		w.Members = append(w.Members, model.GoWorkspaceMember{DeclaredPath: u.Path})
	}
	return w, nil
}

func goReplacements(rs []*modfile.Replace) []model.GoReplacement {
	out := []model.GoReplacement{}
	for _, r := range rs {
		out = append(out, goReplacement(r.Old, r.New))
	}
	return out
}

// goReplacement keeps a local directory apart from a module identity: Go
// marks a filesystem replacement by its empty version.
func goReplacement(from, to module.Version) model.GoReplacement {
	r := model.GoReplacement{FromPath: from.Path, FromVersion: from.Version}
	if to.Version == "" {
		r.Kind, r.ToLocalPath = model.GoReplaceLocal, to.Path
	} else {
		r.Kind, r.ToModulePath, r.ToVersion = model.GoReplaceModule, to.Path, to.Version
	}
	return r
}

// goVendorModule is a vendor/modules.txt module that lists at least one package.
type goVendorModule struct {
	mod      module.Version
	replace  *module.Version
	packages []string // in file order; the scanner corroborates the first that exists
}

// goVendorList is the parsed vendor/modules.txt.
type goVendorList struct {
	modules  []goVendorModule
	explicit map[module.Version]bool
	selected map[string]string // module path -> version providing packages
}

// parseVendorModules ports cmd/go's readVendorList (modload/vendor.go):
// header-only modules are replacement context, not vendored copies.
func parseVendorModules(data []byte) goVendorList {
	l := goVendorList{explicit: map[module.Version]bool{}, selected: map[string]string{}}
	replaces := map[module.Version]module.Version{}
	index := map[module.Version]int{}
	var mod module.Version
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "# ") {
			f := strings.Fields(line)
			if len(f) < 3 {
				continue
			}
			switch {
			case semver.IsValid(f[2]):
				mod, f = module.Version{Path: f[1], Version: f[2]}, f[3:]
			case f[2] == "=>":
				mod, f = module.Version{Path: f[1]}, f[2:]
			default:
				mod = module.Version{}
				continue
			}
			if len(f) >= 2 && f[0] == "=>" {
				if len(f) == 2 {
					replaces[mod] = module.Version{Path: f[1]}
				} else if len(f) == 3 && semver.IsValid(f[2]) {
					replaces[mod] = module.Version{Path: f[1], Version: f[2]}
				}
			}
			continue
		}
		if mod.Path == "" {
			continue
		}
		if annotations, ok := strings.CutPrefix(line, "## "); ok {
			for entry := range strings.SplitSeq(annotations, ";") {
				if strings.TrimSpace(entry) == "explicit" {
					l.explicit[mod] = true
				}
			}
			continue
		}
		if f := strings.Fields(line); len(f) == 1 && module.CheckImportPath(f[0]) == nil {
			i, ok := index[mod]
			if !ok {
				i = len(l.modules)
				index[mod] = i
				l.modules = append(l.modules, goVendorModule{mod: mod})
				l.selected[mod.Path] = mod.Version
			}
			l.modules[i].packages = append(l.modules[i].packages, f[0])
		}
	}
	for i := range l.modules {
		if r, ok := replaces[l.modules[i].mod]; ok {
			l.modules[i].replace = &r
		}
	}
	return l
}

// mismatches reports the obvious staleness cmd/go's checkVendorConsistency
// rejects: a requirement not marked explicit at its version, or an explicit
// entry go.mod no longer requires. Replacement consistency is not compared.
// Before go 1.14 modules.txt carried no explicit markers, so only the
// selected version is compared.
func (l goVendorList) mismatches(p model.GoProject) bool {
	pre114 := p.GoVersion == "" || semver.Compare("v"+p.GoVersion, "v1.14") < 0
	required := map[module.Version]bool{}
	for _, r := range p.Requirements {
		m := module.Version{Path: r.ModulePath, Version: r.RequestedVersion}
		required[m] = true
		if l.explicit[m] {
			continue
		}
		if !pre114 || l.selected[m.Path] != m.Version {
			return true
		}
	}
	for m := range l.explicit {
		if !required[m] {
			return true
		}
	}
	return false
}

// errGoTempName marks an in-progress cache name, ignored as Go ignores it.
var errGoTempName = errors.New("go: temporary cache name")

// goCacheModuleDir decodes an extracted cache directory, given as its
// slash-separated path below the cache root ("github.com/!foo/bar@v1.0.0").
func goCacheModuleDir(rel string) (module.Version, error) {
	i := strings.LastIndexByte(rel, '@')
	if i < 0 {
		return module.Version{}, errors.New("go: no version in cache name")
	}
	if strings.Contains(rel[i+1:], ".tmp-") {
		return module.Version{}, errGoTempName
	}
	return goUnescapeModule(rel[:i], rel[i+1:])
}

// goCacheDownloadFile decodes a cache/download/<escaped-path>/@v/ entry. Only
// the archive, its checksum sidecar and the in-progress marker count; .mod,
// .info, list, lock and temp files are not module evidence.
func goCacheDownloadFile(escPath, name string) (mod module.Version, ext string, ok bool) {
	for _, ext = range []string{".zip", ".ziphash", ".partial"} {
		if escVer, found := strings.CutSuffix(name, ext); found {
			m, err := goUnescapeModule(escPath, escVer)
			return m, ext, err == nil
		}
	}
	return module.Version{}, "", false
}

func goUnescapeModule(escPath, escVer string) (module.Version, error) {
	p, err := module.UnescapePath(escPath)
	if err != nil {
		return module.Version{}, err
	}
	v, err := module.UnescapeVersion(escVer)
	if err != nil {
		return module.Version{}, err
	}
	if err := module.Check(p, v); err != nil {
		return module.Version{}, err
	}
	return module.Version{Path: p, Version: v}, nil
}

// zipArchiveStatus inspects module ZIP metadata without decompressing: every
// entry must sit under "path@version/", checked for at most maxGoZipEntries.
func zipArchiveStatus(data []byte, mod module.Version) string {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return model.GoArtifactUnreadable
	}
	prefix := mod.Path + "@" + mod.Version + "/"
	for i, f := range zr.File {
		if i >= maxGoZipEntries {
			return model.GoArtifactPartial
		}
		if !strings.HasPrefix(f.Name, prefix) {
			return model.GoArtifactUnreadable
		}
	}
	return model.GoArtifactPresent
}

// goBuildInfo reads embedded BuildInfo from bounded bytes. notGo means the
// file is certainly not a Go binary (a script, or an executable without Go
// metadata); otherwise a nil info is unusable metadata, never a guess.
func goBuildInfo(data []byte) (bi *debug.BuildInfo, notGo bool) {
	bi, err := buildinfo.Read(bytes.NewReader(data))
	switch {
	case err == nil:
		if bi.Path == "" && bi.Main.Path == "" {
			return nil, false
		}
		return bi, false
	case err.Error() == "not a Go executable":
		return nil, true
	case err.Error() == "unrecognized file format":
		// The same error covers a text file and a truncated executable.
		return nil, !goExecutableMagic(data)
	}
	return nil, false
}

// goExecutableMagic mirrors the format sniffing in debug/buildinfo for the
// formats DMG's platforms produce.
func goExecutableMagic(data []byte) bool {
	for _, m := range []string{"\x7FELF", "MZ", "\xFE\xED\xFA", "\xCA\xFE\xBA\xBE", "\xCA\xFE\xBA\xBF"} {
		if bytes.HasPrefix(data, []byte(m)) {
			return true
		}
	}
	return len(data) > 1 && bytes.HasPrefix(data[1:], []byte("\xFA\xED\xFE"))
}

// goToolFromBuildInfo maps usable BuildInfo to a tool record owned by the
// binary source. Settings are never read.
func goToolFromBuildInfo(bi *debug.BuildInfo, binPath, sourceID string) model.GoInstalledTool {
	t := model.GoInstalledTool{
		SourceID:        sourceID,
		BinaryPath:      binPath,
		MainPackagePath: bi.Path,
		MainModulePath:  bi.Main.Path,
		Dependencies:    []model.GoBinaryDependency{},
	}
	t.ObservedVersion, t.VersionStatus = goObservedVersion(bi.Main.Version)
	src := goSumSource{kind: model.GoChecksumSourceBinaryBuildInfo, id: sourceID, path: binPath}
	t.Replacement, t.GoChecksumEvidence = goBinaryModule(&bi.Main, src)
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		dep := model.GoBinaryDependency{ModulePath: d.Path}
		dep.ObservedVersion, dep.VersionStatus = goObservedVersion(d.Version)
		dep.Replacement, dep.GoChecksumEvidence = goBinaryModule(d, src)
		t.Dependencies = append(t.Dependencies, dep)
	}
	return t
}

// goBinaryModule returns a BuildInfo module's replacement and the checksum
// evidence for the original module. Replace.Sum belongs to the provider only,
// so a replaced module's own checksum is not applicable.
func goBinaryModule(m *debug.Module, src goSumSource) (*model.GoReplacement, model.GoChecksumEvidence) {
	if m.Replace == nil {
		return nil, goBinarySum(module.Version{Path: m.Path, Version: m.Version}, m.Sum, src)
	}
	r := goReplacement(module.Version{Path: m.Path, Version: m.Version}, module.Version{Path: m.Replace.Path, Version: m.Replace.Version})
	r.GoChecksumEvidence = goBinarySum(module.Version{Path: m.Replace.Path, Version: m.Replace.Version}, m.Replace.Sum, src)
	return &r, model.GoChecksumEvidence{ChecksumStatus: model.GoChecksumNotApplicable}
}

func goBinarySum(mod module.Version, sum string, src goSumSource) model.GoChecksumEvidence {
	if _, status := goObservedVersion(mod.Version); status == model.GoVersionUnknown {
		return model.GoChecksumEvidence{ChecksumStatus: model.GoChecksumNotApplicable} // local or devel build
	}
	src.index = goSumIndex{}
	switch {
	case sum == "":
	case validH1(sum):
		src.index[mod] = []goSumEntry{{model.GoChecksumKindModuleContent, sum}}
	default:
		src.failure = model.GoChecksumInvalid
	}
	var ev model.GoChecksumEvidence
	goChecksums(&ev, mod, src)
	return ev
}

// goObservedVersion keeps real versions verbatim (pseudo, +incompatible,
// +dirty) and never turns a missing or (devel) version into a release.
func goObservedVersion(v string) (string, string) {
	if v == "" || v == "(devel)" {
		return "", model.GoVersionUnknown
	}
	return v, model.GoVersionKnown
}

type goSumEntry struct{ kind, value string }

// goSumIndex maps an exact module path and version to its recorded values.
type goSumIndex map[module.Version][]goSumEntry

// goSumSource is one checksum source consulted for a record. failure is the
// GoChecksum* status for coverage the source could not give ("" when read
// completely); a partially parsed file still contributes its valid lines.
type goSumSource struct {
	kind, id, path string
	failure        string
	index          goSumIndex
}

// parseGoSum reads go.sum-format bytes as three whitespace-separated tokens,
// as cmd/go's readGoSum does. Reasons are codes only; raw lines never leave.
func parseGoSum(data []byte) (goSumIndex, []string) {
	idx := goSumIndex{}
	var reasons []string
	lines := 0
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		if lines++; lines > maxGoSumLines {
			reasons = append(reasons, model.GoReasonChecksumLineLimit)
			break
		}
		if len(line) > maxGoSumLineBytes {
			reasons = append(reasons, model.GoReasonChecksumLineTooLong)
			continue
		}
		f := strings.Fields(string(line))
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			reasons = append(reasons, model.GoReasonMalformedChecksumLine)
			continue
		}
		if f[2] == goEmptyGoModSumBug {
			continue
		}
		if !strings.HasPrefix(f[2], "h1:") {
			if strings.Contains(f[2], ":") {
				reasons = append(reasons, model.GoReasonUnsupportedChecksumScheme)
			} else {
				reasons = append(reasons, model.GoReasonMalformedChecksumLine)
			}
			continue
		}
		if !validH1(f[2]) {
			reasons = append(reasons, model.GoReasonMalformedChecksumLine)
			continue
		}
		kind, version := model.GoChecksumKindModuleContent, f[1]
		if v, ok := strings.CutSuffix(version, "/go.mod"); ok {
			kind, version = model.GoChecksumKindGoMod, v
		}
		key, e := module.Version{Path: f[0], Version: version}, goSumEntry{kind, f[2]}
		if !slices.Contains(idx[key], e) {
			idx[key] = append(idx[key], e)
		}
	}
	slices.Sort(reasons)
	return idx, slices.Compact(reasons)
}

// goSumFailure turns a parsed file's reasons into the checksum status a
// record gets when that file yields no match for it.
func goSumFailure(reasons []string) string {
	failure := ""
	for _, r := range reasons {
		var s string
		switch r {
		case model.GoReasonChecksumLineLimit, model.GoReasonChecksumLineTooLong:
			s = model.GoChecksumPartial
		case model.GoReasonMalformedChecksumLine:
			s = model.GoChecksumInvalid
		case model.GoReasonUnsupportedChecksumScheme:
			s = model.GoChecksumUnsupported
		default:
			continue
		}
		if goChecksumRank(s) > goChecksumRank(failure) {
			failure = s
		}
	}
	return failure
}

// goChecksumRank orders failures when no source matched: a read failure says
// less about the record than a file that was read but held nothing usable.
func goChecksumRank(status string) int {
	switch status {
	case model.GoChecksumUnreadable:
		return 5
	case model.GoChecksumSkipped:
		return 4
	case model.GoChecksumPartial:
		return 3
	case model.GoChecksumInvalid:
		return 2
	case model.GoChecksumUnsupported:
		return 1
	}
	return 0
}

// validH1 accepts only the canonical standard-base64 encoding of a 32-byte
// h1 hash. Syntax only: DMG never verifies content.
func validH1(s string) bool {
	b64, ok := strings.CutPrefix(s, "h1:")
	if !ok {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	return err == nil && len(raw) == sha256.Size && base64.StdEncoding.EncodeToString(raw) == b64
}

// parseZiphash reads a cache .ziphash sidecar, allowing surrounding whitespace.
func parseZiphash(data []byte) (string, bool) {
	v := strings.TrimSpace(string(data))
	return v, validH1(v)
}

// goChecksums sets ev from exact lookups of mod across the attempted sources:
// recorded when every source was complete and one matched, absent when none
// matched, partial when matches came with gaps, otherwise the worst failure.
func goChecksums(ev *model.GoChecksumEvidence, mod module.Version, sources ...goSumSource) {
	var recs []model.GoRecordedChecksum
	failure := ""
	for _, s := range sources {
		for _, e := range s.index[mod] {
			recs = append(recs, model.GoRecordedChecksum{
				Kind: e.kind, Value: e.value, Source: s.kind, SourceID: s.id, SourcePath: s.path,
				Verification: model.GoChecksumNotVerified,
			})
		}
		if goChecksumRank(s.failure) > goChecksumRank(failure) {
			failure = s.failure
		}
	}
	slices.SortFunc(recs, func(a, b model.GoRecordedChecksum) int {
		return cmp.Or(goChecksumKindOrder(a.Kind)-goChecksumKindOrder(b.Kind),
			strings.Compare(a.Source, b.Source), strings.Compare(a.SourcePath, b.SourcePath),
			strings.Compare(a.Value, b.Value))
	})
	recs = slices.CompactFunc(recs, func(a, b model.GoRecordedChecksum) bool {
		return a.Kind == b.Kind && a.Value == b.Value && a.Source == b.Source && a.SourcePath == b.SourcePath
	})
	if len(recs) > maxGoChecksums {
		recs, failure = recs[:maxGoChecksums], model.GoChecksumPartial
	}
	switch {
	case len(recs) > 0 && failure == "":
		ev.ChecksumStatus = model.GoChecksumRecorded
	case len(recs) > 0:
		ev.ChecksumStatus = model.GoChecksumPartial
	case failure == "":
		ev.ChecksumStatus = model.GoChecksumAbsent
	default:
		ev.ChecksumStatus = failure
	}
	ev.RecordedChecksums = recs
}

// goChecksumKindOrder sorts module content before the go.mod-only hash.
func goChecksumKindOrder(kind string) int {
	if kind == model.GoChecksumKindModuleContent {
		return 0
	}
	return 1
}
