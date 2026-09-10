package devicepolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

const (
	dmgPipBegin = "# BEGIN StepSecurity Package Configuration pip -- managed by dmg"
	dmgPipEnd   = "# END StepSecurity Package Configuration pip"
	mdmPipBegin = "# BEGIN StepSecurity Package Configuration pip -- managed by mdm"
	mdmPipEnd   = "# END StepSecurity Package Configuration pip"

	dmgPipDisabledPrefix         = "# [stepsecurity-pypi-pip-dmg] "
	pipBackupPrefix              = ".dmg-"
	pipAppendMetadata            = "# [stepsecurity-pypi-pip-dmg] appended-global"
	pipGlobalMetadata            = "# [stepsecurity-pypi-pip-dmg] existing-global final-newline=false"
	unsafePipRegistryObservation = "\x00"
)

var pipConflictOptions = map[string]bool{
	"index-url":       true,
	"extra-index-url": true,
	"find-links":      true,
	"no-index":        true,
}

type PipObservation struct {
	RegistryURL     string
	ConfigStatus    string
	EffectiveStatus string
	OverrideSource  string
}

type pipManagedFile struct {
	file    *secureuserfile.File
	current bool
}

// PipWriter manages the complete trusted user-tier pip configuration set.
type PipWriter struct {
	exec        executor.Executor
	home        *secureuserfile.Home
	files       []pipManagedFile
	invocations [][]string
	expected    string
	registryURL string
	lastWritten []*secureuserfile.File
}

func NewPipWriter(ctx context.Context, exec executor.Executor, home *secureuserfile.Home, policy PyPIPolicy) (*PipWriter, error) {
	if home == nil {
		return nil, errors.New("pip: nil secure user home")
	}
	expected, err := renderPipSettings(policy)
	if err != nil {
		return nil, err
	}
	discovery, err := configaudit.DiscoverPipUserConfig(ctx, exec)
	if err != nil {
		return nil, err
	}
	files := make([]pipManagedFile, 0, len(discovery.AllowedUserPaths))
	for i, path := range discovery.AllowedUserPaths {
		relative, err := filepath.Rel(home.Path(), filepath.Clean(path))
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return nil, fmt.Errorf("pip: discovered user path is outside resolved home: %w", ErrTargetUnusable)
		}
		file, err := home.Open(relative, pipBackupPrefix, secureuserfile.MaxBytes)
		if err != nil {
			return nil, err
		}
		files = append(files, pipManagedFile{file: file, current: i == 0})
	}
	if len(files) == 0 {
		return nil, errors.New("pip: no trusted user configuration path")
	}
	return &PipWriter{
		exec:        executor.NewUserAwareExecutor(exec, home.Username()),
		home:        home,
		files:       files,
		invocations: discovery.Invocations,
		expected:    expected,
		registryURL: policy.RegistryURL,
	}, nil
}

func renderPipSettings(policy PyPIPolicy) (string, error) {
	registry, err := parsePyPIRegistryURL(policy.RegistryURL)
	if policy.Ecosystem != "pypi" || !canonicalPyPIClients(policy.Clients) || policy.Auth.Scheme != pypiAuthScheme ||
		err != nil || registry.EscapedPath() != "/python/simple" || policy.Auth.APIKey == "" ||
		len(policy.Auth.APIKey) > npmrcMaxKeyBytes || policy.deviceID == "" || len(policy.deviceID) > npmrcMaxSerialBytes ||
		strings.Contains(policy.Auth.APIKey, "::") || !isNPMSafe(policy.Auth.APIKey) || !isNPMSafe(policy.deviceID) ||
		!isValidHost(policy.RegistryHost()) {
		return "", errors.New("pip: policy cannot render safe user settings")
	}
	return "index-url = " + policy.RegistryURL + "\nno-index = false", nil
}

func (w *PipWriter) validateExpected(expected string) error {
	if w == nil || expected != w.expected {
		return errors.New("pip: expected settings do not match the validated policy")
	}
	return nil
}

func (w *PipWriter) Location() string {
	if w == nil {
		return ""
	}
	locations := make([]string, len(w.files))
	for i := range w.files {
		locations[i] = w.files[i].file.Location()
	}
	return strings.Join(locations, ", ")
}

// Read returns the shared managed body only when every applicable user file has it.
func (w *PipWriter) Read() (string, bool, error) {
	selected := 0
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			return "", false, err
		}
		if !pipFileApplicable(managed.current, analysis) {
			continue
		}
		selected++
		if analysis.markers.dmg == nil || analysis.markers.dmg.body != w.expected {
			return "", false, nil
		}
	}
	if selected == 0 {
		return "", false, nil
	}
	return w.expected, true, nil
}

// Write atomically updates every applicable user file and rolls all of them back on partial failure.
func (w *PipWriter) Write(expected string) (string, error) {
	if err := w.validateExpected(expected); err != nil {
		return "", err
	}
	w.lastWritten = nil
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			return "", w.rollbackWritten(err)
		}
		if analysis.markers.mdm {
			return "", w.rollbackWritten(fmt.Errorf("pip: MDM marker conflicts with DMG ownership: %w", ErrTargetUnusable))
		}
		if !pipFileApplicable(managed.current, analysis) {
			continue
		}
		if !analysis.existed {
			if err := w.home.EnsureParent(managed.file.RelativePath()); err != nil {
				return "", w.rollbackWritten(err)
			}
		}
		next, err := rewritePipConfig(analysis, expected)
		if err != nil {
			return "", w.rollbackWritten(err)
		}
		secure, metadataErr := managed.file.MetadataSecure(secureuserfile.FileMode)
		if metadataErr != nil && analysis.existed {
			return "", w.rollbackWritten(metadataErr)
		}
		if analysis.existed && bytes.Equal(next, analysis.data) && secure {
			continue
		}
		if err := managed.file.Commit(next, secureuserfile.FileMode); err != nil {
			return "", w.rollbackWritten(err)
		}
		w.lastWritten = append(w.lastWritten, managed.file)
	}
	if converged, err := w.StaticConverged(expected); err != nil || !converged {
		if err == nil {
			err = errors.New("pip: managed settings did not match readback")
		}
		return "", w.rollbackWritten(err)
	}
	return expected, nil
}

func (w *PipWriter) rollbackWritten(cause error) error {
	rollbackFailed := false
	for i := len(w.lastWritten) - 1; i >= 0; i-- {
		if err := w.lastWritten[i].RestoreSnapshot(); err != nil {
			rollbackFailed = true
		}
	}
	w.lastWritten = nil
	if rollbackFailed {
		return fmt.Errorf("pip: multi-file write failed and rollback was incomplete: %w", ErrWriteUnverified)
	}
	return cause
}

func (w *PipWriter) RestoreSnapshot() error {
	if w == nil || len(w.lastWritten) == 0 {
		return errors.New("pip: no snapshots to restore")
	}
	var firstErr error
	for i := len(w.lastWritten) - 1; i >= 0; i-- {
		if err := w.lastWritten[i].RestoreSnapshot(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	w.lastWritten = nil
	return firstErr
}

func (w *PipWriter) CompleteState(previous AppliedTargetState, hadPrevious bool, current *AppliedTargetState) error {
	resolvedPaths := make(map[string]string, len(w.files))
	for _, managed := range w.files {
		resolved, err := managed.file.ResolvedPath()
		if err != nil {
			return err
		}
		resolvedPaths[managed.file.RelativePath()] = resolved
	}
	if hadPrevious && len(previous.ResolvedPaths) != 0 {
		if len(previous.ResolvedPaths) != len(resolvedPaths) {
			return fmt.Errorf("pip: resolved ownership targets changed: %w", ErrTargetUnusable)
		}
		for relative, expected := range previous.ResolvedPaths {
			if resolvedPaths[relative] != expected {
				return fmt.Errorf("pip: resolved ownership target %q changed from %q to %q: %w", relative, expected, resolvedPaths[relative], ErrTargetUnusable)
			}
		}
		current.ResolvedPaths = maps.Clone(previous.ResolvedPaths)
		return nil
	}
	current.ResolvedPaths = resolvedPaths
	return nil
}

func (w *PipWriter) PrepareClear(previous AppliedTargetState, hadPrevious bool) error {
	if !hadPrevious || emptyOwnershipState(previous) {
		for _, managed := range w.files {
			if _, err := readPipFile(managed.file); err != nil {
				return err
			}
		}
		return nil
	}
	if len(previous.ResolvedPaths) == 0 {
		for _, managed := range w.files {
			analysis, err := readPipFile(managed.file)
			if err != nil {
				return err
			}
			if managed.current && analysis.markers.dmg == nil {
				return fmt.Errorf("pip: legacy ownership target cannot be verified: %w", ErrTargetUnusable)
			}
		}
		return nil
	}
	seen := make(map[string]bool, len(w.files))
	for _, managed := range w.files {
		relative := managed.file.RelativePath()
		expected, ok := previous.ResolvedPaths[relative]
		if !ok {
			return fmt.Errorf("pip: ownership state does not identify %q: %w", relative, ErrTargetUnusable)
		}
		if err := managed.file.RequireResolvedPath(expected); err != nil {
			return err
		}
		seen[relative] = true
	}
	if len(seen) != len(previous.ResolvedPaths) {
		return fmt.Errorf("pip: recorded ownership target is unavailable: %w", ErrTargetUnusable)
	}
	return nil
}

func (w *PipWriter) PrepareWrite(previous AppliedTargetState, hadPrevious bool) error {
	return w.PrepareClear(previous, hadPrevious)
}

func (w *PipWriter) Clear() (bool, error) {
	changed := false
	var firstErr error
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !analysis.existed {
			if analysis.parentPresent {
				if err := managed.file.PurgeBackups(); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			continue
		}
		next, fileChanged, created, err := clearPipConfig(analysis.data)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if fileChanged {
			if created && len(bytes.TrimSpace(next)) == 0 {
				err = managed.file.Remove()
			} else {
				err = managed.file.Commit(next, secureuserfile.FileMode)
			}
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			changed = true
		}
		if err := managed.file.PurgeBackups(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return changed, firstErr
}

func (w *PipWriter) Converged(expected string) (bool, error) {
	return w.StaticConverged(expected)
}

func (w *PipWriter) StaticConverged(expected string) (bool, error) {
	if err := w.validateExpected(expected); err != nil {
		return false, err
	}
	selected := 0
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			return false, err
		}
		if analysis.markers.mdm {
			return false, nil
		}
		if !pipFileApplicable(managed.current, analysis) {
			continue
		}
		selected++
		if !analysis.existed || analysis.markers.dmg == nil || analysis.markers.dmg.body != expected || analysis.activeConflict {
			return false, nil
		}
		secure, err := managed.file.MetadataSecure(secureuserfile.FileMode)
		if err != nil || !secure {
			return false, err
		}
	}
	return selected != 0, nil
}

func (w *PipWriter) MDMOwned() (bool, error) {
	selected := 0
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			return false, err
		}
		if !pipFileApplicable(managed.current, analysis) {
			continue
		}
		selected++
		if !analysis.existed || analysis.markers.mdmBlock == nil {
			return false, nil
		}
	}
	return selected != 0, nil
}

func (w *PipWriter) HasMDMMarker() (bool, error) {
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			return false, err
		}
		if analysis.markers.mdm {
			return true, nil
		}
	}
	return false, nil
}

func (w *PipWriter) HasManagedMarker() (bool, error) {
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			return false, err
		}
		if analysis.markers.dmg != nil || analysis.markers.mdm {
			return true, nil
		}
	}
	return false, nil
}

func pipFileApplicable(current bool, analysis pipAnalysis) bool {
	return current || analysis.markers.dmg != nil || analysis.markers.mdm || analysis.existed && analysis.activeConflict
}

type pipAnalysis struct {
	data           []byte
	existed        bool
	parentPresent  bool
	markers        pipMarkers
	parsed         pipINI
	activeConflict bool
}

func readPipFile(file *secureuserfile.File) (pipAnalysis, error) {
	parentPresent, err := pipParentPresent(file)
	if err != nil || !parentPresent {
		return pipAnalysis{parentPresent: parentPresent}, err
	}
	data, existed, _, err := file.Read()
	if err != nil || !existed {
		return pipAnalysis{existed: existed, parentPresent: true}, err
	}
	analysis, err := analyzePipConfig(data)
	analysis.parentPresent = true
	return analysis, err
}

func pipParentPresent(file *secureuserfile.File) (bool, error) {
	return file.ParentPresent()
}

func analyzePipConfig(data []byte) (pipAnalysis, error) {
	markers, err := scanPipMarkers(data)
	if err != nil {
		return pipAnalysis{}, err
	}
	managedBlock := markers.dmg
	if managedBlock == nil {
		managedBlock = markers.mdmBlock
	}
	withoutManaged := removePipManagedBlock(data, managedBlock)
	parsed, err := parsePipINI(withoutManaged)
	if err != nil {
		return pipAnalysis{}, err
	}
	activeConflict := false
	for _, option := range parsed.options {
		if pipConflictOptions[option.key] {
			activeConflict = true
			break
		}
	}
	return pipAnalysis{data: data, existed: true, markers: markers, parsed: parsed, activeConflict: activeConflict}, nil
}

type pipMarkers struct {
	dmg      *pipManagedBlock
	mdmBlock *pipManagedBlock
	mdm      bool
}

type pipManagedBlock struct {
	start, end              int
	body                    string
	rawBody                 []string
	appendedGlobal          bool
	createdFile             bool
	originalFinalNewline    bool
	existingGlobalNoNewline bool
}

func scanPipMarkers(data []byte) (pipMarkers, error) {
	rest, _ := stripBOM(data)
	if !utf8.Valid(rest) || bytes.IndexByte(rest, 0) >= 0 || hasLoneCR(string(rest)) {
		return pipMarkers{}, fmt.Errorf("pip: invalid text encoding or line endings: %w", ErrTargetUnusable)
	}
	lines := splitPipLines(rest)
	begin, mdmBegin, end := -1, -1, -1
	for i, line := range lines {
		text := strings.TrimSpace(string(rest[line.start:line.contentEnd]))
		switch text {
		case dmgPipBegin:
			if begin >= 0 {
				return pipMarkers{}, fmt.Errorf("pip: duplicate DMG begin marker: %w", ErrTargetUnusable)
			}
			begin = i
		case dmgPipEnd:
			if end >= 0 {
				return pipMarkers{}, fmt.Errorf("pip: duplicate managed end marker: %w", ErrTargetUnusable)
			}
			end = i
		case mdmPipBegin:
			if mdmBegin >= 0 {
				return pipMarkers{}, fmt.Errorf("pip: duplicate MDM begin marker: %w", ErrTargetUnusable)
			}
			mdmBegin = i
		}
	}
	if begin >= 0 && mdmBegin >= 0 {
		return pipMarkers{}, fmt.Errorf("pip: mixed DMG and MDM markers: %w", ErrTargetUnusable)
	}
	activeBegin := begin
	if mdmBegin >= 0 {
		activeBegin = mdmBegin
	}
	if (activeBegin < 0) != (end < 0) || activeBegin >= end && activeBegin >= 0 {
		return pipMarkers{}, fmt.Errorf("pip: malformed managed markers: %w", ErrTargetUnusable)
	}
	markers := pipMarkers{mdm: mdmBegin >= 0}
	if mdmBegin >= 0 {
		markers.mdmBlock = pipMarkerBody(rest, lines, mdmBegin, end)
		return markers, nil
	}
	if begin >= 0 {
		markers.dmg = pipMarkerBody(rest, lines, begin, end)
	}
	return markers, nil
}

func pipMarkerBody(data []byte, lines []pipLine, begin, end int) *pipManagedBlock {
	bodyLines := make([]string, 0, end-begin-1)
	block := &pipManagedBlock{start: lines[begin].start, end: lines[end].end, rawBody: make([]string, 0, end-begin-1)}
	for _, line := range lines[begin+1 : end] {
		text := string(data[line.start:line.contentEnd])
		block.rawBody = append(block.rawBody, strings.TrimRight(text, "\r"))
		if strings.HasPrefix(text, pipAppendMetadata) {
			block.appendedGlobal = true
			block.createdFile = strings.Contains(text, "created=true")
			block.originalFinalNewline = strings.Contains(text, "final-newline=true")
			continue
		}
		if text == pipGlobalMetadata {
			block.existingGlobalNoNewline = true
			continue
		}
		if strings.EqualFold(strings.TrimSpace(text), "[global]") {
			continue
		}
		bodyLines = append(bodyLines, strings.TrimRight(text, "\r"))
	}
	block.body = strings.Join(bodyLines, "\n")
	return block
}

func canonicalMDMPipBody(block *pipManagedBlock, expected string) bool {
	if block == nil {
		return false
	}
	want := strings.Split(expected, "\n")
	got := block.rawBody
	if len(got) != len(want) && len(got) != len(want)+1 && len(got) != len(want)+2 {
		return false
	}
	if len(got) > 0 && got[0] == "# [stepsecurity-pypi-pip-mdm] created=true" {
		if len(got) < 2 || got[1] != "[global]" {
			return false
		}
		got = got[1:]
	}
	if len(got) > 0 && got[0] == "[global]" {
		got = got[1:]
	}
	return slices.Equal(got, want)
}

type pipLine struct{ start, contentEnd, end int }

func splitPipLines(data []byte) []pipLine {
	if len(data) == 0 {
		return nil
	}
	lines := make([]pipLine, 0, bytes.Count(data, []byte("\n"))+1)
	for start := 0; start < len(data); {
		i := bytes.IndexByte(data[start:], '\n')
		end, contentEnd := len(data), len(data)
		if i >= 0 {
			end = start + i + 1
			contentEnd = end - 1
			if contentEnd > start && data[contentEnd-1] == '\r' {
				contentEnd--
			}
		}
		lines = append(lines, pipLine{start: start, contentEnd: contentEnd, end: end})
		start = end
	}
	return lines
}

func removePipManagedBlock(data []byte, block *pipManagedBlock) []byte {
	if block == nil {
		return data
	}
	rest, bom := stripBOM(data)
	prefix := append([]byte(nil), rest[:block.start]...)
	if block.end == len(rest) && (block.appendedGlobal && !block.originalFinalNewline || block.existingGlobalNoNewline) {
		prefix = trimPipFinalNewline(prefix)
	}
	out := append(prefix, rest[block.end:]...)
	return append(append([]byte(nil), bom...), out...)
}

type pipINI struct {
	sections []pipSection
	options  []pipOption
}

type pipSection struct {
	name       string
	headerLine int
}

type pipOption struct {
	section    string
	key, value string
	startLine  int
	endLine    int
	indent     int
}

func parsePipINI(data []byte) (pipINI, error) {
	rest, _ := stripBOM(data)
	if !utf8.Valid(rest) || bytes.IndexByte(rest, 0) >= 0 || hasLoneCR(string(rest)) {
		return pipINI{}, fmt.Errorf("pip: invalid INI text: %w", ErrTargetUnusable)
	}
	lines := splitPipLines(rest)
	result := pipINI{}
	sections := map[string]bool{}
	options := map[string]map[string]bool{}
	section := ""
	lastOption := -1
	for i, line := range lines {
		raw := string(rest[line.start:line.contentEnd])
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			lastOption = -1
			continue
		}
		indent := pipLineIndent(raw)
		if lastOption >= 0 && indent > result.options[lastOption].indent {
			result.options[lastOption].endLine = i + 1
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			close := strings.IndexByte(trimmed, ']')
			suffix := ""
			if close >= 0 {
				suffix = strings.TrimSpace(trimmed[close+1:])
			}
			if close <= 1 || suffix != "" && !strings.HasPrefix(suffix, "#") && !strings.HasPrefix(suffix, ";") {
				return pipINI{}, fmt.Errorf("pip: malformed INI section: %w", ErrTargetUnusable)
			}
			name := strings.ToLower(strings.TrimSpace(trimmed[1:close]))
			if name == "" || sections[name] {
				return pipINI{}, fmt.Errorf("pip: duplicate or empty INI section: %w", ErrTargetUnusable)
			}
			sections[name] = true
			options[name] = map[string]bool{}
			section = name
			result.sections = append(result.sections, pipSection{name: name, headerLine: i})
			lastOption = -1
			continue
		}
		delimiter := strings.IndexAny(raw, "=:")
		if delimiter >= 0 {
			if section == "" {
				return pipINI{}, fmt.Errorf("pip: option appears before a section: %w", ErrTargetUnusable)
			}
			key := normalizePipOption(raw[:delimiter])
			if key == "" || options[section][key] {
				return pipINI{}, fmt.Errorf("pip: duplicate or empty INI option: %w", ErrTargetUnusable)
			}
			options[section][key] = true
			result.options = append(result.options, pipOption{section: section, key: key, value: strings.TrimSpace(raw[delimiter+1:]), startLine: i, endLine: i + 1, indent: indent})
			lastOption = len(result.options) - 1
			continue
		}
		return pipINI{}, fmt.Errorf("pip: malformed INI line: %w", ErrTargetUnusable)
	}
	return result, nil
}

func normalizePipOption(key string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "_", "-")
}

func pipLineIndent(line string) int {
	indent := 0
	for indent < len(line) && (line[indent] == ' ' || line[indent] == '\t') {
		indent++
	}
	return indent
}

func rewritePipConfig(analysis pipAnalysis, expected string) ([]byte, error) {
	base := removePipManagedBlock(analysis.data, analysis.markers.dmg)
	parsed, err := parsePipINI(base)
	if err != nil {
		return nil, err
	}
	rest, bom := stripBOM(base)
	lines := splitPipLines(rest)
	conflictLines := map[int]bool{}
	for _, option := range parsed.options {
		if !pipConflictOptions[option.key] {
			continue
		}
		for i := option.startLine; i < option.endLine; i++ {
			conflictLines[i] = true
		}
	}
	var transformed bytes.Buffer
	for i, line := range lines {
		if conflictLines[i] {
			transformed.WriteString(dmgPipDisabledPrefix)
		}
		transformed.Write(rest[line.start:line.end])
	}
	base = append(append([]byte(nil), bom...), transformed.Bytes()...)

	newline := pipNewline(analysis.data)
	body := strings.ReplaceAll(expected, "\n", newline)
	parsed, err = parsePipINI(base)
	if err != nil {
		return nil, err
	}
	rest, bom = stripBOM(base)
	lines = splitPipLines(rest)
	globalOffset := -1
	if global := findPipSection(parsed.sections, "global"); global >= 0 {
		globalOffset = lines[parsed.sections[global].headerLine].end
	}
	if globalOffset >= 0 {
		global := findPipSection(parsed.sections, "global")
		header := lines[parsed.sections[global].headerLine]
		headerHasNewline := header.end > header.contentEnd
		var out bytes.Buffer
		out.Write(bom)
		out.Write(rest[:globalOffset])
		if !headerHasNewline {
			out.WriteString(newline)
		}
		out.WriteString(dmgPipBegin + newline)
		if !headerHasNewline {
			out.WriteString(pipGlobalMetadata + newline)
		}
		out.WriteString(body + newline + dmgPipEnd + newline)
		out.Write(rest[globalOffset:])
		return out.Bytes(), nil
	}

	created := !analysis.existed
	if analysis.markers.dmg != nil && analysis.markers.dmg.appendedGlobal && len(bytes.TrimSpace(rest)) == 0 {
		created = analysis.markers.dmg.createdFile
	}
	finalNewline := len(rest) != 0 && (bytes.HasSuffix(rest, []byte("\n")) || bytes.HasSuffix(rest, []byte("\r")))
	var out bytes.Buffer
	out.Write(bom)
	out.Write(rest)
	if len(rest) != 0 && !finalNewline {
		out.WriteString(newline)
	}
	out.WriteString(dmgPipBegin + newline)
	out.WriteString(pipAppendMetadata + " created=" + strconv.FormatBool(created) + " final-newline=" + strconv.FormatBool(finalNewline) + newline)
	out.WriteString("[global]" + newline + body + newline + dmgPipEnd + newline)
	return out.Bytes(), nil
}

func findPipSection(sections []pipSection, name string) int {
	for i := range sections {
		if sections[i].name == name {
			return i
		}
	}
	return -1
}

func clearPipConfig(data []byte) ([]byte, bool, bool, error) {
	markers, err := scanPipMarkers(data)
	if err != nil {
		return nil, false, false, err
	}
	rest, bom := stripBOM(data)
	created := false
	changed := false
	if markers.dmg != nil {
		block := markers.dmg
		created = block.createdFile
		prefix := append([]byte(nil), rest[:block.start]...)
		if block.end == len(rest) && (block.appendedGlobal && !block.originalFinalNewline || block.existingGlobalNoNewline) {
			prefix = trimPipFinalNewline(prefix)
		}
		rest = append(prefix, rest[block.end:]...)
		changed = true
	}
	lines := splitPipLines(rest)
	var out bytes.Buffer
	for _, line := range lines {
		content := rest[line.start:line.contentEnd]
		if bytes.HasPrefix(content, []byte(dmgPipDisabledPrefix)) {
			out.Write(content[len(dmgPipDisabledPrefix):])
			out.Write(rest[line.contentEnd:line.end])
			changed = true
		} else {
			out.Write(rest[line.start:line.end])
		}
	}
	result := append(append([]byte(nil), bom...), out.Bytes()...)
	if changed {
		if _, err := parsePipINI(result); err != nil && len(bytes.TrimSpace(out.Bytes())) != 0 {
			return nil, false, false, err
		}
	}
	return result, changed, created, nil
}

func trimPipFinalNewline(data []byte) []byte {
	if bytes.HasSuffix(data, []byte("\r\n")) {
		return data[:len(data)-2]
	}
	if bytes.HasSuffix(data, []byte("\n")) {
		return data[:len(data)-1]
	}
	return data
}

func pipNewline(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

func (w *PipWriter) Observation(ctx context.Context, expected string) (PipObservation, error) {
	observation := PipObservation{OverrideSource: "none"}
	if err := w.validateExpected(expected); err != nil {
		observation.ConfigStatus = "unreadable"
		observation.EffectiveStatus = "unknown"
		observation.OverrideSource = "unknown"
		return observation, err
	}
	static, err := w.observedStaticConverged(expected)
	if err != nil {
		observation.ConfigStatus = "unreadable"
		observation.EffectiveStatus = "unknown"
		observation.OverrideSource = "unknown"
		return observation, err
	}
	if static {
		observation.ConfigStatus = "match"
		observation.RegistryURL = w.registryURL
	} else if w.anyPipConfigExists() {
		observation.ConfigStatus = "mismatch"
		registry, err := w.staticRegistryObservation()
		if err != nil {
			observation.ConfigStatus = "unreadable"
			observation.EffectiveStatus = "unknown"
			observation.OverrideSource = "unknown"
			return observation, err
		}
		if registry != unsafePipRegistryObservation {
			observation.RegistryURL = registry
		}
	} else {
		observation.ConfigStatus = "absent"
	}

	if err := executor.UserEnvironmentError(w.exec); err != nil {
		observation.EffectiveStatus = "unknown"
		observation.OverrideSource = "unknown"
		return observation, err
	}
	if source := w.environmentOverride(); source != "" {
		observation.EffectiveStatus = "mismatch"
		observation.OverrideSource = source
		return observation, nil
	}
	if len(w.invocations) == 0 {
		observation.EffectiveStatus = "not_installed"
		return observation, nil
	}

	overall := "match"
	for _, invocation := range w.invocations {
		status, source, registry := w.probeInvocation(ctx, invocation)
		switch registry {
		case unsafePipRegistryObservation:
			observation.RegistryURL = ""
		case "":
		default:
			observation.RegistryURL = registry
		}
		if status == "mismatch" {
			overall = "mismatch"
			if observation.OverrideSource == "none" || observation.OverrideSource == "unknown" {
				observation.OverrideSource = source
			}
		} else if status == "unknown" && overall == "match" {
			overall = "unknown"
			if source != "none" {
				observation.OverrideSource = "unknown"
			}
		}
	}
	observation.EffectiveStatus = overall
	return observation, nil
}

func (w *PipWriter) observedStaticConverged(expected string) (bool, error) {
	selected := 0
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			return false, err
		}
		if !pipFileApplicable(managed.current, analysis) {
			continue
		}
		selected++
		block := analysis.markers.dmg
		blockMatches := block != nil && block.body == expected
		if block == nil {
			block = analysis.markers.mdmBlock
			blockMatches = canonicalMDMPipBody(block, expected)
		}
		if !analysis.existed || !blockMatches || analysis.activeConflict {
			return false, nil
		}
		secure, err := managed.file.MetadataSecure(secureuserfile.FileMode)
		if err != nil || !secure {
			return false, err
		}
	}
	return selected != 0, nil
}

func (w *PipWriter) anyPipConfigExists() bool {
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err == nil && analysis.existed {
			return true
		}
	}
	return false
}

func (w *PipWriter) staticRegistryObservation() (string, error) {
	registry := ""
	for _, managed := range w.files {
		analysis, err := readPipFile(managed.file)
		if err != nil {
			return "", err
		}
		if !pipFileApplicable(managed.current, analysis) {
			continue
		}
		block := analysis.markers.dmg
		if block == nil {
			block = analysis.markers.mdmBlock
		}
		if block != nil && block.body == w.expected {
			registry = w.registryURL
		}
		for _, option := range analysis.parsed.options {
			if option.key == "index-url" {
				registry = safePipRegistryURL(option.value)
			}
		}
	}
	return registry, nil
}

func (w *PipWriter) environmentOverride() string {
	if index := strings.TrimSpace(w.exec.Getenv("PIP_INDEX_URL")); index != "" && index != w.registryURL {
		return "environment"
	}
	for _, name := range []string{"PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS"} {
		if strings.TrimSpace(w.exec.Getenv(name)) != "" {
			return "environment"
		}
	}
	if noIndex := strings.TrimSpace(w.exec.Getenv("PIP_NO_INDEX")); noIndex != "" && !isPipFalse(noIndex) {
		return "environment"
	}
	if strings.TrimSpace(w.exec.Getenv("PIP_CONFIG_FILE")) != "" {
		return "explicit_config"
	}
	if strings.TrimSpace(w.exec.Getenv("VIRTUAL_ENV")) != "" {
		return "virtualenv"
	}
	if netrc := strings.TrimSpace(w.exec.Getenv("NETRC")); netrc != "" {
		if !filepath.IsAbs(netrc) {
			return "environment"
		}
		if filepath.Clean(netrc) != filepath.Join(w.home.Path(), ".netrc") {
			return "environment"
		}
	}
	return ""
}

func (w *PipWriter) probeInvocation(ctx context.Context, invocation []string) (status, source, registry string) {
	if len(invocation) == 0 {
		return "unknown", "unknown", ""
	}
	name, baseArgs := invocation[0], invocation[1:]
	versionArgs := append(append([]string(nil), baseArgs...), "--version")
	stdout, _, exit, err := w.exec.RunWithTimeout(ctx, 5*time.Second, name, versionArgs...)
	if err != nil || exit != 0 {
		return "unknown", "unknown", ""
	}
	major, minor, ok := parsePipVersion(stdout)
	if !ok {
		return "unknown", "unknown", ""
	}
	if major < 20 || major == 20 && minor < 2 {
		return "unknown", "none", ""
	}
	debugArgs := append(append([]string(nil), baseArgs...), "config", "debug")
	debug, _, exit, err := w.exec.RunWithTimeout(ctx, 10*time.Second, name, debugArgs...)
	if err != nil || exit != 0 || !validPipDebugOutput(debug) {
		return "unknown", "unknown", ""
	}
	listArgs := append(append([]string(nil), baseArgs...), "config", "list", "-v")
	listed, _, exit, err := w.exec.RunWithTimeout(ctx, 10*time.Second, name, listArgs...)
	if err != nil || exit != 0 {
		return "unknown", "unknown", ""
	}
	entries, ok := parsePipEffectiveOutput(listed)
	if !ok {
		return "unknown", "unknown", ""
	}
	indexMatch, noIndexFalse := false, false
	for _, entry := range entries {
		if !pipConflictOptions[entry.key] {
			continue
		}
		entrySource := classifyPipEntrySource(entry, w.files)
		if entry.section != "global" {
			if entry.section == ":env:" {
				entrySource = "environment"
			} else {
				entrySource = "command_section"
			}
		}
		switch entry.key {
		case "index-url":
			if entry.section == "global" && entry.value == w.registryURL {
				indexMatch = true
				continue
			}
			return "mismatch", entrySource, safePipRegistryURL(entry.value)
		case "no-index":
			if entry.section == "global" && isPipFalse(entry.value) {
				noIndexFalse = true
				continue
			}
			return "mismatch", entrySource, ""
		default:
			return "mismatch", entrySource, safePipRegistryURL(entry.value)
		}
	}
	if !indexMatch || !noIndexFalse {
		return "mismatch", "unknown", ""
	}
	return "match", "none", w.registryURL
}

func parsePipVersion(stdout string) (int, int, bool) {
	fields := strings.Fields(strings.TrimSpace(stdout))
	if len(fields) < 2 || fields[0] != "pip" {
		return 0, 0, false
	}
	parts := strings.Split(fields[1], ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	return major, minor, errMajor == nil && errMinor == nil
}

func validPipDebugOutput(stdout string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n") {
		switch strings.TrimSpace(line) {
		case "env_var:", "env:", "global:", "site:", "user:":
			return true
		}
	}
	return false
}

type pipEffectiveEntry struct {
	section, key, value, source string
}

func parsePipEffectiveOutput(stdout string) ([]pipEffectiveEntry, bool) {
	entries := make([]pipEffectiveEntry, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "For variant ") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 || eq+1 >= len(line) || line[eq+1] != '\'' {
			return nil, false
		}
		valueAndSource := line[eq+2:]
		quote := strings.LastIndex(valueAndSource, "'")
		if quote < 0 {
			return nil, false
		}
		value := valueAndSource[:quote]
		tail := strings.TrimSpace(valueAndSource[quote+1:])
		source := ""
		if tail != "" {
			if !strings.HasPrefix(tail, "from ") {
				return nil, false
			}
			source = strings.TrimSpace(strings.TrimPrefix(tail, "from "))
		}
		name := line[:eq]
		dot := strings.LastIndexByte(name, '.')
		if dot <= 0 || dot == len(name)-1 {
			return nil, false
		}
		entries = append(entries, pipEffectiveEntry{section: strings.ToLower(name[:dot]), key: normalizePipOption(name[dot+1:]), value: value, source: source})
	}
	return entries, true
}

func classifyPipEntrySource(entry pipEffectiveEntry, files []pipManagedFile) string {
	if entry.source == "" {
		return "unknown"
	}
	if strings.HasPrefix(entry.source, "PIP_") {
		return "environment"
	}
	for _, managed := range files {
		if filepath.Clean(entry.source) == filepath.Clean(managed.file.Location()) {
			return "none"
		}
	}
	return "system_config"
}

func safePipRegistryURL(raw string) string {
	if raw == "" {
		return ""
	}
	if safe := safeObservedRegistryURL(raw); safe != "" {
		return safe
	}
	return unsafePipRegistryObservation
}

func isPipFalse(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "no", "off":
		return true
	default:
		return false
	}
}
