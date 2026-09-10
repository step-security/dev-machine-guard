package devicepolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

const (
	dmgUVBegin          = "# BEGIN StepSecurity Package Configuration uv -- managed by dmg"
	dmgUVEnd            = "# END StepSecurity Package Configuration uv"
	mdmUVBegin          = "# BEGIN StepSecurity Package Configuration uv -- managed by mdm"
	mdmUVEnd            = "# END StepSecurity Package Configuration uv"
	dmgUVDisabledPrefix = "# [stepsecurity-pypi-uv-dmg] "
	dmgUVCreatedFile    = "# [stepsecurity-pypi-uv-dmg] created=true"
	uvBackupPrefix      = ".dmg-"
	uvProbePackage      = "stepsecurity-policy-probe"
)

var errUVUnsupportedVersion = errors.New("uv: installed version is not supported")

// UVObservation is the secret-free user and effective uv policy state.
type UVObservation struct {
	RegistryURL     string
	ConfigStatus    string
	EffectiveStatus string
	OverrideSource  string
}

// UVWriter manages the resolved user's uv.toml.
type UVWriter struct {
	exec             executor.Executor
	home             *secureuserfile.Home
	file             *secureuserfile.File
	expected         string
	registryURL      string
	installed        bool
	versionKnown     bool
	versionSupported bool

	restoreSnapshot func() error
	purgeBackups    func() error
}

func NewUVWriter(ctx context.Context, exec executor.Executor, home *secureuserfile.Home, policy PyPIPolicy) (*UVWriter, error) {
	if home == nil {
		return nil, errors.New("uv: nil secure user home")
	}
	expected, err := renderUVSettings(policy)
	if err != nil {
		return nil, err
	}
	userExec := executor.NewUserAwareExecutor(exec, home.Username())
	path, err := uvUserConfigPath(userExec, home.Path())
	if err != nil {
		return nil, err
	}
	if err := executor.UserEnvironmentError(userExec); err != nil {
		return nil, fmt.Errorf("uv: resolving user environment: %w", err)
	}
	relative, err := filepath.Rel(home.Path(), path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, fmt.Errorf("uv: user path is outside resolved home: %w", ErrTargetUnusable)
	}
	file, err := home.Open(relative, uvBackupPrefix, secureuserfile.MaxBytes)
	if err != nil {
		return nil, err
	}
	w := &UVWriter{exec: userExec, home: home, file: file, expected: expected, registryURL: policy.RegistryURL}
	w.restoreSnapshot = file.RestoreSnapshot
	w.purgeBackups = file.PurgeBackups
	if _, err := executor.LookPathWithContext(ctx, userExec, "uv"); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return w, nil
	}
	w.installed = true
	stdout, _, exit, err := userExec.RunWithTimeout(ctx, 5*time.Second, "uv", "--version")
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil || exit != 0 {
		return w, nil
	}
	major, minor, patch, ok := parseUVVersion(stdout)
	if !ok {
		w.versionKnown = isUVPrerelease(stdout)
		return w, nil
	}
	w.versionKnown = true
	w.versionSupported = uvVersionAtLeast(major, minor, patch, 0, 10, 0)
	return w, nil
}

func renderUVSettings(policy PyPIPolicy) (string, error) {
	if policy.RegistryURL == "" {
		return "", errors.New("uv: empty registry URL")
	}
	return "index-strategy = \"first-index\"\n\n[[index]]\nname = \"stepsecurity\"\nurl = " + strconv.Quote(policy.RegistryURL) + "\ndefault = true\nauthenticate = \"always\"", nil
}

func uvUserConfigPath(exec executor.Executor, home string) (string, error) {
	root := ""
	if exec.GOOS() == "windows" {
		root = strings.TrimSpace(exec.Getenv("APPDATA"))
		if root == "" {
			root = filepath.Join(home, "AppData", "Roaming")
		}
	} else {
		root = strings.TrimSpace(exec.Getenv("XDG_CONFIG_HOME"))
		if root == "" {
			root = filepath.Join(home, ".config")
		}
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("uv: configuration root must be absolute: %w", ErrTargetUnusable)
	}
	return filepath.Join(filepath.Clean(root), "uv", "uv.toml"), nil
}

func (w *UVWriter) validateExpected(expected string) error {
	if expected == "" || expected != w.expected {
		return errors.New("uv: expected settings do not match validated policy")
	}
	return nil
}

func (w *UVWriter) Location() string { return w.file.Location() }

func (w *UVWriter) readCurrent() ([]byte, bool, os.FileMode, error) {
	present, err := w.file.ParentPresent()
	if err != nil || !present {
		return nil, false, 0, err
	}
	return w.file.Read()
}

func (w *UVWriter) Read() (string, bool, error) {
	ok, err := w.StaticConverged(w.expected)
	if err != nil || !ok {
		return "", false, err
	}
	return w.expected, true, nil
}

func (w *UVWriter) Write(expected string) (string, error) {
	if err := w.validateExpected(expected); err != nil {
		return "", err
	}
	if w.installed && (!w.versionKnown || !w.versionSupported) {
		return "", errUVUnsupportedVersion
	}
	if err := w.home.EnsureParent(w.file.RelativePath()); err != nil {
		return "", err
	}
	current, existed, _, err := w.file.Read()
	if err != nil {
		return "", err
	}
	markers, err := scanUVMarkers(current)
	if err != nil {
		return "", err
	}
	if markers.mdmComplete() {
		return "", fmt.Errorf("uv: MDM marker present: %w", ErrTargetUnusable)
	}
	created := !existed
	if markers.complete() {
		created = markers.created
	}
	updated, err := rewriteUVConfig(current, expected, created)
	if err != nil {
		return "", err
	}
	if err := w.file.Commit(updated, 0o600); err != nil {
		return "", err
	}
	ok, err := w.StaticConverged(expected)
	if err != nil {
		return "", errors.Join(err, w.restoreSnapshot())
	}
	if !ok {
		err = errors.New("uv: committed settings did not verify")
		return "", errors.Join(err, w.restoreSnapshot())
	}
	return expected, nil
}

func (w *UVWriter) Clear() (bool, error) {
	current, existed, _, err := w.readCurrent()
	if err != nil {
		return false, err
	}
	if !existed {
		return false, nil
	}
	markers, err := scanUVMarkers(current)
	if err != nil {
		return false, err
	}
	updated, changed, err := clearUVConfig(current)
	if err != nil || !changed {
		return false, err
	}
	if len(bytes.TrimSpace(stripUTF8BOM(updated))) == 0 && markers.created {
		if err := w.file.Remove(); err != nil {
			return false, err
		}
	} else if err := w.file.Commit(updated, 0o600); err != nil {
		return false, err
	}
	if err := w.purgeBackups(); err != nil {
		return false, errors.Join(err, w.restoreSnapshot())
	}
	return true, nil
}

func (w *UVWriter) Converged(expected string) (bool, error) {
	return w.StaticConverged(expected)
}

func (w *UVWriter) StaticConverged(expected string) (bool, error) {
	if err := w.validateExpected(expected); err != nil {
		return false, err
	}
	data, existed, _, err := w.readCurrent()
	if err != nil || !existed {
		return false, err
	}
	markers, err := scanUVMarkers(data)
	if err != nil {
		return false, err
	}
	if markers.mdmComplete() || !markers.complete() {
		return false, nil
	}
	var doc map[string]any
	if err := toml.Unmarshal(stripUTF8BOM(data), &doc); err != nil {
		return false, fmt.Errorf("uv: parsing managed TOML: %w", ErrTargetUnusable)
	}
	if !uvSemanticMatch(doc, w.registryURL) {
		return false, nil
	}
	return w.file.MetadataSecure(0o600)
}

func (w *UVWriter) RestoreSnapshot() error { return w.file.RestoreSnapshot() }

func (w *UVWriter) MDMOwned() (bool, error) {
	return w.HasMDMMarker()
}

func (w *UVWriter) HasMDMMarker() (bool, error) {
	data, existed, _, err := w.readCurrent()
	if err != nil || !existed {
		return false, err
	}
	markers, err := scanUVMarkers(data)
	if err != nil {
		return false, err
	}
	return markers.mdmComplete(), nil
}

func (w *UVWriter) HasManagedMarker() (bool, error) {
	data, existed, _, err := w.readCurrent()
	if err != nil || !existed {
		return false, err
	}
	markers, err := scanUVMarkers(data)
	if err != nil {
		return false, err
	}
	return markers.complete() || markers.mdmComplete(), nil
}

type uvMarkers struct {
	owner      string
	begin, end int
	created    bool
}

func (m uvMarkers) complete() bool {
	return m.owner == "dmg" && m.begin == 1 && m.end == 1
}

func (m uvMarkers) mdmComplete() bool {
	return m.owner == "mdm" && m.begin == 1 && m.end == 1
}

func uvMultilineStringLines(lines []string) []bool {
	const (
		stringNone = iota
		stringBasic
		stringLiteral
		stringMultilineBasic
		stringMultilineLiteral
	)
	state := stringNone
	inside := make([]bool, len(lines))
	for i, line := range lines {
		inside[i] = state == stringMultilineBasic || state == stringMultilineLiteral
		for j := 0; j < len(line); {
			switch state {
			case stringNone:
				switch {
				case line[j] == '#':
					j = len(line)
				case strings.HasPrefix(line[j:], `"""`):
					state, j = stringMultilineBasic, j+3
				case strings.HasPrefix(line[j:], `'''`):
					state, j = stringMultilineLiteral, j+3
				case line[j] == '"':
					state, j = stringBasic, j+1
				case line[j] == '\'':
					state, j = stringLiteral, j+1
				default:
					j++
				}
			case stringBasic:
				switch line[j] {
				case '\\':
					j += 2
				case '"':
					state, j = stringNone, j+1
				default:
					j++
				}
			case stringLiteral:
				if line[j] == '\'' {
					state = stringNone
				}
				j++
			case stringMultilineBasic:
				if line[j] == '\\' {
					j += 2
				} else if strings.HasPrefix(line[j:], `"""`) {
					state, j = stringNone, j+3
				} else {
					j++
				}
			case stringMultilineLiteral:
				if strings.HasPrefix(line[j:], `'''`) {
					state, j = stringNone, j+3
				} else {
					j++
				}
			}
		}
		if state == stringBasic || state == stringLiteral {
			state = stringNone
		}
	}
	return inside
}

func scanUVMarkers(data []byte) (uvMarkers, error) {
	var m uvMarkers
	active := false
	lines := strings.Split(strings.ReplaceAll(string(stripUTF8BOM(data)), "\r\n", "\n"), "\n")
	stringLines := uvMultilineStringLines(lines)
	for i, line := range lines {
		if stringLines[i] {
			continue
		}
		owner, begin := "", false
		switch strings.TrimSpace(line) {
		case dmgUVBegin:
			owner, begin = "dmg", true
		case mdmUVBegin:
			owner, begin = "mdm", true
		case dmgUVEnd:
		case dmgUVCreatedFile:
			if !active || m.owner != "dmg" || m.created {
				return m, fmt.Errorf("uv: misplaced or duplicated file marker: %w", ErrTargetUnusable)
			}
			m.created = true
			continue
		default:
			continue
		}
		if begin {
			if m.owner == "" {
				m.owner = owner
			}
			if owner != m.owner {
				return m, fmt.Errorf("uv: crossed managed owners: %w", ErrTargetUnusable)
			}
			if active || m.begin != 0 || m.end != 0 {
				return m, fmt.Errorf("uv: nested or duplicated managed marker: %w", ErrTargetUnusable)
			}
			active = true
			m.begin++
			continue
		}
		if !active {
			return m, fmt.Errorf("uv: reversed managed marker: %w", ErrTargetUnusable)
		}
		active = false
		m.end++
	}
	if active || m.owner != "" && !m.complete() && !m.mdmComplete() {
		return m, fmt.Errorf("uv: incomplete managed markers: %w", ErrTargetUnusable)
	}
	return m, nil
}

func rewriteUVConfig(current []byte, expected string, created bool) ([]byte, error) {
	if !utf8.Valid(current) || bytes.IndexByte(current, 0) >= 0 || hasLoneCR(string(current)) {
		return nil, fmt.Errorf("uv: invalid text encoding: %w", ErrTargetUnusable)
	}
	base, _, err := clearUVConfig(current)
	if err != nil {
		return nil, err
	}
	body := stripUTF8BOM(base)
	var parsed map[string]any
	if len(bytes.TrimSpace(body)) > 0 {
		if err := toml.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("uv: parsing TOML: %w", ErrTargetUnusable)
		}
	}
	newline := uvNewline(base)
	hadFinalNewline := bytes.HasSuffix(body, []byte(newline))
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	disabled, firstTable, err := disableUVConflicts(lines)
	if err != nil {
		return nil, err
	}
	managed := []string{dmgUVBegin}
	if created {
		managed = append(managed, dmgUVCreatedFile)
	}
	managed = append(managed,
		"index-strategy = \"first-index\"",
		"",
		"[[index]]",
		"name = \"stepsecurity\"",
		"url = "+strconv.Quote(uvURLFromExpected(expected)),
		"default = true",
		"authenticate = \"always\"",
		dmgUVEnd,
	)
	if firstTable < 0 {
		firstTable = len(disabled)
	}
	out := make([]string, 0, len(disabled)+len(managed))
	out = append(out, disabled[:firstTable]...)
	out = append(out, managed...)
	out = append(out, disabled[firstTable:]...)
	encodedText := strings.Join(out, newline)
	if hadFinalNewline || len(body) == 0 {
		encodedText += newline
	}
	encoded := []byte(encodedText)
	if bytes.HasPrefix(base, []byte{0xef, 0xbb, 0xbf}) {
		encoded = append([]byte{0xef, 0xbb, 0xbf}, encoded...)
	}
	var verify map[string]any
	if err := toml.Unmarshal(stripUTF8BOM(encoded), &verify); err != nil || !uvSemanticMatch(verify, uvURLFromExpected(expected)) {
		return nil, fmt.Errorf("uv: transformed TOML did not verify: %w", ErrTargetUnusable)
	}
	return encoded, nil
}

func disableUVConflicts(lines []string) ([]string, int, error) {
	out := append([]string(nil), lines...)
	firstTable := -1
	section := "root"
	for i := 0; i < len(out); {
		trimmed := strings.TrimSpace(out[i])
		if strings.HasPrefix(trimmed, "[") {
			if firstTable < 0 {
				firstTable = i
			}
			header := normalizedUVHeader(trimmed)
			if header == "[[index]]" {
				end := i + 1
				for end < len(out) && !strings.HasPrefix(strings.TrimSpace(out[end]), "[") {
					end++
				}
				if uvSpanHasMultiline(out[i:end]) {
					return nil, -1, fmt.Errorf("uv: multiline value overlaps index table: %w", ErrTargetUnusable)
				}
				for j := i; j < end; j++ {
					if out[j] != "" {
						out[j] = dmgUVDisabledPrefix + out[j]
					}
				}
				i = end
				section = "root"
				continue
			}
			section = strings.Trim(header, "[]")
			i++
			continue
		}
		key, value, ok := uvAssignment(trimmed)
		if ok && uvConflictKey(section, key) {
			if strings.Contains(value, "\"\"\"") || strings.Contains(value, "'''") || strings.HasPrefix(strings.TrimSpace(value), "[") && !strings.Contains(value, "]") {
				return nil, -1, fmt.Errorf("uv: multiline managed value is ambiguous: %w", ErrTargetUnusable)
			}
			out[i] = dmgUVDisabledPrefix + out[i]
		}
		i++
	}
	return out, firstTable, nil
}

func uvSpanHasMultiline(lines []string) bool {
	for _, line := range lines {
		if strings.Contains(line, "\"\"\"") || strings.Contains(line, "'''") {
			return true
		}
	}
	return false
}

func normalizedUVHeader(line string) string {
	quoted := byte(0)
	escaped := false
	for i := 0; i < len(line); i++ {
		if quoted != 0 {
			if quoted == '"' && escaped {
				escaped = false
				continue
			}
			if quoted == '"' && line[i] == '\\' {
				escaped = true
				continue
			}
			if line[i] == quoted {
				quoted = 0
			}
			continue
		}
		switch line[i] {
		case '\'', '"':
			quoted = line[i]
		case '#':
			line = line[:i]
			i = len(line)
		}
	}
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(line)), " ", "")
}

func uvAssignment(line string) (key, value string, ok bool) {
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return "", "", false
	}
	key = strings.ToLower(strings.Trim(strings.TrimSpace(line[:idx]), "\"'"))
	return key, strings.TrimSpace(line[idx+1:]), true
}

func uvConflictKey(section, key string) bool {
	if section != "root" && section != "pip" {
		return false
	}
	switch strings.ReplaceAll(key, "_", "-") {
	case "index-strategy", "index", "default-index", "index-url", "extra-index-url", "find-links":
		return true
	default:
		return false
	}
}

func clearUVConfig(data []byte) ([]byte, bool, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || hasLoneCR(string(data)) {
		return nil, false, fmt.Errorf("uv: invalid text encoding: %w", ErrTargetUnusable)
	}
	markers, err := scanUVMarkers(data)
	if err != nil {
		return nil, false, err
	}
	if markers.mdmComplete() {
		return data, false, nil
	}
	bom := bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf})
	newline := uvNewline(data)
	lines := strings.Split(strings.ReplaceAll(string(stripUTF8BOM(data)), "\r\n", "\n"), "\n")
	stringLines := uvMultilineStringLines(lines)
	out := make([]string, 0, len(lines))
	inside := false
	changed := false
	for i, line := range lines {
		if stringLines[i] {
			out = append(out, line)
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case dmgUVBegin:
			inside = true
			changed = true
			continue
		case dmgUVEnd:
			inside = false
			continue
		}
		if inside {
			continue
		}
		if strings.HasPrefix(line, dmgUVDisabledPrefix) {
			line = strings.TrimPrefix(line, dmgUVDisabledPrefix)
			changed = true
		}
		out = append(out, line)
	}
	if inside {
		return nil, false, fmt.Errorf("uv: incomplete managed block: %w", ErrTargetUnusable)
	}
	text := strings.Join(out, newline)
	if bom {
		text = string([]byte{0xef, 0xbb, 0xbf}) + text
	}
	updated := []byte(text)
	if changed && len(bytes.TrimSpace(stripUTF8BOM(updated))) > 0 {
		var parsed map[string]any
		if err := toml.Unmarshal(stripUTF8BOM(updated), &parsed); err != nil {
			return nil, false, fmt.Errorf("uv: restored TOML did not verify: %w", ErrTargetUnusable)
		}
	}
	return updated, changed, nil
}

func uvSemanticMatch(doc map[string]any, registryURL string) bool {
	strategy, ok := doc["index-strategy"].(string)
	if !ok || strategy != "first-index" {
		return false
	}
	for _, key := range []string{"index-url", "extra-index-url", "find-links", "default-index"} {
		if _, exists := doc[key]; exists {
			return false
		}
	}
	if pip, ok := doc["pip"].(map[string]any); ok {
		for _, key := range []string{"index", "index-strategy", "index-url", "extra-index-url", "find-links", "default-index"} {
			if _, exists := pip[key]; exists {
				return false
			}
		}
	}
	indexes, ok := doc["index"].([]map[string]any)
	if !ok || len(indexes) != 1 {
		if generic, ok := doc["index"].([]any); ok && len(generic) == 1 {
			index, ok := generic[0].(map[string]any)
			if !ok {
				return false
			}
			indexes = []map[string]any{index}
		} else {
			return false
		}
	}
	index := indexes[0]
	name, _ := index["name"].(string)
	url, _ := index["url"].(string)
	def, _ := index["default"].(bool)
	auth, _ := index["authenticate"].(string)
	return name == "stepsecurity" && url == registryURL && def && auth == "always"
}

func uvURLFromExpected(expected string) string {
	for _, line := range strings.Split(expected, "\n") {
		key, value, ok := uvAssignment(strings.TrimSpace(line))
		if ok && key == "url" {
			unquoted, err := strconv.Unquote(value)
			if err == nil {
				return unquoted
			}
		}
	}
	return ""
}

func stripUTF8BOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
}

func uvNewline(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

func (w *UVWriter) Observation(ctx context.Context, expected string) (UVObservation, error) {
	observation := UVObservation{OverrideSource: "none"}
	if err := w.validateExpected(expected); err != nil {
		observation.ConfigStatus = "unreadable"
		observation.EffectiveStatus = "unknown"
		observation.OverrideSource = "unknown"
		return observation, err
	}
	static, err := w.StaticConverged(expected)
	if err != nil {
		observation.ConfigStatus = "unreadable"
		observation.EffectiveStatus = "unknown"
		observation.OverrideSource = "unknown"
		return observation, err
	}
	if static {
		observation.ConfigStatus = "match"
		observation.RegistryURL = w.registryURL
	} else if data, existed, _, readErr := w.readCurrent(); readErr != nil {
		observation.ConfigStatus = "unreadable"
		observation.EffectiveStatus = "unknown"
		observation.OverrideSource = "unknown"
		return observation, readErr
	} else if existed {
		markers, markerErr := scanUVMarkers(data)
		if markerErr != nil {
			observation.ConfigStatus = "unreadable"
			observation.EffectiveStatus = "unknown"
			observation.OverrideSource = "unknown"
			return observation, markerErr
		}
		if markers.mdmComplete() {
			var doc map[string]any
			if unmarshalErr := toml.Unmarshal(stripUTF8BOM(data), &doc); unmarshalErr != nil {
				observation.ConfigStatus = "unreadable"
				observation.EffectiveStatus = "unknown"
				observation.OverrideSource = "unknown"
				return observation, fmt.Errorf("uv: parsing MDM TOML: %w", ErrTargetUnusable)
			}
			if uvSemanticMatch(doc, w.registryURL) {
				observation.ConfigStatus = "match"
				observation.RegistryURL = w.registryURL
			} else {
				observation.ConfigStatus = "mismatch"
				observation.RegistryURL = observedUVRegistryURL(data)
			}
		} else {
			observation.ConfigStatus = "mismatch"
			observation.RegistryURL = observedUVRegistryURL(data)
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
	if !w.installed {
		observation.EffectiveStatus = "not_installed"
		return observation, nil
	}
	if !w.versionKnown {
		observation.EffectiveStatus = "unknown"
		observation.OverrideSource = "unknown"
		return observation, nil
	}
	if !w.versionSupported {
		observation.EffectiveStatus = "unsupported_version"
		return observation, nil
	}
	status, source, registry := w.probeSettings(ctx)
	observation.EffectiveStatus = status
	observation.OverrideSource = source
	if registry == unsafeUVRegistryObservation {
		observation.RegistryURL = ""
	} else if registry != "" {
		observation.RegistryURL = registry
	}
	return observation, nil
}

const unsafeUVRegistryObservation = "\x00unsafe"

func (w *UVWriter) environmentOverride() string {
	if strings.TrimSpace(w.exec.Getenv("UV_CONFIG_FILE")) != "" || strings.TrimSpace(w.exec.Getenv("UV_NO_CONFIG")) != "" {
		return "explicit_config"
	}
	for _, name := range []string{"UV_INDEX", "UV_DEFAULT_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX_STRATEGY", "UV_FIND_LINKS", "UV_NO_INDEX"} {
		if strings.TrimSpace(w.exec.Getenv(name)) != "" {
			return "environment"
		}
	}
	if netrc := strings.TrimSpace(w.exec.Getenv("NETRC")); netrc != "" {
		if !filepath.IsAbs(netrc) || filepath.Clean(netrc) != filepath.Join(w.home.Path(), ".netrc") {
			return "environment"
		}
	}
	return ""
}

func (w *UVWriter) probeSettings(ctx context.Context) (status, source, registry string) {
	dir, cleanup, err := w.probeDirectory(ctx)
	if err != nil {
		return "unknown", "unknown", ""
	}
	defer cleanup()
	stdout, _, exit, err := w.exec.RunInDir(ctx, dir, 10*time.Second, "uv", "pip", "install", "--show-settings", uvProbePackage)
	if err != nil || exit != 0 {
		return "unknown", "unknown", ""
	}
	status, registry = parseUVShowSettings(stdout, w.registryURL)
	if status == "match" {
		return status, "none", registry
	}
	return status, "unknown", registry
}

func (w *UVWriter) probeDirectory(ctx context.Context) (string, func(), error) {
	base := strings.TrimSpace(w.exec.Getenv("TMPDIR"))
	if base == "" {
		base = os.TempDir()
	}
	base = filepath.Clean(base)
	if !filepath.IsAbs(base) {
		return "", nil, errors.New("uv: target-user temporary directory is not absolute")
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return "", nil, fmt.Errorf("uv: opening target-user temporary root: %w", err)
	}
	fail := func(err error) (string, func(), error) {
		_ = root.Close()
		return "", nil, err
	}
	var dir string
	if w.exec.GOOS() == model.PlatformWindows {
		dir, err = os.MkdirTemp(base, "dmg-uv-probe-")
	} else {
		var exit int
		dir, _, exit, err = w.exec.RunWithTimeout(ctx, 5*time.Second, "mktemp", "-d", filepath.Join(base, "dmg-uv-probe-XXXXXXXX"))
		if err == nil && exit != 0 {
			err = fmt.Errorf("mktemp exited with code %d", exit)
		}
	}
	if err != nil {
		return fail(fmt.Errorf("uv: creating target-user probe directory: %w", err))
	}
	dir = filepath.Clean(strings.TrimSpace(dir))
	relative, relErr := filepath.Rel(base, dir)
	if relErr != nil || filepath.Dir(relative) != "." || filepath.IsAbs(relative) || !strings.HasPrefix(relative, "dmg-uv-probe-") {
		return fail(errors.New("uv: target-user probe directory escaped temporary root"))
	}
	before, err := root.Lstat(relative)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		_ = root.Remove(relative)
		return fail(errors.Join(err, errors.New("uv: target-user probe path is not a real directory")))
	}
	f, err := root.Open(relative)
	if err != nil {
		_ = root.Remove(relative)
		return fail(fmt.Errorf("uv: opening target-user probe directory: %w", err))
	}
	opened, statErr := f.Stat()
	current, lstatErr := root.Lstat(relative)
	identityOK := statErr == nil && lstatErr == nil && current.Mode()&os.ModeSymlink == 0 && current.IsDir() && os.SameFile(opened, current)
	if !identityOK {
		_ = f.Close()
		_ = root.Remove(relative)
		return fail(errors.Join(statErr, lstatErr, errors.New("uv: target-user probe directory changed during open")))
	}
	if w.exec.GOOS() == model.PlatformWindows {
		if err := w.home.ApplyMetadata(f, secureuserfile.ParentMode, true); err != nil {
			_ = f.Close()
			_ = root.Remove(relative)
			return fail(fmt.Errorf("uv: securing target-user probe directory: %w", err))
		}
	}
	ownerErr := w.home.VerifyOwner(f, dir)
	metadataSecure, metadataErr := w.home.MetadataSecure(f, secureuserfile.ParentMode)
	closeErr := f.Close()
	if ownerErr != nil || metadataErr != nil || !metadataSecure || closeErr != nil {
		_ = root.Remove(relative)
		return fail(errors.Join(ownerErr, metadataErr, closeErr, errors.New("uv: insecure target-user probe directory")))
	}
	cleanup := func() {
		_ = root.RemoveAll(relative)
		_ = root.Close()
	}
	return dir, cleanup, nil
}

var uvDebugGivenPattern = regexp.MustCompile(`(?s)given:\s*Some\(\s*("(\\.|[^"\\])*")`)

func parseUVShowSettings(stdout, registryURL string) (status, registry string) {
	if strings.Count(stdout, "index_locations: IndexLocations {") != 1 {
		return "unknown", ""
	}
	locations, ok := uvDebugBlock(stdout, "index_locations: IndexLocations {", '{', '}')
	if !ok {
		return "unknown", ""
	}
	indexes, ok := uvDebugBlock(locations, "indexes: [", '[', ']')
	if !ok {
		return "unknown", ""
	}
	flat, ok := uvDebugBlock(locations, "flat_index: [", '[', ']')
	if !ok {
		return "unknown", ""
	}
	noIndex, ok := uvDebugScalar(locations, "no_index")
	if !ok || noIndex != "false" {
		return "mismatch", ""
	}
	strategy, ok := uvDebugScalar(stdout, "index_strategy")
	if !ok || strategy != "FirstIndex" {
		return "mismatch", ""
	}
	urls, ok := uvDebugURLs(indexes)
	if !ok {
		return "unknown", ""
	}
	if strings.TrimSpace(flat) != "" || len(urls) != 1 || urls[0] != registryURL {
		for _, raw := range urls {
			if safe := safeObservedRegistryURL(raw); safe != "" {
				return "mismatch", safe
			}
		}
		if len(urls) != 0 {
			return "mismatch", unsafeUVRegistryObservation
		}
		return "mismatch", ""
	}
	return "match", registryURL
}

func uvDebugBlock(text, marker string, open, close byte) (string, bool) {
	start := strings.Index(text, marker)
	if start < 0 {
		return "", false
	}
	start += len(marker) - 1
	depth := 0
	quoted := false
	escaped := false
	for i := start; i < len(text); i++ {
		if quoted {
			if escaped {
				escaped = false
			} else if text[i] == '\\' {
				escaped = true
			} else if text[i] == '"' {
				quoted = false
			}
			continue
		}
		if text[i] == '"' {
			quoted = true
			continue
		}
		switch text[i] {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return text[start+1 : i], true
			}
		}
	}
	return "", false
}

func uvDebugScalar(text, key string) (string, bool) {
	var value string
	found := false
	prefix := key + ":"
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if found {
			return "", false
		}
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, prefix), ","))
		found = true
	}
	return value, found
}

func uvDebugURLs(indexes string) ([]string, bool) {
	matches := uvDebugGivenPattern.FindAllStringSubmatch(indexes, -1)
	urls := make([]string, 0, len(matches))
	for _, match := range matches {
		value, err := strconv.Unquote(match[1])
		if err != nil {
			return nil, false
		}
		urls = append(urls, value)
	}
	return urls, true
}

func observedUVRegistryURL(data []byte) string {
	var doc map[string]any
	if err := toml.Unmarshal(stripUTF8BOM(data), &doc); err != nil {
		return ""
	}
	indexes, ok := doc["index"].([]map[string]any)
	if ok {
		for _, index := range indexes {
			if raw, ok := index["url"].(string); ok {
				return safeObservedRegistryURL(raw)
			}
		}
	}
	return ""
}

func isUVPrerelease(stdout string) bool {
	fields := strings.Fields(strings.TrimSpace(stdout))
	if len(fields) < 2 || fields[0] != "uv" {
		return false
	}
	stable, _, found := strings.Cut(fields[1], "-")
	if !found {
		return false
	}
	_, _, _, ok := parseUVVersion("uv " + stable)
	return ok
}

func parseUVVersion(stdout string) (major, minor, patch int, ok bool) {
	fields := strings.Fields(strings.TrimSpace(stdout))
	if len(fields) < 2 || fields[0] != "uv" {
		return 0, 0, 0, false
	}
	parts := strings.Split(fields[1], ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	values := [3]int{}
	for i, part := range parts {
		if part == "" {
			return 0, 0, 0, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return 0, 0, 0, false
		}
		values[i] = value
	}
	return values[0], values[1], values[2], true
}

func uvVersionAtLeast(major, minor, patch, wantMajor, wantMinor, wantPatch int) bool {
	if major != wantMajor {
		return major > wantMajor
	}
	if minor != wantMinor {
		return minor > wantMinor
	}
	return patch >= wantPatch
}
