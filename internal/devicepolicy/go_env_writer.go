package devicepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

const (
	dmgGoEnvBegin          = "# BEGIN StepSecurity Package Configuration go -- managed by dmg"
	mdmGoEnvBegin          = "# BEGIN StepSecurity Package Configuration go -- managed by mdm"
	goEnvEnd               = "# END StepSecurity Package Configuration go"
	dmgGoEnvDisabledPrefix = "# [stepsecurity-go-env-dmg] "
	mdmGoEnvDisabledPrefix = "# [stepsecurity-go-env-mdm] "
	dmgGoEnvCreatedFile    = "# [stepsecurity-go-env-dmg] created=true"
	mdmGoEnvCreatedFile    = "# [stepsecurity-go-env-mdm] created=true"
	dmgGoEnvRestoreCRLF    = "# [stepsecurity-go-env-dmg] restore-crlf=true"
	mdmGoEnvRestoreCRLF    = "# [stepsecurity-go-env-mdm] restore-crlf=true"
	goEnvBackupPrefix      = ".dmg-go-env-"
)

// GoEnvObservation is the secret-free static and effective Go proxy state.
type GoEnvObservation struct {
	RegistryURL     string
	ConfigStatus    string
	EffectiveStatus string
	OverrideSource  string
}

// GoEnvWriter manages only GOPROXY in the resolved user's default Go env file.
type GoEnvWriter struct {
	exec        executor.Executor
	home        *secureuserfile.Home
	file        *secureuserfile.File
	expected    string
	registryURL string
}

func NewGoEnvWriter(exec executor.Executor, home *secureuserfile.Home, policy GoPolicy) (*GoEnvWriter, error) {
	if exec == nil {
		return nil, errors.New("go env: nil executor")
	}
	if home == nil {
		return nil, errors.New("go env: nil secure user home")
	}
	expected, err := renderGoEnvSettings(policy)
	if err != nil {
		return nil, err
	}
	userExec := executor.NewUserAwareExecutor(exec, home.Username())
	path, err := goUserEnvPath(userExec, home.Path())
	if err != nil {
		return nil, err
	}
	if err := executor.UserEnvironmentError(userExec); err != nil && userExec.GOOS() != model.PlatformDarwin {
		return nil, fmt.Errorf("go env: resolving user environment: %w", err)
	}
	relative, err := filepath.Rel(home.Path(), path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, fmt.Errorf("go env: user path is outside resolved home: %w", ErrTargetUnusable)
	}
	file, err := home.Open(relative, goEnvBackupPrefix, secureuserfile.MaxBytes)
	if err != nil {
		return nil, err
	}
	return &GoEnvWriter{exec: userExec, home: home, file: file, expected: expected, registryURL: policy.RegistryURL}, nil
}

func renderGoEnvSettings(policy GoPolicy) (string, error) {
	u, err := parsePyPIRegistryURL(policy.RegistryURL)
	if policy.Ecosystem != "go" || policy.Auth.Scheme != goAuthScheme || err != nil || u.EscapedPath() != "/go" ||
		policy.Auth.APIKey == "" || len(policy.Auth.APIKey) > npmrcMaxKeyBytes || policy.deviceID == "" ||
		len(policy.deviceID) > npmrcMaxSerialBytes || strings.Contains(policy.Auth.APIKey, "::") ||
		!isNPMSafe(policy.Auth.APIKey) || !isNPMSafe(policy.deviceID) || !isValidHost(policy.RegistryHost()) ||
		strings.ContainsAny(policy.RegistryURL, ",|") {
		return "", errors.New("go env: policy cannot render safe user settings")
	}
	return "GOPROXY=" + policy.RegistryURL, nil
}

func goUserEnvPath(exec executor.Executor, home string) (string, error) {
	var root string
	switch exec.GOOS() {
	case model.PlatformDarwin:
		root = filepath.Join(home, "Library", "Application Support")
	case model.PlatformWindows:
		root = strings.TrimSpace(exec.Getenv("APPDATA"))
		if root == "" {
			root = filepath.Join(home, "AppData", "Roaming")
		}
	case model.PlatformLinux:
		root = strings.TrimSpace(exec.Getenv("XDG_CONFIG_HOME"))
		if root == "" {
			root = filepath.Join(home, ".config")
		}
	default:
		return "", fmt.Errorf("go env: unsupported platform %q: %w", exec.GOOS(), ErrTargetUnusable)
	}
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("go env: configuration root must be absolute: %w", ErrTargetUnusable)
	}
	relative, err := filepath.Rel(filepath.Clean(home), root)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("go env: configuration root is outside resolved home: %w", ErrTargetUnusable)
	}
	return filepath.Join(root, "go", "env"), nil
}

func (w *GoEnvWriter) Location() string { return w.file.Location() }

func (w *GoEnvWriter) validateExpected(expected string) error {
	if w == nil || w.file == nil || expected == "" || expected != w.expected {
		return errors.New("go env: expected setting does not match the validated policy")
	}
	return nil
}

func (w *GoEnvWriter) readCurrent() ([]byte, bool, os.FileMode, error) {
	present, err := w.file.ParentPresent()
	if err != nil || !present {
		return nil, false, 0, err
	}
	return w.file.Read()
}

func (w *GoEnvWriter) Read() (string, bool, error) {
	ok, err := w.StaticConverged(w.expected)
	if err != nil || !ok {
		return "", false, err
	}
	return w.expected, true, nil
}

func (w *GoEnvWriter) Write(expected string) (string, error) {
	if err := w.validateExpected(expected); err != nil {
		return "", err
	}
	if err := w.home.EnsureParent(w.file.RelativePath()); err != nil {
		return "", err
	}
	current, existed, _, err := w.file.Read()
	if err != nil {
		return "", err
	}
	markers, err := scanGoEnv(current)
	if err != nil {
		return "", err
	}
	if markers.owner == "mdm" {
		return "", fmt.Errorf("go env: MDM marker present: %w", ErrTargetUnusable)
	}
	created := !existed
	if markers.owner == "dmg" {
		created = markers.created
	}
	updated, err := rewriteGoEnv(current, expected, created, w.exec.GOOS() == model.PlatformWindows)
	if err != nil {
		return "", err
	}
	if err := w.file.Commit(updated, secureuserfile.FileMode); err != nil {
		return "", err
	}
	ok, err := w.StaticConverged(expected)
	if err != nil {
		return "", errors.Join(err, w.file.RestoreSnapshot())
	}
	if !ok {
		return "", errors.Join(errors.New("go env: committed setting did not verify"), w.file.RestoreSnapshot())
	}
	return expected, nil
}

func (w *GoEnvWriter) Clear() (bool, error) {
	current, existed, _, err := w.readCurrent()
	if err != nil {
		return false, err
	}
	if !existed {
		present, err := w.file.ParentPresent()
		if err != nil || !present {
			return false, err
		}
		return false, w.file.PurgeBackups()
	}
	markers, err := scanGoEnv(current)
	if err != nil {
		return false, err
	}
	updated, changed, err := clearGoEnv(current)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, w.file.PurgeBackups()
	}
	if markers.created && len(bytes.TrimSpace(stripUTF8BOM(updated))) == 0 {
		err = w.file.Remove()
	} else {
		err = w.file.Commit(updated, secureuserfile.FileMode)
	}
	if err != nil {
		return false, err
	}
	if err := w.file.PurgeBackups(); err != nil {
		return false, errors.Join(err, w.file.RestoreSnapshot())
	}
	return true, nil
}

func (w *GoEnvWriter) Converged(expected string) (bool, error) {
	return w.StaticConverged(expected)
}

func (w *GoEnvWriter) StaticConverged(expected string) (bool, error) {
	if err := w.validateExpected(expected); err != nil {
		return false, err
	}
	data, existed, _, err := w.readCurrent()
	if err != nil || !existed {
		return false, err
	}
	analysis, err := scanGoEnv(data)
	if err != nil {
		return false, err
	}
	if analysis.owner != "dmg" || analysis.managedValue != expected || analysis.activeOutside ||
		w.exec.GOOS() == model.PlatformWindows && analysis.newline != "\n" {
		return false, nil
	}
	return w.file.MetadataSecure(secureuserfile.FileMode)
}

func (w *GoEnvWriter) RestoreSnapshot() error { return w.file.RestoreSnapshot() }

func (w *GoEnvWriter) ValidateTarget() error {
	data, existed, _, err := w.readCurrent()
	if err != nil || !existed {
		return err
	}
	_, err = scanGoEnv(data)
	return err
}

func (w *GoEnvWriter) HasDMGMarker() (bool, error) { return w.hasMarker("dmg") }
func (w *GoEnvWriter) HasMDMMarker() (bool, error) { return w.hasMarker("mdm") }

func (w *GoEnvWriter) MDMOwned() (bool, error) {
	owned, err := w.HasMDMMarker()
	if err != nil || !owned {
		return owned, err
	}
	secure, err := w.file.MetadataSecure(secureuserfile.FileMode)
	if err != nil {
		return false, err
	}
	if !secure {
		return false, fmt.Errorf("go env: insecure MDM metadata: %w", ErrTargetUnusable)
	}
	return true, nil
}

func (w *GoEnvWriter) hasMarker(owner string) (bool, error) {
	data, existed, _, err := w.readCurrent()
	if err != nil || !existed {
		return false, err
	}
	analysis, err := scanGoEnv(data)
	return analysis.owner == owner, err
}

func (w *GoEnvWriter) CompleteState(previous AppliedTargetState, hadPrevious bool, current *AppliedTargetState) error {
	resolved, err := w.file.ResolvedPath()
	if err != nil {
		return err
	}
	if hadPrevious && previous.ResolvedPath != "" && previous.ResolvedPath != resolved {
		return fmt.Errorf("go env: resolved ownership target changed from %q to %q: %w", previous.ResolvedPath, resolved, ErrTargetUnusable)
	}
	current.ResolvedPath = resolved
	return nil
}

func (w *GoEnvWriter) PrepareClear(previous AppliedTargetState, hadPrevious bool) error {
	if !hadPrevious || emptyOwnershipState(previous) {
		return w.ValidateTarget()
	}
	if previous.ResolvedPath == "" {
		managed, err := w.HasDMGMarker()
		if err != nil {
			return err
		}
		if !managed {
			return fmt.Errorf("go env: legacy ownership target cannot be verified: %w", ErrTargetUnusable)
		}
		return nil
	}
	return w.file.RequireResolvedPath(previous.ResolvedPath)
}

func (w *GoEnvWriter) PrepareWrite(previous AppliedTargetState, hadPrevious bool) error {
	return w.PrepareClear(previous, hadPrevious)
}

func (w *GoEnvWriter) Observation(expected, credentialLocation string) (GoEnvObservation, error) {
	observation := GoEnvObservation{EffectiveStatus: "unknown", OverrideSource: "unknown"}
	data, existed, _, err := w.readCurrent()
	if err != nil {
		observation.ConfigStatus = "unreadable"
		return observation, err
	}
	if !existed {
		observation.ConfigStatus = "absent"
	} else {
		analysis, scanErr := scanGoEnv(data)
		if scanErr != nil {
			observation.ConfigStatus = "unreadable"
			return observation, scanErr
		}
		secure, metadataErr := w.file.MetadataSecure(secureuserfile.FileMode)
		if metadataErr != nil {
			observation.ConfigStatus = "unreadable"
			return observation, metadataErr
		}
		conflicting := analysis.activeOutside
		if analysis.owner == "mdm" {
			conflicting = analysis.activeAfter
		}
		if secure && (analysis.owner == "dmg" || analysis.owner == "mdm") && analysis.managedValue == expected && !conflicting &&
			(w.exec.GOOS() != model.PlatformWindows || analysis.newline == "\n") {
			observation.ConfigStatus = "match"
			observation.RegistryURL = w.registryURL
		} else {
			observation.ConfigStatus = "mismatch"
			observation.RegistryURL = analysis.observedRegistryURL()
		}
	}
	if err := executor.UserEnvironmentError(w.exec); err != nil {
		return observation, err
	}
	classes := make([]string, 0, 4)
	effective := ""
	if visible := strings.TrimSpace(w.exec.Getenv("GOPROXY")); visible != "" {
		classes = append(classes, "environment")
		if visible == w.registryURL {
			effective = "match"
		} else {
			effective = "mismatch"
		}
	}
	if goenv := strings.TrimSpace(w.exec.Getenv("GOENV")); goenv != "" && !sameManagedPath(goenv, w.Location(), w.exec.GOOS()) {
		classes = append(classes, "goenv")
		effective = "mismatch"
	}
	if netrc := strings.TrimSpace(w.exec.Getenv("NETRC")); netrc != "" && !sameManagedPath(netrc, credentialLocation, w.exec.GOOS()) {
		classes = append(classes, "netrc")
		effective = "mismatch"
	}
	if goauth := strings.TrimSpace(w.exec.Getenv("GOAUTH")); goauth != "" && goauth != "netrc" {
		classes = append(classes, "goauth")
		if effective != "mismatch" {
			effective = "unknown"
		}
	}
	if len(classes) == 0 {
		observation.OverrideSource = "none"
		switch observation.ConfigStatus {
		case "match":
			observation.EffectiveStatus = "match"
		case "absent", "mismatch":
			observation.EffectiveStatus = "mismatch"
		default:
			observation.EffectiveStatus = "unknown"
		}
	} else {
		observation.OverrideSource = classes[0]
		if len(classes) > 1 {
			observation.OverrideSource = "multiple"
		}
		observation.EffectiveStatus = effective
	}
	return observation, nil
}

func sameManagedPath(raw, managed, goos string) bool {
	if raw == "off" || managed == "" {
		return false
	}
	if !filepath.IsAbs(raw) {
		return false
	}
	raw, managed = filepath.Clean(raw), filepath.Clean(managed)
	return raw == managed || goos == model.PlatformWindows && strings.EqualFold(raw, managed)
}

type goEnvAnalysis struct {
	owner         string
	created       bool
	begin         int
	end           int
	managedValue  string
	activeOutside bool
	activeAfter   bool
	lastActiveURL string
	newline       string
	restoreCRLF   bool
	bom           bool
}

func scanGoEnv(data []byte) (goEnvAnalysis, error) {
	analysis := goEnvAnalysis{begin: -1, end: -1}
	text, err := validatedGoEnvText(data)
	if err != nil {
		return analysis, err
	}
	analysis.bom = bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf})
	analysis.newline = goEnvNewline(data)
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	inside := false
	managedValues := 0
	reservedOwners := map[string]bool{}
	for i, line := range lines {
		switch line {
		case dmgGoEnvBegin, mdmGoEnvBegin:
			owner := "dmg"
			if line == mdmGoEnvBegin {
				owner = "mdm"
			}
			if inside || analysis.owner != "" {
				return analysis, fmt.Errorf("go env: nested or duplicated managed marker: %w", ErrTargetUnusable)
			}
			analysis.owner, analysis.begin, inside = owner, i, true
			continue
		case goEnvEnd:
			if !inside {
				return analysis, fmt.Errorf("go env: reversed managed marker: %w", ErrTargetUnusable)
			}
			analysis.end, inside = i, false
			continue
		case dmgGoEnvCreatedFile, mdmGoEnvCreatedFile:
			owner := "dmg"
			if line == mdmGoEnvCreatedFile {
				owner = "mdm"
			}
			if !inside || analysis.owner != owner || analysis.created {
				return analysis, fmt.Errorf("go env: misplaced or duplicated file marker: %w", ErrTargetUnusable)
			}
			analysis.created = true
			continue
		case dmgGoEnvRestoreCRLF, mdmGoEnvRestoreCRLF:
			owner := "dmg"
			if line == mdmGoEnvRestoreCRLF {
				owner = "mdm"
			}
			if !inside || analysis.owner != owner || analysis.restoreCRLF {
				return analysis, fmt.Errorf("go env: misplaced or duplicated newline marker: %w", ErrTargetUnusable)
			}
			analysis.restoreCRLF = true
			continue
		}
		switch {
		case strings.HasPrefix(line, dmgGoEnvDisabledPrefix):
			if !strings.HasPrefix(strings.TrimPrefix(line, dmgGoEnvDisabledPrefix), "GOPROXY=") {
				return analysis, fmt.Errorf("go env: invalid DMG disabled setting: %w", ErrTargetUnusable)
			}
			reservedOwners["dmg"] = true
		case strings.HasPrefix(line, mdmGoEnvDisabledPrefix):
			if !strings.HasPrefix(strings.TrimPrefix(line, mdmGoEnvDisabledPrefix), "GOPROXY=") {
				return analysis, fmt.Errorf("go env: invalid MDM disabled setting: %w", ErrTargetUnusable)
			}
			reservedOwners["mdm"] = true
		}
		if strings.HasPrefix(line, "GOPROXY=") {
			if inside {
				managedValues++
				analysis.managedValue = line
			} else {
				analysis.activeOutside = true
				analysis.activeAfter = analysis.activeAfter || analysis.end >= 0
				analysis.lastActiveURL = strings.TrimPrefix(line, "GOPROXY=")
			}
		} else if inside && line != "" {
			return analysis, fmt.Errorf("go env: unexpected managed-block content: %w", ErrTargetUnusable)
		}
	}
	if inside || analysis.owner != "" && analysis.end < 0 {
		return analysis, fmt.Errorf("go env: incomplete managed markers: %w", ErrTargetUnusable)
	}
	if analysis.owner != "" && managedValues != 1 {
		return analysis, fmt.Errorf("go env: managed block must contain one GOPROXY setting: %w", ErrTargetUnusable)
	}
	for owner := range reservedOwners {
		if analysis.owner != owner {
			return analysis, fmt.Errorf("go env: orphaned or mixed disabled prefix: %w", ErrTargetUnusable)
		}
	}
	return analysis, nil
}

func (a goEnvAnalysis) observedRegistryURL() string {
	if safe := safeObservedRegistryURL(a.lastActiveURL); safe != "" {
		return safe
	}
	return safeObservedRegistryURL(strings.TrimPrefix(a.managedValue, "GOPROXY="))
}

func validatedGoEnvText(data []byte) (string, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || hasLoneCR(string(data)) {
		return "", fmt.Errorf("go env: invalid text encoding: %w", ErrTargetUnusable)
	}
	text := string(stripUTF8BOM(data))
	if strings.Contains(text, "\r\n") && strings.Contains(strings.ReplaceAll(text, "\r\n", ""), "\n") {
		return "", fmt.Errorf("go env: mixed line endings: %w", ErrTargetUnusable)
	}
	return text, nil
}

func goEnvNewline(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

func rewriteGoEnv(current []byte, expected string, created, normalizeCRLF bool) ([]byte, error) {
	analysis, err := scanGoEnv(current)
	if err != nil {
		return nil, err
	}
	newline := analysis.newline
	hadFinal := bytes.HasSuffix(current, []byte(newline))
	restoreCRLF := analysis.restoreCRLF || normalizeCRLF && newline == "\r\n"
	if normalizeCRLF {
		newline = "\n"
	}
	if analysis.owner == "mdm" {
		return nil, fmt.Errorf("go env: MDM marker present: %w", ErrTargetUnusable)
	}
	base, _, err := clearGoEnv(current)
	if err != nil {
		return nil, err
	}
	text, err := validatedGoEnvText(base)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "GOPROXY=") {
			lines[i] = dmgGoEnvDisabledPrefix + line
		}
	}
	baseText := strings.Join(lines, newline)
	managed := []string{dmgGoEnvBegin}
	if created {
		managed = append(managed, dmgGoEnvCreatedFile)
	}
	if restoreCRLF {
		managed = append(managed, dmgGoEnvRestoreCRLF)
	}
	managed = append(managed, expected, goEnvEnd)
	block := strings.Join(managed, newline)
	if baseText != "" {
		baseText += newline
	}
	result := baseText + block
	if created || hadFinal {
		result += newline
	}
	if analysis.bom || bytes.HasPrefix(base, []byte{0xef, 0xbb, 0xbf}) {
		result = string([]byte{0xef, 0xbb, 0xbf}) + result
	}
	return []byte(result), nil
}

func clearGoEnv(data []byte) ([]byte, bool, error) {
	analysis, err := scanGoEnv(data)
	if err != nil {
		return nil, false, err
	}
	if analysis.owner != "dmg" {
		return data, false, nil
	}
	text, err := validatedGoEnvText(data)
	if err != nil {
		return nil, false, err
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := append([]string(nil), lines[:analysis.begin]...)
	if len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	out = append(out, lines[analysis.end+1:]...)
	for i, line := range out {
		if strings.HasPrefix(line, dmgGoEnvDisabledPrefix) {
			out[i] = strings.TrimPrefix(line, dmgGoEnvDisabledPrefix)
		}
	}
	newline := analysis.newline
	if analysis.restoreCRLF {
		newline = "\r\n"
	}
	result := strings.Join(out, newline)
	if analysis.bom {
		result = string([]byte{0xef, 0xbb, 0xbf}) + result
	}
	return []byte(result), true, nil
}

var _ Writer = (*GoEnvWriter)(nil)
