package devicepolicy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

const (
	dmgNetrcBegin = "#stepsecurity-package-config-credential-dmg-begin"
	dmgNetrcEnd   = "#stepsecurity-package-config-credential-end"

	mdmNetrcBegin = "#stepsecurity-package-config-credential-mdm-begin"
	mdmNetrcEnd   = "#stepsecurity-package-config-credential-end"

	dmgNetrcDisabledPrefix = "#stepsecurity-package-config-credential-dmg-disabled:"
	mdmNetrcDisabledPrefix = "#stepsecurity-package-config-credential-mdm-disabled:"
	mdmNetrcCreated        = "#stepsecurity-package-config-credential-mdm-created"
	netrcBackupPrefix      = ".dmg-"
)

// NetrcWriter owns only the exact registry host entry inside one user's netrc.
type NetrcWriter struct {
	file      *secureuserfile.File
	alternate *secureuserfile.File
	host      string
	token     string
	expected  string
	goos      string
	lookupEnv func(string) string
}

func NewNetrcWriter(home *secureuserfile.Home, policy PyPIPolicy) (*NetrcWriter, error) {
	if home == nil {
		return nil, errors.New("netrc: nil secure user home")
	}
	registry, registryErr := parsePyPIRegistryURL(policy.RegistryURL)
	host := policy.RegistryHost()
	token := policy.DeviceToken()
	if policy.Ecosystem != "pypi" || !canonicalPyPIClients(policy.Clients) || policy.Auth.Scheme != pypiAuthScheme ||
		registryErr != nil || registry.EscapedPath() != "/python/simple" || policy.Auth.APIKey == "" ||
		len(policy.Auth.APIKey) > npmrcMaxKeyBytes || policy.deviceID == "" || len(policy.deviceID) > npmrcMaxSerialBytes ||
		strings.Contains(policy.Auth.APIKey, "::") || !isNPMSafe(policy.Auth.APIKey) || !isNPMSafe(policy.deviceID) ||
		!isValidHost(host) || !isNetrcCredential(token) {
		return nil, errors.New("netrc: policy cannot render a safe credential entry")
	}
	return newNetrcWriter(home, host, token)
}

// newNetrcWriter builds the shared exact-host credential writer after the
// ecosystem-specific policy parser has validated and derived its inputs.
func newNetrcWriter(home *secureuserfile.Home, host, token string) (*NetrcWriter, error) {
	if home == nil {
		return nil, errors.New("netrc: nil secure user home")
	}
	if !isValidHost(host) || !isNetrcCredential(token) {
		return nil, errors.New("netrc: cannot render a safe credential entry")
	}
	expected := renderNetrcEntry(host, token)

	primary, err := home.Open(".netrc", netrcBackupPrefix, secureuserfile.MaxBytes)
	if err != nil {
		return nil, err
	}
	w := &NetrcWriter{file: primary, host: host, token: token, expected: expected, goos: home.GOOS(), lookupEnv: home.Getenv}
	if home.GOOS() != model.PlatformWindows {
		return w, nil
	}

	alternate, err := home.Open("_netrc", netrcBackupPrefix, secureuserfile.MaxBytes)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := primary.Read(); err != nil {
		return nil, err
	}
	if _, _, _, err := alternate.Read(); err != nil {
		return nil, err
	}
	w.alternate = alternate
	return w, nil
}

func newGoNetrcWriter(home *secureuserfile.Home, host, token string) (*NetrcWriter, error) {
	w, err := newNetrcWriter(home, host, token)
	if err != nil || home.GOOS() != model.PlatformWindows {
		return w, err
	}
	_, underscoreExists, _, err := w.alternate.Read()
	if err != nil {
		return nil, err
	}
	if underscoreExists {
		w.file, w.alternate = w.alternate, w.file
	}
	return w, nil
}

func renderNetrcEntry(host, token string) string {
	return "machine " + host + "\nlogin step-security\npassword " + token
}

func isNetrcCredential(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func (w *NetrcWriter) Location() string {
	if w == nil || w.file == nil {
		return ""
	}
	return w.file.Location()
}

func (w *NetrcWriter) validateExpected(expected string) error {
	if w == nil || w.file == nil || expected != w.expected {
		return errors.New("netrc: expected entry does not match the validated policy")
	}
	return nil
}

// Read returns the DMG-managed entry without its markers.
func (w *NetrcWriter) Read() (string, bool, error) {
	analysis, err := w.readSelected()
	if err != nil || !analysis.existed || analysis.markers.dmg == nil {
		return "", false, err
	}
	return analysis.markers.dmg.body, true, nil
}

// Write migrates at most one ordinary exact-host entry and installs the managed entry.
func (w *NetrcWriter) Write(expected string) (string, error) {
	if err := w.ValidateEffectivePath(); err != nil {
		return "", err
	}
	if err := w.validateExpected(expected); err != nil {
		return "", err
	}
	if err := w.checkAlternateConflict(); err != nil {
		return "", err
	}
	analysis, err := w.readSelected()
	if err != nil {
		return "", err
	}
	if analysis.markers.mdm {
		return "", fmt.Errorf("netrc: MDM marker conflicts with DMG ownership: %w", ErrTargetUnusable)
	}

	next, err := rewriteNetrc(analysis.data, w.host, expected)
	if err != nil {
		return "", err
	}
	if err := w.file.Commit(next, secureuserfile.FileMode); err != nil {
		return "", err
	}
	readback, present, err := w.Read()
	if err != nil || !present || readback != expected {
		if err == nil {
			err = errors.New("netrc: managed credential did not match readback")
		}
		if restoreErr := w.file.RestoreSnapshot(); restoreErr != nil {
			return "", fmt.Errorf("netrc: readback failed and rollback failed: %w", ErrWriteUnverified)
		}
		return "", err
	}
	return readback, nil
}

// Clear removes this lane's block and restores only entries carrying its prefix.
func (w *NetrcWriter) Clear() (bool, error) {
	type candidate struct {
		file     *secureuserfile.File
		analysis netrcAnalysis
	}
	files := []*secureuserfile.File{w.file}
	if w.alternate != nil {
		files = append(files, w.alternate)
	}
	candidates := make([]candidate, 0, len(files))
	owned := -1
	conflict := false
	for _, file := range files {
		data, existed, _, err := file.Read()
		if err != nil {
			return false, err
		}
		analysis := netrcAnalysis{existed: existed}
		if existed {
			analysis, err = analyzeNetrc(data, w.host)
			if err != nil {
				return false, err
			}
			analysis.existed = true
		}
		candidates = append(candidates, candidate{file: file, analysis: analysis})
		if analysis.markers.dmg != nil {
			entries, err := parseNetrc([]byte(analysis.markers.dmg.body))
			if err != nil || len(exactHostEntries(entries, w.host)) != 1 {
				return false, fmt.Errorf("netrc: managed credential host conflicts with ownership state: %w", ErrTargetUnusable)
			}
			if owned < 0 || file == w.file {
				owned = len(candidates) - 1
			}
		} else if analysis.markers.mdm || len(exactHostEntries(analysis.entries, w.host)) != 0 {
			conflict = true
		}
	}
	if owned >= 0 {
		for i, candidate := range candidates {
			if i != owned && (candidate.analysis.markers.mdm || candidate.analysis.markers.dmg == nil && len(exactHostEntries(candidate.analysis.entries, w.host)) != 0) {
				return false, fmt.Errorf("netrc: alternate credential file conflicts with managed file: %w", ErrTargetUnusable)
			}
		}
	} else if conflict {
		return false, fmt.Errorf("netrc: exact-host credential exists without an owned block: %w", ErrTargetUnusable)
	}
	purge := func() error {
		var errs []error
		for _, candidate := range candidates {
			if err := candidate.file.PurgeBackups(); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	if owned < 0 {
		return false, purge()
	}
	target := candidates[owned]
	next, changed, err := clearNetrc(target.analysis.data, w.host)
	if err != nil || !changed {
		return false, err
	}
	rest, _ := stripBOM(next)
	if len(bytes.TrimSpace(rest)) == 0 {
		err = target.file.Remove()
	} else {
		err = target.file.Commit(next, secureuserfile.FileMode)
	}
	if err != nil {
		return false, err
	}
	if err := purge(); err != nil {
		return false, errors.Join(fmt.Errorf("netrc: purge backups: %w", err), target.file.RestoreSnapshot())
	}
	return true, nil
}

func discoverDMGNetrcHost(home *secureuserfile.Home) (string, error) {
	if home == nil {
		return "", errors.New("netrc: nil secure user home")
	}
	var host string
	for _, name := range []string{".netrc", "_netrc"} {
		file, err := home.Open(name, netrcBackupPrefix+name+"-backup-", secureuserfile.MaxBytes)
		if err != nil {
			return "", err
		}
		data, existed, _, err := file.Read()
		if err != nil {
			return "", err
		}
		if !existed {
			continue
		}
		markers, err := scanNetrcMarkers(data)
		if err != nil {
			return "", err
		}
		if markers.dmg == nil {
			continue
		}
		entries, err := parseNetrc([]byte(markers.dmg.body))
		if err != nil || len(entries) != 1 || entries[0].isDefault || !isValidHost(entries[0].host) {
			return "", fmt.Errorf("netrc: cannot derive a trusted managed host: %w", ErrTargetUnusable)
		}
		managedHost := entries[0].host
		if host != "" && (home.GOOS() != model.PlatformWindows || host != managedHost) {
			return "", fmt.Errorf("netrc: conflicting managed credential files: %w", ErrTargetUnusable)
		}
		if _, err := analyzeNetrc(data, managedHost); err != nil {
			return "", err
		}
		host = managedHost
	}
	if host == "" {
		return "", fmt.Errorf("netrc: no trusted managed host: %w", ErrTargetUnusable)
	}
	return host, nil
}

func hasManagedNetrcMarker(home *secureuserfile.Home) (bool, error) {
	if home == nil {
		return false, errors.New("netrc: nil secure user home")
	}
	for _, name := range []string{".netrc", "_netrc"} {
		file, err := home.Open(name, netrcBackupPrefix, secureuserfile.MaxBytes)
		if err != nil {
			return false, err
		}
		managed, err := file.ContainsAny(dmgNetrcBegin, mdmNetrcBegin)
		if err != nil {
			return false, err
		}
		if managed {
			return true, nil
		}
	}
	return false, nil
}

func hasSingleManagedNetrc(home *secureuserfile.Home) (bool, error) {
	if home == nil {
		return false, errors.New("netrc: nil secure user home")
	}
	count := 0
	for _, name := range []string{".netrc", "_netrc"} {
		file, err := home.Open(name, netrcBackupPrefix, secureuserfile.MaxBytes)
		if err != nil {
			return false, err
		}
		data, existed, _, err := file.Read()
		if err != nil {
			return false, err
		}
		if !existed {
			continue
		}
		markers, err := scanNetrcMarkers(data)
		if err != nil {
			return false, err
		}
		if markers.dmg != nil {
			count++
		}
	}
	return count == 1, nil
}

func (w *NetrcWriter) RestoreSnapshot() error { return w.file.RestoreSnapshot() }

func (w *NetrcWriter) Converged(expected string) (bool, error) {
	if err := w.ValidateEffectivePath(); err != nil {
		return false, err
	}
	if err := w.validateExpected(expected); err != nil {
		return false, err
	}
	if err := w.checkAlternateConflict(); err != nil {
		return false, err
	}
	analysis, err := w.readSelected()
	if err != nil || !analysis.existed {
		return false, err
	}
	if analysis.markers.mdm || analysis.markers.dmg == nil || analysis.markers.dmg.body != expected {
		return false, nil
	}
	entries := exactHostEntries(analysis.entries, w.host)
	if len(entries) > 1 {
		return false, fmt.Errorf("netrc: duplicate exact-host entries: %w", ErrTargetUnusable)
	}
	if len(entries) != 1 || !entryMatches(entries[0], w.host, "step-security", w.token) {
		return false, nil
	}
	return w.file.MetadataSecure(secureuserfile.FileMode)
}

// Observation returns only a secret-free credential verdict.
func (w *NetrcWriter) Observation(expected string) (string, error) {
	if err := w.ValidateEffectivePath(); err != nil {
		return authTokenMismatch, nil
	}
	if err := w.validateExpected(expected); err != nil {
		return authTokenUnreadable, err
	}
	if err := w.checkAlternateConflict(); err != nil {
		return authTokenUnreadable, err
	}
	analysis, err := w.readSelected()
	if err != nil {
		return authTokenUnreadable, err
	}
	if !analysis.existed {
		return authTokenAbsent, nil
	}
	entries := exactHostEntries(analysis.entries, w.host)
	if len(entries) == 0 {
		return authTokenAbsent, nil
	}
	if len(entries) > 1 {
		return authTokenUnreadable, fmt.Errorf("netrc: duplicate exact-host entries: %w", ErrTargetUnusable)
	}
	if !entryMatches(entries[0], w.host, "step-security", w.token) {
		return authTokenMismatch, nil
	}
	secure, err := w.file.MetadataSecure(secureuserfile.FileMode)
	if err != nil {
		return authTokenUnreadable, err
	}
	if !secure {
		return authTokenMismatch, nil
	}
	return authTokenMatch, nil
}

func (w *NetrcWriter) MDMOwned() (bool, error) {
	analysis, err := w.readSelected()
	if err != nil || !analysis.existed || analysis.markers.mdmBlock == nil {
		return false, err
	}
	entries, err := parseNetrc([]byte(analysis.markers.mdmBlock.body))
	if err != nil {
		return false, err
	}
	return len(exactHostEntries(entries, w.host)) == 1, nil
}

func (w *NetrcWriter) HasMDMMarker() (bool, error) {
	analysis, err := w.readSelected()
	if err != nil || !analysis.existed {
		return false, err
	}
	return analysis.markers.mdm, nil
}

// ValidateEffectivePath fails closed when NETRC redirects credential lookup
// away from the file this writer owns.
func (w *NetrcWriter) ValidateEffectivePath() error {
	if w.lookupEnv == nil {
		return nil
	}
	override := strings.TrimSpace(w.lookupEnv("NETRC"))
	if override == "" {
		return nil
	}
	if !filepath.IsAbs(override) {
		return fmt.Errorf("netrc: NETRC override must be absolute: %w", ErrTargetUnusable)
	}
	override, managed := filepath.Clean(override), filepath.Clean(w.Location())
	if override != managed && (w.goos != model.PlatformWindows || !strings.EqualFold(override, managed)) {
		return fmt.Errorf("netrc: NETRC overrides the managed credential file: %w", ErrTargetUnusable)
	}
	return nil
}

func (w *NetrcWriter) checkAlternateConflict() error {
	if w.alternate == nil {
		return nil
	}
	data, existed, _, err := w.alternate.Read()
	if err != nil || !existed {
		return err
	}
	analysis, err := analyzeNetrc(data, w.host)
	if err != nil {
		return err
	}
	exact := exactHostEntries(analysis.entries, w.host)
	managedBlock := analysis.markers.dmg
	if managedBlock == nil {
		managedBlock = analysis.markers.mdmBlock
	}
	if managedBlock != nil {
		managed, err := parseNetrc([]byte(managedBlock.body))
		if err == nil && len(exactHostEntries(managed, w.host)) == 1 && len(exact) == 1 {
			return nil
		}
	}
	if analysis.markers.dmg != nil || analysis.markers.mdm || len(exact) != 0 {
		return fmt.Errorf("netrc: alternate credential file conflicts with selected file: %w", ErrTargetUnusable)
	}
	return nil
}

func (w *NetrcWriter) readSelected() (netrcAnalysis, error) {
	if w == nil || w.file == nil {
		return netrcAnalysis{}, errors.New("netrc: nil writer")
	}
	data, existed, _, err := w.file.Read()
	if err != nil || !existed {
		return netrcAnalysis{existed: existed}, err
	}
	analysis, err := analyzeNetrc(data, w.host)
	analysis.existed = true
	return analysis, err
}

const authTokenUnreadable = "unreadable"

type netrcAnalysis struct {
	data    []byte
	existed bool
	entries []netrcEntry
	markers netrcMarkers
}

type netrcMarkers struct {
	dmg         *netrcManagedBlock
	mdmBlock    *netrcManagedBlock
	dmgDisabled *netrcDisabledEntry
	mdmDisabled *netrcDisabledEntry
	mdm         bool
}

type netrcDisabledEntry struct {
	line    netrcLine
	decoded []byte
}

type netrcManagedBlock struct {
	start int
	end   int
	body  string
}

type netrcEntry struct {
	host                       string
	login, account, pass       string
	startToken, startLine, end int
	isDefault                  bool
}

func analyzeNetrc(data []byte, host string) (netrcAnalysis, error) {
	markers, err := scanNetrcMarkers(data)
	if err != nil {
		return netrcAnalysis{}, err
	}
	for _, disabled := range []*netrcDisabledEntry{markers.dmgDisabled, markers.mdmDisabled} {
		if disabled != nil {
			if err := validateNetrcDisabledEntry(disabled.decoded, host); err != nil {
				return netrcAnalysis{}, err
			}
		}
	}
	rest, _ := stripBOM(data)
	entries, err := parseNetrc(rest)
	if err != nil {
		return netrcAnalysis{}, err
	}
	for _, block := range []*netrcManagedBlock{markers.dmg, markers.mdmBlock} {
		if block == nil {
			continue
		}
		bodyEntries, err := parseNetrc([]byte(block.body))
		if err != nil || len(bodyEntries) != 1 || bodyEntries[0].isDefault {
			return netrcAnalysis{}, fmt.Errorf("netrc: malformed managed credential block: %w", ErrTargetUnusable)
		}
	}
	return netrcAnalysis{data: data, existed: true, entries: entries, markers: markers}, nil
}

func exactHostEntries(entries []netrcEntry, host string) []netrcEntry {
	out := make([]netrcEntry, 0, 1)
	for _, entry := range entries {
		if !entry.isDefault && entry.host == host {
			out = append(out, entry)
		}
	}
	return out
}

func entryMatches(entry netrcEntry, host, login, password string) bool {
	return !entry.isDefault && entry.host == host && entry.login == login && entry.pass == password
}

func rewriteNetrc(data []byte, host, expected string) ([]byte, error) {
	analysis, err := analyzeNetrc(data, host)
	if err != nil {
		return nil, err
	}
	if len(exactHostEntries(analysis.entries, host)) > 1 {
		return nil, fmt.Errorf("netrc: duplicate exact-host entries: %w", ErrTargetUnusable)
	}
	rest, bom := stripBOM(data)
	if analysis.markers.dmg != nil {
		rest = append(append([]byte(nil), rest[:analysis.markers.dmg.start]...), rest[analysis.markers.dmg.end:]...)
	}
	entries, err := parseNetrc(rest)
	if err != nil {
		return nil, err
	}
	exact := exactHostEntries(entries, host)
	if len(exact) > 1 {
		return nil, fmt.Errorf("netrc: duplicate exact-host entries: %w", ErrTargetUnusable)
	}
	if len(exact) == 1 {
		entry := exact[0]
		if entry.end <= entry.startLine || len(bytes.TrimSpace(rest[entry.startLine:entry.startToken])) != 0 {
			return nil, fmt.Errorf("netrc: exact-host entry shares a line with another entry: %w", ErrTargetUnusable)
		}
		rest = encodeNetrcEntry(rest, entry.startLine, entry.end)
	}

	newline := netrcNewline(data)
	var out bytes.Buffer
	out.Write(bom)
	out.Write(rest)
	if len(rest) != 0 {
		// This separator belongs to the managed block, so clear can remove it exactly.
		out.WriteString(newline)
	}
	out.WriteString(dmgNetrcBegin)
	out.WriteString(newline)
	out.WriteString(strings.ReplaceAll(expected, "\n", newline))
	out.WriteString(newline)
	out.WriteString(dmgNetrcEnd)
	out.WriteString(newline)
	return out.Bytes(), nil
}

func clearNetrc(data []byte, host string) ([]byte, bool, error) {
	analysis, err := analyzeNetrc(data, host)
	if err != nil {
		return nil, false, err
	}
	rest, bom := stripBOM(data)
	changed := false
	if analysis.markers.dmg != nil {
		rest = append(append([]byte(nil), rest[:analysis.markers.dmg.start]...), rest[analysis.markers.dmg.end:]...)
		changed = true
	}
	restored, decoded, err := decodeNetrcEntries(rest, dmgNetrcDisabledPrefix)
	if err != nil {
		return nil, false, err
	}
	changed = changed || decoded
	if !changed {
		return data, false, nil
	}
	if _, err := parseNetrc(restored); err != nil {
		return nil, false, err
	}
	return append(append([]byte(nil), bom...), restored...), true, nil
}

func encodeNetrcEntry(data []byte, start, end int) []byte {
	entry := data[start:end]
	var terminator []byte
	switch {
	case bytes.HasSuffix(entry, []byte("\r\n")):
		terminator = []byte("\r\n")
	case bytes.HasSuffix(entry, []byte("\n")):
		terminator = []byte("\n")
	}
	encoded := base64.RawURLEncoding.EncodeToString(entry)
	out := make([]byte, 0, len(data)-len(entry)+len(dmgNetrcDisabledPrefix)+len(encoded)+len(terminator))
	out = append(out, data[:start]...)
	out = append(out, dmgNetrcDisabledPrefix...)
	out = append(out, encoded...)
	out = append(out, terminator...)
	out = append(out, data[end:]...)
	return out
}

func decodeNetrcEntries(data []byte, prefix string) ([]byte, bool, error) {
	lines := splitNetrcLines(data)
	var out bytes.Buffer
	changed := false
	for _, line := range lines {
		content := data[line.start:line.contentEnd]
		if !bytes.HasPrefix(content, []byte(prefix)) {
			out.Write(data[line.start:line.end])
			continue
		}
		decoded, err := decodeNetrcDisabledEntry(string(content[len(prefix):]))
		if err != nil {
			return nil, false, err
		}
		out.Write(decoded)
		changed = true
	}
	return out.Bytes(), changed, nil
}

func decodeNetrcDisabledEntry(encoded string) ([]byte, error) {
	if encoded == "" || base64.RawURLEncoding.DecodedLen(len(encoded)) > secureuserfile.MaxBytes {
		return nil, fmt.Errorf("netrc: invalid disabled credential entry size: %w", ErrTargetUnusable)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("netrc: malformed disabled credential entry: %w", ErrTargetUnusable)
	}
	return decoded, nil
}

func validateNetrcDisabledEntry(data []byte, host string) error {
	if len(data) > secureuserfile.MaxBytes || hasNetrcOwnershipLine(data) {
		return fmt.Errorf("netrc: invalid disabled credential entry: %w", ErrTargetUnusable)
	}
	entries, err := parseNetrc(data)
	if err != nil || len(entries) != 1 || entries[0].isDefault || entries[0].host != host ||
		entries[0].startLine != 0 || entries[0].end != len(data) {
		return fmt.Errorf("netrc: disabled credential entry is not one exact-host entry: %w", ErrTargetUnusable)
	}
	return nil
}

func hasNetrcOwnershipLine(data []byte) bool {
	for _, line := range splitNetrcLines(data) {
		text := strings.TrimSpace(string(data[line.start:line.contentEnd]))
		if text == dmgNetrcBegin || text == mdmNetrcBegin || text == dmgNetrcEnd || text == mdmNetrcCreated ||
			strings.HasPrefix(text, dmgNetrcDisabledPrefix) || strings.HasPrefix(text, mdmNetrcDisabledPrefix) {
			return true
		}
	}
	return false
}

type netrcLine struct {
	start, contentEnd, end int
}

func splitNetrcLines(data []byte) []netrcLine {
	lines := make([]netrcLine, 0, bytes.Count(data, []byte("\n"))+1)
	for start := 0; start < len(data); {
		i := bytes.IndexByte(data[start:], '\n')
		end := len(data)
		contentEnd := end
		if i >= 0 {
			end = start + i + 1
			contentEnd = end - 1
			if contentEnd > start && data[contentEnd-1] == '\r' {
				contentEnd--
			}
		}
		lines = append(lines, netrcLine{start: start, contentEnd: contentEnd, end: end})
		start = end
	}
	return lines
}

func scanNetrcMarkers(data []byte) (netrcMarkers, error) {
	rest, _ := stripBOM(data)
	if !utf8.Valid(rest) || bytes.IndexByte(rest, 0) >= 0 || hasLoneCR(string(rest)) {
		return netrcMarkers{}, fmt.Errorf("netrc: invalid text encoding or line endings: %w", ErrTargetUnusable)
	}
	lines := splitNetrcLines(rest)
	var begins, ends, mdmBegins, mdmCreated []netrcLine
	var dmgDisabled, mdmDisabled []netrcDisabledEntry
	for _, line := range lines {
		raw := string(rest[line.start:line.contentEnd])
		text := strings.TrimSpace(raw)
		switch {
		case text == dmgNetrcBegin:
			if raw != text {
				return netrcMarkers{}, fmt.Errorf("netrc: managed marker contains whitespace: %w", ErrTargetUnusable)
			}
			begins = append(begins, line)
		case text == dmgNetrcEnd:
			if raw != text {
				return netrcMarkers{}, fmt.Errorf("netrc: managed marker contains whitespace: %w", ErrTargetUnusable)
			}
			ends = append(ends, line)
		case text == mdmNetrcBegin:
			if raw != text {
				return netrcMarkers{}, fmt.Errorf("netrc: managed marker contains whitespace: %w", ErrTargetUnusable)
			}
			mdmBegins = append(mdmBegins, line)
		case text == mdmNetrcCreated:
			if raw != text {
				return netrcMarkers{}, fmt.Errorf("netrc: created marker contains whitespace: %w", ErrTargetUnusable)
			}
			mdmCreated = append(mdmCreated, line)
		case strings.HasPrefix(text, dmgNetrcDisabledPrefix):
			if raw != text {
				return netrcMarkers{}, fmt.Errorf("netrc: disabled credential entry contains whitespace: %w", ErrTargetUnusable)
			}
			decoded, err := decodeNetrcDisabledEntry(strings.TrimPrefix(text, dmgNetrcDisabledPrefix))
			if err != nil {
				return netrcMarkers{}, err
			}
			dmgDisabled = append(dmgDisabled, netrcDisabledEntry{line: line, decoded: decoded})
		case strings.HasPrefix(text, mdmNetrcDisabledPrefix):
			if raw != text {
				return netrcMarkers{}, fmt.Errorf("netrc: disabled credential entry contains whitespace: %w", ErrTargetUnusable)
			}
			decoded, err := decodeNetrcDisabledEntry(strings.TrimPrefix(text, mdmNetrcDisabledPrefix))
			if err != nil {
				return netrcMarkers{}, err
			}
			mdmDisabled = append(mdmDisabled, netrcDisabledEntry{line: line, decoded: decoded})
		}
	}
	if len(begins) > 1 || len(mdmBegins) > 1 || len(ends) > 1 || len(mdmCreated) > 1 || len(dmgDisabled) > 1 || len(mdmDisabled) > 1 ||
		(len(begins) != 0 && len(mdmBegins) != 0) || (len(dmgDisabled) != 0 && len(mdmDisabled) != 0) {
		return netrcMarkers{}, fmt.Errorf("netrc: duplicate or conflicting managed ownership: %w", ErrTargetUnusable)
	}
	if len(begins) == 0 && len(mdmBegins) == 0 {
		if len(ends) != 0 || len(mdmCreated) != 0 || len(dmgDisabled) != 0 || len(mdmDisabled) != 0 {
			return netrcMarkers{}, fmt.Errorf("netrc: orphaned managed ownership: %w", ErrTargetUnusable)
		}
		return netrcMarkers{}, nil
	}
	if len(begins) == 1 {
		if len(ends) != 1 || begins[0].start >= ends[0].start || len(mdmCreated) != 0 || len(mdmDisabled) != 0 ||
			(len(dmgDisabled) == 1 && dmgDisabled[0].line.start >= begins[0].start) {
			return netrcMarkers{}, fmt.Errorf("netrc: malformed or crossed-lane managed ownership: %w", ErrTargetUnusable)
		}
		block, err := netrcMarkerBlock(rest, begins[0], ends[0])
		markers := netrcMarkers{dmg: block}
		if len(dmgDisabled) == 1 {
			markers.dmgDisabled = &dmgDisabled[0]
		}
		return markers, err
	}
	if len(ends) != 1 || mdmBegins[0].start >= ends[0].start || len(dmgDisabled) != 0 ||
		(len(mdmDisabled) == 1 && mdmDisabled[0].line.start >= mdmBegins[0].start) ||
		(len(mdmCreated) == 1 && (mdmCreated[0].start <= mdmBegins[0].start || mdmCreated[0].start >= ends[0].start)) {
		return netrcMarkers{}, fmt.Errorf("netrc: malformed or crossed-lane managed ownership: %w", ErrTargetUnusable)
	}
	block, err := netrcMarkerBlock(rest, mdmBegins[0], ends[0])
	markers := netrcMarkers{mdm: true, mdmBlock: block}
	if len(mdmDisabled) == 1 {
		markers.mdmDisabled = &mdmDisabled[0]
	}
	return markers, err
}

func netrcMarkerBlock(data []byte, begin, end netrcLine) (*netrcManagedBlock, error) {
	bodyBytes := trimOneNetrcNewline(data[begin.end:end.start])
	body := strings.ReplaceAll(string(bodyBytes), "\r\n", "\n")
	blockStart := begin.start
	if blockStart > 0 {
		switch {
		case blockStart >= 2 && bytes.Equal(data[blockStart-2:blockStart], []byte("\r\n")):
			blockStart -= 2
		case data[blockStart-1] == '\n':
			blockStart--
		default:
			return nil, fmt.Errorf("netrc: managed marker is not line-delimited: %w", ErrTargetUnusable)
		}
	}
	return &netrcManagedBlock{start: blockStart, end: end.end, body: body}, nil
}

func trimOneNetrcNewline(data []byte) []byte {
	if bytes.HasSuffix(data, []byte("\r\n")) {
		return data[:len(data)-2]
	}
	if bytes.HasSuffix(data, []byte("\n")) {
		return data[:len(data)-1]
	}
	return data
}

func netrcNewline(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

type netrcToken struct {
	value     string
	start     int
	lineStart int
}

func lexNetrc(data []byte) ([]netrcToken, error) {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || hasLoneCR(string(data)) {
		return nil, fmt.Errorf("netrc: invalid text encoding or line endings: %w", ErrTargetUnusable)
	}
	var tokens []netrcToken
	for i := 0; i < len(data); {
		for i < len(data) {
			if data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r' {
				i++
				continue
			}
			break
		}
		if i >= len(data) {
			break
		}
		start := i
		lineStart := bytes.LastIndexByte(data[:start], '\n') + 1
		var value strings.Builder
		quote := byte(0)
		for i < len(data) {
			c := data[i]
			if quote != 0 {
				switch c {
				case quote:
					quote = 0
					i++
				case '\\':
					if i+1 >= len(data) || data[i+1] == '\n' || data[i+1] == '\r' {
						return nil, fmt.Errorf("netrc: malformed quoted token: %w", ErrTargetUnusable)
					}
					value.WriteByte(data[i+1])
					i += 2
				default:
					value.WriteByte(c)
					i++
				}
				continue
			}
			switch c {
			case '\'', '"':
				quote = c
				i++
			case '\\':
				if i+1 >= len(data) || data[i+1] == '\n' || data[i+1] == '\r' {
					return nil, fmt.Errorf("netrc: malformed escaped token: %w", ErrTargetUnusable)
				}
				value.WriteByte(data[i+1])
				i += 2
			case ' ', '\t', '\n', '\r':
				goto tokenDone
			default:
				value.WriteByte(c)
				i++
			}
		}
	tokenDone:
		if quote != 0 || value.Len() == 0 {
			return nil, fmt.Errorf("netrc: malformed tokenization: %w", ErrTargetUnusable)
		}
		tokens = append(tokens, netrcToken{value: value.String(), start: start, lineStart: lineStart})
	}
	return tokens, nil
}

func skipNetrcLine(tokens []netrcToken, i int) int {
	lineStart := tokens[i].lineStart
	for i < len(tokens) && tokens[i].lineStart == lineStart {
		i++
	}
	return i
}

func parseNetrc(data []byte) ([]netrcEntry, error) {
	tokens, err := lexNetrc(data)
	if err != nil {
		return nil, err
	}
	entries := make([]netrcEntry, 0)
	for i := 0; i < len(tokens); {
		token := tokens[i]
		if strings.HasPrefix(token.value, "#") {
			i = skipNetrcLine(tokens, i)
			continue
		}
		entry := netrcEntry{startToken: token.start, startLine: token.lineStart}
		switch token.value {
		case "machine":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("netrc: machine has no name: %w", ErrTargetUnusable)
			}
			entry.host = tokens[i].value
			i++
		case "default":
			entry.isDefault = true
			i++
		case "macdef":
			return nil, fmt.Errorf("netrc: macdef is unsupported: %w", ErrTargetUnusable)
		default:
			return nil, fmt.Errorf("netrc: directive outside an entry: %w", ErrTargetUnusable)
		}

		seen := map[string]bool{}
		for i < len(tokens) && tokens[i].value != "machine" && tokens[i].value != "default" && tokens[i].value != "macdef" {
			if strings.HasPrefix(tokens[i].value, "#") {
				i = skipNetrcLine(tokens, i)
				continue
			}
			directive := tokens[i].value
			if directive != "login" && directive != "account" && directive != "password" {
				return nil, fmt.Errorf("netrc: unsupported entry directive: %w", ErrTargetUnusable)
			}
			if seen[directive] {
				return nil, fmt.Errorf("netrc: duplicate entry directive: %w", ErrTargetUnusable)
			}
			seen[directive] = true
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("netrc: entry directive has no value: %w", ErrTargetUnusable)
			}
			value := tokens[i].value
			switch directive {
			case "login":
				entry.login = value
			case "account":
				entry.account = value
			case "password":
				entry.pass = value
			}
			i++
		}
		entry.end = len(data)
		if i < len(tokens) {
			entry.end = tokens[i].lineStart
		}
		entries = append(entries, entry)
	}
	defaultSeen := false
	for _, entry := range entries {
		if entry.isDefault {
			if defaultSeen {
				return nil, fmt.Errorf("netrc: duplicate default entries: %w", ErrTargetUnusable)
			}
			defaultSeen = true
		}
	}
	return entries, nil
}
