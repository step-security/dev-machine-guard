package configaudit

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Severity constants — strings on purpose so the JSON model is human-grep-able.
const (
	pipSevCritical = "CRITICAL"
	pipSevHigh     = "HIGH"
	pipSevMedium   = "MEDIUM"
	pipSevLow      = "LOW"
	pipSevInfo     = "INFO"
)

// evaluatePipFindings walks every (file, section, key, value) entry plus
// every PIP_* env var and emits the catalog from spec §6 (pip-001 ..
// pip-024). Returns a stable-sorted slice keyed by (severity desc, ID,
// source).
//
// Rules are independent — multiple rules may fire on the same source.
// Severity escalation is layered: a credential-bearing key in a git-
// tracked file triggers BOTH pip-001 (creds) AND pip-004 (committed
// secrets) at CRITICAL, and the rendering layer can collapse them if
// desired.
func evaluatePipFindings(audit *model.PipAudit) []model.PipFinding {
	var findings []model.PipFinding
	emit := func(f model.PipFinding) { findings = append(findings, f) }

	// --- env-var rules ---
	for _, ev := range audit.EnvVars {
		evaluateEnvVarFindings(ev, emit)
	}

	// --- PIP_CONFIG_FILE redirection / disable ---
	evaluatePipConfigFileEnv(audit, emit)

	// --- per-file rules ---
	for _, f := range audit.Files {
		if !f.Exists {
			continue
		}
		// Each section's entries get walked; auth-key escalation considers
		// whether the file is git-tracked.
		for _, sec := range f.Sections {
			for _, kv := range sec.Entries {
				for _, v := range kv.Values {
					evaluateValueFindings(f, sec.Name, kv.Key, v, emit)
				}
				// Some rules (pip-007 on trusted-host, pip-023 require-hashes)
				// trigger on the *presence* of a key regardless of value count;
				// fold those in here for clarity.
				evaluateKeyPresenceFindings(f, sec.Name, kv, emit)
			}
		}
		// File-level rules: legacy path, mode permissions.
		evaluateFileLevelFindings(f, emit)
	}

	// --- netrc presence (informational; we don't parse contents) ---
	if audit.Netrc != nil && audit.Netrc.Exists && audit.Netrc.Mode != "" {
		if mode, ok := parseModeOctal(audit.Netrc.Mode); ok {
			if mode&0o077 != 0 {
				emit(model.PipFinding{
					ID:          "pip-netrc-perms",
					Severity:    pipSevMedium,
					Category:    "file-permissions",
					Source:      audit.Netrc.Path,
					Detail:      fmt.Sprintf("~/.netrc has mode %s — group/other readable. curl refuses to read this; pip via requests may still read it.", audit.Netrc.Mode),
					Remediation: "chmod 0600 " + audit.Netrc.Path,
				})
			} else {
				emit(model.PipFinding{
					ID:       "pip-netrc-present",
					Severity: pipSevInfo,
					Category: "informational",
					Source:   audit.Netrc.Path,
					Detail:   "~/.netrc present (mode " + audit.Netrc.Mode + "). pip falls back to it for index credentials.",
				})
			}
		}
	}

	// Stable ordering: severity desc → id → source.
	sortFindings(findings)
	return findings
}

// evaluateEnvVarFindings runs the env-var-targeted rules from spec §3 / §6.
func evaluateEnvVarFindings(ev model.PipEnvVar, emit func(model.PipFinding)) {
	// pip-001 — embedded creds in URL value
	if u, has := urlHasEmbeddedCreds(ev.Value); has {
		emit(model.PipFinding{
			ID:          "pip-001",
			Severity:    pipSevCritical,
			Category:    "credential-exposure",
			Source:      ev.Name,
			Key:         pipKeyForEnvName(ev.Name),
			ValueShown:  redactCredsInValue(ev.Value),
			Detail:      "URL value embeds plaintext credentials in env var.",
			Remediation: "Move the credential to a keyring entry or ~/.netrc (mode 0600), or fetch on demand via a CI secret store.",
		})
		_ = u
	}
	// pip-002 / pip-006 / pip-008 — http:// scheme
	if urlIsHTTP(ev.Value) {
		key := strings.ToLower(pipKeyForEnvName(ev.Name))
		switch key {
		case "extra-index-url":
			emit(httpSchemeFinding("pip-002", pipSevCritical, ev.Name, "", key, ev.Value))
		case "index-url":
			emit(httpSchemeFinding("pip-006", pipSevHigh, ev.Name, "", key, ev.Value))
		case "find-links":
			emit(httpSchemeFinding("pip-008", pipSevHigh, ev.Name, "", key, ev.Value))
		}
	}
	// pip-003 — embedded creds in proxy
	if ev.Name == "PIP_PROXY" || ev.Name == "HTTP_PROXY" || ev.Name == "HTTPS_PROXY" {
		if _, has := urlHasEmbeddedCreds(ev.Value); has {
			emit(model.PipFinding{
				ID:          "pip-003",
				Severity:    pipSevCritical,
				Category:    "credential-exposure",
				Source:      ev.Name,
				Key:         pipKeyForEnvName(ev.Name),
				ValueShown:  redactCredsInValue(ev.Value),
				Detail:      "Proxy URL embeds credentials. Anything reading this env var sees them in plaintext.",
				Remediation: "Use a credential helper (cntlm, kinit, keyring) instead of inline proxy creds.",
			})
		}
	}
	// pip-005 — extra-index-url present (any value)
	if pipKeyForEnvName(ev.Name) == "extra-index-url" && strings.TrimSpace(ev.Value) != "" {
		emit(model.PipFinding{
			ID:          "pip-005",
			Severity:    pipSevHigh,
			Category:    "dependency-confusion",
			Source:      ev.Name,
			Key:         "extra-index-url",
			ValueShown:  redactCredsInValue(ev.Value),
			Detail:      "Extra index configured. pip queries every index and installs the highest version found — an attacker controlling this index can override public-package versions (dependency-confusion).",
			Remediation: "Prefer --index-url for the canonical source; or use PEP 503 simple-repository tooling that scopes packages to specific indexes.",
		})
	}
	// pip-007 — trusted-host (any value)
	if pipKeyForEnvName(ev.Name) == "trusted-host" && strings.TrimSpace(ev.Value) != "" {
		hosts := strings.Fields(ev.Value)
		for _, h := range hosts {
			emit(model.PipFinding{
				ID:          "pip-007",
				Severity:    pipSevHigh,
				Category:    "tls-disabled",
				Source:      ev.Name,
				Key:         "trusted-host",
				ValueShown:  h,
				Detail:      fmt.Sprintf("trusted-host=%s disables HTTPS verification for that host. Any MITM on the path can serve trojaned packages.", h),
				Remediation: "Remove the trusted-host entry and resolve the underlying TLS issue (corporate CA, valid cert, etc.).",
			})
		}
	}
	// pip-011 — no-build-isolation = true
	if pipKeyForEnvName(ev.Name) == "no-build-isolation" && parseTruthy(ev.Value) {
		emit(model.PipFinding{
			ID:          "pip-011",
			Severity:    pipSevMedium,
			Category:    "install-integrity",
			Source:      ev.Name,
			Key:         "no-build-isolation",
			ValueShown:  ev.Value,
			Detail:      "Build isolation disabled. Packages can install with access to the host's installed packages, which can mask supply-chain issues at build time.",
			Remediation: "Leave PIP_NO_BUILD_ISOLATION unset (default false) unless you have a specific need.",
		})
	}
}

// evaluatePipConfigFileEnv handles pip-020 (redirected) and pip-021 (devnull-skip).
func evaluatePipConfigFileEnv(audit *model.PipAudit, emit func(model.PipFinding)) {
	var pcfValue string
	for _, ev := range audit.EnvVars {
		if ev.Name == "PIP_CONFIG_FILE" {
			pcfValue = ev.Value
			break
		}
	}
	if pcfValue == "" {
		return
	}
	// pip-021: devnull / nul disables all config-file loads.
	base := strings.ToLower(filepath.Base(pcfValue))
	if _, isNull := devNullPaths[base]; isNull || strings.EqualFold(pcfValue, "/dev/null") {
		emit(model.PipFinding{
			ID:          "pip-021",
			Severity:    pipSevMedium,
			Category:    "config-disabled",
			Source:      "PIP_CONFIG_FILE",
			Key:         "PIP_CONFIG_FILE",
			ValueShown:  pcfValue,
			Detail:      "PIP_CONFIG_FILE points to /dev/null (or nul) — pip skips loading every config file. Legitimate for hermetic CI; suspicious on a developer machine.",
			Remediation: "Verify the value is intentional. If the operator didn't set it, investigate the parent process.",
		})
		return
	}
	// pip-020: redirected to a non-default location. We can't know the
	// "expected" location with certainty, so we surface any value that
	// isn't under one of the known config dirs.
	if !looksLikeStandardPipConfigPath(pcfValue) {
		emit(model.PipFinding{
			ID:          "pip-020",
			Severity:    pipSevMedium,
			Category:    "config-redirection",
			Source:      "PIP_CONFIG_FILE",
			Key:         "PIP_CONFIG_FILE",
			ValueShown:  pcfValue,
			Detail:      "PIP_CONFIG_FILE redirects pip to read config from a non-standard location.",
			Remediation: "Confirm the override is intentional; the redirected file becomes the highest-precedence config source.",
		})
	}
}

// looksLikeStandardPipConfigPath returns true for paths that match a
// typical user/global pip config location. Used to decide whether
// PIP_CONFIG_FILE = X is suspicious.
func looksLikeStandardPipConfigPath(p string) bool {
	p = strings.ToLower(p)
	for _, pat := range []string{"/pip/pip.conf", "/pip/pip.ini", `\pip\pip.ini`, "/pip.conf", `\pip.ini`} {
		if strings.HasSuffix(p, pat) {
			return true
		}
	}
	return false
}

// isLegacyPipConfigPath returns true for paths matching the legacy pip
// config location: `~/.pip/pip.conf` (Unix) or `%HOME%\pip\pip.ini`
// (Windows). Detected via suffix rather than the discovery `Layer` label
// because `pip config debug` reports the legacy path under the "user"
// layer when pip itself is installed.
//
// On Windows, three locations share the `\pip\pip.ini` suffix:
//
//	%PROGRAMDATA%\pip\pip.ini  (global, not legacy)
//	%APPDATA%\pip\pip.ini      (current user, not legacy)
//	%HOME%\pip\pip.ini         (legacy)
//
// We discriminate by checking that the path does NOT include an
// `\appdata\` or `\programdata\` component — both unique to the
// non-legacy locations.
func isLegacyPipConfigPath(p string) bool {
	pl := strings.ToLower(p)
	if strings.HasSuffix(pl, "/.pip/pip.conf") {
		return true
	}
	if strings.HasSuffix(pl, `\pip\pip.ini`) &&
		!strings.Contains(pl, `\appdata\`) &&
		!strings.Contains(pl, `\programdata\`) {
		return true
	}
	return false
}

// evaluateValueFindings runs rules that depend on the value of a single
// (section, key, value) entry from a parsed file.
func evaluateValueFindings(f model.PipConfigFile, section, key, value string, emit func(model.PipFinding)) {
	keyLower := strings.ToLower(key)

	// pip-001 — embedded credentials in any value
	if _, has := urlHasEmbeddedCreds(value); has {
		sev := pipSevCritical
		emit(model.PipFinding{
			ID:          "pip-001",
			Severity:    sev,
			Category:    "credential-exposure",
			Source:      f.Path,
			Section:     section,
			Key:         key,
			ValueShown:  redactCredsInValue(value),
			Detail:      "URL value embeds plaintext credentials in pip config file.",
			Remediation: "Move the credential to a keyring entry or ~/.netrc (mode 0600), or fetch from a secret store at install time.",
		})
		// pip-004 — escalates if file is git-tracked.
		if f.GitTracked {
			emit(model.PipFinding{
				ID:          "pip-004",
				Severity:    pipSevCritical,
				Category:    "credential-exposure",
				Source:      f.Path,
				Section:     section,
				Key:         key,
				ValueShown:  redactCredsInValue(value),
				Detail:      "Credential-bearing pip config file is committed to git. Wherever this repo is published, the credential is published.",
				Remediation: "Remove the credential, rotate it immediately, and rewrite git history (git filter-repo) to purge old commits.",
			})
		}
	}

	// HTTP scheme rules. Each key has its own pip-NNN.
	if urlIsHTTP(value) {
		switch keyLower {
		case "extra-index-url":
			emit(httpSchemeFinding("pip-002", pipSevCritical, f.Path, section, key, value))
		case "index-url":
			emit(httpSchemeFinding("pip-006", pipSevHigh, f.Path, section, key, value))
		case "find-links":
			emit(httpSchemeFinding("pip-008", pipSevHigh, f.Path, section, key, value))
		}
	}

	// pip-003 — proxy with embedded creds
	if keyLower == "proxy" {
		if _, has := urlHasEmbeddedCreds(value); has {
			emit(model.PipFinding{
				ID:          "pip-003",
				Severity:    pipSevCritical,
				Category:    "credential-exposure",
				Source:      f.Path,
				Section:     section,
				Key:         key,
				ValueShown:  redactCredsInValue(value),
				Detail:      "Proxy URL embeds credentials.",
				Remediation: "Use a credential helper (cntlm, kinit, keyring) instead of inline proxy creds.",
			})
		}
	}

	// pip-005 — extra-index-url present (any value)
	if keyLower == "extra-index-url" && strings.TrimSpace(value) != "" {
		emit(model.PipFinding{
			ID:          "pip-005",
			Severity:    pipSevHigh,
			Category:    "dependency-confusion",
			Source:      f.Path,
			Section:     section,
			Key:         key,
			ValueShown:  redactCredsInValue(value),
			Detail:      "Extra index configured. pip queries every index and installs the highest version found — an attacker controlling this index can override public-package versions (dependency-confusion).",
			Remediation: "Prefer --index-url for the canonical source; or use PEP 503 simple-repository tooling that scopes packages to specific indexes.",
		})
	}

	// pip-007 — trusted-host (any host present). Files use one host per
	// parsed value, so we emit one finding per value here. The env-var
	// path emits one per space-separated host in the same way.
	if keyLower == "trusted-host" && strings.TrimSpace(value) != "" {
		emit(model.PipFinding{
			ID:          "pip-007",
			Severity:    pipSevHigh,
			Category:    "tls-disabled",
			Source:      f.Path,
			Section:     section,
			Key:         key,
			ValueShown:  value,
			Detail:      fmt.Sprintf("trusted-host=%s disables HTTPS verification for that host. Any MITM on the path can serve trojaned packages.", value),
			Remediation: "Remove the trusted-host entry and resolve the underlying TLS issue (corporate CA, valid cert, etc.).",
		})
	}

	// pip-009 / pip-010 — cert / client-cert configured (informational; severity MEDIUM)
	switch keyLower {
	case "cert":
		emit(model.PipFinding{
			ID:          "pip-009",
			Severity:    pipSevMedium,
			Category:    "tls-trust",
			Source:      f.Path,
			Section:     section,
			Key:         key,
			ValueShown:  value,
			Detail:      "Custom CA bundle configured. Verify the file at this path exists and is owned by a trusted account.",
			Remediation: "Confirm the CA file is part of the org's intended trust store.",
		})
	case "client-cert":
		emit(model.PipFinding{
			ID:          "pip-010",
			Severity:    pipSevMedium,
			Category:    "credential-exposure",
			Source:      f.Path,
			Section:     section,
			Key:         key,
			ValueShown:  value,
			Detail:      "Client certificate configured. Verify the key file is mode 0600 and not world-readable.",
			Remediation: "chmod 0600 on the client key file; rotate if it ever was world-readable.",
		})
	}

	// pip-011 — no-build-isolation
	if keyLower == "no-build-isolation" && parseTruthy(value) {
		emit(model.PipFinding{
			ID:          "pip-011",
			Severity:    pipSevMedium,
			Category:    "install-integrity",
			Source:      f.Path,
			Section:     section,
			Key:         key,
			ValueShown:  value,
			Detail:      "Build isolation disabled. Packages install with access to the host's site-packages — supply-chain issues at build time may be masked.",
			Remediation: "Set no-build-isolation = false (or remove the line) unless you have a specific need.",
		})
	}

	// pip-012 — no-binary = :all:
	if keyLower == "no-binary" && strings.TrimSpace(value) == ":all:" {
		emit(model.PipFinding{
			ID:          "pip-012",
			Severity:    pipSevMedium,
			Category:    "install-integrity",
			Source:      f.Path,
			Section:     section,
			Key:         key,
			ValueShown:  value,
			Detail:      "no-binary = :all: forces source builds for every package, which run setup.py — i.e. arbitrary Python code at install time.",
			Remediation: "Pin to specific packages that genuinely need source builds rather than disabling wheels globally.",
		})
	}

	// pip-013 — cache-dir in /tmp or world-writable
	if keyLower == "cache-dir" {
		v := strings.TrimSpace(value)
		if strings.HasPrefix(v, "/tmp/") || strings.HasPrefix(v, "/var/tmp/") {
			emit(model.PipFinding{
				ID:          "pip-013",
				Severity:    pipSevMedium,
				Category:    "path-tampering",
				Source:      f.Path,
				Section:     section,
				Key:         key,
				ValueShown:  v,
				Detail:      "cache-dir under /tmp — predictable, world-traversable, and prone to cache-poisoning by a co-tenant.",
				Remediation: "Use $HOME/.cache/pip or another user-owned, owner-only-writable path.",
			})
		}
	}

	// pip-015 — index-url non-default (informational; HTTPS only)
	if keyLower == "index-url" {
		v := strings.TrimSpace(value)
		if v != "" && v != "https://pypi.org/simple" && v != "https://pypi.org/simple/" && !urlIsHTTP(v) {
			emit(model.PipFinding{
				ID:         "pip-015",
				Severity:   pipSevInfo,
				Category:   "dependency-source",
				Source:     f.Path,
				Section:    section,
				Key:        key,
				ValueShown: redactCredsInValue(v),
				Detail:     "index-url overrides PyPI to a private index. This is normal in many orgs — surfaced for inventory.",
			})
		}
	}

	// pip-016 — keyring-provider = disabled (informational)
	if keyLower == "keyring-provider" && strings.EqualFold(strings.TrimSpace(value), "disabled") {
		emit(model.PipFinding{
			ID:         "pip-016",
			Severity:   pipSevLow,
			Category:   "auth-narrowing",
			Source:     f.Path,
			Section:    section,
			Key:        key,
			ValueShown: value,
			Detail:     "keyring-provider = disabled. pip won't consult the system keyring; only URL-embedded creds, env vars, and ~/.netrc are used.",
		})
	}

	// pip-017 — no-cache-dir = true
	if keyLower == "no-cache-dir" && parseTruthy(value) {
		emit(model.PipFinding{
			ID:         "pip-017",
			Severity:   pipSevLow,
			Category:   "informational",
			Source:     f.Path,
			Section:    section,
			Key:        key,
			ValueShown: value,
			Detail:     "Cache disabled — every install fetches fresh from the index.",
		})
	}

	// pip-018 — pre = true
	if keyLower == "pre" && parseTruthy(value) {
		emit(model.PipFinding{
			ID:         "pip-018",
			Severity:   pipSevLow,
			Category:   "informational",
			Source:     f.Path,
			Section:    section,
			Key:        key,
			ValueShown: value,
			Detail:     "pre = true — pre-release versions are eligible for install. Reduces version predictability.",
		})
	}

	// pip-023 (positive) — require-hashes = true
	if keyLower == "require-hashes" && parseTruthy(value) {
		emit(model.PipFinding{
			ID:         "pip-023",
			Severity:   pipSevInfo,
			Category:   "defensive-control",
			Source:     f.Path,
			Section:    section,
			Key:        key,
			ValueShown: value,
			Detail:     "require-hashes = true — every install must include a hash. Strong defensive control against tampered indexes.",
		})
	}

	// pip-024 (positive) — only-binary = :all: in [install]
	if keyLower == "only-binary" && strings.TrimSpace(value) == ":all:" && section == "install" {
		emit(model.PipFinding{
			ID:         "pip-024",
			Severity:   pipSevInfo,
			Category:   "defensive-control",
			Source:     f.Path,
			Section:    section,
			Key:        key,
			ValueShown: value,
			Detail:     "only-binary = :all: blocks source builds — installs cannot run setup.py. Strong defensive control.",
		})
	}
}

// evaluateKeyPresenceFindings handles rules that fire on key presence
// regardless of value count or repeats. Currently empty (most presence
// rules are handled per-value above), but kept as a hook for future
// rules that need a "saw it once" pattern.
func evaluateKeyPresenceFindings(_ model.PipConfigFile, _ string, _ model.PipKeyValue, _ func(model.PipFinding)) {
	// no-op for now
}

// evaluateFileLevelFindings handles rules that depend on file metadata
// rather than parsed values: legacy paths, mode permissions.
func evaluateFileLevelFindings(f model.PipConfigFile, emit func(model.PipFinding)) {
	// pip-019 — legacy ~/.pip/pip.conf or %HOME%\pip\pip.ini in use.
	//
	// Detected by path suffix rather than the discovery layer label,
	// because when pip itself is installed `pip config debug` reports the
	// legacy path under the "user" layer (pip doesn't expose the "legacy"
	// concept). Path matching catches both cases.
	if isLegacyPipConfigPath(f.Path) {
		emit(model.PipFinding{
			ID:          "pip-019",
			Severity:    pipSevLow,
			Category:    "hygiene",
			Source:      f.Path,
			Detail:      "Legacy pip config location in use. pip will keep loading it, but the current location ($XDG_CONFIG_HOME/pip/pip.conf or %APPDATA%\\pip\\pip.ini) is preferred.",
			Remediation: "Move the file to the current location; delete the legacy one.",
		})
	}

	// pip-022 — file mode broader than 0644 (or 0600 when contains creds)
	if f.Mode == "" {
		return // Windows, where we don't compute permissions
	}
	mode, ok := parseModeOctal(f.Mode)
	if !ok {
		return
	}
	containsCreds := fileContainsEmbeddedCreds(f)
	switch {
	case containsCreds && mode&0o077 != 0:
		emit(model.PipFinding{
			ID:          "pip-022",
			Severity:    pipSevHigh,
			Category:    "file-permissions",
			Source:      f.Path,
			Detail:      fmt.Sprintf("Config file contains embedded credentials AND has mode %s — group/other readable. Anyone with shell access reads the secret.", f.Mode),
			Remediation: fmt.Sprintf("chmod 0600 %s and rotate the credential.", f.Path),
		})
	case mode&0o022 != 0 && f.Layer == "global":
		emit(model.PipFinding{
			ID:          "pip-022",
			Severity:    pipSevHigh,
			Category:    "file-permissions",
			Source:      f.Path,
			Detail:      fmt.Sprintf("Global pip config has mode %s — group/other writable. A non-root account can change pip's defaults for every user.", f.Mode),
			Remediation: fmt.Sprintf("chown root:root and chmod 0644 %s.", f.Path),
		})
	case mode > 0o644:
		emit(model.PipFinding{
			ID:          "pip-022",
			Severity:    pipSevMedium,
			Category:    "file-permissions",
			Source:      f.Path,
			Detail:      fmt.Sprintf("Config file mode %s is broader than 0644.", f.Mode),
			Remediation: fmt.Sprintf("chmod 0644 %s (or 0600 if it contains credentials).", f.Path),
		})
	}
}

// fileContainsEmbeddedCreds returns true if any URL value across any
// section of the file embeds credentials. Used to decide whether mode
// findings should escalate.
func fileContainsEmbeddedCreds(f model.PipConfigFile) bool {
	for _, sec := range f.Sections {
		for _, kv := range sec.Entries {
			for _, v := range kv.Values {
				if _, has := urlHasEmbeddedCreds(v); has {
					return true
				}
			}
		}
	}
	return false
}

// httpSchemeFinding builds the common shape used by pip-002 / pip-006 /
// pip-008. The caller picks the ID and severity.
func httpSchemeFinding(id, sev, source, section, key, value string) model.PipFinding {
	return model.PipFinding{
		ID:          id,
		Severity:    sev,
		Category:    "tls-disabled",
		Source:      source,
		Section:     section,
		Key:         key,
		ValueShown:  redactCredsInValue(value),
		Detail:      fmt.Sprintf("%s uses http:// — registry traffic is unencrypted and trivially MITM-able.", key),
		Remediation: "Switch to https:// (with a valid cert if it's an internal index).",
	}
}

// parseTruthy mimics pip's RawConfigParser-derived bool semantics:
// `true` / `yes` / `1` / `on` (case-insensitive) are truthy. Empty
// string is NOT false — but for our finding rules we want exact
// matching, so empty returns false.
func parseTruthy(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "true", "yes", "1", "on":
		return true
	}
	return false
}

// parseModeOctal parses a mode string like "0644" or "0o644" into a
// uint32. Returns false on parse failure.
func parseModeOctal(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	s = strings.TrimPrefix(s, "0o")
	s = strings.TrimPrefix(s, "0")
	if s == "" {
		return 0, true // "0" alone is mode 0
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// sortFindings produces a deterministic ordering for output. We sort by
// severity (CRITICAL → HIGH → MEDIUM → LOW → INFO), then by ID, then by
// source for tie-breaking. Stable sort so equal-keyed rows preserve
// the order they were emitted.
func sortFindings(findings []model.PipFinding) {
	rank := func(s string) int {
		switch s {
		case pipSevCritical:
			return 0
		case pipSevHigh:
			return 1
		case pipSevMedium:
			return 2
		case pipSevLow:
			return 3
		case pipSevInfo:
			return 4
		}
		return 99
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank(findings[i].Severity) != rank(findings[j].Severity) {
			return rank(findings[i].Severity) < rank(findings[j].Severity)
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Source < findings[j].Source
	})
}
