package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// EnvDeviceID is the environment variable that overrides the device identity
// template. It beats the config.json `device_id` key, which in turn beats the
// machine identity resolved by SerialNumber (id.go). Fleets that provision
// machines from a script (a VDI host pool, an image pipeline) set it
// machine-wide at bootstrap.
const EnvDeviceID = "STEPSEC_DEVICE_ID"

// Identity sources, reported to the backend as device_id_source so support can
// answer "why does this device have this id" from the row alone. "serial"
// covers every machine-derived id (hardware serial, the machine-wide id file,
// a generated fallback).
const (
	IdentitySourceEnv    = "env"
	IdentitySourceConfig = "config"
	IdentitySourceSerial = "serial"
)

// Identity template tokens. The template is a literal, or any mix of literal
// text and these tokens; it is expanded then sanitized (SanitizeDeviceID). A
// device is always a machine: there is no user token, because the users of a
// shared host are reported inside its device (user_identity and user_token on
// every upload), not as devices of their own.
const (
	TokenSerial   = "{serial}"
	TokenHostname = "{hostname}"
	// legacyTokenUser was an identity token in an unreleased build; a
	// template that still carries it is reported with a specific message
	// and falls back to the machine identity like any unknown token.
	legacyTokenUser = "{user}"
)

// maxDeviceIDLen bounds a configured id. Longer ids keep a readable prefix and
// gain a deterministic hash suffix so two long templates never collide.
const (
	maxDeviceIDLen      = 128
	longIDPrefixLen     = 115
	longIDHashSuffixLen = 12
	// UserTokenFingerprintLen is the length of the sha256 hex fingerprint of
	// the full principal appended to a user token (see userToken): 48 bits,
	// so two accounts sharing a short name on one host cannot be made to
	// collide by chance or by choosing a domain name.
	UserTokenFingerprintLen = 12
	// MaxUserTokenLen bounds a user token, and so a per-session state scope:
	// a sanitized short name, a dash and the fingerprint.
	MaxUserTokenLen = maxDeviceIDLen + 1 + UserTokenFingerprintLen
)

// Identity is the resolved device identity for this run.
//
// DeviceID is what EVERY backend call uses (through ID / IDForGuest): the run
// gate, run-status beacons, the rules fetch, the upload bodies, device policy,
// hooks and the telemetry payload's device_id. Serial is the machine identity
// SerialNumber resolved and ships as the payload's serial_number regardless of
// how DeviceID was produced, so a rebuilt virtual desktop that keeps its
// configured identity still reports the hardware change.
type Identity struct {
	DeviceID string
	Serial   string
	Source   string // IdentitySource*
	Template string // the raw env/config value; "" when Source == serial
	// Incomplete is true when a token expanded empty: {serial} on a machine
	// with no usable serial, {hostname} on a nameless host without one. An
	// incomplete identity must not reach the backend, so callers skip the run
	// and say why.
	Incomplete bool
	// Issue is a human-readable note for the log ("" when nothing is wrong):
	// an unknown token, a template that sanitized to nothing, and so on.
	Issue string
	// UserToken names the signed-in user this run scans for: the account's
	// short name plus a fingerprint of the full principal (userToken), "" for
	// a service account. Every upload and beacon carries it as user_token so
	// the backend files the run under the right user of this device.
	UserToken string
	// PerSession is true when this host scans every signed-in session
	// separately (device/multiuser.go): each session's run keeps its own
	// state and lock, all of them reporting under this one device.
	PerSession bool
	// SessionScope names the per-session state directory (paths.StateDir):
	// UserToken when PerSession and a user is signed in, else "".
	SessionScope string
}

// IdentityTemplate returns the identity template in force: STEPSEC_DEVICE_ID
// when set, else config.json's device_id, else "" (machine identity). The
// source is returned alongside so callers can report it.
func IdentityTemplate(exec executor.Executor) (template, source string) {
	if v := strings.TrimSpace(exec.Getenv(EnvDeviceID)); v != "" {
		return v, IdentitySourceEnv
	}
	if v := strings.TrimSpace(config.DeviceID); v != "" {
		return v, IdentitySourceConfig
	}
	return "", IdentitySourceSerial
}

// HasIdentityTemplate reports whether the device identity is configured rather
// than derived from the machine identity.
func HasIdentityTemplate(exec executor.Executor) bool {
	t, _ := IdentityTemplate(exec)
	return t != ""
}

// ResolveIdentity turns the configured template (or its absence) plus the
// probed facts into the identity used for every backend call, and records the
// session facts (UserToken, PerSession, SessionScope). Pure apart from the
// env/config read in IdentityTemplate and the per-session snapshot.
//
// The machine-identity path is byte-identical to what the agent always sent:
// no sanitization is applied when there is no template, so an existing fleet
// never re-registers after an upgrade (VMware serials with spaces included).
func ResolveIdentity(exec executor.Executor, serial, hostname, user string) Identity {
	template, source := IdentityTemplate(exec)
	id := resolveWith(template, source, serial, hostname)
	id.UserToken = UserToken(exec, user)
	if on, _ := PerSessionScanning(exec); on {
		id.PerSession = true
		id.SessionScope = id.UserToken
	}
	return id
}

// AttachIdentity resolves the identity for a gathered Device and records it on
// the struct (DeviceID, DeviceIDSource, DeviceIDTemplate, IdentityIncomplete,
// UserToken, PerSessionScanning), which is what ID reads. Gather calls it;
// telemetry calls it again after a late serial resolve.
func AttachIdentity(exec executor.Executor, dev *model.Device) {
	id := ResolveIdentity(exec, dev.SerialNumber, dev.Hostname, dev.UserIdentity)
	dev.DeviceID = id.DeviceID
	dev.DeviceIDSource = id.Source
	dev.DeviceIDTemplate = TemplateForReport(id.Template)
	dev.IdentityIncomplete = id.Incomplete
	dev.UserToken = id.UserToken
	dev.PerSessionScanning = id.PerSession
}

// resolveWith is the pure core of ResolveIdentity. An empty template is the
// machine identity (usableSerial applies, never a placeholder). A literal with
// no tokens is used exactly as given, the same contract as a configured
// device id before templates existed; only token expansions are sanitized,
// because they inject values (host names) nobody vetted.
func resolveWith(template, source, serial, hostname string) Identity {
	fallback := func(issue string) Identity {
		id := Identity{Serial: serial, Source: IdentitySourceSerial, Template: template, Issue: issue}
		if usableSerial(serial) {
			id.DeviceID = serial
		}
		return id
	}
	if template == "" {
		return fallback("")
	}

	id := Identity{Serial: serial, Source: source, Template: template}
	if !strings.Contains(template, "{") {
		id.DeviceID = strings.TrimSpace(template)
		return id
	}
	expanded, issue, incomplete := expandIdentityTemplate(template, serial, hostname)
	if issue != "" {
		// An unknown token is a configuration mistake, not a reason to stop
		// scanning: fall back to the machine identity and say so.
		return fallback(issue)
	}
	if incomplete {
		id.Incomplete = true
		return id
	}
	id.DeviceID = SanitizeDeviceID(expanded)
	if id.DeviceID == "" {
		return fallback("device identity template " + template + " produced an empty id; using the machine identity")
	}
	return id
}

// expandIdentityTemplate substitutes the known tokens (case-insensitively). It
// returns the expanded string, a non-empty issue for an unknown token, and
// incomplete=true when a token expanded to nothing usable.
func expandIdentityTemplate(template, serial, hostname string) (expanded, issue string, incomplete bool) {
	var b strings.Builder
	rest := template
	for {
		open := strings.Index(rest, "{")
		if open < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:open])
		closeRel := strings.Index(rest[open:], "}")
		if closeRel < 0 {
			// Unbalanced brace: treat the remainder as literal text.
			b.WriteString(rest[open:])
			break
		}
		token := strings.ToLower(rest[open : open+closeRel+1])
		rest = rest[open+closeRel+1:]
		switch token {
		case TokenSerial:
			if !usableSerial(serial) {
				incomplete = true
			}
			b.WriteString(serial)
		case TokenHostname:
			// A host without a usable name falls back to its machine
			// identity, as the dashboard does when it has no name to show:
			// "unknown" would collide across every nameless host.
			h := hostnameToken(hostname, serial)
			if h == "" {
				incomplete = true
			}
			b.WriteString(h)
		case legacyTokenUser:
			return "", "device identity template " + template + " uses {user}, which is not an identity token: a device is the machine and its users are reported inside it (known tokens: {serial} {hostname}); using the machine identity", false
		default:
			return "", "device identity template " + template + " has an unknown token " + token +
				" (known: {serial} {hostname}); using the machine identity", false
		}
	}
	return b.String(), "", incomplete
}

// hostnameToken is the {hostname} expansion: the lowercased host name, else
// the machine identity when the host has no usable name (empty, "unknown",
// "localhost"), else "" (incomplete). The loaders apply the same rule.
func hostnameToken(hostname, serial string) string {
	switch h := strings.ToLower(strings.TrimSpace(hostname)); h {
	case "", "unknown", "localhost", "localhost.localdomain":
		if usableSerial(serial) {
			return serial
		}
		return ""
	default:
		return h
	}
}

// UserToken is the token the agent reports for the signed-in user (payload
// and beacon user_token) and uses as the per-session state scope: "" for a
// service account, else userToken sanitized for file names and keys.
func UserToken(exec executor.Executor, user string) string {
	return SanitizeDeviceID(userToken(exec.GOOS(), exec.IsRoot(), user))
}

// userToken reduces a user identity to a key-safe token. A service account
// becomes empty. Otherwise the token is the readable short name (an email's
// local part, DOMAIN\ stripped, lowercased, sanitized) plus a fingerprint of
// the whole lowercased principal: CORP\alice and HOST\alice, or
// alice@a.example and alice@b.example, share a short name but never a state
// scope, a lock or a user entry on the device, and a name whose readable part
// sanitizes to nothing (a non-Latin display name) still yields a usable token.
// The loaders apply the same rule.
func userToken(platform string, root bool, user string) string {
	u := strings.TrimSpace(user)
	if isServiceAccount(platform, root, u) {
		return ""
	}
	principal := strings.ToLower(u)
	short := principal
	if at := strings.Index(short, "@"); at >= 0 {
		short = short[:at]
	}
	if bs := strings.LastIndex(short, `\`); bs >= 0 {
		short = short[bs+1:]
	}
	short = SanitizeDeviceID(short)
	fp := UserTokenFingerprint(principal)
	if short == "" {
		return "user-" + fp
	}
	return short + "-" + fp
}

// UserTokenFingerprint is the fingerprint part of a user token: the first
// UserTokenFingerprintLen hex digits of the sha256 of the lowercased full
// principal (DOMAIN\user, or the whole email).
func UserTokenFingerprint(principal string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(principal))))
	return hex.EncodeToString(sum[:])[:UserTokenFingerprintLen]
}

// IsServiceAccount reports whether a user identity names a daemon context
// rather than a developer: empty or unknown, root when the process is root,
// and on Windows the well-known service accounts (NT AUTHORITY\SYSTEM, LOCAL
// SERVICE, NETWORK SERVICE, the NT SERVICE\ virtual accounts) and machine
// accounts (trailing $). It is the single predicate behind the payload's
// no_user_logged_in flag and the empty user token.
func IsServiceAccount(exec executor.Executor, user string) bool {
	return isServiceAccount(exec.GOOS(), exec.IsRoot(), user)
}

func isServiceAccount(platform string, root bool, user string) bool {
	u := strings.TrimSpace(user)
	if u == "" || u == "unknown" {
		return true
	}
	if u == "root" && root {
		return true
	}
	lower := strings.ToLower(u)
	for _, prefix := range []string{`nt authority\`, `nt service\`, `window manager\`, `font driver host\`} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if platform == model.PlatformWindows {
		switch lower {
		case "system", "local service", "network service":
			return true
		}
		if strings.HasSuffix(lower, "$") {
			return true
		}
	}
	return false
}

// SanitizeDeviceID makes a configured id safe for every key it is embedded in
// (DynamoDB composite keys use '#', S3 prefixes use '/'): runes outside
// [A-Za-z0-9._~-] become '-', runs of '-' collapse, leading and trailing '-'
// and '.' are trimmed, and an id longer than 128 bytes keeps its first 115
// bytes plus a 12-hex-digit sha256 suffix so it stays unique and readable.
// Returns "" when nothing survives. Applied ONLY to configured ids; the
// machine-identity path is never touched.
func SanitizeDeviceID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '~' || r == '-'
		if !ok {
			r = '-'
		}
		if r == '-' {
			if lastDash {
				continue
			}
			lastDash = true
		} else {
			lastDash = false
		}
		b.WriteRune(r)
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return ""
	}
	if len(out) > maxDeviceIDLen {
		sum := sha256.Sum256([]byte(out))
		out = strings.TrimRight(out[:longIDPrefixLen], "-.") + "-" + hex.EncodeToString(sum[:])[:longIDHashSuffixLen]
	}
	return out
}

// ResolvedDeviceID resolves the identity without a full Gather: the machine
// identity comes from SerialNumber (cached per process, so a second caller
// pays nothing) and only when the template needs it (the machine identity
// itself, {serial}, or {hostname} on a host without a usable name); hostname
// and user are cheap. Used by the run gate ahead of the device_info phase and
// by `uninstall --retire`.
func ResolvedDeviceID(ctx context.Context, exec executor.Executor) Identity {
	template, _ := IdentityTemplate(exec)
	lower := strings.ToLower(template)
	hostname := getHostname(ctx, exec, exec.GOOS())
	user := developerIdentity(ctx, exec)
	serial := ""
	if template == "" || strings.Contains(lower, TokenSerial) ||
		(strings.Contains(lower, TokenHostname) && hostnameToken(hostname, "") == "") {
		serial = SerialNumber(ctx, exec)
	}
	id := ResolveIdentity(exec, serial, hostname, user)
	if serial == "" && id.Source == IdentitySourceSerial {
		// The template fell back to the machine identity (an unknown token,
		// an empty expansion): resolve the serial now rather than handing
		// back an empty id that would skip the check-in.
		serial = SerialNumber(ctx, exec)
		id = ResolveIdentity(exec, serial, hostname, user)
	}
	return id
}

// SessionScope returns the per-session state scope for this run: the user
// token when this host scans every signed-in session separately and the
// current user is a real developer, else "" (shared state). It probes nothing
// (no serial, no hostname) so main can call it before any state path is
// touched.
func SessionScope(exec executor.Executor) string {
	if on, _ := PerSessionScanning(exec); !on {
		return ""
	}
	return UserToken(exec, developerIdentity(context.Background(), exec))
}

// TemplateForReport is the template the payload reports as
// device_id_template: the template in force when it carries a token, "" for
// the hardware serial and for a literal id, which the backend already sees as
// device_id.
func TemplateForReport(template string) string {
	if strings.Contains(template, "{") {
		return template
	}
	return ""
}
