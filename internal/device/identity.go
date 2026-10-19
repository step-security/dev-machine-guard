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
// text and these tokens; it is expanded then sanitized (SanitizeDeviceID).
const (
	TokenSerial   = "{serial}"
	TokenHostname = "{hostname}"
	TokenUser     = "{user}"
)

// maxDeviceIDLen bounds a configured id. Longer ids keep a readable prefix and
// gain a deterministic hash suffix so two long templates never collide.
const (
	maxDeviceIDLen      = 128
	longIDPrefixLen     = 115
	longIDHashSuffixLen = 12
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
	// PerUser is true when the template contained {user}: each logged-in user
	// of this machine is a separate device, and the agent keeps per-user state.
	PerUser bool
	// UserScope is the sanitized {user} token when PerUser and the identity is
	// complete; it names the per-user state directory (paths.StateDir).
	UserScope string
	// Incomplete is true when a token expanded empty: {user} under a service
	// account (SYSTEM, LOCAL SERVICE), or {serial} on a machine with no usable
	// serial. An incomplete identity must not reach the backend — a serial-only
	// fallback row would be exactly the phantom device the template exists to
	// prevent — so callers skip the run and say why.
	Incomplete bool
	// Issue is a human-readable note for the log ("" when nothing is wrong):
	// an unknown token, a template that sanitized to nothing, and so on.
	Issue string
}

// IdentityTemplate returns the configured identity template: STEPSEC_DEVICE_ID
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
// probed facts into the identity used for every backend call. Pure apart from
// the env/config read in IdentityTemplate.
//
// The machine-identity path is byte-identical to what the agent always sent:
// no sanitization is applied when there is no template, so an existing fleet
// never re-registers after an upgrade (VMware serials with spaces included).
func ResolveIdentity(exec executor.Executor, serial, hostname, user string) Identity {
	template, source := IdentityTemplate(exec)
	return resolveWith(template, source, serial, hostname, user, exec.GOOS(), exec.IsRoot())
}

// AttachIdentity resolves the identity for a gathered Device and records it on
// the struct (DeviceID, DeviceIDSource, IdentityPerUser, IdentityIncomplete),
// which is what ID reads. Gather calls it; telemetry calls it again after a
// late serial resolve.
func AttachIdentity(exec executor.Executor, dev *model.Device) {
	id := ResolveIdentity(exec, dev.SerialNumber, dev.Hostname, dev.UserIdentity)
	dev.DeviceID = id.DeviceID
	dev.DeviceIDSource = id.Source
	dev.IdentityPerUser = id.PerUser
	dev.IdentityIncomplete = id.Incomplete
}

// resolveWith is the pure core of ResolveIdentity. An empty template is the
// machine identity (usableSerial applies, never a placeholder). A literal with
// no tokens is used exactly as given, the same contract as a configured
// device id before templates existed; only token expansions are sanitized,
// because they inject values (user names, host names) nobody vetted.
func resolveWith(template, source, serial, hostname, user, platform string, root bool) Identity {
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
	expanded, issue, incomplete := expandIdentityTemplate(template, serial, hostname, user, platform, root)
	id.PerUser = strings.Contains(strings.ToLower(template), TokenUser)
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
	if id.PerUser {
		id.UserScope = SanitizeDeviceID(userToken(platform, root, user))
	}
	return id
}

// expandIdentityTemplate substitutes the known tokens (case-insensitively). It
// returns the expanded string, a non-empty issue for an unknown token, and
// incomplete=true when a token expanded to nothing usable.
func expandIdentityTemplate(template, serial, hostname, user, platform string, root bool) (expanded, issue string, incomplete bool) {
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
			h := strings.ToLower(strings.TrimSpace(hostname))
			if h == "" {
				incomplete = true
			}
			b.WriteString(h)
		case TokenUser:
			u := userToken(platform, root, user)
			if u == "" {
				incomplete = true
			}
			b.WriteString(u)
		default:
			return "", "device identity template " + template + " has an unknown token " + token +
				" (known: {serial} {hostname} {user}); using the machine identity", false
		}
	}
	return b.String(), "", incomplete
}

// userToken reduces a user identity to the form used inside a device id: a
// service account becomes empty, an email keeps its local part, a DOMAIN\user
// loses the domain, and the result is lowercased. The empty result is what
// makes a {user} template incomplete under SYSTEM.
func userToken(platform string, root bool, user string) string {
	u := strings.TrimSpace(user)
	if isServiceAccount(platform, root, u) {
		return ""
	}
	if at := strings.Index(u, "@"); at >= 0 {
		u = u[:at]
	}
	if bs := strings.LastIndex(u, `\`); bs >= 0 {
		u = u[bs+1:]
	}
	return strings.ToLower(strings.TrimSpace(u))
}

// IsServiceAccount reports whether a user identity names a daemon context
// rather than a developer: empty or unknown, root when the process is root,
// and on Windows the well-known service accounts (NT AUTHORITY\SYSTEM, LOCAL
// SERVICE, NETWORK SERVICE, the NT SERVICE\ virtual accounts) and machine
// accounts (trailing $). It is the single predicate behind the payload's
// no_user_logged_in flag and the {user} identity token.
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
// pays nothing) and only when the template needs it; hostname and user are
// cheap. Used by the run gate ahead of the device_info phase and by
// `uninstall --retire`.
func ResolvedDeviceID(ctx context.Context, exec executor.Executor) Identity {
	template, _ := IdentityTemplate(exec)
	serial := ""
	if template == "" || strings.Contains(strings.ToLower(template), TokenSerial) {
		serial = SerialNumber(ctx, exec)
	}
	hostname := getHostname(ctx, exec, exec.GOOS())
	return ResolveIdentity(exec, serial, hostname, getDeveloperIdentity(exec))
}

// IdentityUserScope returns the per-user state scope for this run: the
// sanitized {user} token when the identity template contains it and the
// current user is a real developer, else "". It probes nothing (no serial, no
// hostname) so main can call it before any state path is touched.
func IdentityUserScope(exec executor.Executor) string {
	template, _ := IdentityTemplate(exec)
	if !strings.Contains(strings.ToLower(template), TokenUser) {
		return ""
	}
	return SanitizeDeviceID(userToken(exec.GOOS(), exec.IsRoot(), getDeveloperIdentity(exec)))
}
