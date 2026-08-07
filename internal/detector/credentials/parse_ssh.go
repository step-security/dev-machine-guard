package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// SSH key file markers. Classification reads the header and stops, which is why the
// read cap for this source is a kilobyte rather than a megabyte.
//
// The cap bounds the exposure; it does not exclude the key body. A key file smaller
// than the cap is read whole, and a modern one is: an unencrypted ed25519 key is
// around four hundred bytes. The guarantee this source holds to is the one every
// other parser here holds to — no byte of what was read is serialised, logged,
// fingerprinted, counted or retained past the classification, and only the header
// fields are ever examined.
const (
	opensshBegin   = "-----BEGIN OPENSSH PRIVATE KEY-----"
	pkcs8Begin     = "-----BEGIN PRIVATE KEY-----"
	pkcs8EncBegin  = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
	legacyKeyMark  = " PRIVATE KEY-----"
	opensshMagic   = "openssh-key-v1\x00"
	puttyHeader    = "PuTTY-User-Key-File-"
	puttyEncrypted = "Encryption:"
)

// sshSkipSuffixes are the files that live beside private keys and are not
// private keys. Reporting a public half or a certificate as a credential would
// tell a developer their published key is exposed.
var sshSkipSuffixes = []string{".pub", ".cer", ".crt", ".csr"}

// sshSkipNames are the configuration and bookkeeping files kept in the same
// directory.
var sshSkipNames = map[string]bool{
	"config":           true,
	"known_hosts":      true,
	"known_hosts2":     true,
	"authorized_keys":  true,
	"authorized_keys2": true,
	"allowed_signers":  true,
	"environment":      true,
	"rc":               true,
}

// looksLikeKeyFile keeps the directory listing from opening files that are
// obviously not keys. A file it admits is still classified from its contents,
// and a file it rejects is never read.
func looksLikeKeyFile(name string) bool {
	if sshSkipNames[name] {
		return false
	}
	lower := strings.ToLower(name)
	for _, suffix := range sshSkipSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return !strings.HasPrefix(name, ".")
}

// classifySSHKey decides whether a file is a private key and, if so, what guards
// it. The second return is false for anything that is not a private key.
//
// The formats differ in where the answer lives. The current OpenSSH format states
// its key-derivation function in a binary header, and the test is whether that
// function is set rather than which cipher is named: cipher defaults change between
// releases while the derivation function is stable. A key held in a hardware
// authenticator is that same format with no derivation function, since there is no
// passphrase to derive from — reading the public-key algorithm first is what keeps
// the safest key a developer can own from reading as an unprotected one. The legacy
// and PKCS#8 formats state it in text, in two different ways.
func classifySSHKey(data []byte) (string, bool) {
	text := string(data)

	switch {
	case strings.Contains(text, opensshBegin):
		return classifyOpenSSHKey(data), true
	case strings.Contains(text, pkcs8EncBegin):
		return model.CredentialProtectionProtected, true
	case strings.Contains(text, pkcs8Begin):
		return model.CredentialProtectionPlaintext, true
	case strings.Contains(text, puttyHeader):
		return classifyPuTTYKey(text), true
	case strings.Contains(text, legacyKeyMark) && strings.Contains(text, "-----BEGIN "):
		return classifyLegacyPEMKey(text), true
	}
	return "", false
}

// classifyOpenSSHKey reads the binary header of the current OpenSSH format. An
// undecodable or truncated header resolves to unknown and to nothing else: the file
// announced itself as a private key, so absence of evidence is not safety.
func classifyOpenSSHKey(data []byte) string {
	blob, ok := decodeOpenSSHHeader(data)
	if !ok {
		return model.CredentialProtectionUnknown
	}
	if !bytes.HasPrefix(blob, []byte(opensshMagic)) {
		return model.CredentialProtectionUnknown
	}
	rest := blob[len(opensshMagic):]

	// The cipher name is read past rather than used: which cipher a release
	// defaults to changes, so matching on it dates the parser.
	_, rest, ok = readSSHString(rest)
	if !ok {
		return model.CredentialProtectionUnknown
	}
	kdf, rest, ok := readSSHString(rest)
	if !ok {
		return model.CredentialProtectionUnknown
	}
	// Skip the derivation options and the key count to reach the public key.
	_, rest, ok = readSSHString(rest)
	if !ok {
		return model.CredentialProtectionUnknown
	}
	if len(rest) < 4 {
		return model.CredentialProtectionUnknown
	}
	pub, _, ok := readSSHString(rest[4:])
	if !ok {
		return model.CredentialProtectionUnknown
	}
	algorithm, _, ok := readSSHString(pub)
	if !ok {
		return model.CredentialProtectionUnknown
	}

	// A hardware-backed key holds a handle rather than the secret, so it is
	// protected whether or not a local passphrase also guards the handle.
	if strings.HasPrefix(string(algorithm), "sk-") {
		return model.CredentialProtectionProtected
	}
	switch name := string(kdf); name {
	case "none":
		return model.CredentialProtectionPlaintext
	case "":
		// The field is mandatory, so an empty one means the header did not parse
		// the way it announced itself.
		return model.CredentialProtectionUnknown
	default:
		return model.CredentialProtectionProtected
	}
}

// decodeOpenSSHHeader decodes the base64 body far enough to reach the header fields.
// The generator wraps at 70 characters, not a multiple of four, so truncating to the
// last whole group is what makes a truncated read decode at all.
//
// For a file smaller than the read cap this decodes the whole body, private section
// included. Only the header fields are then read, and the blob is not retained.
func decodeOpenSSHHeader(data []byte) ([]byte, bool) {
	body := extractPEMBody(string(data), opensshBegin)
	if body == "" {
		return nil, false
	}
	body = body[:len(body)-len(body)%4]
	if body == "" {
		return nil, false
	}
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, false
	}
	return blob, true
}

// extractPEMBody joins the base64 lines that follow a header line, stopping at
// the closing line or at the end of what was read. The read is capped, so the
// closing line is often absent and its absence is not an error.
func extractPEMBody(text, header string) string {
	i := strings.Index(text, header)
	if i < 0 {
		return ""
	}
	var body strings.Builder
	for line := range strings.SplitSeq(text[i+len(header):], "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "-----") {
			break
		}
		body.WriteString(trimmed)
	}
	return body.String()
}

// readSSHString reads one length-prefixed field. The length is bounded by what
// remains, so a corrupt or truncated header cannot drive an allocation or read
// past the buffer.
func readSSHString(b []byte) (value, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	// Compared as int64, which both a uint32 length and a slice length widen into
	// without wrapping, so the bound holds for any header the file can carry.
	n := binary.BigEndian.Uint32(b[:4])
	if int64(n) > int64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// classifyLegacyPEMKey reads the text headers of the legacy format, where an
// encrypted key is marked by a procedure-type header rather than by a different
// begin line.
func classifyLegacyPEMKey(text string) string {
	head := text
	if i := strings.Index(text, "-----BEGIN "); i >= 0 {
		head = text[i:]
	}
	if strings.Contains(head, "Proc-Type:") && strings.Contains(head, "ENCRYPTED") {
		return model.CredentialProtectionProtected
	}
	if strings.Contains(head, "DEK-Info:") {
		return model.CredentialProtectionProtected
	}
	return model.CredentialProtectionPlaintext
}

// classifyPuTTYKey reads the encryption field of the PuTTY format, which states
// it in the clear near the top of the file.
func classifyPuTTYKey(text string) string {
	for line := range strings.SplitSeq(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, puttyEncrypted) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, puttyEncrypted))
		if value == "" || strings.EqualFold(value, "none") {
			return model.CredentialProtectionPlaintext
		}
		return model.CredentialProtectionProtected
	}
	// The field is mandatory in this format, so a file without it was truncated or
	// is malformed, and nothing has been established about what guards it.
	return model.CredentialProtectionUnknown
}
