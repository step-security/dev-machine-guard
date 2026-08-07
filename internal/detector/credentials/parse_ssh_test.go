package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// sshString renders one length-prefixed field of the OpenSSH key format.
func sshString(value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(out[:4], uint32(len(value)))
	copy(out[4:], value)
	return out
}

// opensshKey builds a key file in the current OpenSSH format. bodyPad grows the
// encoded body past the header so a capped read can be exercised.
func opensshKey(cipher, kdf, algorithm string, bodyPad int) []byte {
	blob := []byte(opensshMagic)
	blob = append(blob, sshString([]byte(cipher))...)
	blob = append(blob, sshString([]byte(kdf))...)
	blob = append(blob, sshString(nil)...) // derivation options

	keyCount := make([]byte, 4)
	binary.BigEndian.PutUint32(keyCount, 1)
	blob = append(blob, keyCount...)

	pub := sshString([]byte(algorithm))
	pub = append(pub, sshString(bytes.Repeat([]byte{'p'}, 32))...)
	blob = append(blob, sshString(pub)...)

	if bodyPad > 0 {
		blob = append(blob, bytes.Repeat([]byte{'k'}, bodyPad)...)
	}
	return pemWrap(opensshBegin, "-----END OPENSSH PRIVATE KEY-----", blob)
}

// pemWrap wraps a body at 70 characters, which is what the key generator does and
// is not a multiple of four — the property the header decoder has to survive.
func pemWrap(begin, end string, blob []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(blob)
	var b bytes.Buffer
	b.WriteString(begin)
	b.WriteString("\n")
	for len(encoded) > 70 {
		b.WriteString(encoded[:70])
		b.WriteString("\n")
		encoded = encoded[70:]
	}
	b.WriteString(encoded)
	b.WriteString("\n")
	b.WriteString(end)
	b.WriteString("\n")
	return b.Bytes()
}

func TestClassifySSHKey(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		want  string
		isKey bool
	}{
		{name: "current format with no passphrase", data: opensshKey("none", "none", "ssh-ed25519", 0), want: model.CredentialProtectionPlaintext, isKey: true},
		// The test is whether a derivation function is set, not which cipher is
		// named: cipher defaults change between releases.
		{name: "current format with a passphrase", data: opensshKey("aes256-ctr", "bcrypt", "ssh-ed25519", 0), want: model.CredentialProtectionProtected, isKey: true},
		{name: "unfamiliar cipher with a derivation function is still protected", data: opensshKey("some-future-cipher", "bcrypt", "ssh-ed25519", 0), want: model.CredentialProtectionProtected, isKey: true},
		// A hardware-backed key stores a handle rather than the secret and has no
		// passphrase to derive from, so reading the algorithm first is what keeps
		// the safest key a developer can own from reading as an unprotected one.
		{name: "hardware-backed key with no derivation function", data: opensshKey("none", "none", "sk-ssh-ed25519@openssh.com", 0), want: model.CredentialProtectionProtected, isKey: true},
		{name: "hardware-backed key of the other algorithm", data: opensshKey("none", "none", "sk-ecdsa-sha2-nistp256@openssh.com", 0), want: model.CredentialProtectionProtected, isKey: true},
		{name: "encrypted pkcs8", data: []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\ndmFsdWU=\n-----END ENCRYPTED PRIVATE KEY-----\n"), want: model.CredentialProtectionProtected, isKey: true},
		{name: "plain pkcs8", data: []byte("-----BEGIN PRIVATE KEY-----\ndmFsdWU=\n-----END PRIVATE KEY-----\n"), want: model.CredentialProtectionPlaintext, isKey: true},
		// The legacy format marks encryption with a header rather than a different
		// begin line.
		{name: "legacy format with a passphrase", data: []byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\ndmFsdWU=\n-----END RSA PRIVATE KEY-----\n"), want: model.CredentialProtectionProtected, isKey: true},
		{name: "legacy format without a passphrase", data: []byte("-----BEGIN RSA PRIVATE KEY-----\ndmFsdWU=\n-----END RSA PRIVATE KEY-----\n"), want: model.CredentialProtectionPlaintext, isKey: true},
		{name: "legacy elliptic-curve format", data: []byte("-----BEGIN EC PRIVATE KEY-----\ndmFsdWU=\n-----END EC PRIVATE KEY-----\n"), want: model.CredentialProtectionPlaintext, isKey: true},
		{name: "putty format without a passphrase", data: []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: octocat\n"), want: model.CredentialProtectionPlaintext, isKey: true},
		{name: "putty format with a passphrase", data: []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: octocat\n"), want: model.CredentialProtectionProtected, isKey: true},
		// The field is mandatory in that format, so a file without it was
		// truncated or is malformed and nothing has been established.
		{name: "putty format missing the mandatory field", data: []byte("PuTTY-User-Key-File-3: ssh-ed25519\nComment: octocat\n"), want: model.CredentialProtectionUnknown, isKey: true},
		// The file announced itself as a private key, so absence of evidence is
		// inconclusive rather than safe.
		{name: "current format with an undecodable body", data: []byte(opensshBegin + "\nnot base64 at all !!!\n"), want: model.CredentialProtectionUnknown, isKey: true},
		{name: "current format with a header cut short", data: pemWrap(opensshBegin, "-----END OPENSSH PRIVATE KEY-----", []byte(opensshMagic)), want: model.CredentialProtectionUnknown, isKey: true},
		{name: "current format with the wrong magic", data: pemWrap(opensshBegin, "-----END OPENSSH PRIVATE KEY-----", []byte("not-a-key-v1\x00padding-to-decode")), want: model.CredentialProtectionUnknown, isKey: true},
		{name: "public half is not a private key", data: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample octocat@example.com\n"), isKey: false},
		{name: "certificate is not a private key", data: []byte("-----BEGIN CERTIFICATE-----\ndmFsdWU=\n-----END CERTIFICATE-----\n"), isKey: false},
		{name: "known hosts content is not a private key", data: []byte("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample\n"), isKey: false},
		{name: "empty file", data: nil, isKey: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, isKey := classifySSHKey(tt.data)
			if isKey != tt.isKey {
				t.Fatalf("isKey = %v, want %v", isKey, tt.isKey)
			}
			if got != tt.want {
				t.Errorf("protection = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClassifySSHKey_CappedReadStillClassifies is the regression the base64
// truncation exists for. The read stops at the header cap and the generator wraps at
// a width that is not a multiple of four, so without truncating to the last whole
// group every real key would decode to nothing and report as unclassified.
func TestClassifySSHKey_CappedReadStillClassifies(t *testing.T) {
	full := opensshKey("none", "none", "ssh-ed25519", 4096)
	if int64(len(full)) <= capKeyHeader {
		t.Fatalf("key of %d bytes does not exceed the cap; the test proves nothing", len(full))
	}
	capped := full[:capKeyHeader]

	// The body arriving mid-group is the whole point of the case.
	body := extractPEMBody(string(capped), opensshBegin)
	if len(body)%4 == 0 {
		t.Fatalf("capped body of %d characters is already whole groups; the test proves nothing", len(body))
	}

	got, isKey := classifySSHKey(capped)
	if !isKey {
		t.Fatal("a capped read must still be recognised as a private key")
	}
	if got != model.CredentialProtectionPlaintext {
		t.Errorf("protection = %q, want %q", got, model.CredentialProtectionPlaintext)
	}
}

// TestClassifySSHKey_ReadsOnlyTheHeader holds the reason the cap is a kilobyte: the
// fields that decide protection are near the front, so the body stays off the heap.
func TestClassifySSHKey_ReadsOnlyTheHeader(t *testing.T) {
	full := opensshKey("aes256-ctr", "bcrypt", "ssh-ed25519", 8192)
	head := full[:capKeyHeader]
	got, isKey := classifySSHKey(head)
	if !isKey || got != model.CredentialProtectionProtected {
		t.Errorf("classify(head) = %q/%v, want %q/true", got, isKey, model.CredentialProtectionProtected)
	}
}

func TestLooksLikeKeyFile(t *testing.T) {
	tests := map[string]bool{
		"id_ed25519":             true,
		"id_rsa":                 true,
		"work_key":               true,
		"id_ecdsa_sk":            true,
		"id_rsa.pub":             false,
		"id_ed25519.pub":         false,
		"id_ed25519-cert.pub":    false,
		"server.crt":             false,
		"client.cer":             false,
		"request.csr":            false,
		"config":                 false,
		"known_hosts":            false,
		"known_hosts2":           false,
		"authorized_keys":        false,
		"authorized_keys2":       false,
		"allowed_signers":        false,
		"environment":            false,
		"rc":                     false,
		".DS_Store":              false,
		".ssh-agent-environment": false,
	}
	for name, want := range tests {
		if got := looksLikeKeyFile(name); got != want {
			t.Errorf("looksLikeKeyFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestExtractPEMBody_StopsAtTheClosingLine(t *testing.T) {
	text := "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\ntrailing junk\n"
	if got := extractPEMBody(text, opensshBegin); got != "AAAABBBB" {
		t.Errorf("body = %q, want %q", got, "AAAABBBB")
	}
	if got := extractPEMBody("no header here", opensshBegin); got != "" {
		t.Errorf("body = %q, want empty", got)
	}
}

func TestReadSSHString_BoundedByWhatRemains(t *testing.T) {
	value, rest, ok := readSSHString(append(sshString([]byte("abc")), 'x'))
	if !ok || string(value) != "abc" || string(rest) != "x" {
		t.Errorf("read = %q/%q/%v, want %q/%q/true", value, rest, ok, "abc", "x")
	}
	// A length longer than the buffer must fail rather than drive an allocation.
	oversized := []byte{0xff, 0xff, 0xff, 0xff, 'a'}
	if _, _, ok := readSSHString(oversized); ok {
		t.Error("a length past the end of the buffer must not be read")
	}
	if _, _, ok := readSSHString([]byte{0, 0}); ok {
		t.Error("a buffer too short for the length prefix must not be read")
	}
}

func TestClassifyPuTTYKey_IgnoresTrailingWhitespace(t *testing.T) {
	text := "PuTTY-User-Key-File-3: ssh-ed25519\r\nEncryption: none\r\n"
	if got := classifyPuTTYKey(text); got != model.CredentialProtectionPlaintext {
		t.Errorf("protection = %q, want %q", got, model.CredentialProtectionPlaintext)
	}
	if !strings.Contains(text, puttyEncrypted) {
		t.Fatal("the fixture must carry the field this reads")
	}
}
