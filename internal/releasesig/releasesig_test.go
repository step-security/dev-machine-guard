package releasesig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The v1.17.0 linux_amd64 signature as published on the GitHub release,
// checked against the pinned production key. If this fails, the agent would
// refuse every real download.
func TestVerifyChecksum_RealRelease(t *testing.T) {
	sum := string(readFixture(t, "real-1.17.0-linux_amd64.sha256"))
	sig := readFixture(t, "real-1.17.0-linux_amd64.sha256.sig")

	if err := VerifyChecksum(sum, sig); err != nil {
		t.Fatalf("real release signature rejected: %v", err)
	}
	if err := VerifyChecksum(strings.ToUpper(sum)+"\n", sig); err != nil {
		t.Errorf("checksum case/whitespace should not matter: %v", err)
	}

	tampered := []byte(sum)
	tampered[0] ^= 1
	if err := VerifyChecksum(string(tampered), sig); err == nil {
		t.Error("tampered checksum accepted")
	}
}

func TestVerify_TestKey(t *testing.T) {
	testKey := strings.TrimSpace(string(readFixture(t, "test-key.pub")))
	msg := []byte("abc123")

	cases := []struct {
		name    string
		key     string
		ns      string
		msg     []byte
		sig     string
		wantErr string
	}{
		{name: "valid base64 form", key: testKey, ns: Namespace, msg: msg, sig: "test-abc123.sig"},
		{name: "valid armored form", key: testKey, ns: Namespace, msg: msg, sig: "test-abc123-armored.sig"},
		{name: "wrong message", key: testKey, ns: Namespace, msg: []byte("abc124"), sig: "test-abc123.sig", wantErr: "does not match"},
		{name: "wrong namespace", key: testKey, ns: Namespace, msg: msg, sig: "test-abc123-other-ns.sig", wantErr: "namespace"},
		{name: "release key rejects test signature", key: PublicKey, ns: Namespace, msg: msg, sig: "test-abc123.sig", wantErr: "unexpected key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(tc.key, tc.ns, tc.msg, readFixture(t, tc.sig))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestVerify_Malformed(t *testing.T) {
	for name, sig := range map[string][]byte{
		"empty":        nil,
		"not base64":   []byte("%%%"),
		"not armored":  []byte("aGVsbG8="),
		"wrong block":  []byte("-----BEGIN FOO-----\naGVsbG8=\n-----END FOO-----\n"),
		"short blob":   []byte("-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n"),
		"bad magic":    []byte("-----BEGIN SSH SIGNATURE-----\nQUFBQUFBAAAAAQ==\n-----END SSH SIGNATURE-----\n"),
		"huge length":  []byte("-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAf////8=\n-----END SSH SIGNATURE-----\n"),
		"zero version": []byte("-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAA==\n-----END SSH SIGNATURE-----\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyChecksum("abc", sig); err == nil {
				t.Fatal("malformed signature accepted")
			}
		})
	}
}
