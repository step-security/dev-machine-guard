//go:build !windows

package authenticode

func verifyTrusted(string) (*trustedSigner, error) { return nil, ErrUnsupported }
