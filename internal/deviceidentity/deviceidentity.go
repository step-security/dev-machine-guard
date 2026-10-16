// Package deviceidentity verifies custom IDs before any device-scoped work.
package deviceidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
)

func usableSerial(serial string) bool {
	serial = strings.ToLower(strings.TrimSpace(serial))
	switch serial {
	case "", "unknown", "none", "default string", "system serial number", "not specified", "not applicable", "to be filled by o.e.m.":
		return false
	}
	return strings.Trim(serial, "0- ") != ""
}

func ownerID(serial string) (string, error) {
	serial = strings.TrimSpace(serial)
	source := "serial:" + serial
	if !usableSerial(serial) {
		source = "fallback:" + uuid.NewString()
	}
	sum := sha256.Sum256([]byte(source))
	return persistedOwnerID(hex.EncodeToString(sum[:]))
}

// Keep ownership in local bootstrap state, independent of a shared config or
// relocated install directory. Never silently regenerate a damaged identity.
func persistedOwnerID(candidate string) (string, error) {
	path := config.DeviceIdentityFilePath()
	read := func() (string, error) {
		data, err := os.ReadFile(path) // #nosec G304 -- fixed machine-local bootstrap identity path; no remote input.
		if err != nil {
			return "", err
		}
		id := strings.TrimSpace(string(data))
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != sha256.Size {
			return "", fmt.Errorf("invalid device owner identity in %s", path)
		}
		return id, nil
	}
	if id, err := read(); !errors.Is(err, os.ErrNotExist) {
		return id, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	id := candidate
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G304 -- fixed machine-local bootstrap identity path; exclusive creation prevents replacement.
	if errors.Is(err, os.ErrExist) {
		return read()
	}
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(id + "\n")
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return id, nil
}

// Verify fails closed on collisions, offline backends and older backends which
// cannot verify ownership. Ordinary machine-derived IDs do not call this path.
func Verify(ctx context.Context, endpoint, apiKey, customer, deviceID, serial string) (string, error) {
	owner, err := ownerID(serial)
	if err != nil {
		return "", fmt.Errorf("resolving custom device ID ownership: %w", err)
	}
	if !usableSerial(serial) {
		serial = "unknown"
	}
	body, err := json.Marshal(map[string]any{"device_id": deviceID, "identity_check": true, "machine_id": owner, "serial_number": serial})
	if err != nil {
		return "", err
	}
	target := strings.TrimRight(endpoint, "/") + "/v1/" + url.PathEscape(customer) + "/developer-mdm-agent/telemetry/upload-url"
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Version", buildinfo.Version)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", errors.New("cannot verify custom device ID ownership; check backend connectivity and retry")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("custom device_id %q is already assigned to a different machine; choose another device_id", deviceID)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("custom device ID verification failed (HTTP %d); retry after resolving the backend error", resp.StatusCode)
	}
	var result struct {
		DeviceID string `json:"device_id"`
		Verified bool   `json:"device_identity_verified"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return "", errors.New("invalid device identity verification response")
	}
	if !result.Verified || result.DeviceID != deviceID {
		return "", errors.New("backend does not support custom device ID collision protection; upgrade the backend before using device_id")
	}
	return owner, nil
}
