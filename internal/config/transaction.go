package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/identity"
)

// explicitIdentities validates identity keys without losing merge semantics or
// unknown config fields. Device validation applies only to explicit imports;
// existing configured device IDs remain readable for compatibility. A
// bootstrap file (bootstrapFile) keeps v1.18.1's reading of device_id: an
// empty value clears the override, null leaves it as it is.
func explicitIdentities(data []byte, includeDevice, bootstrapFile bool) (map[string]string, error) {
	fields := map[string]string{}
	d := json.NewDecoder(strings.NewReader(string(data)))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("configuration must be a JSON object")
	}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		kind := ""
		if strings.EqualFold(key.(string), "user_id") {
			kind = "user"
		}
		if includeDevice && strings.EqualFold(key.(string), "device_id") {
			kind = "device"
		}
		if kind == "" {
			continue
		}
		if _, exists := fields[kind]; exists {
			return nil, fmt.Errorf("duplicate %s_id", kind)
		}
		if string(value) == "null" {
			if kind == "device" && bootstrapFile {
				continue
			}
			return nil, fmt.Errorf("%s_id must be a non-empty string", kind)
		}
		var raw string
		if err := json.Unmarshal(value, &raw); err != nil {
			return nil, err
		}
		// A device id may also be a template the agent expands per scan, or
		// "-" to clear the override; a user id is always a literal.
		var id string
		if kind == "device" && bootstrapFile && strings.TrimSpace(raw) == "" {
			id = ""
		} else if kind == "device" {
			id, err = identity.NormalizeDevice(raw)
		} else {
			id, err = identity.Normalize(raw, kind)
		}
		if err != nil {
			return nil, err
		}
		fields[kind] = id
	}
	return fields, nil
}

// readExistingStrict retains upstream's ErrConfigInvalid sentinel.
func readExistingStrict() (*ConfigFile, error) { return readExisting() }

// Kernel-backed locks survive no process: closing/crashing releases them. The
// lock file is intentionally retained; deleting it could split the lock domain.
func lockConfig() (func(), error) {
	if fileOverride != "" {
		return nil, fmt.Errorf("--config is read-only; configure cannot write through an overridden config")
	}
	dir := writeConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// #nosec G304 -- fixed lock basename under the resolved config directory, never an identity-derived path.
	f, err := os.OpenFile(filepath.Join(dir, "config.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if prev, err := os.Stat(WriteConfigFilePath()); err == nil {
		preserveOwner(f.Name(), prev)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		locked, err := tryConfigLock(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if locked {
			break
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("configuration is busy; retry configure")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Refuse writes into a config hidden by an authoritative scope. Also catches
	// migration from an existing user config under an elevated Windows process.
	if ConfigFilePath() != WriteConfigFilePath() {
		if _, err := os.Stat(ConfigFilePath()); !errors.Is(err, os.ErrNotExist) {
			_ = f.Close()
			return nil, fmt.Errorf("configuration read/write scopes differ; run configure in the context that owns %s", ConfigFilePath())
		}
	}
	return func() { _ = f.Close() }, nil
}

// writeAtomic commits a complete file; the old config remains intact if writing,
// syncing or replacing fails. Callers hold the configuration transaction lock.
type atomicConfigFile interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

func writeAtomic(path string, data []byte, mode os.FileMode, machine bool) error {
	return writeAtomicFile(path, data, mode, machine, func(dir string) (atomicConfigFile, error) {
		return os.CreateTemp(dir, ".config-*")
	})
}

func writeAtomicFile(path string, data []byte, mode os.FileMode, machine bool, create func(string) (atomicConfigFile, error)) error {
	f, err := create(filepath.Dir(path))
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if prev, err := os.Stat(path); err == nil {
		preserveOwner(tmp, prev)
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if n, err := f.Write(data); err != nil {
		return err
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if machine {
		if err := hardenMachineConfigACL(tmp); err != nil {
			return err
		}
	}
	return replaceConfig(tmp, path)
}
