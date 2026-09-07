//go:build !windows

package device

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// This file is the exec-based (reg.exe) counterpart to the native registry
// probes in wsl_windows.go. On a real non-Windows OS GatherWSL returns before
// reaching here; it exists so mock-based tests can simulate Windows via
// SetGOOS("windows"), matching the device_other.go / registry_other.go pattern
// (AGENTS.md §2.5). It reads only HKCU (a single simulated user) rather than
// enumerating every HKU hive — sufficient for the simulated inputs.

var regValueLine = regexp.MustCompile(`^(\S.*?)\s{2,}(REG_\w+)\s{2,}(.*)$`)

// regSection is one key block from `reg query ... /s` output.
type regSection struct {
	path   string
	values map[string]string
}

// parseRegRecursive splits `reg query <key> /s` output into per-key sections.
// A non-indented line is a key path; indented `NAME    TYPE    DATA` lines are
// its values (DATA may contain single spaces, e.g. "Windows Subsystem for Linux").
func parseRegRecursive(out string) []regSection {
	var sections []regSection
	var cur *regSection
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			sections = append(sections, regSection{path: strings.TrimSpace(line), values: map[string]string{}})
			cur = &sections[len(sections)-1]
			continue
		}
		if cur == nil {
			continue
		}
		if m := regValueLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			cur.values[m[1]] = strings.TrimSpace(m[3])
		}
	}
	return sections
}

func wslRegistryInventory(exec executor.Executor) ([]model.WSLDistro, bool) {
	stdout, _, _, err := exec.Run(context.Background(), "reg", "query", `HKCU\`+lxssUserSubpath, "/s")
	if err != nil {
		return nil, false // reg.exe couldn't run — inconclusive
	}
	sections := parseRegRecursive(decodeWinCLI(stdout))

	var defaultGUID string
	for _, s := range sections {
		if strings.EqualFold(s.path, `HKEY_CURRENT_USER\`+lxssUserSubpath) {
			defaultGUID = s.values["DefaultDistribution"]
		}
	}

	var distros []model.WSLDistro
	prefix := strings.ToLower(`HKEY_CURRENT_USER\` + lxssUserSubpath + `\`)
	for _, s := range sections {
		lower := strings.ToLower(s.path)
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		guid := s.path[len(prefix):]
		if strings.Contains(guid, `\`) { // only direct children (the distro GUIDs)
			continue
		}
		name := s.values["DistributionName"]
		if name == "" {
			continue
		}
		distros = append(distros, model.WSLDistro{
			Name:       name,
			DistroID:   guid,
			WSLVersion: wslVersionFromFlags(parseRegDWORD(s.values["Flags"])),
			Default:    guid == defaultGUID,
			BasePath:   s.values["BasePath"],
			DefaultUID: parseRegDWORDOpt(s.values["DefaultUid"]),
		})
	}
	sortDistros(distros)
	return distros, true
}

func wslServiceInstalled(exec executor.Executor) (bool, bool) {
	ok := false
	for _, svc := range wslServiceNames {
		_, _, code, err := exec.Run(context.Background(), "reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services\`+svc)
		if err != nil {
			continue // couldn't run reg for this one
		}
		ok = true
		if code == 0 {
			return true, true
		}
	}
	return false, ok
}

func wslPackageVersion(_ context.Context, exec executor.Executor) string {
	for _, root := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		stdout, _, _, err := exec.Run(context.Background(), "reg", "query", root, "/s")
		if err != nil {
			continue
		}
		for _, s := range parseRegRecursive(decodeWinCLI(stdout)) {
			if strings.EqualFold(strings.TrimSpace(s.values["DisplayName"]), "Windows Subsystem for Linux") {
				if v := strings.TrimSpace(s.values["DisplayVersion"]); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// wslServiceRunning has no exec-based counterpart worth having: `sc query` would
// be exactly the subprocess the gate exists to avoid. Off Windows it reports
// "unknown", which makes the caller behave as it did before the gate and still
// run the probe.
func wslServiceRunning(_ executor.Executor) (bool, bool) { return false, false }

// parseRegDWORDOpt is parseRegDWORD for values whose absence must stay
// distinguishable from zero — DefaultUid 0 means root, not "unreadable".
func parseRegDWORDOpt(s string) *uint32 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	raw := strings.TrimSpace(s)
	base, digits := 10, raw
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		base, digits = 16, raw[2:]
	}
	v, err := strconv.ParseUint(digits, base, 32)
	if err != nil {
		return nil
	}
	u := uint32(v)
	return &u
}

// parseRegDWORD reads a reg.exe REG_DWORD literal ("0x7") to a uint64. 0 on error.
func parseRegDWORD(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if v, err := strconv.ParseUint(s[2:], 16, 64); err == nil {
			return v
		}
		return 0
	}
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		return v
	}
	return 0
}
