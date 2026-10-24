//go:build !windows

package detector

import (
	"context"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// regValueRe matches a `reg query` value line: name, type, data separated by
// four spaces (names may contain single spaces).
var regValueRe = regexp.MustCompile(`^\s+(.+?)\s{4}(REG_\w+)(?:\s{4}(.*))?$`)

// readARPEntries is the non-Windows twin of the native reader: it parses
// `reg query <root> /s`. Only mock-based tests running with
// SetGOOS("windows") reach it.
func readARPEntries(ctx context.Context, exec executor.Executor) []arpEntry {
	var out []arpEntry
	for _, src := range []struct{ root, hive, view string }{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "HKLM", "64"},
		{`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "HKLM", "32"},
		{`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "HKCU", ""},
	} {
		stdout, _, _, err := exec.Run(ctx, "reg", "query", src.root, "/s")
		if err != nil {
			continue
		}
		out = append(out, parseRegQueryARP(stdout, src.hive, src.view)...)
	}
	return out
}

func parseRegQueryARP(stdout, hive, view string) []arpEntry {
	var out []arpEntry
	var cur *arpEntry
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "HKEY_") {
			flush()
			name := line[strings.LastIndex(line, `\`)+1:]
			cur = &arpEntry{KeyName: strings.TrimSpace(name), Hive: hive, View: view}
			continue
		}
		m := regValueRe.FindStringSubmatch(line)
		if m == nil || cur == nil {
			continue
		}
		name, typ, data := m[1], m[2], strings.TrimSpace(m[3])
		dword := func() uint64 {
			v, _ := strconv.ParseUint(strings.TrimPrefix(data, "0x"), 16, 64)
			return v
		}
		switch name {
		case "DisplayName":
			cur.DisplayName = data
		case "DisplayVersion":
			cur.DisplayVersion = data
		case "Publisher":
			cur.Publisher = data
		case "InstallLocation":
			cur.InstallLocation = data
		case "InstallDate":
			cur.InstallDate = data
		case "URLInfoAbout":
			cur.URLInfoAbout = data
		case "ParentKeyName":
			cur.ParentKeyName = data
		case "ReleaseType":
			cur.ReleaseType = data
		case "SystemComponent":
			cur.SystemComponent = typ == "REG_DWORD" && dword() == 1
		case "WindowsInstaller":
			cur.WindowsInstaller = typ == "REG_DWORD" && dword() == 1
		case "EstimatedSize":
			if v := dword(); typ == "REG_DWORD" && v <= math.MaxUint32 {
				cur.EstimatedSizeKB = uint32(v)
			}
		}
	}
	flush()
	// The root key itself carries no values; drop it.
	filtered := out[:0]
	for _, e := range out {
		if !strings.EqualFold(e.KeyName, "Uninstall") {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
