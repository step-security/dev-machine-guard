//go:build windows

package updatestate

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Restart Manager reports which processes hold files open.
var (
	rstrtmgr                = windows.NewLazySystemDLL("rstrtmgr.dll")
	procRmStartSession      = rstrtmgr.NewProc("RmStartSession")
	procRmRegisterResources = rstrtmgr.NewProc("RmRegisterResources")
	procRmGetList           = rstrtmgr.NewProc("RmGetList")
	procRmEndSession        = rstrtmgr.NewProc("RmEndSession")
)

const (
	rmSessionKeyLen = 32
	rmMaxAppName    = 255
	rmMaxSvcName    = 63
	maxHolders      = 8
)

type rmUniqueProcess struct {
	ProcessID        uint32
	ProcessStartTime windows.Filetime
}

type rmProcessInfo struct {
	Process          rmUniqueProcess
	AppName          [rmMaxAppName + 1]uint16
	ServiceShortName [rmMaxSvcName + 1]uint16
	ApplicationType  uint32
	AppStatus        uint32
	TSSessionID      uint32
	Restartable      int32
}

// fileHolders returns "<image> pid <n> (<name>)" for each process holding
// one of paths open, or nil when none is found or Restart Manager fails.
func fileHolders(paths []string) []string {
	if len(paths) == 0 || procRmStartSession.Find() != nil {
		return nil
	}
	var session uint32
	var key [rmSessionKeyLen + 1]uint16
	if r, _, _ := procRmStartSession.Call(uintptr(unsafe.Pointer(&session)), 0, uintptr(unsafe.Pointer(&key[0]))); r != 0 {
		return nil
	}
	defer func() { _, _, _ = procRmEndSession.Call(uintptr(session)) }()

	names := make([]*uint16, 0, len(paths))
	for _, p := range paths {
		if u, err := windows.UTF16PtrFromString(p); err == nil {
			names = append(names, u)
		}
	}
	if len(names) == 0 {
		return nil
	}
	if r, _, _ := procRmRegisterResources.Call(uintptr(session), uintptr(len(names)), uintptr(unsafe.Pointer(&names[0])), 0, 0, 0, 0); r != 0 {
		return nil
	}
	var infos []rmProcessInfo
	for range 3 { // the list can grow between calls
		var needed, n uint32
		var reasons uint32
		var first *rmProcessInfo
		if len(infos) > 0 {
			n = uint32(len(infos)) // #nosec G115 -- small
			first = &infos[0]
		}
		r, _, _ := procRmGetList.Call(uintptr(session), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(first)), uintptr(unsafe.Pointer(&reasons)))
		if r == 0 {
			infos = infos[:n]
			break
		}
		if windows.Errno(r) != windows.ERROR_MORE_DATA {
			return nil
		}
		infos = make([]rmProcessInfo, needed)
	}
	var out []string
	for _, pi := range infos {
		if len(out) == maxHolders {
			out = append(out, fmt.Sprintf("and %d more", len(infos)-maxHolders))
			break
		}
		pid := pi.Process.ProcessID
		name := windows.UTF16ToString(pi.AppName[:])
		image := processImage(pid)
		switch {
		case image != "" && name != "" && name != image:
			out = append(out, fmt.Sprintf("%s pid %d (%s)", image, pid, name))
		case image != "":
			out = append(out, fmt.Sprintf("%s pid %d", image, pid))
		default:
			out = append(out, fmt.Sprintf("%s pid %d", name, pid))
		}
	}
	return out
}

// processImage is the base name of pid's executable, "" if unreadable.
func processImage(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer func() { _ = windows.CloseHandle(h) }()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return filepath.Base(windows.UTF16ToString(buf[:n]))
}
