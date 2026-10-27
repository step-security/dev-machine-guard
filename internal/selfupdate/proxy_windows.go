//go:build windows

package selfupdate

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modwinhttp                              = windows.NewLazySystemDLL("winhttp.dll")
	procWinHttpGetDefaultProxyConfiguration = modwinhttp.NewProc("WinHttpGetDefaultProxyConfiguration")
	procGlobalFree                          = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
)

const winhttpAccessTypeNamedProxy = 3

// winhttpProxyInfo is WINHTTP_PROXY_INFO.
type winhttpProxyInfo struct {
	accessType  uint32
	proxy       *uint16
	proxyBypass *uint16
}

// loadMachineProxy reads the WinHTTP default proxy (netsh winhttp set proxy).
func loadMachineProxy() *machineProxy {
	if procWinHttpGetDefaultProxyConfiguration.Find() != nil {
		return nil
	}
	var info winhttpProxyInfo
	r, _, _ := procWinHttpGetDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&info)))
	defer func() {
		for _, p := range []*uint16{info.proxy, info.proxyBypass} {
			if p != nil {
				_, _, _ = procGlobalFree.Call(uintptr(unsafe.Pointer(p)))
			}
		}
	}()
	if r == 0 || info.accessType != winhttpAccessTypeNamedProxy || info.proxy == nil {
		return nil
	}
	return parseWinHTTPProxy(windows.UTF16PtrToString(info.proxy), windows.UTF16PtrToString(info.proxyBypass))
}
