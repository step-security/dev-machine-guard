package device

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func stubIMDS(t *testing.T, answer map[string]bool) *[]string {
	t.Helper()
	var asked []string
	prev := imdsProbe
	imdsProbe = func(_ context.Context, cloud string) bool {
		asked = append(asked, cloud)
		return answer[cloud]
	}
	t.Cleanup(func() { imdsProbe = prev })
	return &asked
}

func TestVendorFromStrings(t *testing.T) {
	tests := []struct{ name, manufacturer, product, want string }{
		{"hyper-v generic", "Microsoft Corporation", "Virtual Machine", VirtVendorHyperV},
		{"vmware", "VMware, Inc.", "VMware Virtual Platform", VirtVendorVMware},
		{"ec2 nitro", "Amazon EC2", "t3.large", VirtVendorAWS},
		{"xen hvm", "Xen", "HVM domU", VirtVendorXen},
		{"virtualbox", "innotek GmbH", "VirtualBox", VirtVendorVirtualBox},
		{"parallels", "Parallels Software International Inc.", "Parallels Virtual Platform", VirtVendorParallels},
		{"qemu", "QEMU", "Standard PC (Q35 + ICH9, 2009)", VirtVendorQEMU},
		{"kvm red hat", "Red Hat", "KVM", VirtVendorKVM},
		{"gce", "Google", "Google Compute Engine", VirtVendorGCP},
		{"nutanix", "Nutanix", "AHV", VirtVendorOther},
		{"dell laptop", "Dell Inc.", "XPS 15 9530", ""},
		{"lenovo", "LENOVO", "20XW004LUS", ""},
		{"mac", "Apple Inc.", "MacBookPro18,3", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := vendorFromStrings(tc.manufacturer, tc.product); got != tc.want {
				t.Errorf("vendorFromStrings(%q, %q) = %q, want %q", tc.manufacturer, tc.product, got, tc.want)
			}
		})
	}
}

func TestClassifySMBIOS(t *testing.T) {
	if v := classifySMBIOS(smbiosInfo{}, VirtSourceSMBIOS); v.Type != model.VirtualizationUnknown {
		t.Errorf("no strings must be unknown, got %+v", v)
	}
	if v := classifySMBIOS(smbiosInfo{Manufacturer: "Dell Inc.", Product: "Latitude"}, VirtSourceSMBIOS); v.Type != model.VirtualizationPhysical || v.Vendor != "" {
		t.Errorf("laptop must be physical, got %+v", v)
	}
	if v := classifySMBIOS(smbiosInfo{Manufacturer: "VMware, Inc."}, VirtSourceDMI); v.Type != model.VirtualizationVirtual || v.Vendor != VirtVendorVMware || v.Source != VirtSourceDMI {
		t.Errorf("vmware must be virtual via dmi, got %+v", v)
	}
}

func TestDetectVirtualization_WindowsAzureViaIMDS(t *testing.T) {
	asked := stubIMDS(t, map[string]bool{VirtVendorAzure: true})
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetCommand("Microsoft Corporation\n", "", 0, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Manufacturer")
	mock.SetCommand("Virtual Machine\n", "", 0, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Model")
	v := detectVirtualization(context.Background(), mock)
	if v.Type != model.VirtualizationVirtual || v.Vendor != VirtVendorAzure || v.Source != VirtSourceIMDS {
		t.Fatalf("got %+v", v)
	}
	if len(*asked) != 1 || (*asked)[0] != VirtVendorAzure {
		t.Errorf("only the azure probe must run, got %v", *asked)
	}
}

func TestDetectVirtualization_WindowsHyperVWithoutIMDS(t *testing.T) {
	stubIMDS(t, nil)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetCommand("Microsoft Corporation", "", 0, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Manufacturer")
	mock.SetCommand("Virtual Machine", "", 0, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Model")
	v := detectVirtualization(context.Background(), mock)
	if v.Type != model.VirtualizationVirtual || v.Vendor != VirtVendorHyperV || v.Source != VirtSourceSMBIOS {
		t.Fatalf("got %+v", v)
	}
}

func TestDetectVirtualization_WindowsPhysicalNeverProbes(t *testing.T) {
	asked := stubIMDS(t, map[string]bool{VirtVendorAzure: true, VirtVendorAWS: true})
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	mock.SetCommand("Dell Inc.", "", 0, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Manufacturer")
	mock.SetCommand("XPS 15 9530", "", 0, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Model")
	v := detectVirtualization(context.Background(), mock)
	if v.Type != model.VirtualizationPhysical || v.Vendor != "" {
		t.Fatalf("got %+v", v)
	}
	if len(*asked) != 0 {
		t.Errorf("a physical machine must never call a metadata service, got %v", *asked)
	}
}

func TestDetectVirtualization_Darwin(t *testing.T) {
	stubIMDS(t, nil)
	tests := []struct {
		name, present, hwModel string
		wantType, wantVendor   string
	}{
		{"physical mac", "0", "MacBookPro18,3", model.VirtualizationPhysical, ""},
		{"apple virtualization", "1", "VirtualMac2,1", model.VirtualizationVirtual, VirtVendorApple},
		{"vmware fusion", "1", "VMware7,1", model.VirtualizationVirtual, VirtVendorVMware},
		{"parallels", "1", "Parallels Virtual Platform", model.VirtualizationVirtual, VirtVendorParallels},
		{"unknown hypervisor", "1", "Mystery1,1", model.VirtualizationVirtual, VirtVendorOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.SetGOOS(model.PlatformDarwin)
			mock.SetCommand(tc.present+"\n", "", 0, "sysctl", "-n", "kern.hv_vmm_present")
			mock.SetCommand(tc.hwModel+"\n", "", 0, "sysctl", "-n", "hw.model")
			v := detectVirtualization(context.Background(), mock)
			if v.Type != tc.wantType || v.Vendor != tc.wantVendor || v.Source != VirtSourceSysctl {
				t.Errorf("got %+v, want %s/%s/sysctl", v, tc.wantType, tc.wantVendor)
			}
		})
	}
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformDarwin)
	if v := detectVirtualization(context.Background(), mock); v.Type != model.VirtualizationUnknown {
		t.Errorf("sysctl failure must be unknown, got %+v", v)
	}
}

func TestDetectVirtualization_Linux(t *testing.T) {
	t.Run("systemd-detect-virt kvm then aws probe", func(t *testing.T) {
		asked := stubIMDS(t, map[string]bool{VirtVendorAWS: true})
		mock := executor.NewMock()
		mock.SetGOOS(model.PlatformLinux)
		mock.SetPath("systemd-detect-virt", "/usr/bin/systemd-detect-virt")
		mock.SetCommand("amazon\n", "", 0, "systemd-detect-virt", "--vm")
		v := detectVirtualization(context.Background(), mock)
		if v.Type != model.VirtualizationVirtual || v.Vendor != VirtVendorAWS || v.Source != VirtSourceIMDS {
			t.Fatalf("got %+v", v)
		}
		if len(*asked) != 1 {
			t.Errorf("asked = %v", *asked)
		}
	})
	t.Run("systemd-detect-virt none", func(t *testing.T) {
		stubIMDS(t, nil)
		mock := executor.NewMock()
		mock.SetGOOS(model.PlatformLinux)
		mock.SetPath("systemd-detect-virt", "/usr/bin/systemd-detect-virt")
		mock.SetCommand("none\n", "", 1, "systemd-detect-virt", "--vm")
		if v := detectVirtualization(context.Background(), mock); v.Type != model.VirtualizationPhysical || v.Source != VirtSourceSystemd {
			t.Fatalf("got %+v", v)
		}
	})
	t.Run("dmi fallback", func(t *testing.T) {
		stubIMDS(t, nil)
		mock := executor.NewMock()
		mock.SetGOOS(model.PlatformLinux)
		mock.SetFile("/sys/class/dmi/id/sys_vendor", []byte("QEMU\n"))
		mock.SetFile("/sys/class/dmi/id/product_name", []byte("Standard PC (i440FX + PIIX, 1996)\n"))
		if v := detectVirtualization(context.Background(), mock); v.Type != model.VirtualizationVirtual || v.Vendor != VirtVendorQEMU || v.Source != VirtSourceDMI {
			t.Fatalf("got %+v", v)
		}
	})
	t.Run("cpuinfo fallback", func(t *testing.T) {
		stubIMDS(t, nil)
		mock := executor.NewMock()
		mock.SetGOOS(model.PlatformLinux)
		mock.SetFile("/proc/cpuinfo", []byte("flags\t\t: fpu vme hypervisor sse\n"))
		if v := detectVirtualization(context.Background(), mock); v.Type != model.VirtualizationVirtual || v.Source != VirtSourceCPUInfo {
			t.Fatalf("got %+v", v)
		}
		plain := executor.NewMock()
		plain.SetGOOS(model.PlatformLinux)
		plain.SetFile("/proc/cpuinfo", []byte("flags\t\t: fpu vme sse\n"))
		if v := detectVirtualization(context.Background(), plain); v.Type != model.VirtualizationPhysical {
			t.Fatalf("got %+v", v)
		}
	})
	t.Run("nothing readable", func(t *testing.T) {
		stubIMDS(t, nil)
		mock := executor.NewMock()
		mock.SetGOOS(model.PlatformLinux)
		if v := detectVirtualization(context.Background(), mock); v.Type != model.VirtualizationUnknown {
			t.Fatalf("got %+v", v)
		}
	})
}

func TestDetectVirtualization_MemoizedAndGatherAttaches(t *testing.T) {
	stubIMDS(t, nil)
	ResetVirtualizationCache()
	t.Cleanup(ResetVirtualizationCache)
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformDarwin)
	mock.SetCommand("1\n", "", 0, "sysctl", "-n", "kern.hv_vmm_present")
	mock.SetCommand("VirtualMac2,1\n", "", 0, "sysctl", "-n", "hw.model")
	first := DetectVirtualization(context.Background(), mock)
	mock.SetCommand("0\n", "", 0, "sysctl", "-n", "kern.hv_vmm_present")
	if second := DetectVirtualization(context.Background(), mock); second != first {
		t.Error("DetectVirtualization must memoize per process")
	}
	if first.Vendor != VirtVendorApple {
		t.Errorf("got %+v", first)
	}
}

func TestFormatVirtualization(t *testing.T) {
	tests := []struct {
		name string
		v    *model.Virtualization
		want string
	}{
		{"nil", nil, ""},
		{"physical", &model.Virtualization{Type: model.VirtualizationPhysical, Source: VirtSourceSMBIOS}, "physical"},
		{"virtual with vendor and source", &model.Virtualization{Type: model.VirtualizationVirtual, Vendor: VirtVendorAzure, Source: VirtSourceIMDS}, "virtual (azure, imds)"},
		{"virtual bare", &model.Virtualization{Type: model.VirtualizationVirtual}, "virtual"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatVirtualization(tc.v); got != tc.want {
				t.Errorf("FormatVirtualization = %q, want %q", got, tc.want)
			}
		})
	}
}
