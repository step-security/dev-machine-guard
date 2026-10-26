package device

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Virtualization detection: is this machine a VM, and on whose hypervisor?
//
// Evidence, in order of trust: the cloud instance metadata service (only
// probed when SMBIOS/DMI already names that cloud's hypervisor family, so a
// physical machine never makes a network call), the SMBIOS/DMI manufacturer
// and product strings, the macOS hv_vmm_present sysctl, systemd-detect-virt,
// and the cpuinfo hypervisor flag. The CPUID hypervisor bit is deliberately
// NOT used on Windows: a physical PC with Hyper-V or Virtualization-Based
// Security enabled sets it too.

// Vendor labels (model.Virtualization.Vendor).
const (
	VirtVendorAzure      = "azure"
	VirtVendorAWS        = "aws"
	VirtVendorGCP        = "gcp"
	VirtVendorHyperV     = "hyperv"
	VirtVendorVMware     = "vmware"
	VirtVendorKVM        = "kvm"
	VirtVendorQEMU       = "qemu"
	VirtVendorXen        = "xen"
	VirtVendorParallels  = "parallels"
	VirtVendorVirtualBox = "virtualbox"
	VirtVendorApple      = "apple"
	VirtVendorOther      = "other"
)

// Evidence sources (model.Virtualization.Source).
const (
	VirtSourceIMDS    = "imds"
	VirtSourceSMBIOS  = "smbios"
	VirtSourceDMI     = "dmi"
	VirtSourceSysctl  = "sysctl"
	VirtSourceCPUInfo = "cpuinfo"
	VirtSourceSystemd = "systemd"
)

const (
	virtProbeTimeout = 5 * time.Second
	imdsTimeout      = 2 * time.Second
)

// smbiosInfo is what the firmware says about the machine.
type smbiosInfo struct {
	Manufacturer string
	Product      string
	BIOSVendor   string
}

var (
	virtOnce   sync.Once
	virtCached *model.Virtualization
)

// DetectVirtualization classifies the machine once per process (the answer
// cannot change while the agent runs) on its own bounded context, so a
// caller's expiring ctx can never poison the cache. Gather calls it.
func DetectVirtualization(_ context.Context, exec executor.Executor) *model.Virtualization {
	virtOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), virtProbeTimeout)
		defer cancel()
		virtCached = detectVirtualization(ctx, exec)
	})
	return virtCached
}

// ResetVirtualizationCache drops the memoized answer. For tests.
func ResetVirtualizationCache() {
	virtOnce = sync.Once{}
	virtCached = nil
}

// detectVirtualization is the unmemoized probe.
func detectVirtualization(ctx context.Context, exec executor.Executor) *model.Virtualization {
	var v *model.Virtualization
	switch exec.GOOS() {
	case model.PlatformWindows:
		v = classifySMBIOS(windowsSMBIOS(ctx, exec), VirtSourceSMBIOS)
	case model.PlatformDarwin:
		v = detectDarwin(ctx, exec)
	default:
		v = detectLinux(ctx, exec)
	}
	applyIMDS(ctx, v)
	return v
}

// classifySMBIOS turns firmware strings into a classification. Empty strings
// everywhere mean the source could not be read: unknown, not physical.
func classifySMBIOS(info smbiosInfo, source string) *model.Virtualization {
	if strings.TrimSpace(info.Manufacturer+info.Product+info.BIOSVendor) == "" {
		return &model.Virtualization{Type: model.VirtualizationUnknown, Source: source}
	}
	if vendor := vendorFromStrings(info.Manufacturer, info.Product, info.BIOSVendor); vendor != "" {
		return &model.Virtualization{Type: model.VirtualizationVirtual, Vendor: vendor, Source: source}
	}
	return &model.Virtualization{Type: model.VirtualizationPhysical, Source: source}
}

// vendorFromStrings maps manufacturer/product style strings to a vendor label,
// or "" when none of them names a hypervisor.
func vendorFromStrings(fields ...string) string {
	joined := strings.ToLower(strings.Join(fields, " | "))
	has := func(s string) bool { return strings.Contains(joined, s) }
	switch {
	case has("microsoft corporation") && has("virtual machine"):
		return VirtVendorHyperV
	case has("vmware"):
		return VirtVendorVMware
	case has("amazon ec2") || has("amazon"):
		return VirtVendorAWS
	case has("xen") || has("hvm domu"):
		return VirtVendorXen
	case has("innotek") || has("virtualbox"):
		return VirtVendorVirtualBox
	case has("parallels"):
		return VirtVendorParallels
	case has("qemu"):
		return VirtVendorQEMU
	case has("kvm") || has("red hat") || has("redhat"):
		return VirtVendorKVM
	case has("google"):
		return VirtVendorGCP
	case has("virtualmac") || has("apple virtual"):
		return VirtVendorApple
	case has("hyper-v"):
		return VirtVendorHyperV
	case has("nutanix") || has("bochs") || has("openstack") || has("virtual"):
		return VirtVendorOther
	}
	return ""
}

// detectDarwin uses the kernel's own answer: kern.hv_vmm_present is 1 inside
// any Virtualization.framework, VMware or Parallels guest.
func detectDarwin(ctx context.Context, exec executor.Executor) *model.Virtualization {
	out, _, _, err := exec.RunWithTimeout(ctx, imdsTimeout, "sysctl", "-n", "kern.hv_vmm_present")
	if err != nil {
		return &model.Virtualization{Type: model.VirtualizationUnknown, Source: VirtSourceSysctl}
	}
	if strings.TrimSpace(out) != "1" {
		return &model.Virtualization{Type: model.VirtualizationPhysical, Source: VirtSourceSysctl}
	}
	vendor := VirtVendorOther
	if m, _, _, err := exec.RunWithTimeout(ctx, imdsTimeout, "sysctl", "-n", "hw.model"); err == nil {
		switch v := vendorFromStrings(m); v {
		case VirtVendorApple, VirtVendorVMware, VirtVendorParallels:
			vendor = v
		}
	}
	return &model.Virtualization{Type: model.VirtualizationVirtual, Vendor: vendor, Source: VirtSourceSysctl}
}

// detectLinux prefers systemd-detect-virt (--vm: hypervisors only, never
// containers), then DMI, then the cpuinfo hypervisor flag.
func detectLinux(ctx context.Context, exec executor.Executor) *model.Virtualization {
	if _, err := exec.LookPath("systemd-detect-virt"); err == nil {
		out, _, _, err := exec.RunWithTimeout(ctx, imdsTimeout, "systemd-detect-virt", "--vm")
		if err == nil || strings.TrimSpace(out) != "" {
			switch kind := strings.ToLower(strings.TrimSpace(out)); kind {
			case "none":
				return &model.Virtualization{Type: model.VirtualizationPhysical, Source: VirtSourceSystemd}
			case "":
			default:
				return &model.Virtualization{Type: model.VirtualizationVirtual, Vendor: systemdVendor(kind), Source: VirtSourceSystemd}
			}
		}
	}
	vendorData, verr := exec.ReadFile("/sys/class/dmi/id/sys_vendor")
	productData, perr := exec.ReadFile("/sys/class/dmi/id/product_name")
	if verr == nil || perr == nil {
		return classifySMBIOS(smbiosInfo{Manufacturer: string(vendorData), Product: string(productData)}, VirtSourceDMI)
	}
	if cpuinfo, err := exec.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(" "+strings.ToLower(string(cpuinfo))+" ", " hypervisor ") {
			return &model.Virtualization{Type: model.VirtualizationVirtual, Vendor: VirtVendorOther, Source: VirtSourceCPUInfo}
		}
		return &model.Virtualization{Type: model.VirtualizationPhysical, Source: VirtSourceCPUInfo}
	}
	return &model.Virtualization{Type: model.VirtualizationUnknown}
}

// systemdVendor maps systemd-detect-virt's ids to vendor labels.
func systemdVendor(kind string) string {
	switch kind {
	case "kvm":
		return VirtVendorKVM
	case "qemu":
		return VirtVendorQEMU
	case "vmware":
		return VirtVendorVMware
	case "microsoft":
		return VirtVendorHyperV
	case "xen":
		return VirtVendorXen
	case "oracle":
		return VirtVendorVirtualBox
	case "parallels":
		return VirtVendorParallels
	case "amazon":
		return VirtVendorAWS
	case "google":
		return VirtVendorGCP
	case "apple":
		return VirtVendorApple
	}
	return VirtVendorOther
}

// applyIMDS upgrades a hypervisor-family answer to the cloud that runs it by
// asking that cloud's instance metadata service. Only families that can be a
// cloud are probed, and only on a virtual verdict, so a physical machine never
// touches the link-local address.
func applyIMDS(ctx context.Context, v *model.Virtualization) {
	if v == nil || v.Type != model.VirtualizationVirtual {
		return
	}
	switch v.Vendor {
	case VirtVendorHyperV:
		if imdsProbe(ctx, VirtVendorAzure) {
			v.Vendor, v.Source = VirtVendorAzure, VirtSourceIMDS
		}
	case VirtVendorXen, VirtVendorAWS:
		if imdsProbe(ctx, VirtVendorAWS) {
			v.Vendor, v.Source = VirtVendorAWS, VirtSourceIMDS
		}
	case VirtVendorGCP:
		if imdsProbe(ctx, VirtVendorGCP) {
			v.Source = VirtSourceIMDS
		}
	}
}

// imdsProbe asks the named cloud's metadata service whether this is one of
// its instances. A var so tests never reach the network.
var imdsProbe = probeIMDS

func probeIMDS(ctx context.Context, cloud string) bool {
	ctx, cancel := context.WithTimeout(ctx, imdsTimeout)
	defer cancel()
	client := &http.Client{Timeout: imdsTimeout}
	get := func(method, url string, headers map[string]string) (string, bool) {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return "", false
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", false
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode != http.StatusOK {
			return "", false
		}
		return strings.TrimSpace(string(body)), true
	}
	switch cloud {
	case VirtVendorAzure:
		id, ok := get(http.MethodGet, "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text",
			map[string]string{"Metadata": "true"})
		return ok && id != ""
	case VirtVendorAWS:
		token, ok := get(http.MethodPut, "http://169.254.169.254/latest/api/token",
			map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"})
		if !ok || token == "" {
			return false
		}
		id, ok := get(http.MethodGet, "http://169.254.169.254/latest/meta-data/instance-id",
			map[string]string{"X-aws-ec2-metadata-token": token})
		return ok && id != ""
	case VirtVendorGCP:
		id, ok := get(http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/id",
			map[string]string{"Metadata-Flavor": "Google"})
		return ok && id != ""
	}
	return false
}

// FormatVirtualization renders a classification for logs and the pretty
// output: "virtual (azure, imds)" / "physical" / "unknown".
func FormatVirtualization(v *model.Virtualization) string {
	if v == nil {
		return ""
	}
	if v.Type != model.VirtualizationVirtual {
		return v.Type
	}
	parts := []string{}
	if v.Vendor != "" {
		parts = append(parts, v.Vendor)
	}
	if v.Source != "" {
		parts = append(parts, v.Source)
	}
	if len(parts) == 0 {
		return v.Type
	}
	return v.Type + " (" + strings.Join(parts, ", ") + ")"
}
