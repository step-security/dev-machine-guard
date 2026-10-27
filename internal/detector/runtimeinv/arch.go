package runtimeinv

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
)

// binaryArch reads the CPU architecture from the executable header (headers
// only; the binary is never run). Returns "" when the format is unknown.
func binaryArch(path string) string {
	if f, err := pe.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		switch f.Machine {
		case pe.IMAGE_FILE_MACHINE_AMD64:
			return "amd64"
		case pe.IMAGE_FILE_MACHINE_ARM64:
			return "arm64"
		case pe.IMAGE_FILE_MACHINE_I386:
			return "386"
		}
		return ""
	}
	if f, err := elf.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		switch f.Machine {
		case elf.EM_X86_64:
			return "amd64"
		case elf.EM_AARCH64:
			return "arm64"
		case elf.EM_386:
			return "386"
		}
		return ""
	}
	if f, err := macho.OpenFat(path); err == nil {
		_ = f.Close()
		return "universal"
	}
	if f, err := macho.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		switch f.Cpu {
		case macho.CpuAmd64:
			return "amd64"
		case macho.CpuArm64:
			return "arm64"
		}
	}
	return ""
}
