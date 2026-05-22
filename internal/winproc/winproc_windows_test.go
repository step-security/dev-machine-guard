//go:build windows

package winproc

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestHideWindow_SetsAttrs(t *testing.T) {
	cmd := exec.Command("cmd.exe")
	HideWindow(cmd)

	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr was not allocated")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Error("HideWindow flag not set")
	}
	if cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Errorf("CREATE_NO_WINDOW not OR'd into CreationFlags (got 0x%x)", cmd.SysProcAttr.CreationFlags)
	}
}

// Pre-existing SysProcAttr fields must survive — we OR our flag in
// rather than replacing the struct.
func TestHideWindow_MergesExistingAttrs(t *testing.T) {
	const otherFlag uint32 = 0x00000200 // CREATE_NEW_PROCESS_GROUP
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: otherFlag,
		Token:         42,
	}

	HideWindow(cmd)

	if cmd.SysProcAttr.CreationFlags&otherFlag == 0 {
		t.Error("pre-existing CreationFlags bit was clobbered")
	}
	if cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Error("CREATE_NO_WINDOW not OR'd in")
	}
	if cmd.SysProcAttr.Token != 42 {
		t.Errorf("Token field clobbered (want 42, got %d)", cmd.SysProcAttr.Token)
	}
}

// Repeat invocations should be idempotent.
func TestHideWindow_Idempotent(t *testing.T) {
	cmd := exec.Command("cmd.exe")
	HideWindow(cmd)
	flags1 := cmd.SysProcAttr.CreationFlags
	HideWindow(cmd)
	if cmd.SysProcAttr.CreationFlags != flags1 {
		t.Errorf("second call mutated CreationFlags (0x%x -> 0x%x)", flags1, cmd.SysProcAttr.CreationFlags)
	}
}
