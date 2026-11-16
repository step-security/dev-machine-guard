package schtasks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// reconcileExec answers the schtasks calls ReconcileTaskSettings makes: the
// existence queries, the XML queries (the imported XML once a task was
// re-imported) and the re-imports, whose XML it records per task.
func reconcileExec(t *testing.T, registered bool) (*scriptedExec, map[string]string) {
	t.Helper()
	imported := map[string]string{}
	ex := &scriptedExec{Mock: executor.NewMock(), fn: func(args []string) (string, int) {
		switch {
		case args[0] == "/query" && len(args) == 3:
			if registered {
				return "", 0
			}
			return "", 1
		case args[0] == "/query" && len(args) == 4 && args[3] == "/xml":
			if xml, ok := imported[args[2]]; ok {
				return string(encodeTaskXMLUTF16(xml)), 0
			}
			return string(encodeTaskXMLUTF16(defaultTaskXML)), 0
		case args[0] == "/create" && len(args) >= 5:
			b, err := os.ReadFile(args[4])
			if err != nil {
				t.Fatalf("reading imported XML: %v", err)
			}
			imported[args[2]] = decodeTaskXML(string(b))
			return "", 0
		}
		return "", 1
	}}
	return ex, imported
}

// withSharedHost makes the mock a Windows host whose sticky marker says it
// scans every signed-in session separately.
func withSharedHost(t *testing.T, ex *scriptedExec) {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(device.SetMachineStateDirForTest(dir))
	ex.SetGOOS("windows")
	if err := os.WriteFile(filepath.Join(dir, "multi-user.json"), []byte(`{"since":1,"reason":"edition"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileTaskSettings_AppliesParallelOnceHostScansPerSession(t *testing.T) {
	ex, imported := reconcileExec(t, true)
	withSharedHost(t, ex)

	perSession, registered := ReconcileTaskSettings(ex, newTestLogger(), 4*time.Hour)
	if !perSession || !registered {
		t.Fatalf("perSession=%v registered=%v, want true/true", perSession, registered)
	}
	for _, name := range []string{taskName, logonTaskName} {
		xml, ok := imported[name]
		if !ok {
			t.Fatalf("task %q was not re-imported; imported: %v", name, imported)
		}
		if !strings.Contains(xml, "<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>") {
			t.Errorf("task %q re-imported without the Parallel policy:\n%s", name, xml)
		}
	}
}

func TestReconcileTaskSettings_SingleUserHostKeepsIgnoreNew(t *testing.T) {
	ex, imported := reconcileExec(t, true)
	t.Cleanup(device.SetMachineStateDirForTest(t.TempDir()))
	ex.SetGOOS("windows")

	perSession, registered := ReconcileTaskSettings(ex, newTestLogger(), 4*time.Hour)
	if perSession || !registered {
		t.Fatalf("perSession=%v registered=%v, want false/true", perSession, registered)
	}
	for name, xml := range imported {
		if strings.Contains(xml, "Parallel") {
			t.Errorf("task %q got the Parallel policy under a shared identity:\n%s", name, xml)
		}
	}
}

func TestReconcileTaskSettings_NoTaskIsNoop(t *testing.T) {
	ex, imported := reconcileExec(t, false)
	withSharedHost(t, ex)

	perSession, registered := ReconcileTaskSettings(ex, newTestLogger(), 4*time.Hour)
	if perSession || registered {
		t.Fatalf("perSession=%v registered=%v, want false/false", perSession, registered)
	}
	if len(imported) != 0 {
		t.Errorf("re-imported %v although no task is registered", imported)
	}
}
