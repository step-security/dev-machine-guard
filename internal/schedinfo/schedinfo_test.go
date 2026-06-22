package schedinfo

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestParsePlist(t *testing.T) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.stepsecurity.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/stepsecurity-dev-machine-guard</string>
        <string>send-telemetry</string>
        <string>--scheduled</string>
    </array>
    <key>StartInterval</key>
    <integer>14400</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>/Users/dev</string>
    </dict>
</dict>
</plist>`
	pl, err := parsePlist([]byte(plist))
	if err != nil {
		t.Fatalf("parsePlist: %v", err)
	}
	if pl.StartInterval != 14400 {
		t.Errorf("StartInterval = %d, want 14400", pl.StartInterval)
	}
	if !pl.RunAtLoad {
		t.Error("RunAtLoad = false, want true")
	}
	if len(pl.ProgramArguments) != 3 ||
		pl.ProgramArguments[1] != "send-telemetry" ||
		pl.ProgramArguments[2] != "--scheduled" {
		t.Errorf("ProgramArguments = %v", pl.ProgramArguments)
	}
}

func TestParsePlist_RunAtLoadFalse(t *testing.T) {
	plist := `<plist version="1.0"><dict>
	<key>RunAtLoad</key><false/>
	<key>StartInterval</key><integer>3600</integer>
	</dict></plist>`
	pl, err := parsePlist([]byte(plist))
	if err != nil {
		t.Fatal(err)
	}
	if pl.RunAtLoad {
		t.Error("RunAtLoad should be false")
	}
	if pl.StartInterval != 3600 {
		t.Errorf("StartInterval = %d, want 3600", pl.StartInterval)
	}
}

func TestParsePlist_Garbage(t *testing.T) {
	// Malformed XML returns an error (the caller records it as a warning and
	// carries on) — it must not panic.
	if _, err := parsePlist([]byte("<plist><dict><key>oops")); err == nil {
		t.Error("expected an error for truncated plist")
	}
}

func TestApplyLaunchctlPrint(t *testing.T) {
	out := `com.stepsecurity.agent = {
	active count = 0
	state = waiting
	pid = 4321
	program = /usr/local/bin/stepsecurity-dev-machine-guard
	last exit code = 2
}`
	var info Info
	applyLaunchctlPrint(&info, out)
	if info.State != "waiting" {
		t.Errorf("State = %q, want waiting", info.State)
	}
	if info.PID == nil || *info.PID != 4321 {
		t.Errorf("PID = %v, want 4321", info.PID)
	}
	if info.LastExitCode == nil || *info.LastExitCode != 2 {
		t.Errorf("LastExitCode = %v, want 2", info.LastExitCode)
	}
}

func TestApplyLaunchctlList(t *testing.T) {
	out := `{
	"LastExitStatus" = 0;
	"PID" = 999;
	"Label" = "com.stepsecurity.agent";
};`
	var info Info
	applyLaunchctlList(&info, out)
	if info.LastExitCode == nil || *info.LastExitCode != 0 {
		t.Errorf("LastExitCode = %v, want 0", info.LastExitCode)
	}
	if info.PID == nil || *info.PID != 999 {
		t.Errorf("PID = %v, want 999", info.PID)
	}
}

func TestApplySchtasksList(t *testing.T) {
	out := `Folder: \
HostName:                             DESKTOP
TaskName:                             \StepSecurity Dev Machine Guard
Next Run Time:                        6/22/2026 4:00:00 PM
Status:                               Ready
Last Run Time:                        6/22/2026 12:00:00 PM
Last Result:                          0
Task To Run:                          "C:\Program Files\StepSecurity\stepsecurity-dev-machine-guard-task.exe" send-telemetry --scheduled
Number of Missed Runs:                3
Schedule Type:                        Hourly`
	var info Info
	applySchtasksList(&info, out)
	if info.LastRunTime != "6/22/2026 12:00:00 PM" {
		t.Errorf("LastRunTime = %q", info.LastRunTime)
	}
	if info.NextRunTime != "6/22/2026 4:00:00 PM" {
		t.Errorf("NextRunTime = %q", info.NextRunTime)
	}
	if info.State != "Ready" {
		t.Errorf("State = %q, want Ready", info.State)
	}
	if info.LastExitCode == nil || *info.LastExitCode != 0 {
		t.Errorf("LastExitCode = %v, want 0", info.LastExitCode)
	}
	if info.MissedRuns == nil || *info.MissedRuns != 3 {
		t.Errorf("MissedRuns = %v, want 3", info.MissedRuns)
	}
	if info.Management != ManagementBinary {
		t.Errorf("Management = %v, want binary", info.Management)
	}
}

func TestManagementFromCmd(t *testing.T) {
	cases := []struct {
		cmd  string
		want Management
	}{
		{"/bin/bash /Users/x/.stepsecurity/bin/stepsecurity-loader.sh send-telemetry --scheduled", ManagementLoader},
		{`"C:\Program Files\StepSecurity\stepsecurity-dev-machine-guard-task.exe" send-telemetry --scheduled`, ManagementBinary},
		{"/usr/local/bin/stepsecurity-dev-machine-guard send-telemetry", ManagementBinary},
		{"/opt/something/else --flag", ManagementUnknown},
	}
	for _, c := range cases {
		if got := managementFromCmd(c.cmd); got != c.want {
			t.Errorf("managementFromCmd(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

func TestScanColonField_ExactMatch(t *testing.T) {
	out := "Run Time: nope\nLast Run Time: yes\n"
	// "Last Run Time" must not be satisfied by the substring "Run Time".
	if v, ok := scanColonField(out, "Last Run Time"); !ok || v != "yes" {
		t.Errorf(`scanColonField("Last Run Time") = %q,%v; want "yes",true`, v, ok)
	}
}

// Log must tolerate both a fully-populated and a zero-value Info without panicking.
func TestLog_NoPanic(t *testing.T) {
	log := progress.NewLogger(progress.LevelDebug)
	pid, code, missed := 5, 0, 1
	ral := true
	Log(Info{
		Platform: "darwin", Manager: "launchd", Scheduled: true, Loaded: true,
		Management: ManagementBinary, IntervalSeconds: 14400, ConfiguredHours: 4,
		RunAtLoad: &ral, LastRunTime: "now", NextRunTime: "later",
		LastExitCode: &code, MissedRuns: &missed, PID: &pid, State: "waiting",
		UnitPath: "/x.plist", Raw: "raw output", Warnings: []string{"w1"},
	}, log)
	Log(Info{}, log)
}
