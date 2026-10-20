package systemd

import (
	"strings"
	"testing"
	"text/template"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// TestStartTimer_IssuesPlainStart asserts the timer-activation command does
// not carry --now (which would be redundant for `start`) and targets the
// expected unit name. Deliberately separate from Install so the install-time
// race fix (issue #62) — enable without --now, then StartTimer after the
// inline scan — stays locked in.
func TestStartTimer_IssuesPlainStart(t *testing.T) {
	mock := executor.NewMock()
	mock.SetCommand("", "", 0, "systemctl", "--user", "start", unitName+".timer")

	if err := StartTimer(mock, progress.NewLogger(progress.LevelInfo)); err != nil {
		t.Fatalf("StartTimer returned error: %v", err)
	}
}

// TestStartTimer_PropagatesFailure asserts the function surfaces a non-zero
// systemctl exit so the install command can warn the operator.
func TestStartTimer_PropagatesFailure(t *testing.T) {
	mock := executor.NewMock()
	mock.SetCommand("", "Failed to start: Unit not found", 1,
		"systemctl", "--user", "start", unitName+".timer")

	err := StartTimer(mock, progress.NewLogger(progress.LevelInfo))
	if err == nil {
		t.Fatal("expected error from non-zero systemctl exit, got nil")
	}
	if !strings.Contains(err.Error(), "exit code 1") {
		t.Errorf("error should reference the exit code: %v", err)
	}
}

// TestSystemdEnvEscape covers every escape the helper claims to handle.
// A raw newline is the load-bearing case: without escaping it would
// terminate the Environment= directive mid-value and let trailing
// content parse as a new top-level unit-file line.
func TestSystemdEnvEscape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain path no-op", "/opt/stepsecurity", "/opt/stepsecurity"},
		{"backslash doubled", `C:\Step\Security`, `C:\\Step\\Security`},
		{"double quote escaped", `/opt/"weird"/dir`, `/opt/\"weird\"/dir`},
		{"newline escaped", "/opt/a\nINJECTED=1", `/opt/a\nINJECTED=1`},
		{"carriage return escaped", "/opt/a\rb", `/opt/a\rb`},
		{"tab escaped", "/opt/a\tb", `/opt/a\tb`},
		// Order matters: the backslash-first pass means \n in input
		// (literal two-char sequence) becomes \\n, not \n.
		{"literal backslash-n stays literal", `/opt/a\nb`, `/opt/a\\nb`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := systemdEnvEscape(tc.in); got != tc.want {
				t.Errorf("systemdEnvEscape(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestOnCalendarFor(t *testing.T) {
	cases := map[int]string{
		0:    "*-*-* *:00:00",
		1:    "*-*-* *:00:00",
		4:    "*-*-* 00/4:00:00",
		5:    "*-*-* 00/5:00:00",
		12:   "*-*-* 00/12:00:00",
		23:   "*-*-* 00/23:00:00",
		24:   "*-*-* 00:00:00",
		36:   "*-*-* 00:00:00",
		48:   "*-*-01/2 00:00:00",
		168:  "*-*-01/7 00:00:00",
		9999: "*-*-01/31 00:00:00",
	}
	for hours, want := range cases {
		if got := onCalendarFor(hours); got != want {
			t.Errorf("onCalendarFor(%d) = %q, want %q", hours, got, want)
		}
	}
}

// TestTimerTemplate_Golden locks the generated timer: realtime OnCalendar
// (Persistent=true is a no-op on monotonic timers) and no monotonic triggers.
func TestTimerTemplate_Golden(t *testing.T) {
	tmpl := template.Must(template.New("unit").Parse(timerTmpl))
	var sb strings.Builder
	if err := tmpl.Execute(&sb, unitTemplateData{OnCalendar: onCalendarFor(4)}); err != nil {
		t.Fatal(err)
	}
	want := `[Unit]
Description=StepSecurity Dev Machine Guard periodic scan

[Timer]
OnBootSec=5min
OnCalendar=*-*-* 00/4:00:00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
`
	if got := sb.String(); got != want {
		t.Errorf("timer unit mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
