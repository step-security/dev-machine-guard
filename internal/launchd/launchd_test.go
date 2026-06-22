package launchd

import (
	"strings"
	"testing"
	"text/template"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestPlistTemplate_RunAtLoadAndScheduled(t *testing.T) {
	tmpl, err := template.New("plist").Parse(plistTmpl)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, plistTemplateData{
		Label:           label,
		BinaryPath:      "/usr/local/bin/stepsecurity-dev-machine-guard",
		IntervalSeconds: 14400,
		LogDir:          "/Users/dev/.stepsecurity",
	}); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	out := sb.String()

	// RunAtLoad must be true so login/boot is a (gated) catch-up trigger.
	if !strings.Contains(out, "<key>RunAtLoad</key>\n    <true/>") {
		t.Errorf("plist must set RunAtLoad=true:\n%s", out)
	}
	if strings.Contains(out, "<false/>") {
		t.Errorf("plist must not contain RunAtLoad=false:\n%s", out)
	}
	if !strings.Contains(out, "<string>send-telemetry</string>") {
		t.Errorf("plist must invoke send-telemetry:\n%s", out)
	}
}

func TestDomainTarget(t *testing.T) {
	root := executor.NewMock()
	root.SetIsRoot(true)
	if domain, target := DomainTarget(root); domain != "system" || target != "system/"+label {
		t.Errorf("root DomainTarget = %q,%q; want system, system/%s", domain, target, label)
	}

	user := executor.NewMock()
	user.SetIsRoot(false)
	domain, target := DomainTarget(user)
	if !strings.HasPrefix(domain, "gui/") {
		t.Errorf("non-root domain = %q, want gui/<uid>", domain)
	}
	if target != domain+"/"+label {
		t.Errorf("target = %q, want %q", target, domain+"/"+label)
	}
}
