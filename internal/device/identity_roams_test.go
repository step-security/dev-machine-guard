package device

import "testing"

func TestTemplateRoams(t *testing.T) {
	tests := []struct {
		name, template string
		want           bool
	}{
		{"user only", "{user}", true},
		{"user with literal prefix", "avd-{user}", true},
		{"case-insensitive token", "{USER}", true},
		{"hostname and user", "{hostname}-{user}", false},
		{"serial and user", "{serial}-{user}", false},
		{"hostname only", "{hostname}", false},
		{"serial", "{serial}", false},
		{"literal", "asset-12345", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := TemplateRoams(tc.template); got != tc.want {
				t.Errorf("TemplateRoams(%q) = %v, want %v", tc.template, got, tc.want)
			}
		})
	}
}

func TestTemplateForReport(t *testing.T) {
	tests := []struct{ template, want string }{
		{"{hostname}-{user}", "{hostname}-{user}"},
		{"{user}", "{user}"},
		{"asset-12345", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := TemplateForReport(tc.template); got != tc.want {
			t.Errorf("TemplateForReport(%q) = %q, want %q", tc.template, got, tc.want)
		}
	}
}
