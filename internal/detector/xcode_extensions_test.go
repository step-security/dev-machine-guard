package detector

import (
	"testing"
)

func TestParsePluginkitLine(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantID    string
		wantVer   string
		wantPub   string
		wantName  string
		wantNil   bool
	}{
		{
			name:     "enabled extension",
			line:     "+    com.charcoaldesign.SwiftFormat-for-Xcode.SourceEditorExtension(0.60.1)",
			wantID:   "com.charcoaldesign.SwiftFormat-for-Xcode.SourceEditorExtension",
			wantVer:  "0.60.1",
			wantPub:  "com.charcoaldesign",
			wantName: "SwiftFormat-for-Xcode",
		},
		{
			name:     "disabled extension",
			line:     "-    com.example.MyTool.SourceEditorExtension(1.2.3)",
			wantID:   "com.example.MyTool.SourceEditorExtension",
			wantVer:  "1.2.3",
			wantPub:  "com.example",
			wantName: "MyTool",
		},
		{
			name:     "null version",
			line:     "+    com.example.SomePlugin.Extension((null))",
			wantID:   "com.example.SomePlugin.Extension",
			wantVer:  "unknown",
			wantPub:  "com.example",
			wantName: "SomePlugin",
		},
		{
			name:    "empty line",
			line:    "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := parsePluginkitLine(tt.line)
			if tt.wantNil {
				if ext != nil {
					t.Errorf("expected nil, got %+v", ext)
				}
				return
			}
			if ext == nil {
				t.Fatal("expected non-nil extension")
			}
			if ext.ID != tt.wantID {
				t.Errorf("ID: got %q, want %q", ext.ID, tt.wantID)
			}
			if ext.Version != tt.wantVer {
				t.Errorf("Version: got %q, want %q", ext.Version, tt.wantVer)
			}
			if ext.Publisher != tt.wantPub {
				t.Errorf("Publisher: got %q, want %q", ext.Publisher, tt.wantPub)
			}
			if ext.Name != tt.wantName {
				t.Errorf("Name: got %q, want %q", ext.Name, tt.wantName)
			}
			if ext.IDEType != "xcode" {
				t.Errorf("IDEType: got %q, want xcode", ext.IDEType)
			}
			if ext.Source != "user_installed" {
				t.Errorf("Source: got %q, want user_installed", ext.Source)
			}
		})
	}
}
