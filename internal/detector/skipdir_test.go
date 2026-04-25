package detector

import (
	"testing"
)

func TestIsIDEInternalPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Windows IDE paths
		{`C:\Users\dev\AppData\Local\Programs\Antigravity\resources\app\extensions\css`, true},
		{`C:\Users\dev\AppData\Local\Programs\cursor\resources\app\extensions\git`, true},
		{`C:\Program Files\Microsoft VS Code\resources\app\extensions\typescript`, true},
		{`C:\Users\dev\AppData\Local\Programs\cursor\resources\app\extensions`, true},

		// macOS IDE paths
		{"/Applications/Visual Studio Code.app/Contents/Resources/app/extensions/css", true},
		{"/Applications/Cursor.app/Contents/Resources/app/extensions/git", true},
		{"/Applications/Windsurf.app/Contents/Resources/app/extensions/html", true},

		// Linux IDE paths
		{"/usr/share/code/resources/app/extensions/typescript", true},
		{"/opt/Windsurf/resources/app/extensions/css", true},
		{"/usr/share/cursor/resources/app/extensions/git", true},

		// User projects - should NOT be skipped
		{`C:\Users\dev\myapp`, false},
		{"/home/user/my-project", false},
		{"/Users/dev/work/webapp", false},
		{`C:\Users\dev\code\project`, false},

		// Edge cases - paths that look similar but aren't IDE internals
		{"/home/user/resources/data", false},
		{"/home/user/my-app/extensions", false},
		{"/home/user/app/extensions", false},

		// Eclipse internal
		{`C:\Users\dev\eclipse\plugins\org.eclipse.core`, true},
		{"/opt/eclipse/plugins/something", true},

		// Empty
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isIDEInternalPath(tt.path)
			if got != tt.want {
				t.Errorf("isIDEInternalPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestShouldSkipDir(t *testing.T) {
	tests := []struct {
		dirName  string
		fullPath string
		want     bool
	}{
		// Standard skips (original behavior)
		{"node_modules", "/project/node_modules", true},
		{".git", "/project/.git", true},
		{".cache", "/project/.cache", true},
		{".hidden", "/project/.hidden", true},

		// IDE internal directories
		{"css", "/Applications/Cursor.app/Contents/Resources/app/extensions/css", true},
		{"typescript", `C:\Program Files\Microsoft VS Code\resources\app\extensions\typescript`, true},

		// Normal directories - should NOT be skipped
		{"src", "/project/src", false},
		{"lib", "/project/lib", false},
		{"packages", "/project/packages", false},
		{"extensions", "/project/extensions", false},
	}

	for _, tt := range tests {
		t.Run(tt.dirName+"_"+tt.fullPath, func(t *testing.T) {
			got := shouldSkipDir(tt.dirName, tt.fullPath)
			if got != tt.want {
				t.Errorf("shouldSkipDir(%q, %q) = %v, want %v", tt.dirName, tt.fullPath, got, tt.want)
			}
		})
	}
}
