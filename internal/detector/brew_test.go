package detector

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func newTestLogger() *progress.Logger {
	return progress.NewNoop()
}

func stubBrewGitVersion(mock *executor.Mock, repo, revision, version string) {
	mock.SetFile(repo+"/.git/HEAD", []byte("ref: refs/heads/stable\n"))
	mock.SetFile(repo+"/.git/refs/heads/stable", []byte(revision+"\n"))
	mock.SetFile(repo+"/.git/describe-cache/"+revision, []byte(version+"\n"))
}

func TestBrewDetector_Found(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")
	stubBrewGitVersion(mock, "/opt/homebrew", "abc123", "4.3.5")

	det := NewBrewDetector(mock)
	result := det.DetectBrew(context.Background())

	if result == nil {
		t.Fatal("expected brew to be detected")
	}
	if result.Name != "homebrew" {
		t.Errorf("expected name homebrew, got %s", result.Name)
	}
	if result.Version != "4.3.5" {
		t.Errorf("expected version 4.3.5, got %s", result.Version)
	}
	if result.Path != "/opt/homebrew/bin/brew" {
		t.Errorf("expected path /opt/homebrew/bin/brew, got %s", result.Path)
	}
}

func TestBrewDetector_FoundAtStandardPathOutsidePATH(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/opt/homebrew/bin/brew", []byte{})
	stubBrewGitVersion(mock, "/opt/homebrew", "abc123", "4.3.5")

	det := NewBrewDetector(mock)
	result := det.DetectBrew(context.Background())

	if result == nil {
		t.Fatal("expected brew to be detected")
	}
	if result.Version != "4.3.5" {
		t.Errorf("expected version 4.3.5, got %s", result.Version)
	}
	if result.Path != "/opt/homebrew/bin/brew" {
		t.Errorf("expected path /opt/homebrew/bin/brew, got %s", result.Path)
	}
}

func TestBrewDetector_FoundAtHomebrewRepositoryLayout(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/usr/local/bin/brew", []byte{})
	stubBrewGitVersion(mock, "/usr/local/Homebrew", "abc123", "4.3.5")

	det := NewBrewDetector(mock)
	result := det.DetectBrew(context.Background())

	if result == nil {
		t.Fatal("expected brew to be detected")
	}
	if result.Version != "4.3.5" {
		t.Errorf("expected version 4.3.5, got %s", result.Version)
	}
	if result.Path != "/usr/local/bin/brew" {
		t.Errorf("expected path /usr/local/bin/brew, got %s", result.Path)
	}
}

func TestBrewDetector_VersionFromPackedTag(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/opt/homebrew/bin/brew", []byte{})
	mock.SetFile("/opt/homebrew/.git/HEAD", []byte("ref: refs/heads/stable\n"))
	mock.SetFile("/opt/homebrew/.git/packed-refs", []byte("abc123 refs/heads/stable\nabc123 refs/tags/4.3.5\n"))

	det := NewBrewDetector(mock)
	result := det.DetectBrew(context.Background())

	if result == nil {
		t.Fatal("expected brew to be detected")
	}
	if result.Version != "4.3.5" {
		t.Errorf("expected version 4.3.5, got %s", result.Version)
	}
}

func TestBrewDetector_UnknownVersionWhenGitMetadataUnavailable(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/opt/homebrew/bin/brew", []byte{})

	det := NewBrewDetector(mock)
	result := det.DetectBrew(context.Background())

	if result == nil {
		t.Fatal("expected brew to be detected")
	}
	if result.Version != "unknown" {
		t.Errorf("expected unknown version, got %s", result.Version)
	}
}

func TestBrewDetector_NotFound(t *testing.T) {
	mock := executor.NewMock()
	det := NewBrewDetector(mock)
	result := det.DetectBrew(context.Background())

	if result != nil {
		t.Error("expected nil when brew is not installed")
	}
}

func TestBrewDetector_ListFormulae(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")
	mock.SetCommand("ca-certificates 2024.2.2\ncurl 8.4.0\ngit 2.43.0\nopenssl@3 3.2.0\n", "", 0, "/opt/homebrew/bin/brew", "list", "--formula", "--versions")

	det := NewBrewDetector(mock)
	formulae := det.ListFormulae(context.Background())

	if len(formulae) != 4 {
		t.Fatalf("expected 4 formulae, got %d", len(formulae))
	}
	if formulae[0].Name != "ca-certificates" || formulae[0].Version != "2024.2.2" {
		t.Errorf("unexpected first formula: %+v", formulae[0])
	}
}

func TestBrewDetector_ListFormulaeAtStandardPathOutsidePATH(t *testing.T) {
	mock := executor.NewMock()
	mock.SetFile("/opt/homebrew/bin/brew", []byte{})
	mock.SetCommand("curl 8.4.0\ngit 2.43.0\n", "", 0, "/opt/homebrew/bin/brew", "list", "--formula", "--versions")

	det := NewBrewDetector(mock)
	formulae := det.ListFormulae(context.Background())

	if len(formulae) != 2 {
		t.Fatalf("expected 2 formulae, got %d", len(formulae))
	}
	if formulae[0].Name != "curl" || formulae[0].Version != "8.4.0" {
		t.Errorf("unexpected first formula: %+v", formulae[0])
	}
}

func TestBrewDetector_ListCasks(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("brew", "/opt/homebrew/bin/brew")
	mock.SetCommand("firefox 120.0\ngoogle-chrome 120.0.6099.109\nvisual-studio-code 1.85.0\n", "", 0, "/opt/homebrew/bin/brew", "list", "--cask", "--versions")

	det := NewBrewDetector(mock)
	casks := det.ListCasks(context.Background())

	if len(casks) != 3 {
		t.Fatalf("expected 3 casks, got %d", len(casks))
	}
	if casks[0].Name != "firefox" || casks[0].Version != "120.0" {
		t.Errorf("unexpected first cask: %+v", casks[0])
	}
}

func TestBrewScanner_FormulaeResult(t *testing.T) {
	scanner := NewBrewScanner(executor.NewMock(), newTestLogger())
	pkgs := []model.BrewPackage{
		{Name: "curl", Version: "8.4.0"},
		{Name: "git", Version: "2.43.0"},
	}
	result := scanner.FormulaeResult(pkgs)

	if result.ScanType != "formulae" {
		t.Errorf("expected scan type formulae, got %s", result.ScanType)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if result.LineCount != 2 {
		t.Errorf("expected line count 2, got %d", result.LineCount)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.RawStdoutBase64)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	want := "curl 8.4.0\ngit 2.43.0\n"
	if string(decoded) != want {
		t.Errorf("stdout mismatch: got %q, want %q", string(decoded), want)
	}
}

func TestBrewScanner_CasksResult(t *testing.T) {
	scanner := NewBrewScanner(executor.NewMock(), newTestLogger())
	pkgs := []model.BrewPackage{
		{Name: "firefox", Version: "120.0"},
		{Name: "google-chrome", Version: "120.0.6099.109"},
	}
	result := scanner.CasksResult(pkgs)

	if result.ScanType != "casks" {
		t.Errorf("expected scan type casks, got %s", result.ScanType)
	}
	if result.LineCount != 2 {
		t.Errorf("expected line count 2, got %d", result.LineCount)
	}
	if result.RawStdoutBase64 == "" {
		t.Error("expected non-empty base64 stdout")
	}
}

func TestBrewScanner_EmptyInput(t *testing.T) {
	scanner := NewBrewScanner(executor.NewMock(), newTestLogger())
	result := scanner.FormulaeResult(nil)

	if result.LineCount != 0 {
		t.Errorf("expected line count 0, got %d", result.LineCount)
	}
	decoded, _ := base64.StdEncoding.DecodeString(result.RawStdoutBase64)
	if len(decoded) != 0 {
		t.Errorf("expected empty stdout, got %q", string(decoded))
	}
}
