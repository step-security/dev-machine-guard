package containerlife

import (
	"github.com/step-security/dev-machine-guard/internal/model"
	"strings"
	"testing"
)

func TestMetadataValidation(t *testing.T) {
	for _, url := range []string{"http://example.com/repo", "https://secret@example.com/repo", "https://example.com/repo?token=secret", "https://example.com/repo?", "https://example.com/repo#", "https:///repo", "https://example.com/" + strings.Repeat("x", 2048)} {
		err := validateMetadata(model.ContainerMetadata{RepositoryURL: url})
		if err == nil {
			t.Fatal("accepted unsafe URL")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("error leaked URL")
		}
	}
	for _, m := range []model.ContainerMetadata{{WorkspaceName: strings.Repeat("x", 129)}, {WorkspaceName: "a\nb"}, {Environment: "other"}} {
		if validateMetadata(m) == nil {
			t.Fatalf("accepted invalid metadata: %+v", m)
		}
	}
	if err := validateMetadata(model.ContainerMetadata{WorkspaceName: "widgets", RepositoryURL: "https://github.com/example-org/widgets", Environment: "devcontainer"}); err != nil {
		t.Fatal(err)
	}
	if m, err := readMetadata(t.TempDir()); err != nil || m != nil {
		t.Fatalf("legacy metadata: %+v %v", m, err)
	}
}
