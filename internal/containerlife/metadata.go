package containerlife

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"unicode"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func validateMetadata(m model.ContainerMetadata) error {
	if len(m.WorkspaceName) > 128 || strings.IndexFunc(m.WorkspaceName, unicode.IsControl) >= 0 {
		return errors.New("workspace name must be at most 128 bytes without control characters")
	}
	switch m.Environment {
	case "", "docker", "devcontainer", "codespaces":
	default:
		return errors.New("environment must be docker, devcontainer or codespaces")
	}
	if m.RepositoryURL != "" {
		u, err := url.Parse(m.RepositoryURL)
		if len(m.RepositoryURL) > 2048 || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(m.RepositoryURL, "#") {
			return errors.New("repository URL must be HTTPS without credentials, query or fragment")
		}
	}
	return nil
}

func readMetadata(dir string) (*model.ContainerMetadata, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	b, err := root.ReadFile("metadata.json")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m model.ContainerMetadata
	if err = json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if err = validateMetadata(m); err != nil {
		return nil, err
	}
	return &m, nil
}
