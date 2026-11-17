//go:build linux

package containerlife

import (
	"encoding/json"
	"os"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Metadata is separate from runtime state so setup cannot overwrite a running generation.
func (r *runtime) configureMetadata(provided map[string]string) error {
	if len(provided) == 0 {
		return nil
	}
	f, err := r.acquire("setup.lock")
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := readMetadata(r.dir)
	if err != nil {
		return err
	}
	if m == nil {
		m = &model.ContainerMetadata{}
	}
	for key, value := range provided {
		switch key {
		case "workspace-name":
			m.WorkspaceName = value
		case "repository-url":
			m.RepositoryURL = value
		case "environment":
			m.Environment = value
		}
	}
	if err = validateMetadata(*m); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(r.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.WriteFile("metadata.json.tmp", b, 0600); err != nil {
		return err
	}
	return root.Rename("metadata.json.tmp", "metadata.json")
}
