package detector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// claudeState is the selected content of Claude Code's .claude.json: the
// project registry keys and the recorded skill-use counters. One bounded read
// serves both consumers; nothing else in the file is retained.
type claudeState struct {
	path         string
	projects     []string
	skillUsage   map[string]json.RawMessage
	absent       bool
	code         string // whole-file read/parse failure
	projectsCode string
	usageCode    string
}

// readClaudeState reads <dir>/.claude.json with path and size guards.
func readClaudeState(exec executor.Executor, skipper *tcc.Skipper, dir string) claudeState {
	st := claudeState{path: filepath.Join(dir, ".claude.json")}
	if skipper.WithinProtected(st.path) {
		st.code = model.AgentScanErrUnsafePath
		return st
	}
	exec = exec.GuardedFiles([]string{dir}, func(p string) string {
		if skipper.WithinProtected(p) {
			return "tcc_protected"
		}
		return ""
	}, maxJSONConfigBytes)
	fi, err := exec.Stat(st.path)
	if errors.Is(err, os.ErrNotExist) {
		st.absent = true
		return st
	}
	if err != nil {
		st.code = readCode(err)
		return st
	}
	switch {
	case !fi.Mode().IsRegular():
		st.code = model.AgentScanErrReadFailed
		return st
	case fi.Size() > maxJSONConfigBytes:
		st.code = model.AgentScanErrLimitExceeded
		return st
	}
	content, err := exec.ReadFile(st.path)
	if err != nil {
		st.code = model.AgentScanErrReadFailed
		return st
	}
	if len(content) > maxJSONConfigBytes {
		st.code = model.AgentScanErrLimitExceeded
		return st
	}
	var parsed *struct {
		Projects   json.RawMessage `json:"projects"`
		SkillUsage json.RawMessage `json:"skillUsage"`
	}
	if err := json.Unmarshal(content, &parsed); err != nil || parsed == nil {
		st.code = model.AgentScanErrParseFailed
		return st
	}
	var projects map[string]json.RawMessage
	if len(parsed.Projects) > 0 && (json.Unmarshal(parsed.Projects, &projects) != nil || projects == nil) {
		st.projectsCode = model.AgentScanErrParseFailed
	} else {
		for p := range projects {
			st.projects = append(st.projects, p)
		}
	}
	if len(parsed.SkillUsage) > 0 && (json.Unmarshal(parsed.SkillUsage, &st.skillUsage) != nil || st.skillUsage == nil) {
		st.usageCode = model.AgentScanErrParseFailed
	}
	return st
}

// discoverClaudeProjects returns recorded project paths verbatim and unsorted.
// Read or project-parse failures return nil; invalid usage does not affect projects.
func discoverClaudeProjects(exec executor.Executor) []string {
	return readClaudeState(exec, nil, getHomeDir(exec)).projects
}
