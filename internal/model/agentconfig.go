package model

// AI agent configuration wire types. Each settings source an agent reads is
// reported with the allowlisted posture keys and the hooks written in it. The
// scan reports file contents only: it never says whether a hook runs, whether a
// source is trusted, or which of several values the agent applies.

// Source scopes.
const (
	AgentConfigScopeManaged = "managed"
	AgentConfigScopeUser    = "user"
	AgentConfigScopeProject = "project"
)

// Source channels: how the agent receives the source.
const (
	AgentConfigChannelFile            = "file"
	AgentConfigChannelMacOSProfile    = "macos_profile"
	AgentConfigChannelWindowsRegistry = "windows_registry"
)

// Source states. An unreadable source exists but could not be read or parsed;
// its settings and hooks are empty.
const (
	AgentConfigStateRead       = "read"
	AgentConfigStateUnreadable = "unreadable"
)

// AgentConfigScan lists, per AI coding agent, the settings sources found on
// the device with the posture keys and hooks written in them. It reports file
// contents only: it does not say whether a hook runs or which value applies.
type AgentConfigScan struct {
	RepositoriesScanned int           `json:"repositories_scanned"`
	Agents              []AgentConfig `json:"agents"`
}

// AgentCount is the number of agents reported; zero for a nil scan.
func (s *AgentConfigScan) AgentCount() int {
	if s == nil {
		return 0
	}
	return len(s.Agents)
}

type AgentConfig struct {
	Agent     string              `json:"agent"`
	Truncated bool                `json:"truncated"`
	Sources   []AgentConfigSource `json:"sources"`
}

type AgentConfigSource struct {
	Scope    string               `json:"scope"`   // managed | user | project
	Channel  string               `json:"channel"` // file | macos_profile | windows_registry
	Path     string               `json:"path"`    // home folder shown as ~
	State    string               `json:"state"`   // read | unreadable
	Settings []AgentConfigSetting `json:"settings"`
	Hooks    []AgentConfigHook    `json:"hooks"`
}

// AgentConfigSetting holds one allowlisted key as written. Scalars use Value;
// lists and objects use Values.
type AgentConfigSetting struct {
	Key    string   `json:"key"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
}

type AgentConfigHook struct {
	Event          string `json:"event"`
	Matcher        string `json:"matcher"`
	HandlerType    string `json:"handler_type"` // lower-cased, [a-z0-9_]: command, http, mcp_tool, prompt, agent, ...
	CommandDisplay string `json:"command_display"`
	CommandSHA256  string `json:"command_sha256"` // of the redacted text before the display cut
}
