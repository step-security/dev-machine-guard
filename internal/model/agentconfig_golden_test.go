package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Shared wire fixture with Agent API.
const agentConfigGoldenPath = "testdata/agent_config_v1_golden.json"

type agentConfigGolden struct {
	AgentConfig *AgentConfigScan `json:"agent_config"`
}

func loadAgentConfigGolden(t *testing.T) ([]byte, *AgentConfigScan) {
	t.Helper()
	raw, err := os.ReadFile(agentConfigGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var doc agentConfigGolden
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("golden payload does not fit the model: %v", err)
	}
	if doc.AgentConfig == nil {
		t.Fatal("golden has no agent_config")
	}
	return raw, doc.AgentConfig
}

func TestAgentConfigGolden_RoundTripsWithNoDroppedField(t *testing.T) {
	raw, scan := loadAgentConfigGolden(t)
	encoded, err := json.Marshal(agentConfigGolden{AgentConfig: scan})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := decodeGeneric(t, encoded), decodeGeneric(t, raw); !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the payload\n got: %s\nwant: %s", encoded, raw)
	}
}

func TestAgentConfigGolden_CoversTheVocabulary(t *testing.T) {
	_, scan := loadAgentConfigGolden(t)
	seen := map[string]bool{}
	for _, a := range scan.Agents {
		seen["agent:"+a.Agent] = true
		if a.Truncated {
			seen["truncated"] = true
		}
		if len(a.Sources) == 0 {
			seen["no sources"] = true
		}
		for _, s := range a.Sources {
			seen["scope:"+s.Scope], seen["channel:"+s.Channel], seen["state:"+s.State] = true, true, true
			for _, h := range s.Hooks {
				seen["handler:"+h.HandlerType] = true
			}
		}
	}
	for _, want := range []string{
		"agent:claude-code", "agent:codex", "agent:cursor", "agent:gemini-cli", "agent:github-copilot",
		"scope:" + AgentConfigScopeManaged, "scope:" + AgentConfigScopeUser, "scope:" + AgentConfigScopeProject,
		"channel:" + AgentConfigChannelFile, "channel:" + AgentConfigChannelMacOSProfile, "channel:" + AgentConfigChannelWindowsRegistry,
		"state:" + AgentConfigStateRead, "state:" + AgentConfigStateUnreadable,
		"handler:command", "handler:http", "handler:prompt", "truncated", "no sources",
	} {
		if !seen[want] {
			t.Errorf("golden does not cover %s", want)
		}
	}
}

var (
	handlerTypeRE = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	sha256HexRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	loginRE       = regexp.MustCompile(`(?i)/Users/|/home/|C:\\\\Users\\\\`)
)

// The invariants the reader guarantees and the backend relies on.
func TestAgentConfigGolden_Invariants(t *testing.T) {
	raw, scan := loadAgentConfigGolden(t)
	if strings.Contains(string(raw), "null") {
		t.Error("golden holds a null list")
	}
	if loginRE.Match(raw) {
		t.Error("golden holds a home folder")
	}
	rank := map[string]int{AgentConfigScopeManaged: 0, AgentConfigScopeUser: 1, AgentConfigScopeProject: 2}
	if !slices.IsSortedFunc(scan.Agents, func(a, b AgentConfig) int { return strings.Compare(a.Agent, b.Agent) }) {
		t.Error("agents not sorted")
	}
	for _, a := range scan.Agents {
		hooks := 0
		if len(a.Sources) > 250 {
			t.Errorf("%s: %d sources", a.Agent, len(a.Sources))
		}
		for i, s := range a.Sources {
			if i > 0 {
				p := a.Sources[i-1]
				if rank[p.Scope] > rank[s.Scope] || rank[p.Scope] == rank[s.Scope] && p.Path > s.Path {
					t.Errorf("%s: %s before %s", a.Agent, p.Path, s.Path)
				}
			}
			if len(s.Path) > 1024 {
				t.Errorf("%s: path over the cap", a.Agent)
			}
			if s.State == AgentConfigStateUnreadable && len(s.Settings)+len(s.Hooks) != 0 {
				t.Errorf("%s: unreadable source with content", a.Agent)
			}
			for _, set := range s.Settings {
				if len(set.Value) > 256 || len(set.Values) > 50 {
					t.Errorf("%s: setting %s over the cap", a.Agent, set.Key)
				}
			}
			hooks += len(s.Hooks)
			for _, h := range s.Hooks {
				if !handlerTypeRE.MatchString(h.HandlerType) || !sha256HexRE.MatchString(h.CommandSHA256) {
					t.Errorf("%s: hook %+v", a.Agent, h)
				}
				if len(h.Event) > 256 || len(h.Matcher) > 256 || len(h.CommandDisplay) > 256 {
					t.Errorf("%s: hook field over the cap", a.Agent)
				}
				sum := sha256.Sum256([]byte(h.CommandDisplay))
				if len(h.CommandDisplay) < 256 && h.CommandSHA256 != hex.EncodeToString(sum[:]) {
					t.Errorf("%s: hash of %q does not match", a.Agent, h.CommandDisplay)
				}
			}
		}
		if hooks > 100 {
			t.Errorf("%s: %d hooks", a.Agent, hooks)
		}
	}
}
