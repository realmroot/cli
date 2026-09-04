package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

const (
	defaultAgentRuntime            = "toolbox"
	defaultAgentRuntimeDisplayName = "Realmroot Toolbox"
)

var sessionEnvironmentNames = map[string][]string{
	"claude":  {"CLAUDE_CODE_SESSION_ID"},
	"codex":   {"AGENT_SESSION_ID", "CODEX_THREAD_ID"},
	"copilot": {"COPILOT_AGENT_SESSION_ID"},
	"goose":   {"AGENT_SESSION_ID"},
	"hermes":  {"HERMES_SESSION_ID", "HERMES_SESSION_KEY"},
	"pi":      {"PI_SESSION_ID"},
}

type environmentLookup func(string) (string, bool)

type runtimeDetector struct {
	name        string
	displayName string
	matches     func(environmentLookup) bool
}

var runtimeDetectors = []runtimeDetector{
	{name: "antigravity", displayName: "Antigravity", matches: hasEnvironment("ANTIGRAVITY_AGENT")},
	{name: "opencode", displayName: "OpenCode", matches: hasEnvironment("OPENCODE")},
	{name: "goose", displayName: "Goose", matches: hasEnvironment("GOOSE_TERMINAL")},
	{name: "qwen", displayName: "Qwen", matches: hasEnvironment("QWEN_CODE")},
	{name: "cursor", displayName: "Cursor", matches: hasEnvironment("CURSOR_AGENT")},
	{name: "kiro", displayName: "Kiro", matches: hasEnvironments("AGENT_DISPLAY_OUT", "AGENT_CONTEXT_OUT")},
	{name: "pi", displayName: "Pi", matches: hasAnyEnvironment("PI_CODING_AGENT", "PI_SESSION_ID")},
	{name: "codex", displayName: "Codex", matches: hasAnyEnvironment("CODEX_CI", "CODEX_THREAD_ID")},
	{name: "copilot", displayName: "Copilot", matches: hasAnyEnvironment("COPILOT_CLI", "COPILOT_AGENT_SESSION_ID")},
	{name: "gemini", displayName: "Gemini", matches: hasEnvironment("GEMINI_CLI")},
	{name: "claude", displayName: "Claude", matches: hasAnyEnvironment("CLAUDECODE", "CLAUDE_CODE_SESSION_ID")},
	{name: "hermes", displayName: "Hermes", matches: hasAnyEnvironment("HERMES_INTERACTIVE", "HERMES_SESSION_ID", "HERMES_SESSION_KEY")},
}

func agentRuntime() (string, error) {
	return detectAgentRuntime(os.LookupEnv)
}

func agentSession(runtime string) (string, bool) {
	return detectAgentSession(runtime, os.LookupEnv)
}

func AgentSessionCacheKey() (string, error) {
	runtime, err := agentRuntime()
	if err != nil {
		return "", err
	}
	sessionID, ok := agentSession(runtime)
	if !ok {
		return runtime + "-none", nil
	}
	digest := sha256.Sum256([]byte(runtime + "\x00" + sessionID))
	return runtime + "-" + hex.EncodeToString(digest[:16]), nil
}

func detectAgentSession(runtime string, lookup environmentLookup) (string, bool) {
	names := sessionEnvironmentNames[runtime]
	if len(names) == 0 {
		names = []string{"AGENT_SESSION_ID"}
	}
	for _, name := range names {
		if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
			return value, true
		}
	}
	return "", false
}

func detectAgentRuntime(lookup environmentLookup) (string, error) {
	if value, ok := lookup("AGENT"); ok && strings.TrimSpace(value) != "" {
		return normalizeAgentRuntime(value)
	}
	for _, detector := range runtimeDetectors {
		if detector.matches(lookup) {
			return detector.name, nil
		}
	}
	return defaultAgentRuntime, nil
}

func agentDisplayName(runtime string) string {
	if value := strings.TrimSpace(os.Getenv("REALMROOT_AGENT_NAME")); value != "" {
		return value
	}
	if runtime == defaultAgentRuntime {
		return defaultAgentRuntimeDisplayName
	}
	for _, detector := range runtimeDetectors {
		if detector.name == runtime {
			return detector.displayName
		}
	}
	return runtime
}

func normalizeAgentRuntime(value string) (string, error) {
	runtime := strings.ToLower(strings.TrimSpace(value))
	if runtime == "" || len(runtime) > 64 {
		return "", errors.New("AGENT must name a runtime with 1 to 64 characters")
	}
	for index, char := range runtime {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			if index > 0 || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
				continue
			}
		}
		return "", errors.New("AGENT must contain only letters, numbers, dots, underscores, or hyphens")
	}
	return runtime, nil
}

func hasEnvironment(name string) func(environmentLookup) bool {
	return func(lookup environmentLookup) bool {
		_, ok := lookup(name)
		return ok
	}
}

func hasEnvironments(names ...string) func(environmentLookup) bool {
	return func(lookup environmentLookup) bool {
		for _, name := range names {
			if _, ok := lookup(name); !ok {
				return false
			}
		}
		return true
	}
}

func hasAnyEnvironment(names ...string) func(environmentLookup) bool {
	return func(lookup environmentLookup) bool {
		for _, name := range names {
			if _, ok := lookup(name); ok {
				return true
			}
		}
		return false
	}
}
