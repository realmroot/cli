package agent

import (
	"strings"
	"testing"
)

func TestDetectAgentRuntimeUsesExplicitAgentRuntime(t *testing.T) {
	runtime, err := detectAgentRuntime(testEnvironment(map[string]string{
		"AGENT":      "Custom-Runtime",
		"CLAUDECODE": "",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if runtime != "custom-runtime" {
		t.Fatalf("runtime = %q", runtime)
	}
}

func TestDetectAgentRuntimeRecognizesAgentTools(t *testing.T) {
	for _, test := range []struct {
		environment map[string]string
		expected    string
	}{
		{environment: map[string]string{"ANTIGRAVITY_AGENT": ""}, expected: "antigravity"},
		{environment: map[string]string{"OPENCODE": ""}, expected: "opencode"},
		{environment: map[string]string{"GOOSE_TERMINAL": ""}, expected: "goose"},
		{environment: map[string]string{"QWEN_CODE": ""}, expected: "qwen"},
		{environment: map[string]string{"CURSOR_AGENT": ""}, expected: "cursor"},
		{environment: map[string]string{"AGENT_DISPLAY_OUT": "", "AGENT_CONTEXT_OUT": ""}, expected: "kiro"},
		{environment: map[string]string{"PI_CODING_AGENT": ""}, expected: "pi"},
		{environment: map[string]string{"CODEX_THREAD_ID": "thread-1"}, expected: "codex"},
		{environment: map[string]string{"COPILOT_AGENT_SESSION_ID": "session-1"}, expected: "copilot"},
		{environment: map[string]string{"GEMINI_CLI": ""}, expected: "gemini"},
		{environment: map[string]string{"CLAUDE_CODE_SESSION_ID": "session-2"}, expected: "claude"},
		{environment: map[string]string{"HERMES_SESSION_ID": "session-3"}, expected: "hermes"},
	} {
		runtime, err := detectAgentRuntime(testEnvironment(test.environment))
		if err != nil {
			t.Fatal(err)
		}
		if runtime != test.expected {
			t.Fatalf("environment %#v resolved runtime %q", test.environment, runtime)
		}
	}
}

func TestDetectAgentRuntimeFallsBackToRestish(t *testing.T) {
	runtime, err := detectAgentRuntime(testEnvironment(nil))
	if err != nil {
		t.Fatal(err)
	}
	if runtime != defaultAgentRuntime {
		t.Fatalf("runtime = %q", runtime)
	}
}

func TestDetectAgentRuntimeRejectsInvalidExplicitRuntime(t *testing.T) {
	if _, err := detectAgentRuntime(testEnvironment(map[string]string{"AGENT": "../codex"})); err == nil {
		t.Fatal("expected invalid AGENT runtime to fail")
	}
}

func TestAgentDisplayNameDefaultsToDetectedRuntime(t *testing.T) {
	t.Run("[spec: agent-identity/agent-identity-enrollment]", func(t *testing.T) {
		t.Setenv("REALMROOT_AGENT_NAME", "")
		if name := agentDisplayName("codex"); name != "Codex" {
			t.Fatalf("Agent display name = %q", name)
		}
	})
}

func TestAgentDisplayNameUsesExplicitOverride(t *testing.T) {
	t.Setenv("REALMROOT_AGENT_NAME", "  Build Agent  ")
	if name := agentDisplayName("codex"); name != "Build Agent" {
		t.Fatalf("Agent display name = %q", name)
	}
}

func TestNormalizeDeviceDisplayNameRejectsMissingDeviceName(t *testing.T) {
	if _, err := normalizeDeviceDisplayName("  "); err == nil {
		t.Fatal("expected an empty device name to fail")
	}
}

func TestDetectAgentSessionReturnsRawRuntimeIdentifier(t *testing.T) {
	for _, test := range []struct {
		runtime     string
		environment map[string]string
		expected    string
	}{
		{runtime: "codex", environment: map[string]string{"CODEX_THREAD_ID": "thread-1"}, expected: "thread-1"},
		{runtime: "claude", environment: map[string]string{"CLAUDE_CODE_SESSION_ID": "session-2"}, expected: "session-2"},
		{runtime: "copilot", environment: map[string]string{"COPILOT_AGENT_SESSION_ID": "session-3"}, expected: "session-3"},
		{runtime: "goose", environment: map[string]string{"AGENT_SESSION_ID": "session-4"}, expected: "session-4"},
		{runtime: "hermes", environment: map[string]string{"HERMES_SESSION_ID": "session-5"}, expected: "session-5"},
		{runtime: "pi", environment: map[string]string{"PI_SESSION_ID": "session-6"}, expected: "session-6"},
	} {
		sessionID, ok := detectAgentSession(test.runtime, testEnvironment(test.environment))
		if !ok || sessionID != test.expected {
			t.Fatalf("runtime %q session = %q, %v", test.runtime, sessionID, ok)
		}
	}
	if sessionID, ok := detectAgentSession("codex", testEnvironment(nil)); ok || sessionID != "" {
		t.Fatalf("missing session = %q, %v", sessionID, ok)
	}
}

func TestAgentSessionCacheKeySeparatesRawSessionIdentifiers(t *testing.T) {
	t.Setenv("AGENT", "codex")
	t.Setenv("CODEX_THREAD_ID", "thread-secret-1")
	first, err := AgentSessionCacheKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_THREAD_ID", "thread-secret-2")
	second, err := AgentSessionCacheKey()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || strings.Contains(first, "thread-secret") || strings.Contains(second, "thread-secret") {
		t.Fatalf("session cache keys = %q, %q", first, second)
	}
}

func testEnvironment(values map[string]string) environmentLookup {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}
