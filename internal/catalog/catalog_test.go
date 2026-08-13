package catalog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/realmroot/toolbox/internal/agent"
)

func TestResourceServerCommandName(t *testing.T) {
	tests := []struct {
		identifier, want string
		wantError        bool
	}{
		{identifier: "realmroot", want: "platform"},
		{identifier: "github", want: "github"},
		{identifier: "platform", wantError: true},
		{identifier: "get", wantError: true},
		{identifier: "sync", wantError: true},
	}
	for _, test := range tests {
		got, err := resourceServerCommandName(test.identifier)
		if (err != nil) != test.wantError {
			t.Fatalf("%s error = %v", test.identifier, err)
		}
		if got != test.want {
			t.Fatalf("%s command = %q, want %q", test.identifier, got, test.want)
		}
	}
}

func TestToolIntegrationsDistinguishesMissingCapability(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("content-type", "application/json")
		_, _ = response.Write([]byte(`{"openapi":"3.1.0"}`))
	}))
	defer server.Close()
	service, err := agent.NewService(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(service, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ToolIntegrations(context.Background(), ResourceServer{CommandName: "wallet", ResourceURL: server.URL})
	if !errors.Is(err, ErrNoToolIntegrations) {
		t.Fatalf("error = %v", err)
	}
}

func TestToolIntegrationsTreatsNonJSONResourceAsMissingCapability(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = response.Write([]byte(`<html></html>`))
	}))
	defer server.Close()
	service, err := agent.NewService(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(service, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ToolIntegrations(context.Background(), ResourceServer{CommandName: "platform", ResourceURL: server.URL})
	if !errors.Is(err, ErrNoToolIntegrations) {
		t.Fatalf("error = %v", err)
	}
}

func TestAgentSkillsDiscoversAndValidatesIndex(t *testing.T) {
	// [spec: cli/resource-server-skills]
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/.well-known/agent-skills/index.json" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		response.Header().Set("content-type", "application/json")
		_, _ = fmt.Fprintf(response, `{
			"$schema":"https://schemas.agentskills.io/discovery/0.2.0/schema.json",
			"skills":[{
				"name":"github-workflow",
				"type":"archive",
				"description":"Operate GitHub repositories through Realmroot Toolbox.",
				"url":"github-workflow.tar.gz",
				"digest":"sha256:%s"
			}]
		}`, strings.Repeat("a", 64))
	}))
	defer server.Close()
	service, err := agent.NewService(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(service, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	index, err := client.AgentSkills(context.Background(), ResourceServer{CommandName: "github", ResourceURL: server.URL + "/api"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || index.URL != server.URL+"/.well-known/agent-skills/index.json" || len(index.Skills) != 1 {
		t.Fatalf("requests=%d index=%#v", requests, index)
	}
	wantURL := server.URL + "/.well-known/agent-skills/github-workflow.tar.gz"
	if index.Skills[0].URL != wantURL || index.Skills[0].Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("skill = %#v", index.Skills[0])
	}
}

func TestAgentSkillsDistinguishesMissingIndex(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	service, err := agent.NewService(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(service, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AgentSkills(context.Background(), ResourceServer{CommandName: "example", ResourceURL: server.URL})
	if !errors.Is(err, ErrNoAgentSkills) {
		t.Fatalf("error = %v", err)
	}
}

func TestAgentSkillsRejectsInvalidDigest(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("content-type", "application/json")
		_, _ = response.Write([]byte(`{
			"$schema":"https://schemas.agentskills.io/discovery/0.2.0/schema.json",
			"skills":[{"name":"example","type":"skill-md","description":"Example.","url":"SKILL.md","digest":"sha256:nope"}]
		}`))
	}))
	defer server.Close()
	service, err := agent.NewService(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(service, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AgentSkills(context.Background(), ResourceServer{CommandName: "example", ResourceURL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "invalid digest") {
		t.Fatalf("error = %v", err)
	}
}
