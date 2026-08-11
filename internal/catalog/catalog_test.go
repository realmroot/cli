package catalog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
