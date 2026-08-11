package access

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/realmroot/toolbox/internal/catalog"
	"github.com/realmroot/toolbox/internal/realmrootapi"
)

var (
	errConnectionRequested = errors.New("connection requested")
	errAccessRequested     = errors.New("access requested")
)

type recordingClient struct {
	connectionRequests int
	accessRequests     int
}

func (client *recordingClient) CreateConnectionRequestWithResponse(context.Context, string, realmrootapi.CreateConnectionRequestJSONRequestBody, ...realmrootapi.RequestEditorFn) (*realmrootapi.CreateConnectionRequestResponse, error) {
	client.connectionRequests++
	return nil, errConnectionRequested
}

func (client *recordingClient) GetConnectionRequestWithResponse(context.Context, string, string, ...realmrootapi.RequestEditorFn) (*realmrootapi.GetConnectionRequestResponse, error) {
	panic("unexpected connection request poll")
}

func (client *recordingClient) CreateAgentAuthorizationRequestWithResponse(context.Context, realmrootapi.CreateAgentAuthorizationRequestJSONRequestBody, ...realmrootapi.RequestEditorFn) (*realmrootapi.CreateAgentAuthorizationRequestResponse, error) {
	client.accessRequests++
	return nil, errAccessRequested
}

func TestRequestSkipsConnectionForNativeResource(t *testing.T) {
	client := &recordingClient{}
	service := &Service{api: client}
	_, err := service.Request(context.Background(), catalog.ResourceServer{
		ID: "resource-1", ConnectionStatus: "not_required",
	}, []string{"agents:read"}, nil, "Read Agent status")
	if !errors.Is(err, errAccessRequested) {
		t.Fatalf("Request() error = %v, want access request", err)
	}
	if client.connectionRequests != 0 || client.accessRequests != 1 {
		t.Fatalf("connection requests = %d, access requests = %d", client.connectionRequests, client.accessRequests)
	}
}

func (client *recordingClient) GetAgentAuthorizationRequestWithResponse(context.Context, string, ...realmrootapi.RequestEditorFn) (*realmrootapi.GetAgentAuthorizationRequestResponse, error) {
	panic("unexpected access request poll")
}

func TestRequestReconcilesEveryRequiredAccountConnection(t *testing.T) {
	for _, status := range []string{"not_connected", "connected"} {
		t.Run(status, func(t *testing.T) {
			client := &recordingClient{}
			service := &Service{api: client}
			_, err := service.Request(context.Background(), catalog.ResourceServer{
				ID: "resource-1", ConnectionStatus: status,
			}, []string{"contents:write"}, nil, "Update repository content")
			if !errors.Is(err, errConnectionRequested) {
				t.Fatalf("Request() error = %v, want connection request", err)
			}
			if client.connectionRequests != 1 || client.accessRequests != 0 {
				t.Fatalf("connection requests = %d, access requests = %d", client.connectionRequests, client.accessRequests)
			}
		})
	}
}

func TestNormalizedScopes(t *testing.T) {
	got := normalizedScopes([]string{" contents:read ", "metadata:read", "contents:read", ""})
	want := []string{"contents:read", "metadata:read"}
	if len(got) != len(want) {
		t.Fatalf("scopes = %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("scopes = %#v", got)
		}
	}
}

func TestAuthorizationDetailRequiresStringValues(t *testing.T) {
	if _, _, err := detail(map[string]any{"type": "github_installation", "installation_id": 123}); err == nil {
		t.Fatal("numeric authorization detail was accepted")
	}
	typeName, values, err := detail(map[string]any{"type": "github_installation", "installation_id": "123"})
	if err != nil || typeName != "github_installation" || values["installation_id"] != "123" {
		t.Fatalf("detail = %q %#v, err = %v", typeName, values, err)
	}
}

func TestReadyReceiptDoesNotExposeInternalCredentialBinding(t *testing.T) {
	value := receipt(
		catalog.ResourceServer{CommandName: "github"},
		"https://adapters.realmroot.dev/github",
		[]string{"issues:read"},
		[]map[string]any{{"type": "github_installation", "installation_id": "123"}},
	)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	if strings.Contains(output, "credentialSource") || strings.Contains(output, "reference") {
		t.Fatalf("public receipt exposes internal credential binding: %s", output)
	}
	for _, expected := range []string{`"status":"ready"`, `"resourceServer":"github"`, `"scopes":["issues:read"]`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("public receipt omitted %s: %s", expected, output)
		}
	}
}
