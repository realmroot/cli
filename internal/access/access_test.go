package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/realmroot/cli/internal/catalog"
	"github.com/realmroot/cli/internal/realmrootapi"
)

var (
	errAccessRequested = errors.New("access requested")
)

type recordingClient struct {
	accessRequests int
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
	}, []string{"agents:read"}, nil, "Read Agent status", RequestOptions{})
	if !errors.Is(err, errAccessRequested) {
		t.Fatalf("Request() error = %v, want access request", err)
	}
	if client.accessRequests != 1 {
		t.Fatalf("access requests = %d", client.accessRequests)
	}
}

func (client *recordingClient) GetAgentAuthorizationRequestWithResponse(context.Context, string, ...realmrootapi.RequestEditorFn) (*realmrootapi.GetAgentAuthorizationRequestResponse, error) {
	panic("unexpected access request poll")
}

func TestRequestUsesOneAccessRequestForEveryConnectionState(t *testing.T) {
	for _, status := range []string{"not_connected", "connected"} {
		t.Run(status, func(t *testing.T) {
			client := &recordingClient{}
			service := &Service{api: client}
			_, err := service.Request(context.Background(), catalog.ResourceServer{
				ID: "resource-1", ConnectionStatus: status,
			}, []string{"contents:write"}, nil, "Update repository content", RequestOptions{})
			if !errors.Is(err, errAccessRequested) {
				t.Fatalf("Request() error = %v, want access request", err)
			}
			if client.accessRequests != 1 {
				t.Fatalf("access requests = %d", client.accessRequests)
			}
		})
	}
}

type pendingClient struct{}

func (*pendingClient) CreateAgentAuthorizationRequestWithResponse(context.Context, realmrootapi.CreateAgentAuthorizationRequestJSONRequestBody, ...realmrootapi.RequestEditorFn) (*realmrootapi.CreateAgentAuthorizationRequestResponse, error) {
	response := &realmrootapi.CreateAgentAuthorizationRequestResponse{HTTPResponse: &http.Response{StatusCode: http.StatusCreated}}
	body := []byte(`{
		"id":"request-1","agentId":"agent-1","resourceServerId":"resource-1","scopes":["issues:read"],
		"authorizationDetails":[],"reason":null,"status":"pending","createdAt":"2026-08-12T00:00:00Z",
		"updatedAt":"2026-08-12T00:00:00Z","expiresAt":"2026-08-12T00:10:00Z","decidedAt":null,
		"interaction":{"type":"user-approval","status":"pending","url":"https://id.realmroot.dev/agent/resource-access/approve#token=secret","expiresAt":"2026-08-12T00:10:00Z"},
		"credentialOffer":{"type":"dpop","resourceIndicator":"","authorizationDetails":[],"endpoint":"","proof":{"method":"jkt","algorithm":"ES256","uri":""}}
	}`)
	if err := json.Unmarshal(body, &response.JSON201); err != nil {
		return nil, err
	}
	return response, nil
}

func (*pendingClient) GetAgentAuthorizationRequestWithResponse(context.Context, string, ...realmrootapi.RequestEditorFn) (*realmrootapi.GetAgentAuthorizationRequestResponse, error) {
	panic("handoff request must not poll")
}

func TestRequestHandoffReturnsApprovalLinkWithoutOpeningOrPolling(t *testing.T) {
	// [spec: cli/task-scoped-access-handoff]
	service := &Service{api: &pendingClient{}}
	receipt, err := service.Request(context.Background(), catalog.ResourceServer{
		ID: "resource-1", CommandName: "github", ConnectionStatus: "not_connected",
	}, []string{"issues:read"}, nil, "Read issues", RequestOptions{Handoff: true})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "pending" || receipt.ApprovalURL == "" || receipt.ResourceIndicator != "" {
		t.Fatalf("receipt = %#v", receipt)
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
	)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	if strings.Contains(output, "credentialSource") || strings.Contains(output, "reference") || strings.Contains(output, "authorizationDetails") {
		t.Fatalf("public receipt exposes internal credential binding: %s", output)
	}
	for _, expected := range []string{`"status":"ready"`, `"resourceServer":"github"`, `"scopes":["issues:read"]`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("public receipt omitted %s: %s", expected, output)
		}
	}
}
