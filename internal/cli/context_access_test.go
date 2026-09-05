package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/realmroot/cli/internal/access"
	"github.com/realmroot/cli/internal/agent"
	"github.com/realmroot/cli/internal/catalog"
)

func authorityContexts() []catalog.AuthorizationDetail {
	return []catalog.AuthorizationDetail{
		{ID: "user-1", Name: "Ambor", AccountAuthorizationStatus: "not_required", AuthorizationDetail: map[string]any{"type": "realmroot_authority", "authority": "user", "id": "user-1"}, AuthorizedScopes: []string{"agents:read"}},
		{ID: "org-1", Name: "Platform", AccountAuthorizationStatus: "not_required", AuthorizationDetail: map[string]any{"type": "realmroot_authority", "authority": "organization", "id": "org-1"}, AuthorizedScopes: []string{"applications:read"}, RequestableScopes: []string{"permissions:read"}},
	}
}

type accessRecorder struct {
	calls   int
	details []map[string]any
	scopes  []string
	status  string
	err     error
}

func (r *accessRecorder) Request(_ context.Context, server catalog.ResourceServer, scopes []string, details []map[string]any, _ string, _ access.RequestOptions) (access.Receipt, error) {
	r.calls++
	r.details, r.scopes = details, scopes
	return access.Receipt{Status: r.status, ResourceServer: server.CommandName, Scopes: scopes}, r.err
}

func TestAccessRequestDefersBoundaryDecisionToServer(t *testing.T) {
	// [spec: cli/access-context-preflight]
	details := authorityContexts()
	selected := []map[string]any{details[0].AuthorizationDetail}
	body := []byte(`{"error":{"code":"requested_scopes_exceed_controller_boundary","message":"Controller cannot grant these scopes. No approval request was created.","requestId":"server-request-1","details":{"context":{"id":"user-1","type":"user"},"scopes":["applications:read"]}}}`)
	service := &accessRecorder{err: &access.ResponseError{StatusCode: 403, Body: body}}
	var stderr bytes.Buffer
	result, err := (&App{stderr: &stderr}).requestAccess(context.Background(), service, catalog.ResourceServer{CommandName: "platform", ConnectionStatus: "not_required"}, []string{"applications:read"}, details, selected, "saved_default", "inspect", access.RequestOptions{})
	if err != service.err || service.calls != 1 || !reflect.DeepEqual(service.details, selected) {
		t.Fatalf("must call server without switching Context: err=%v service=%+v", err, service)
	}
	if !bytes.Equal(result.Error, body) {
		t.Fatalf("server error changed: %s", result.Error)
	}
	if len(result.Contexts) != 2 || !result.Contexts[0].Current {
		t.Fatalf("Contexts changed: %+v", result.Contexts)
	}
	// Discovery can be stale: a missing catalog permission must not override server success.
	service.err, service.status = nil, "ready"
	result, err = (&App{stderr: &stderr}).requestAccess(context.Background(), service, catalog.ResourceServer{ConnectionStatus: "not_required"}, []string{"applications:read"}, details, selected, "saved_default", "inspect", access.RequestOptions{})
	if err != nil || result.Status != "ready" || len(result.Error) != 0 || service.calls != 2 {
		t.Fatalf("server decision ignored: %+v %v", result, err)
	}
}

func TestAccessResultsKeepContextMetadataAndExternalExpansion(t *testing.T) {
	// [spec: cli/access-context-preflight]
	for _, external := range []bool{false, true} {
		for _, status := range []string{"pending", "ready"} {
			details := authorityContexts()[1:]
			server := catalog.ResourceServer{CommandName: "platform", ConnectionStatus: "not_required"}
			if external {
				server.ConnectionStatus = "connected"
				details[0].AccountAuthorizationStatus = "authorized"
				details[0].AuthorizedScopes, details[0].RequestableScopes = nil, nil
			}
			selected := []map[string]any{details[0].AuthorizationDetail}
			service := &accessRecorder{status: status}
			var stderr bytes.Buffer
			result, err := (&App{stderr: &stderr, json: true}).requestAccess(context.Background(), service, server, []string{" permissions:read ", "permissions:read"}, details, selected, "command_line", "inspect", access.RequestOptions{Handoff: true})
			if err != nil || service.calls != 1 || result.Status != status || !reflect.DeepEqual(service.details, selected) || !reflect.DeepEqual(service.scopes, []string{"permissions:read"}) {
				t.Fatalf("external=%v result=%+v err=%v service=%+v", external, result, err, service)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"id":"org-1"`, `"type":"organization"`, `"source":"command_line"`} {
				if !bytes.Contains(encoded, []byte(want)) {
					t.Fatalf("missing %s in %s", want, encoded)
				}
			}
			if stderr.Len() == 0 {
				t.Fatal("missing pre-approval diagnostics in JSON mode")
			}
		}
	}
}

func TestContextSelectionReportsSourceWithoutChangingDefault(t *testing.T) {
	// [spec: cli/access-context-preflight]
	t.Setenv("REALMROOT_STATE_DIR", t.TempDir())
	service, err := agent.NewService("https://id.example.com", http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	server := catalog.ResourceServer{ResourceURL: "https://api.example.com"}
	details := authorityContexts()
	app := &App{}
	_, source, err := app.resolveContextSelection(service, server, details[:1], "")
	if err != nil || source != "only_available" {
		t.Fatalf("source=%s err=%v", source, err)
	}
	if err := service.StoreContext(server.ResourceURL, []map[string]any{details[0].AuthorizationDetail}); err != nil {
		t.Fatal(err)
	}
	selected, source, err := app.resolveContextSelection(service, server, details, "org-1")
	if err != nil || source != "command_line" || !sameDetails(details[1].AuthorizationDetail, selected) {
		t.Fatalf("source=%s selected=%v err=%v", source, selected, err)
	}
	selected, source, err = app.resolveContextSelection(service, server, details, "")
	if err != nil || source != "saved_default" || !sameDetails(details[0].AuthorizationDetail, selected) {
		t.Fatalf("source=%s selected=%v err=%v", source, selected, err)
	}
}
