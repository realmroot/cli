package cli

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/realmroot/cli/internal/agent"
	"github.com/realmroot/cli/internal/catalog"
)

func TestResolveContextClearsAStaleSelectionWhenTheCatalogIsEmpty(t *testing.T) {
	t.Setenv("REALMROOT_STATE_DIR", t.TempDir())
	service, err := agent.NewService("https://id.example.com", http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	server := catalog.ResourceServer{
		CommandName: "github",
		ResourceURL: "https://api.example.com",
	}
	if err := service.StoreContext(server.ResourceURL, []map[string]any{{
		"type": "workspace", "identifier": "removed",
	}}); err != nil {
		t.Fatal(err)
	}

	selected, err := (&App{}).resolveContext(service, server, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if selected != nil {
		t.Fatalf("selected Context = %#v", selected)
	}
	if _, err := service.SelectedContext(server.ResourceURL); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale Context still exists: %v", err)
	}
}

func TestResolveContextUsesResourceTemplatesBeforeTheAccountIsConnected(t *testing.T) {
	t.Setenv("REALMROOT_STATE_DIR", t.TempDir())
	service, err := agent.NewService("https://id.example.com", http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	template := map[string]any{"type": "https://api.example.com/authorization-details/workspace"}
	server := catalog.ResourceServer{
		CommandName: "example", ResourceURL: "https://api.example.com", ConnectionStatus: "not_connected",
		AuthorizationDetails: []map[string]any{template},
	}

	selected, err := (&App{}).resolveContext(service, server, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || !sameDetails(template, selected) {
		t.Fatalf("selected Context = %#v", selected)
	}
}

func TestResolveContextGuidesAMissingContextIDToConnections(t *testing.T) {
	// [spec: cli/missing-context-guidance]
	t.Setenv("REALMROOT_STATE_DIR", t.TempDir())
	service, err := agent.NewService("https://id.example.com", http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	server := catalog.ResourceServer{
		CommandName: "github", ResourceURL: "https://api.example.com", ConnectionStatus: "connected",
	}
	existing := []catalog.AuthorizationDetail{{
		ID: "ctx_existing", Name: "existing-org", AuthorizationDetail: map[string]any{"type": "installation", "installation_id": "701"},
	}}

	selected, err := (&App{}).resolveContext(service, server, existing, "ctx_missing")
	if selected != nil || err == nil {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}
	want := `Context ID "ctx_missing" is not available; connect or update it in Realmroot Connections: https://id.example.com/connections`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

func TestContextByIDSelectsStableIDDespiteDuplicateNames(t *testing.T) {
	// [spec: cli/resource-server-context]
	details := []catalog.AuthorizationDetail{
		{ID: "ctx_first", Name: "wakatoken", AuthorizationDetail: map[string]any{"installation_id": "701"}},
		{ID: "ctx_second", Name: "wakatoken", AuthorizationDetail: map[string]any{"installation_id": "702"}},
	}
	selected, err := contextBySelector(details, "ctx_second")
	if err != nil || selected.AuthorizationDetail["installation_id"] != "702" {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}
	if _, err := contextBySelector(details, "wakatoken"); err == nil || err.Error() != `Context ID "wakatoken" is not available` {
		t.Fatalf("name selection error = %v", err)
	}
}

func TestContextSelectorKeepsTemporaryNameCompatibilityOnlyWithoutIDs(t *testing.T) {
	detail := catalog.AuthorizationDetail{
		Name:                "legacy-workspace",
		AuthorizationDetail: map[string]any{"type": "workspace", "id": "workspace-1"},
	}
	selected, err := contextBySelector([]catalog.AuthorizationDetail{detail}, "LEGACY-WORKSPACE")
	if err != nil || !sameDetails(detail.AuthorizationDetail, []map[string]any{selected.AuthorizationDetail}) {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}
}
