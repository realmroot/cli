package cli

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/realmroot/toolbox/internal/agent"
	"github.com/realmroot/toolbox/internal/catalog"
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

func TestResolveContextGuidesAMissingNamedContextToConnections(t *testing.T) {
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
		Name: "existing-org", AuthorizationDetail: map[string]any{"type": "installation", "installation_id": "701"},
	}}

	selected, err := (&App{}).resolveContext(service, server, existing, "new-org")
	if selected != nil || err == nil {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}
	want := `Context "new-org" is not available; connect or update it in Realmroot Connections: https://id.example.com/connections`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

func TestNamedContextUsesAUniqueCaseInsensitiveProviderName(t *testing.T) {
	detail := catalog.AuthorizationDetail{
		Name:                "wakatoken",
		AuthorizationDetail: map[string]any{"type": "installation", "installation_id": "702"},
	}
	selected, err := namedContext([]catalog.AuthorizationDetail{detail}, "WakaToken")
	if err != nil {
		t.Fatal(err)
	}
	if !sameDetails(detail.AuthorizationDetail, []map[string]any{selected.AuthorizationDetail}) {
		t.Fatalf("selected Context = %#v", selected)
	}
}

func TestNamedContextPrefersExactCaseAndRejectsFoldedAmbiguity(t *testing.T) {
	details := []catalog.AuthorizationDetail{
		{Name: "wakatoken", AuthorizationDetail: map[string]any{"installation_id": "701"}},
		{Name: "WakaToken", AuthorizationDetail: map[string]any{"installation_id": "702"}},
	}
	selected, err := namedContext(details, "WakaToken")
	if err != nil || selected.AuthorizationDetail["installation_id"] != "702" {
		t.Fatalf("exact selected=%#v err=%v", selected, err)
	}
	if _, err := namedContext(details, "WAKATOKEN"); err == nil || err.Error() != `Context name "WAKATOKEN" is ambiguous` {
		t.Fatalf("folded ambiguity error = %v", err)
	}
}
