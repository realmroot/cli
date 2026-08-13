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
