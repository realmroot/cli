package cli

import (
	"bytes"
	"encoding/json"
	"github.com/realmroot/cli/internal/catalog"
	"reflect"
	"strings"
	"testing"
)

func TestContextListShowsPermissionNamesWithoutExtraFlags(t *testing.T) {
	// [spec: cli/resource-server-context]
	details := []catalog.AuthorizationDetail{
		{ID: "user-1", Name: "Ambor", AuthorizationDetail: map[string]any{"type": "realmroot_authority", "authority": "user", "id": "user-1"}, AuthorizedScopes: []string{"agents:read"}, RequestableScopes: []string{"agents:write"}},
		{ID: "org-1", Name: "Platform", AuthorizationDetail: map[string]any{"type": "realmroot_authority", "authority": "organization", "id": "org-1"}, AuthorizedScopes: []string{"applications:read"}},
	}
	items := listContexts(details, []map[string]any{details[0].AuthorizationDetail}, catalog.Scope{Value: "agents:read"}, catalog.Scope{Value: "agents:write"}, catalog.Scope{Value: "applications:read"})
	if len(items) != 2 || !items[0].Current || items[1].Current || !reflect.DeepEqual(items[0].UnavailableScopes, []string{"applications:read"}) || !reflect.DeepEqual(items[0].AuthorizedScopes, []string{"agents:read"}) || !reflect.DeepEqual(items[0].RequestableScopes, []string{"agents:write"}) {
		t.Fatalf("incorrect Context list: %+v", items)
	}
	for _, asJSON := range []bool{false, true} {
		var output bytes.Buffer
		app := &App{stdout: &output, json: asJSON}
		if err := app.printContexts(contextResult{ResourceServer: "platform", Contexts: items}); err != nil {
			t.Fatal(err)
		}
		for _, expected := range []string{"Ambor", "Platform", "user-1", "org-1", "agents:read", "agents:write", "applications:read"} {
			if !strings.Contains(output.String(), expected) {
				t.Fatalf("list omitted %s: %s", expected, &output)
			}
		}
		if asJSON {
			var result contextResult
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.Contexts, items) {
				t.Fatalf("JSON changed permission facts: %s", &output)
			}
		}
	}
}
