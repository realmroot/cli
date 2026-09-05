package cli

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/realmroot/cli/internal/access"
	"github.com/realmroot/cli/internal/agent"
	"github.com/realmroot/cli/internal/catalog"
)

type authorityFixture struct {
	binding   agent.CredentialBinding
	err       error
	requested []string
	handoff   bool
}

func (f *authorityFixture) BindingForAuthorizationContextAllAuthority(string, []map[string]any) (agent.CredentialBinding, error) {
	return f.binding, f.err
}
func (f *authorityFixture) Request(_ context.Context, _ catalog.ResourceServer, scopes []string, _ []map[string]any, _ string, options access.RequestOptions) (access.Receipt, error) {
	f.requested = scopes
	f.handoff = options.Handoff
	return access.Receipt{Status: "ready"}, nil
}
func TestNewSessionAcquiresOnlyExistingContextPermissions(t *testing.T) {
	selected := []map[string]any{{"type": "workspace", "identifier": "one"}}
	details := []catalog.AuthorizationDetail{{AuthorizationDetail: selected[0], AuthorizedScopes: []string{"contents:read"}, RequestableScopes: []string{"contents:write"}}}
	fixture := &authorityFixture{err: os.ErrNotExist}
	if err := acquireExistingAuthority(context.Background(), fixture, fixture, catalog.ResourceServer{ResourceURL: "https://example.test"}, details, selected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture.requested, []string{"contents:read"}) || !fixture.handoff {
		t.Fatalf("unexpected request: %#v", fixture)
	}
}
func TestExistingLocalAuthorityDoesNotRequestAgain(t *testing.T) {
	selected := []map[string]any{{"type": "workspace", "identifier": "one"}}
	details := []catalog.AuthorizationDetail{{AuthorizationDetail: selected[0], AuthorizedScopes: []string{"contents:read"}}}
	fixture := &authorityFixture{binding: agent.CredentialBinding{Scopes: []string{"contents:read"}}}
	if err := acquireExistingAuthority(context.Background(), fixture, fixture, catalog.ResourceServer{}, details, selected); err != nil {
		t.Fatal(err)
	}
	if fixture.requested != nil {
		t.Fatal("requested existing local authority")
	}
}
func TestNoGrantDoesNotStartAnApproval(t *testing.T) {
	fixture := &authorityFixture{err: os.ErrNotExist}
	if err := acquireExistingAuthority(context.Background(), fixture, fixture, catalog.ResourceServer{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if fixture.requested != nil {
		t.Fatal("requested ungranted authority")
	}
}
