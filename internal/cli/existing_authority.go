package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/realmroot/cli/internal/access"
	"github.com/realmroot/cli/internal/agent"
	"github.com/realmroot/cli/internal/catalog"
)

type existingAuthorityStore interface {
	BindingForAuthorizationContextAllAuthority(string, []map[string]any) (agent.CredentialBinding, error)
}
type existingAuthorityRequester interface {
	Request(context.Context, catalog.ResourceServer, []string, []map[string]any, string, access.RequestOptions) (access.Receipt, error)
}

func acquireExistingAuthority(ctx context.Context, store existingAuthorityStore, requester existingAuthorityRequester, server catalog.ResourceServer, contexts []catalog.AuthorizationDetail, selected []map[string]any) error {
	var scopes []string
	for _, detail := range contexts {
		if sameDetails(detail.AuthorizationDetail, selected) {
			scopes = slices.Clone(detail.AuthorizedScopes)
			slices.Sort(scopes)
			scopes = slices.Compact(scopes)
			break
		}
	}
	if len(scopes) == 0 {
		return nil
	}
	binding, err := store.BindingForAuthorizationContextAllAuthority(server.ResourceURL, selected)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && allScopesPresent(scopes, binding.Scopes) {
		return nil
	}
	receipt, err := requester.Request(ctx, server, scopes, selected, "Acquire existing Agent permissions for this Session", access.RequestOptions{Handoff: true})
	if err != nil {
		return err
	}
	if receipt.Status != "ready" {
		return fmt.Errorf("previously granted %s permissions are no longer available; request access explicitly", server.CommandName)
	}
	return nil
}
func allScopesPresent(required, available []string) bool {
	for _, scope := range required {
		if !slices.Contains(available, scope) {
			return false
		}
	}
	return true
}
