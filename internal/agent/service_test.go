package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const secondCredentialSourceReference = "rrcs_ZmVkY2JhOTg3NjU0MzIxMA"

func TestSelectedContextIsIndependentFromCredentialBindings(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}),
	})
	details := []map[string]any{{"type": "workspace", "identifier": "workspace-2"}}
	if err := service.StoreContext(resource, details); err != nil {
		t.Fatal(err)
	}
	selected, err := service.SelectedContext(resource)
	if err != nil {
		t.Fatal(err)
	}
	if !sameAuthorizationDetails(selected, details) {
		t.Fatalf("selected Context = %#v", selected)
	}
	if _, err := service.activeBinding(resource); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Context selection changed credential binding: %v", err)
	}
}

func TestBindingForScopeAlternativesReusesOlderOfferInActiveContext(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}, []string{"files:write"}),
	})
	writeActiveBindings(t, service, 2, map[string]any{
		resource: map[string]any{"reference": testCredentialSourceReference, "scopes": []string{"files:write"}},
	})

	binding, err := service.BindingForScopeAlternatives(resource, [][]string{{"files:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Reference != testCredentialSourceReference || len(binding.Scopes) != 1 || binding.Scopes[0] != "files:read" {
		t.Fatalf("binding = %#v", binding)
	}
	active, err := service.ActiveBindingForResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Scopes) != 1 || active.Scopes[0] != "files:read" {
		t.Fatalf("active binding = %#v", active)
	}
}

func TestBindingForScopeAlternativesSelectsUniqueMatchingAuthorizationContext(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference:   sourceWithScopes(t, "workspace-1", []string{"files:write"}),
		secondCredentialSourceReference: sourceWithScopes(t, "workspace-2", []string{"files:read"}),
	})
	writeActiveBindings(t, service, 2, map[string]any{
		resource: map[string]any{"reference": testCredentialSourceReference, "scopes": []string{"files:write"}},
	})

	binding, err := service.BindingForScopeAlternatives(resource, [][]string{{"files:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Reference != secondCredentialSourceReference || len(binding.Scopes) != 1 || binding.Scopes[0] != "files:read" {
		t.Fatalf("binding = %#v", binding)
	}
	stored, err := service.activeBinding(resource)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Reference != secondCredentialSourceReference {
		t.Fatalf("active binding = %#v", stored)
	}
}

func TestBindingForScopeAlternativesRejectsAmbiguousAuthorizationContexts(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference:   sourceWithScopes(t, "workspace-1", []string{"files:read"}),
		secondCredentialSourceReference: sourceWithScopes(t, "workspace-2", []string{"files:read"}),
	})

	_, err := service.BindingForScopeAlternatives(resource, [][]string{{"files:read"}})
	if !errors.Is(err, ErrAuthorizationContextAmbiguous) {
		t.Fatalf("error = %v", err)
	}
}

func TestBindingForResourceReportsEveryOfferInActiveContext(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}, []string{"files:write"}),
	})
	writeActiveBindings(t, service, 2, map[string]any{
		resource: map[string]any{"reference": testCredentialSourceReference, "scopes": []string{"files:write"}},
	})

	binding, err := service.BindingForResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	if len(binding.Scopes) != 2 || binding.Scopes[0] != "files:read" || binding.Scopes[1] != "files:write" {
		t.Fatalf("binding scopes = %#v", binding.Scopes)
	}
}

func TestActiveBindingForResourceKeepsExactOfferForNativeTools(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}, []string{"files:write"}),
	})
	writeActiveBindings(t, service, 2, map[string]any{
		resource: map[string]any{"reference": testCredentialSourceReference, "scopes": []string{"files:write"}},
	})

	binding, err := service.ActiveBindingForResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	if len(binding.Scopes) != 1 || binding.Scopes[0] != "files:write" {
		t.Fatalf("binding scopes = %#v", binding.Scopes)
	}
}

func TestAuthorizationContextsSelectsAnExistingContextWithoutExposingItsReference(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference:   sourceWithScopes(t, "workspace-1", []string{"files:write"}, []string{"files:read"}),
		secondCredentialSourceReference: sourceWithScopes(t, "workspace-2", []string{"files:read"}),
	})
	writeActiveBindings(t, service, 2, map[string]any{
		resource: map[string]any{"reference": testCredentialSourceReference, "scopes": []string{"files:write"}},
	})

	contexts, err := service.AuthorizationContexts(resource)
	if err != nil {
		t.Fatal(err)
	}
	if len(contexts) != 2 || !contexts[0].Active || contexts[1].Active {
		t.Fatalf("contexts = %#v", contexts)
	}
	selected, err := service.SelectAuthorizationContext(resource, []map[string]any{{"type": "workspace", "identifier": "workspace-2"}})
	if err != nil {
		t.Fatal(err)
	}
	if !selected.Active || len(selected.Scopes) != 1 || selected.Scopes[0] != "files:read" {
		t.Fatalf("selected = %#v", selected)
	}
	active, err := service.ActiveBindingForResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	if active.Reference != secondCredentialSourceReference || len(active.Scopes) != 1 || active.Scopes[0] != "files:read" {
		t.Fatalf("active = %#v", active)
	}
}

func TestBindingForAuthorizationContextDoesNotChangeTheActiveContext(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference:   sourceWithScopes(t, "workspace-1", []string{"files:read"}),
		secondCredentialSourceReference: sourceWithScopes(t, "workspace-2", []string{"files:write"}),
	})
	writeActiveBindings(t, service, 2, map[string]any{
		resource: map[string]any{"reference": testCredentialSourceReference, "scopes": []string{"files:read"}},
	})

	binding, _, err := service.BindingForAuthorizationContext(resource, []map[string]any{{"type": "workspace", "identifier": "workspace-2"}})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Reference != secondCredentialSourceReference {
		t.Fatalf("binding = %#v", binding)
	}
	active, err := service.ActiveBindingForResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	if active.Reference != testCredentialSourceReference {
		t.Fatalf("active binding changed = %#v", active)
	}
}

func TestBindingForReferenceScopeAlternativesNeverSwitchesAuthorizationContext(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference:   sourceWithScopes(t, "workspace-1", []string{"files:read"}),
		secondCredentialSourceReference: sourceWithScopes(t, "workspace-2", []string{"files:write"}),
	})

	_, err := service.BindingForReferenceScopeAlternatives(resource, testCredentialSourceReference, [][]string{{"files:write"}})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v", err)
	}
	binding, err := service.BindingForReferenceScopeAlternatives(resource, secondCredentialSourceReference, [][]string{{"files:write"}})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Reference != secondCredentialSourceReference || len(binding.Scopes) != 1 || binding.Scopes[0] != "files:write" {
		t.Fatalf("binding = %#v", binding)
	}
}

func sourceWithScopes(t *testing.T, workspace string, scopeSets ...[]string) credentialSource {
	t.Helper()
	offers := make([]dpopCredential, 0, len(scopeSets))
	for index, scopes := range scopeSets {
		offer := testCredential(t, "", time.Time{})
		offer.AuthorizationDetails = []map[string]any{{"type": "workspace", "identifier": workspace}}
		offer.Scopes = append([]string(nil), scopes...)
		offer.CredentialEndpoint = "https://auth.example.com/api/access-requests/request-" + workspace + "-" + string(rune('a'+index)) + "/credentials"
		offers = append(offers, offer)
	}
	return credentialSource{
		ResourceIndicator: offers[0].ResourceIndicator, AuthorizationDetails: offers[0].AuthorizationDetails, Offers: offers,
	}
}

func serviceWithCredentialSources(t *testing.T, sources map[string]credentialSource) (*Service, string) {
	t.Helper()
	t.Setenv("AGENT", defaultAgentRuntime)
	memory := newCredentialState(t, testCredential(t, "", time.Time{}))
	memory.state.CredentialSources = sources
	store := &fileStateStore{root: t.TempDir()}
	target := agentTarget{Runtime: defaultAgentRuntime, Origin: memory.state.Origin, Issuer: memory.state.Issuer}
	path := store.path(target)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(memory.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		return &Service{origin: memory.state.Origin, states: store}, source.ResourceIndicator
	}
	t.Fatal("test requires a credential source")
	return nil, ""
}

func writeActiveBindings(t *testing.T, service *Service, version int, items map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"version": version, "items": items})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(service.states.root, "bindings.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
