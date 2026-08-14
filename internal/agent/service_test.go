package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const secondCredentialSourceReference = "rrcs_ZmVkY2JhOTg3NjU0MzIxMA"

func TestExecutionIdentityUsesImmutableUsernameForGitAttribution(t *testing.T) {
	// [spec: cli/native-resource-tool]
	service, _ := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"contents:write"}),
	})
	configuration := decodedAgentConfiguration(t)
	if err := service.states.StoreAgentConfiguration(service.origin, configuration, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	target := agentTarget{
		Runtime: defaultAgentRuntime, Origin: service.origin, Issuer: configuration.AgentIdentityIssuer,
	}
	state, err := service.states.Load(target)
	if err != nil {
		t.Fatal(err)
	}
	state.Name = "A Mutable Display Name"
	state.Identity.Subject = "opaque-and-unreadable-subject"
	state.Identity.Username = "codex.019feeeb650474ecbfdcda5259f73fc0"
	if err := service.states.Update(target, state); err != nil {
		t.Fatal(err)
	}

	identity, err := service.ExecutionIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if identity.Name != "codex.019feeeb650474ecbfdcda5259f73fc0" || identity.Email != "codex.019feeeb650474ecbfdcda5259f73fc0@agents.realmroot.dev" {
		t.Fatalf("execution identity = %#v", identity)
	}
}

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

func TestClearContextRemovesOnlyTheSelectedResource(t *testing.T) {
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}),
	})
	otherResource := "https://api.example.com/other"
	if err := service.StoreContext(resource, []map[string]any{{"type": "workspace", "identifier": "workspace-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := service.StoreContext(otherResource, []map[string]any{{"type": "account", "identifier": "account-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := service.ClearContext(resource); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SelectedContext(resource); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleared Context error = %v", err)
	}
	if _, err := service.SelectedContext(otherResource); err != nil {
		t.Fatalf("unrelated Context was removed: %v", err)
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

func TestExecutionBindingStartsWithOneApprovedAuthoritySet(t *testing.T) {
	// [spec: cli/native-resource-tool]
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(
			t,
			"workspace-1",
			[]string{"contents:write"},
			[]string{"metadata:read"},
		),
	})
	details := []map[string]any{{"type": "workspace", "identifier": "workspace-1"}}

	binding, err := service.ExecutionBinding(resource, details)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Reference != testCredentialSourceReference || len(binding.Scopes) != 1 || binding.Scopes[0] != "contents:write" {
		t.Fatalf("initial execution binding = %#v", binding)
	}

	readBinding, err := service.BindingForReferenceScopeAlternatives(
		resource,
		binding.Reference,
		[][]string{{"metadata:read"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(readBinding.Scopes) != 1 || readBinding.Scopes[0] != "metadata:read" {
		t.Fatalf("challenged execution binding = %#v", readBinding)
	}
}

func TestExecutionBindingUsesOneApprovedSetFromTheActiveSource(t *testing.T) {
	// [spec: cli/native-resource-tool]
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(
			t,
			"workspace-1",
			[]string{"contents:read"},
			[]string{"contents:write"},
		),
	})
	writeActiveBindings(t, service, 2, map[string]any{
		resource: map[string]any{
			"reference": testCredentialSourceReference,
			"scopes":    []string{"contents:read", "contents:write"},
		},
	})

	binding, err := service.ExecutionBinding(resource, nil)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Reference != testCredentialSourceReference || len(binding.Scopes) != 1 || binding.Scopes[0] != "contents:read" {
		t.Fatalf("execution binding = %#v", binding)
	}
}

func TestExecutionBindingSelectsTheOnlySourceWithoutAContext(t *testing.T) {
	// [spec: cli/native-resource-tool]
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}),
	})

	binding, err := service.ExecutionBinding(resource, nil)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Reference != testCredentialSourceReference || len(binding.Scopes) != 1 || binding.Scopes[0] != "files:read" {
		t.Fatalf("execution binding = %#v", binding)
	}
	active, err := service.ActiveBindingForResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	if active.Reference != binding.Reference || len(active.Scopes) != 1 || active.Scopes[0] != "files:read" {
		t.Fatalf("active binding = %#v", active)
	}
}

func TestExecutionBindingRejectsAnAmbiguousContext(t *testing.T) {
	// [spec: cli/native-resource-tool]
	service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
		testCredentialSourceReference:   sourceWithScopes(t, "workspace-1", []string{"files:read"}),
		secondCredentialSourceReference: sourceWithScopes(t, "workspace-2", []string{"files:read"}),
	})

	_, err := service.ExecutionBinding(resource, nil)
	if !errors.Is(err, ErrAuthorizationContextAmbiguous) {
		t.Fatalf("error = %v", err)
	}
}

func TestExecutionBindingReportsMissingAndInvalidAuthorityState(t *testing.T) {
	// [spec: cli/native-resource-tool]
	t.Run("missing", func(t *testing.T) {
		t.Setenv("AGENT", defaultAgentRuntime)
		service := &Service{states: &fileStateStore{root: t.TempDir()}}
		if _, err := service.ExecutionBinding("https://resource.example", nil); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("invalid runtime", func(t *testing.T) {
		service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
			testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}),
		})
		t.Setenv("AGENT", "!")
		if _, err := service.ExecutionBinding(resource, nil); err == nil {
			t.Fatal("invalid runtime was accepted")
		}
	})

	t.Run("invalid active binding", func(t *testing.T) {
		service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
			testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}),
		})
		if err := os.WriteFile(filepath.Join(service.states.root, "bindings.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := service.ExecutionBinding(resource, nil); err == nil {
			t.Fatal("invalid active binding was accepted")
		}
	})

	t.Run("previous active binding version", func(t *testing.T) {
		service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
			testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}),
		})
		writeActiveBindings(t, service, 1, map[string]any{resource: testCredentialSourceReference})
		if _, err := service.ExecutionBinding(resource, nil); err == nil || !strings.Contains(err.Error(), "unsupported version") {
			t.Fatalf("previous active binding version was not rejected: %v", err)
		}
	})

	t.Run("unwritable active binding", func(t *testing.T) {
		service, resource := serviceWithCredentialSources(t, map[string]credentialSource{
			testCredentialSourceReference: sourceWithScopes(t, "workspace-1", []string{"files:read"}),
		})
		if err := os.Chmod(service.states.root, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(service.states.root, 0o700) })
		if _, err := service.ExecutionBinding(resource, nil); err == nil {
			t.Fatal("unwritable active binding was accepted")
		}
	})
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

func decodedAgentConfiguration(t *testing.T) agentConfiguration {
	t.Helper()
	encoded, err := json.Marshal(testAgentConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	var configuration agentConfiguration
	if err := json.Unmarshal(encoded, &configuration); err != nil {
		t.Fatal(err)
	}
	return configuration
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
