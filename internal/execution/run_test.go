package execution

import (
	"slices"
	"strings"
	"testing"
)

func TestIntersectScopesDropsRevokedAuthority(t *testing.T) {
	got := intersectScopes(
		[]string{"administration:write", "contents:write", "metadata:read"},
		[]string{"contents:write", "metadata:read"},
	)
	if !slices.Equal(got, []string{"contents:write", "metadata:read"}) {
		t.Fatalf("effective scopes = %v", got)
	}
}

func TestPermittedScopeAlternativeUsesCompletePublishedAlternative(t *testing.T) {
	got, err := permittedScopeAlternative(
		[][]string{{"administration:write"}, {"metadata:read", "pull_requests:write"}},
		[]string{"metadata:read", "pull_requests:write"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"metadata:read", "pull_requests:write"}) {
		t.Fatalf("selected scopes = %v", got)
	}
	_, err = permittedScopeAlternative([][]string{{"administration:write"}}, []string{"metadata:read"})
	if err == nil || !strings.Contains(err.Error(), "outside the selected Resource Context") {
		t.Fatalf("error = %v", err)
	}
}

func TestExitErrorExplainsHowToRequestMissingNativeAuthority(t *testing.T) {
	errorText := (&ExitError{
		Code: 1, ResourceServer: "github",
		RequiredScopeAlternatives: [][]string{{"contents:write", "workflows:write"}},
	}).Error()
	for _, expected := range []string{
		"native command exited with status 1",
		"realmroot agent request --resource-server github --scope contents:write --scope workflows:write",
	} {
		if !strings.Contains(errorText, expected) {
			t.Fatalf("error = %q", errorText)
		}
	}
}
