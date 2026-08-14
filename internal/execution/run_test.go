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
