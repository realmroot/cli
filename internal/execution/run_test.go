package execution

import (
	"strings"
	"testing"
)

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
