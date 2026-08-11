package access

import "testing"

func TestNormalizedScopes(t *testing.T) {
	got := normalizedScopes([]string{" contents:read ", "metadata:read", "contents:read", ""})
	want := []string{"contents:read", "metadata:read"}
	if len(got) != len(want) {
		t.Fatalf("scopes = %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("scopes = %#v", got)
		}
	}
}

func TestAuthorizationDetailRequiresStringValues(t *testing.T) {
	if _, _, err := detail(map[string]any{"type": "github_installation", "installation_id": 123}); err == nil {
		t.Fatal("numeric authorization detail was accepted")
	}
	typeName, values, err := detail(map[string]any{"type": "github_installation", "installation_id": "123"})
	if err != nil || typeName != "github_installation" || values["installation_id"] != "123" {
		t.Fatalf("detail = %q %#v, err = %v", typeName, values, err)
	}
}
