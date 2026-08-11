package catalog

import "testing"

func TestResourceServerCommandName(t *testing.T) {
	tests := []struct {
		identifier, want string
		wantError        bool
	}{
		{identifier: "realmroot", want: "platform"},
		{identifier: "github", want: "github"},
		{identifier: "platform", wantError: true},
		{identifier: "get", wantError: true},
	}
	for _, test := range tests {
		got, err := resourceServerCommandName(test.identifier)
		if (err != nil) != test.wantError {
			t.Fatalf("%s error = %v", test.identifier, err)
		}
		if got != test.want {
			t.Fatalf("%s command = %q, want %q", test.identifier, got, test.want)
		}
	}
}
