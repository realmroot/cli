package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRootHelpExposesOnlyProductCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	command := New(&stdout, &stderr)
	command.SetArgs([]string{"--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	for _, expected := range []string{"agent", "toolbox"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("help omitted %s:\n%s", expected, output)
		}
	}
	for _, hidden := range []string{"plugin", "cache", "cert"} {
		if strings.Contains(output, hidden) {
			t.Fatalf("help exposed %s:\n%s", hidden, output)
		}
	}
}

func TestToolboxHelpDoesNotCallRealmroot(t *testing.T) {
	var stdout, stderr bytes.Buffer
	command := New(&stdout, &stderr)
	command.SetArgs([]string{"toolbox", "--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Discover and operate Resource Servers") {
		t.Fatalf("help = %q", stdout.String())
	}
}

func TestParseToolboxFlags(t *testing.T) {
	app := &App{}
	args, err := app.parseToolboxFlags([]string{"--json", "github", "repos", "get"})
	if err != nil || !app.json || strings.Join(args, " ") != "github repos get" {
		t.Fatalf("args=%v json=%v err=%v", args, app.json, err)
	}
}

func TestServicesUseBoundedHTTPClient(t *testing.T) {
	app := &App{origin: "https://id.realmroot.dev"}
	_, _, httpClient, err := app.services()
	if err != nil {
		t.Fatal(err)
	}
	if httpClient.Timeout != 30*time.Second {
		t.Fatalf("HTTP timeout = %s, want 30s", httpClient.Timeout)
	}
}
