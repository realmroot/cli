package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/realmroot/toolbox/internal/catalog"
	restish "github.com/saltbo/restish/v2"
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
	args, err := app.parseToolboxFlags([]string{"--json", "--search", "list zones", "--scope=zone.read", "--profile=staging", "--content-type", "json", "--validate", "github", "repos", "get"})
	if err != nil || !app.json || app.search != "list zones" || app.scope != "zone.read" || app.profile != "staging" || strings.Join(args, " ") != "--rsh-profile=staging --rsh-content-type json --rsh-validate github repos get" {
		t.Fatalf("args=%v json=%v search=%q scope=%q profile=%v err=%v", args, app.json, app.search, app.scope, app.profile, err)
	}
}

func TestParseToolboxFlagsPreservesArgumentsAfterSeparator(t *testing.T) {
	app := &App{}
	args, err := app.parseToolboxFlags([]string{"post", "https://example.com", "--", "--no-browser"})
	if err != nil || app.noBrowser || strings.Join(args, " ") != "post https://example.com -- --no-browser" {
		t.Fatalf("args=%v noBrowser=%v err=%v", args, app.noBrowser, err)
	}
}

func TestParseToolboxFlagsPreservesOperationScopeFlag(t *testing.T) {
	app := &App{}
	args, err := app.parseToolboxFlags([]string{"cloudflare", "workers", "list", "--scope", "provider-value"})
	if err != nil || app.scope != "" || strings.Join(args, " ") != "cloudflare workers list --scope provider-value" {
		t.Fatalf("args=%v discoveryScope=%q err=%v", args, app.scope, err)
	}
}

func TestParseToolboxFlagsRejectsEmptyDiscoveryQuery(t *testing.T) {
	app := &App{}
	if _, err := app.parseToolboxFlags([]string{"cloudflare", "--search", "  "}); err == nil {
		t.Fatal("expected empty --search to fail")
	}
}

func TestToolboxRuntimeErrorUsesProductVocabulary(t *testing.T) {
	err := toolboxRuntimeError{cause: errors.New("Restish rejected --rsh-output-format in restish config")}
	if got := err.Error(); got != "Toolbox rejected --output in toolbox config" {
		t.Fatalf("error = %q", got)
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

func TestResourceServerSummariesDoNotIncludePublishedScopes(t *testing.T) {
	summaries := summarizeResourceServers([]catalog.ResourceServer{{
		ID: "server-1", CommandName: "cloudflare", Identifier: "cloudflare", Name: "Cloudflare",
		ConnectionStatus: "connected", ConnectionScopes: []string{"zone.read"},
		Scopes: []catalog.Scope{{Value: "zone.read"}, {Value: "zone.write"}},
	}})
	encoded, err := json.Marshal(summaries)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	if strings.Contains(output, `"scopes"`) || !strings.Contains(output, `"scopeCount":2`) || !strings.Contains(output, `"authorizedScopes":["zone.read"]`) {
		t.Fatalf("summary JSON = %s", output)
	}
}

func TestSmallResourceServerOverviewIncludesCompleteInventory(t *testing.T) {
	server := catalog.ResourceServer{CommandName: "wallet", Scopes: []catalog.Scope{{Value: "wallet:read"}}}
	details := []catalog.AuthorizationDetail{{Name: "wallet"}}
	operations := []restish.OperationInspection{{ID: "showWallet", Command: []string{"wallet", "show"}, Method: "GET"}}

	overview := buildResourceServerOverview(server, details, operations, discoveryOptions{})

	if overview.Mode != overviewModeExpanded || len(overview.Scopes) != 1 || len(overview.AuthorizationDetails) != 1 || len(overview.Operations) != 1 {
		t.Fatalf("overview = %#v", overview)
	}
}

func TestLargeResourceServerOverviewIsCompact(t *testing.T) {
	server := catalog.ResourceServer{CommandName: "cloudflare", ConnectionScopes: []string{"zone.read"}, Scopes: make([]catalog.Scope, 252)}
	operations := makeOperations(2652)

	overview := buildResourceServerOverview(server, nil, operations, discoveryOptions{})

	if overview.Mode != overviewModeCompact || len(overview.Scopes) != 0 || len(overview.Operations) != 0 {
		t.Fatalf("overview = %#v", overview)
	}
	if overview.ScopeCount != 252 || overview.OperationCount != 2652 {
		t.Fatalf("counts = scopes %d, operations %d", overview.ScopeCount, overview.OperationCount)
	}
}

func TestResourceServerSearchIsBoundedAndKeepsOperationSecurity(t *testing.T) {
	server := catalog.ResourceServer{CommandName: "cloudflare", Scopes: make([]catalog.Scope, 252)}
	operations := makeOperations(80)
	for index := range operations {
		operations[index].Summary = "List worker routes"
		operations[index].CredentialAlternatives = [][]restish.CredentialRequirementInspection{{{ID: "oauth2", Needs: []string{"workers-routes.read"}}}}
	}

	overview := buildResourceServerOverview(server, nil, operations, discoveryOptions{Search: "worker routes"})

	if overview.Mode != overviewModeFiltered || overview.MatchCount != 80 || len(overview.Operations) != maxDiscoveryResults || !overview.Truncated {
		t.Fatalf("overview = %#v", overview)
	}
	if got := operationScopeSummary(overview.Operations[0]); got != "workers-routes.read" {
		t.Fatalf("scope summary = %q", got)
	}
}

func TestResourceServerSearchDoesNotCombineTermsAcrossFields(t *testing.T) {
	operations := []restish.OperationInspection{
		{ID: "listCertificates", Command: []string{"zone", "certificates"}, Summary: "List certificates"},
		{ID: "listZones", Command: []string{"zone", "list"}, Summary: "List Zones"},
	}

	matched := filterOperations(operations, discoveryOptions{Search: "list zones"})

	if len(matched) != 1 || matched[0].ID != "listZones" {
		t.Fatalf("matched = %#v", matched)
	}
}

func TestResourceServerSearchRanksExactSummaryFirst(t *testing.T) {
	operations := []restish.OperationInspection{
		{ID: "zonesContentList", Command: []string{"zones", "content-list"}, Summary: "List content"},
		{ID: "listZones", Command: []string{"zone", "list"}, Summary: "List Zones"},
	}

	matched := filterOperations(operations, discoveryOptions{Search: "list zones"})

	if len(matched) != 2 || matched[0].ID != "listZones" {
		t.Fatalf("matched = %#v", matched)
	}
}

func TestResourceServerAllExplicitlyExpandsLargeInventory(t *testing.T) {
	server := catalog.ResourceServer{CommandName: "cloudflare", Scopes: make([]catalog.Scope, 252)}
	operations := makeOperations(80)

	overview := buildResourceServerOverview(server, nil, operations, discoveryOptions{All: true})

	if overview.Mode != overviewModeExpanded || len(overview.Scopes) != 252 || len(overview.Operations) != 80 || overview.Truncated {
		t.Fatalf("overview = %#v", overview)
	}
}

func TestOperationScopeSummaryIncludesOnlyScopesAndDeduplicates(t *testing.T) {
	operation := restish.OperationInspection{CredentialAlternatives: [][]restish.CredentialRequirementInspection{
		{{ID: "oauth2", Needs: []string{"agents:read"}}},
		{{ID: "anotherOAuth", Needs: []string{"agents:read"}}},
		{{ID: "bearerAuth"}},
		{{ID: "cookieAuth"}},
	}}

	if got := operationScopeSummary(operation); got != "agents:read" {
		t.Fatalf("scope summary = %q", got)
	}
}

func TestOperationScopeSummaryIsEmptyWithoutScopes(t *testing.T) {
	operation := restish.OperationInspection{CredentialAlternatives: [][]restish.CredentialRequirementInspection{
		{{ID: "bearerAuth"}},
		{{ID: "cookieAuth"}},
	}}

	if got := operationScopeSummary(operation); got != "" {
		t.Fatalf("scope summary = %q", got)
	}
}

func TestFilteredOverviewOmitsScopeLineWithoutScopes(t *testing.T) {
	var stdout bytes.Buffer
	app := &App{stdout: &stdout}
	overview := resourceServerOverview{
		ResourceServer: resourceServerSummary{CommandName: "example", Identifier: "example"},
		Mode:           overviewModeFiltered, MatchCount: 1,
		Operations: []restish.OperationInspection{{Command: []string{"things", "list"}, Method: "GET"}},
	}

	if err := app.printResourceServerOverview(overview); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "scopes:") {
		t.Fatalf("output contains an empty scope line:\n%s", stdout.String())
	}
}

func makeOperations(count int) []restish.OperationInspection {
	operations := make([]restish.OperationInspection, count)
	for index := range operations {
		operations[index] = restish.OperationInspection{
			ID: "operation", Command: []string{"workers", "list"}, Method: "GET", Path: "/workers",
		}
	}
	return operations
}
