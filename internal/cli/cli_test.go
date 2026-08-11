package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realmroot/toolbox/internal/agent"
	"github.com/realmroot/toolbox/internal/catalog"
	restish "github.com/saltbo/restish/v2"
)

func TestConfigureRestishPathsUsesVersionedCache(t *testing.T) {
	t.Setenv("RSH_CONFIG_DIR", "")
	t.Setenv("RSH_CACHE_DIR", "")
	if err := configureRestishPaths(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("RSH_CACHE_DIR"); !strings.HasSuffix(got, filepath.Join("realmroot", "restish", "v2")) {
		t.Fatalf("RSH_CACHE_DIR = %q", got)
	}
}

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
	for _, hidden := range []string{"--profile", "--auth", "--print", "Restish", "restish", "--rsh-"} {
		if strings.Contains(stdout.String(), hidden) {
			t.Fatalf("help exposed %q:\n%s", hidden, stdout.String())
		}
	}
}

func TestExecHelpExplainsDiscoveryAndExecution(t *testing.T) {
	var stdout, stderr bytes.Buffer
	command := New(&stdout, &stderr)
	command.SetArgs([]string{"exec", "--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	for _, expected := range []string{
		"Run without arguments to list every available native command",
		"realmroot exec github",
		"realmroot exec github -- git fetch origin",
		"realmroot exec cloudflare -- wrangler deployments list",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("help omitted %q:\n%s", expected, output)
		}
	}
}

func TestParseToolboxFlags(t *testing.T) {
	app := &App{}
	args, err := app.parseToolboxFlags([]string{"--json", "--search", "list zones", "--scope=zone.read", "--content-type", "json", "--validate", "github", "repos", "get"})
	if err != nil || !app.json || app.search != "list zones" || app.scope != "zone.read" || strings.Join(args, " ") != "--rsh-content-type json --rsh-validate github repos get" {
		t.Fatalf("args=%v json=%v search=%q scope=%q err=%v", args, app.json, app.search, app.scope, err)
	}
}

func TestParseExecFlagsPreservesNativeArgumentsAfterSeparator(t *testing.T) {
	app := &App{}
	args, options, err := app.parseExecFlags([]string{"--json", "--context", "realmroot", "github", "--", "gh", "pr", "list", "--json"})
	if err != nil || !app.json || strings.Join(args, " ") != "github -- gh pr list --json" {
		t.Fatalf("args=%v json=%v err=%v", args, app.json, err)
	}
	if options.context != "realmroot" {
		t.Fatalf("options = %#v", options)
	}
}

func TestResourceServerContextUsesDisplayContractWithoutRawDetails(t *testing.T) {
	// [spec: cli/resource-server-context]
	details := []catalog.AuthorizationDetail{{
		Name: "realmroot", Description: "Organization GitHub App installation",
		AuthorizationDetail:        map[string]any{"type": "github_installation", "installation_id": "42"},
		Metadata:                   map[string]string{"accountType": "Organization"},
		AccountAuthorizationStatus: "authorized", AuthorizedScopes: []string{"issues:read"},
	}}
	selected := []map[string]any{{"type": "github_installation", "installation_id": "42"}}
	summaries := listContexts(details, selected)
	encoded, err := json.Marshal(summaries)
	if err != nil {
		t.Fatal(err)
	}
	output := string(encoded)
	if !summaries[0].Current || !strings.Contains(output, `"name":"realmroot"`) ||
		strings.Contains(output, "installation_id") || strings.Contains(output, "authorizationDetail") {
		t.Fatalf("Context summaries = %s", output)
	}
}

func TestParseExecFlagsAcceptsRealmrootOriginBeforeSeparator(t *testing.T) {
	app := &App{}
	args, _, err := app.parseExecFlags([]string{"--realmroot-origin=https://id.example", "github"})
	if err != nil || app.origin != "https://id.example" || strings.Join(args, " ") != "github" {
		t.Fatalf("args=%v origin=%q err=%v", args, app.origin, err)
	}
}

func TestParseToolboxFlagsRejectsInternalAndRemovedProductOptions(t *testing.T) {
	for _, args := range [][]string{{"--rsh-profile", "staging"}, {"--profile", "staging"}, {"--profile=staging"}, {"--auth", "oauth"}, {"--auth=oauth"}, {"--print", "h"}, {"--print=h"}} {
		if _, err := (&App{}).parseToolboxFlags(args); err == nil {
			t.Fatalf("options %v were accepted", args)
		}
	}
}

func TestParseToolboxFlagsIncludesResponseHeadersThroughProductOption(t *testing.T) {
	args, err := (&App{}).parseToolboxFlags([]string{"github", "repos", "get", "--include"})
	if err != nil || strings.Join(args, " ") != "github repos get --rsh-print hb" {
		t.Fatalf("args=%v err=%v", args, err)
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

func TestPrepareOperationCredentialsBindsOpenAPICredentialID(t *testing.T) {
	config := &restish.Config{APIs: map[string]*restish.APIConfig{
		"github": {Profiles: map[string]*restish.ProfileConfig{
			"default": {Auth: &restish.AuthConfig{Type: "dpop", Params: map[string]string{"source": "realmroot", "reference": "internal-reference"}}},
		}},
	}}
	inspection := githubOperationInspection()
	binding := &agent.CredentialBinding{Reference: "internal-reference", Scopes: []string{"issues:read"}}

	if err := prepareOperationCredentials(config, catalog.ResourceServer{CommandName: "github"}, inspection, []string{"issues", "issues-get", "realmroot", "toolbox"}, "default", binding); err != nil {
		t.Fatal(err)
	}
	profile := config.APIs["github"].Profiles["default"]
	credential := profile.Credentials["realmrootOidc"]
	if profile.Auth != nil || credential == nil || credential.Auth == nil || credential.Auth.Type != "dpop" {
		t.Fatalf("profile = %#v", profile)
	}
	if strings.Join(credential.Satisfies, " ") != "issues:read" {
		t.Fatalf("credential scopes = %#v", credential.Satisfies)
	}
}

func TestPrepareOperationCredentialsReplacesStaleProfileReference(t *testing.T) {
	config := &restish.Config{APIs: map[string]*restish.APIConfig{
		"github": {Profiles: map[string]*restish.ProfileConfig{
			"default": {Auth: &restish.AuthConfig{Type: "dpop", Params: map[string]string{"source": "realmroot", "reference": "stale-reference"}}},
		}},
	}}
	binding := &agent.CredentialBinding{Reference: "selected-reference", Scopes: []string{"issues:read"}}

	if err := prepareOperationCredentials(config, catalog.ResourceServer{CommandName: "github"}, githubOperationInspection(), []string{"issues", "issues-get"}, "default", binding); err != nil {
		t.Fatal(err)
	}
	credential := config.APIs["github"].Profiles["default"].Credentials["realmrootOidc"]
	if credential == nil || credential.Auth == nil || credential.Auth.Params["reference"] != "selected-reference" {
		t.Fatalf("credential = %#v", credential)
	}
}

func TestOperationScopeAlternativesPreserveOAuthAlternatives(t *testing.T) {
	operation := githubOperationInspection().Operations[0]
	if got := operationCredentialScopeAlternatives(operation); len(got) != 2 || strings.Join(got[0], " ") != "issues:read" || strings.Join(got[1], " ") != "metadata:read" {
		t.Fatalf("scope alternatives = %#v", got)
	}
}

type recordingOperationCredentialResolver struct {
	binding      agent.CredentialBinding
	err          error
	resource     string
	alternatives [][]string
}

func (r *recordingOperationCredentialResolver) BindingForScopeAlternatives(resource string, alternatives [][]string) (agent.CredentialBinding, error) {
	r.resource = resource
	r.alternatives = alternatives
	return r.binding, r.err
}

func (r *recordingOperationCredentialResolver) BindingForAuthorizationContextScopeAlternatives(resource string, _ []map[string]any, alternatives [][]string) (agent.CredentialBinding, error) {
	return r.BindingForScopeAlternatives(resource, alternatives)
}

func TestResolveOperationCredentialBindingSelectsExistingOfferForOperation(t *testing.T) {
	resolver := &recordingOperationCredentialResolver{binding: agent.CredentialBinding{
		Reference: "selected-reference", Scopes: []string{"issues:read"},
	}}
	server := catalog.ResourceServer{CommandName: "github", ResourceURL: "https://api.example.com/github"}

	binding, err := resolveOperationCredentialBinding(
		resolver,
		server,
		githubOperationInspection(),
		[]string{"issues", "issues-get"},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if binding == nil || binding.Reference != "selected-reference" || resolver.resource != server.ResourceURL ||
		len(resolver.alternatives) != 2 || strings.Join(resolver.alternatives[0], " ") != "issues:read" {
		t.Fatalf("binding = %#v, resource = %q, alternatives = %#v", binding, resolver.resource, resolver.alternatives)
	}
}

func TestResolveOperationCredentialBindingDoesNotResolveHelp(t *testing.T) {
	resolver := &recordingOperationCredentialResolver{err: errors.New("resolver must not run")}
	binding, err := resolveOperationCredentialBinding(
		resolver,
		catalog.ResourceServer{CommandName: "github", ResourceURL: "https://api.example.com/github"},
		githubOperationInspection(),
		[]string{"issues", "issues-get", "--help"},
		nil,
	)
	if err != nil || binding != nil || resolver.resource != "" {
		t.Fatalf("binding = %#v, resource = %q, error = %v", binding, resolver.resource, err)
	}
}

func TestResolveOperationCredentialBindingReportsMissingExistingOffer(t *testing.T) {
	resolver := &recordingOperationCredentialResolver{err: os.ErrNotExist}
	_, err := resolveOperationCredentialBinding(
		resolver,
		catalog.ResourceServer{CommandName: "github", ResourceURL: "https://api.example.com/github"},
		githubOperationInspection(),
		[]string{"issues", "issues-get"},
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "no approved Agent authority") || !strings.Contains(err.Error(), "issues:read") {
		t.Fatalf("error = %v", err)
	}
}

func TestMissingOperationAuthorityUsesOnlyProductVocabulary(t *testing.T) {
	err := prepareOperationCredentials(
		&restish.Config{APIs: map[string]*restish.APIConfig{"github": {}}},
		catalog.ResourceServer{CommandName: "github"},
		githubOperationInspection(),
		[]string{"issues", "issues-get", "realmroot", "toolbox"},
		"default",
		nil,
	)
	if err == nil {
		t.Fatal("missing Agent authority was accepted")
	}
	message := err.Error()
	for _, expected := range []string{"Resource Server \"github\"", "issues:read OR metadata:read", "realmroot agent request"} {
		if !strings.Contains(message, expected) {
			t.Fatalf("error omitted %q: %s", expected, message)
		}
	}
	for _, internal := range []string{"profile", "credential binding", "realmrootOidc", "auth add", "Restish"} {
		if strings.Contains(message, internal) {
			t.Fatalf("error exposes %q: %s", internal, message)
		}
	}
}

func TestInsufficientOperationAuthorityReportsActiveAndRequiredScopes(t *testing.T) {
	binding := &agent.CredentialBinding{Reference: "internal-reference", Scopes: []string{"contents:read"}}
	err := prepareOperationCredentials(
		&restish.Config{APIs: map[string]*restish.APIConfig{"github": {}}},
		catalog.ResourceServer{CommandName: "github"},
		githubOperationInspection(),
		[]string{"issues", "issues-get"},
		"default",
		binding,
	)
	if err == nil || !strings.Contains(err.Error(), "active scopes: contents:read") || !strings.Contains(err.Error(), "required scopes: issues:read OR metadata:read") {
		t.Fatalf("error = %v", err)
	}
}

func TestOperationHelpDoesNotRequireAgentAuthority(t *testing.T) {
	err := prepareOperationCredentials(
		&restish.Config{APIs: map[string]*restish.APIConfig{"github": {}}},
		catalog.ResourceServer{CommandName: "github"},
		githubOperationInspection(),
		[]string{"issues", "issues-get", "--help"},
		"default",
		nil,
	)
	if err != nil {
		t.Fatalf("operation help required authority: %v", err)
	}
}

func githubOperationInspection() restish.APIInspection {
	return restish.APIInspection{Operations: []restish.OperationInspection{{
		ID: "issuesGet", Command: []string{"issues", "issues-get"}, Method: "GET", Path: "/repos/{owner}/{repo}/issues/{number}",
		CredentialAlternatives: [][]restish.CredentialRequirementInspection{
			{{ID: "realmrootOidc", Kind: "oauth2-dpop", Needs: []string{"issues:read"}}},
			{{ID: "realmrootOidc", Kind: "oauth2-dpop", Needs: []string{"metadata:read"}}},
		},
	}}}
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
	if strings.Contains(output, `"scopes"`) || strings.Contains(output, `"id"`) || strings.Contains(output, `"available"`) || !strings.Contains(output, `"scopeCount":2`) || !strings.Contains(output, `"connectedAccountScopes":["zone.read"]`) {
		t.Fatalf("summary JSON = %s", output)
	}
}

func TestSmallResourceServerOverviewIncludesCompleteInventory(t *testing.T) {
	server := catalog.ResourceServer{CommandName: "wallet", Scopes: []catalog.Scope{{Value: "wallet:read"}}}
	details := []catalog.AuthorizationDetail{{Name: "wallet"}}
	operations := []restish.OperationInspection{{ID: "showWallet", Command: []string{"wallet", "show"}, Method: "GET"}}

	overview := buildResourceServerOverview(server, details, operations, discoveryOptions{})

	if overview.Mode != overviewModeExpanded || len(overview.Scopes) != 1 || len(overview.Contexts) != 1 || len(overview.Operations) != 1 {
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

func TestCompactOverviewKeepsBoundedAuthorizationDetails(t *testing.T) {
	server := catalog.ResourceServer{CommandName: "cloudflare", Scopes: make([]catalog.Scope, 252)}
	details := make([]catalog.AuthorizationDetail, maxCompactAuthorization+1)
	for index := range details {
		details[index] = catalog.AuthorizationDetail{Name: "account", AuthorizationDetail: map[string]any{"type": "cloudflare_account"}}
	}

	overview := buildResourceServerOverview(server, details, makeOperations(80), discoveryOptions{})

	if overview.Mode != overviewModeCompact || len(overview.Contexts) != maxCompactAuthorization || !overview.ContextTruncated {
		t.Fatalf("overview = %#v", overview)
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

func TestScopeFilterKeepsOnlyMatchingScopeAlternativesAndHidesCredentialSchemes(t *testing.T) {
	operations := []restish.OperationInspection{{
		ID: "getContent", Command: []string{"repos", "get-content"}, Method: "GET", Path: "/repos/{owner}/{repo}/contents/{path}",
		CredentialAlternatives: [][]restish.CredentialRequirementInspection{
			{{ID: "realmrootOidc", Kind: "oauth2-dpop", Needs: []string{"contents:read"}}},
			{{ID: "realmrootOidc", Kind: "oauth2-dpop", Needs: []string{"metadata:read"}}},
		},
	}}
	overview := buildResourceServerOverview(catalog.ResourceServer{CommandName: "github"}, nil, operations, discoveryOptions{Scope: "contents:read"})

	if got := operationScopeSummary(overview.Operations[0]); got != "contents:read" {
		t.Fatalf("scope summary = %q", got)
	}
	encoded, err := json.Marshal(overview)
	if err != nil {
		t.Fatal(err)
	}
	for _, internal := range []string{"realmrootOidc", "oauth2-dpop", "metadata:read", "credentialAlternatives"} {
		if strings.Contains(string(encoded), internal) {
			t.Fatalf("overview JSON exposed %q: %s", internal, encoded)
		}
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
	operation := summarizeOperations([]restish.OperationInspection{{CredentialAlternatives: [][]restish.CredentialRequirementInspection{
		{{ID: "oauth2", Needs: []string{"agents:read"}}},
		{{ID: "anotherOAuth", Needs: []string{"agents:read"}}},
		{{ID: "bearerAuth"}},
		{{ID: "cookieAuth"}},
	}}}, "")[0]

	if got := operationScopeSummary(operation); got != "agents:read" {
		t.Fatalf("scope summary = %q", got)
	}
}

func TestOperationScopeSummaryIsEmptyWithoutScopes(t *testing.T) {
	operation := summarizeOperations([]restish.OperationInspection{{CredentialAlternatives: [][]restish.CredentialRequirementInspection{
		{{ID: "bearerAuth"}},
		{{ID: "cookieAuth"}},
	}}}, "")[0]

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
		Operations: []operationSummary{{Command: []string{"things", "list"}, Method: "GET"}},
	}

	if err := app.printResourceServerOverview(overview); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "scopes:") {
		t.Fatalf("output contains an empty scope line:\n%s", stdout.String())
	}
}

func TestResourceServerOverviewAdvertisesNativeCommands(t *testing.T) {
	var stdout bytes.Buffer
	app := &App{stdout: &stdout}
	overview := resourceServerOverview{
		ResourceServer: resourceServerSummary{CommandName: "github", Identifier: "github", Name: "GitHub"},
		Mode:           overviewModeCompact,
		NativeCommands: []string{"git", "gh"},
	}

	if err := app.printResourceServerOverview(overview); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	for _, expected := range []string{
		"Native commands:",
		"realmroot exec github -- git <arguments>",
		"realmroot exec github -- gh <arguments>",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output omitted %q:\n%s", expected, output)
		}
	}
}

func TestNativeToolSummaryListsExactCommandForms(t *testing.T) {
	var stdout bytes.Buffer
	app := &App{stdout: &stdout}
	if err := app.printNativeToolSummary(nativeToolSummary{
		ResourceServer: "cloudflare",
		Commands:       []string{"wrangler", "npx wrangler", "pnpm wrangler"},
	}); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	for _, expected := range []string{
		"realmroot exec cloudflare -- wrangler <arguments>",
		"realmroot exec cloudflare -- npx wrangler <arguments>",
		"realmroot exec cloudflare -- pnpm wrangler <arguments>",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output omitted %q:\n%s", expected, output)
		}
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
