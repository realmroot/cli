package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/realmroot/toolbox/internal/access"
	"github.com/realmroot/toolbox/internal/agent"
	"github.com/realmroot/toolbox/internal/catalog"
	"github.com/realmroot/toolbox/internal/execution"
	restish "github.com/saltbo/restish/v2"
	"github.com/spf13/cobra"
)

type App struct {
	stdout    io.Writer
	stderr    io.Writer
	origin    string
	json      bool
	noBrowser bool
	profile   string
	search    string
	scope     string
	all       bool
}

func New(stdout, stderr io.Writer) *cobra.Command {
	app := &App{stdout: stdout, stderr: stderr, origin: agent.DefaultOrigin}
	root := &cobra.Command{
		Use:           "realmroot",
		Short:         "Operate private Resources as a stable Agent",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().StringVar(&app.origin, "realmroot-origin", environment("REALMROOT_ORIGIN", agent.DefaultOrigin), "Realmroot deployment origin")
	root.PersistentFlags().BoolVar(&app.json, "json", false, "print Toolbox and Agent results as JSON")
	root.AddCommand(app.agentCommand(), app.toolboxCommand(), app.execCommand())
	return root
}

func (a *App) execCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "exec <resource-server> -- <native-command> [args...]",
		Short:              "Run a native tool with approved Agent authority",
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				return command.Help()
			}
			if len(args) < 2 {
				return errors.New("usage: realmroot exec <resource-server> -- <native-command> [args...]")
			}
			resourceServer := args[0]
			args = args[1:]
			if args[0] == "--" {
				args = args[1:]
			}
			if len(args) == 0 {
				return errors.New("native command is required after --")
			}
			service, catalogClient, httpClient, err := a.services()
			if err != nil {
				return err
			}
			server, err := catalogClient.Find(command.Context(), resourceServer)
			if err != nil {
				return err
			}
			integrations, err := catalogClient.ToolIntegrations(command.Context(), server)
			if err != nil {
				return err
			}
			runner := execution.NewRunner(service, httpClient, command.InOrStdin(), a.stdout, a.stderr)
			return runner.Run(command.Context(), server, integrations, args)
		},
	}
}

func (a *App) agentCommand() *cobra.Command {
	command := &cobra.Command{Use: "agent", Short: "Manage this stable Agent identity and its Resource access"}
	command.AddCommand(
		&cobra.Command{Use: "enroll", Short: "Enroll this Agent with controller approval", Args: cobra.NoArgs, RunE: a.enroll},
		&cobra.Command{Use: "whoami", Short: "Print the current stable Agent identity", Args: cobra.NoArgs, RunE: a.whoami},
		a.requestCommand(),
	)
	return command
}

func (a *App) requestCommand() *cobra.Command {
	var resourceServer string
	var scopes []string
	var authorizationDetails []string
	var reason string
	command := &cobra.Command{
		Use:   "request",
		Short: "Request exact task-scoped authority from a Resource Server",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if resourceServer == "" {
				return errors.New("--resource-server is required")
			}
			details, err := parseAuthorizationDetails(authorizationDetails)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(command.Context(), 15*time.Minute)
			defer cancel()
			agentService, catalogClient, httpClient, err := a.services()
			if err != nil {
				return err
			}
			server, err := catalogClient.Find(ctx, resourceServer)
			if err != nil {
				return err
			}
			accessService, err := access.New(agentService, httpClient)
			if err != nil {
				return err
			}
			receipt, err := accessService.Request(ctx, server, scopes, details, reason)
			if err != nil {
				return err
			}
			return a.printJSON(receipt)
		},
	}
	command.Flags().StringVar(&resourceServer, "resource-server", "", "Toolbox Resource Server name, such as github or platform")
	command.Flags().StringArrayVar(&scopes, "scope", nil, "exact published scope to request (repeatable)")
	command.Flags().StringArrayVar(&authorizationDetails, "authorization-detail", nil, "authorization detail JSON object (repeatable)")
	command.Flags().StringVar(&reason, "reason", "", "controller-facing reason for the request")
	return command
}

func (a *App) toolboxCommand() *cobra.Command {
	command := &cobra.Command{
		Use:                "toolbox [resource-server [operation...]]",
		Short:              "Discover and operate Resource Servers",
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, args []string) error {
			var err error
			args, err = a.parseToolboxFlags(args)
			if err != nil {
				return err
			}
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				return command.Help()
			}
			ctx, cancel := context.WithTimeout(command.Context(), 15*time.Minute)
			defer cancel()
			agentService, catalogClient, _, err := a.services()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if a.discoveryOptions().active() {
					return errors.New("--search, --scope, and --all require a Resource Server name")
				}
				return a.listResourceServers(ctx, catalogClient)
			}
			if len(args) == 1 && !genericHTTPMethod(args[0]) {
				return a.showResourceServer(ctx, agentService, catalogClient, args[0])
			}
			if a.discoveryOptions().active() {
				return errors.New("--search, --scope, and --all apply only to a Resource Server overview")
			}
			return a.runRestish(ctx, agentService, catalogClient, args)
		},
	}
	command.Flags().String("output", "auto", "response format: auto, json, yaml, table, raw, or another supported formatter")
	command.Flags().String("print", "auto", "response parts to print")
	command.Flags().StringArray("header", nil, `request header in "Name: Value" format (repeatable)`)
	command.Flags().StringArray("query", nil, `query parameter in "key=value" format (repeatable)`)
	command.Flags().String("filter", "", "filter or project the response")
	command.Flags().String("content-type", "", "request body content type")
	command.Flags().String("timeout", "", "request timeout, such as 30s")
	command.Flags().String("profile", "", "Resource Server profile")
	command.Flags().String("auth", "", "explicit OpenAPI security alternative")
	command.Flags().String("search", "", "find operations by command, summary, method, path, or operation ID")
	command.Flags().String("scope", "", "find operations requiring an exact scope")
	command.Flags().Bool("all", false, "show the complete Resource Server inventory")
	command.Flags().Bool("no-browser", false, "do not open controller approval pages")
	command.Flags().Bool("no-paginate", false, "return only the first page")
	command.Flags().Int("max-pages", 25, "maximum pages to fetch (0 is unlimited)")
	command.Flags().Int("max-items", 0, "maximum items to process (0 is unlimited)")
	command.Flags().Bool("no-cache", false, "bypass the response cache")
	command.Flags().Bool("validate", false, "validate a generated operation body before sending")
	command.Flags().Bool("generate-body", false, "print a generated operation body example and exit")
	command.Flags().Int("retry", 2, "maximum transient retry attempts")
	command.Flags().CountP("verbose", "v", "show request and response diagnostics")
	return command
}

func (a *App) parseToolboxFlags(args []string) ([]string, error) {
	result := make([]string, 0, len(args))
	positionals := 0
	valueFlags := map[string]string{
		"--output": "--rsh-output-format", "--print": "--rsh-print", "--header": "--rsh-header",
		"--query": "--rsh-query", "--filter": "--rsh-filter", "--timeout": "--rsh-timeout",
		"--content-type": "--rsh-content-type",
		"--profile":      "--rsh-profile", "--auth": "--rsh-auth", "--max-pages": "--rsh-max-pages",
		"--max-items": "--rsh-max-items", "--retry": "--rsh-retry",
	}
	booleanFlags := map[string]string{
		"--no-browser": "--rsh-no-browser", "--no-paginate": "--rsh-no-paginate", "--no-cache": "--rsh-no-cache",
		"--validate": "--rsh-validate", "--generate-body": "--rsh-generate-body",
	}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch argument {
		case "--":
			return append(result, args[index:]...), nil
		case "--json":
			a.json = true
		case "--all":
			if positionals <= 1 {
				a.all = true
			} else {
				result = append(result, argument)
			}
		case "--search", "--scope":
			if positionals > 1 {
				result = append(result, argument)
				continue
			}
			if index+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a value", argument)
			}
			index++
			if strings.TrimSpace(args[index]) == "" {
				return nil, fmt.Errorf("%s requires a non-empty value", argument)
			}
			if argument == "--search" {
				a.search = args[index]
			} else {
				a.scope = args[index]
			}
		case "--realmroot-origin":
			if index+1 >= len(args) {
				return nil, errors.New("--realmroot-origin requires a value")
			}
			index++
			a.origin = args[index]
		case "--verbose", "-v":
			result = append(result, "--rsh-verbose")
		case "-p":
			if index+1 >= len(args) {
				return nil, errors.New("-p requires a value")
			}
			index++
			a.profile = args[index]
			result = append(result, "--rsh-profile", a.profile)
		default:
			if positionals <= 1 && strings.HasPrefix(argument, "--search=") {
				a.search = strings.TrimPrefix(argument, "--search=")
				if strings.TrimSpace(a.search) == "" {
					return nil, errors.New("--search requires a non-empty value")
				}
				continue
			}
			if positionals <= 1 && strings.HasPrefix(argument, "--scope=") {
				a.scope = strings.TrimPrefix(argument, "--scope=")
				if strings.TrimSpace(a.scope) == "" {
					return nil, errors.New("--scope requires a non-empty value")
				}
				continue
			}
			if internal, ok := booleanFlags[argument]; ok {
				if argument == "--no-browser" {
					a.noBrowser = true
				}
				result = append(result, internal)
				continue
			}
			if internal, ok := valueFlags[argument]; ok {
				if index+1 >= len(args) {
					return nil, fmt.Errorf("%s requires a value", argument)
				}
				index++
				if argument == "--profile" {
					a.profile = args[index]
				}
				result = append(result, internal, args[index])
				continue
			}
			translated := false
			for public, internal := range valueFlags {
				if strings.HasPrefix(argument, public+"=") {
					value := strings.TrimPrefix(argument, public+"=")
					if public == "--profile" {
						a.profile = value
					}
					result = append(result, internal+"="+value)
					translated = true
					break
				}
			}
			if !translated {
				result = append(result, argument)
				if !strings.HasPrefix(argument, "-") {
					positionals++
				}
			}
		}
	}
	return result, nil
}

func (a *App) enroll(command *cobra.Command, _ []string) error {
	service, _, _, err := a.services()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(command.Context(), 15*time.Minute)
	defer cancel()
	identity, err := service.Enroll(ctx)
	if err != nil {
		return err
	}
	return a.printJSON(identity)
}

func (a *App) whoami(command *cobra.Command, _ []string) error {
	service, _, _, err := a.services()
	if err != nil {
		return err
	}
	identity, err := service.WhoAmI(command.Context())
	if err != nil {
		return err
	}
	return a.printJSON(identity)
}

func (a *App) listResourceServers(ctx context.Context, client *catalog.Client) error {
	servers, err := client.List(ctx)
	if err != nil {
		return err
	}
	if a.json {
		return a.printJSON(summarizeResourceServers(servers))
	}
	w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tRESOURCE SERVER\tCONNECTION\tDESCRIPTION")
	for _, server := range servers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", server.CommandName, server.Identifier, server.ConnectionStatus, server.Name)
	}
	return w.Flush()
}

func (a *App) showResourceServer(ctx context.Context, service *agent.Service, client *catalog.Client, name string) error {
	config, servers, err := client.RestishConfig(ctx)
	if err != nil {
		return err
	}
	var server catalog.ResourceServer
	for _, candidate := range servers {
		if candidate.CommandName == name {
			server = candidate
			break
		}
	}
	if server.CommandName == "" {
		return fmt.Errorf("Resource Server %q is not available", name)
	}
	details, err := client.AuthorizationDetails(ctx, server)
	if err != nil {
		return err
	}
	runtime, err := a.newRestishRuntime(service, config)
	if err != nil {
		return err
	}
	inspection, err := runtime.InspectAPI(ctx, server.CommandName, "default")
	if err != nil {
		return err
	}
	overview := buildResourceServerOverview(server, details, inspection.Operations, a.discoveryOptions())
	if a.json {
		return a.printJSON(overview)
	}
	return a.printResourceServerOverview(overview)
}

func (a *App) printResourceServerOverview(overview resourceServerOverview) error {
	server := overview.ResourceServer
	fmt.Fprintf(a.stdout, "Resource Server: %s (%s)\nName: %s\nResource: %s\nConnection: %s\n", server.CommandName, server.Identifier, server.Name, server.ResourceURL, server.ConnectionStatus)
	if len(server.AuthorizedScopes) > 0 {
		fmt.Fprintf(a.stdout, "Authorized scopes: %s\n", strings.Join(server.AuthorizedScopes, ", "))
	}
	if overview.Mode == overviewModeCompact {
		fmt.Fprintf(a.stdout, "\nCapabilities:\n  Operations: %d\n  Requestable scopes: %d\n  Authorization details: %d\n", overview.OperationCount, overview.ScopeCount, overview.AuthorizationDetailCount)
		fmt.Fprintf(a.stdout, "\nFind operations:\n  realmroot toolbox %s --search \"list zones\"\n  realmroot toolbox %s --scope zone.read\n  realmroot toolbox %s --all\n", server.CommandName, server.CommandName, server.CommandName)
		return nil
	}
	if overview.Mode == overviewModeExpanded {
		fmt.Fprintln(a.stdout, "\nScopes:")
		for _, scope := range overview.Scopes {
			fmt.Fprintf(a.stdout, "  %-28s %s\n", scope.Value, scope.Description)
		}
		fmt.Fprintln(a.stdout, "\nAuthorization details:")
		for _, detail := range overview.AuthorizationDetails {
			fmt.Fprintf(a.stdout, "  %s\n    account: %s\n    authorized: %s\n    requestable: %s\n", detail.Name, detail.AccountAuthorizationStatus, strings.Join(detail.AuthorizedScopes, ", "), strings.Join(detail.RequestableScopes, ", "))
		}
	} else {
		fmt.Fprintf(a.stdout, "\nMatching operations: %d\n", overview.MatchCount)
	}
	if len(overview.Operations) == 0 {
		if overview.Mode == overviewModeFiltered {
			fmt.Fprintln(a.stdout, "No operations matched.")
		}
		return nil
	}
	fmt.Fprintln(a.stdout, "\nOperations:")
	if overview.Mode == overviewModeFiltered {
		for _, operation := range overview.Operations {
			fmt.Fprintf(a.stdout, "  realmroot toolbox %s %s\n    method: %s\n", server.CommandName, strings.Join(operation.Command, " "), operation.Method)
			if scopes := operationScopeSummary(operation); scopes != "" {
				fmt.Fprintf(a.stdout, "    scopes: %s\n", scopes)
			}
			if operation.Summary != "" {
				fmt.Fprintf(a.stdout, "    description: %s\n", operation.Summary)
			}
		}
		if overview.Truncated {
			fmt.Fprintf(a.stdout, "\nShowing %d of %d matches. Add --all to show every match.\n", len(overview.Operations), overview.MatchCount)
		}
		return nil
	}
	w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  COMMAND\tMETHOD\tSCOPES\tDESCRIPTION")
	for _, operation := range overview.Operations {
		fmt.Fprintf(w, "  realmroot toolbox %s %s\t%s\t%s\t%s\n",
			server.CommandName, strings.Join(operation.Command, " "), operation.Method,
			operationScopeSummary(operation), operation.Summary)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if overview.Truncated {
		fmt.Fprintf(a.stdout, "\nShowing %d of %d matches. Add --all to show every match.\n", len(overview.Operations), overview.MatchCount)
	}
	return nil
}

func (a *App) discoveryOptions() discoveryOptions {
	return discoveryOptions{Search: strings.TrimSpace(a.search), Scope: strings.TrimSpace(a.scope), All: a.all}
}

func (a *App) runRestish(ctx context.Context, service *agent.Service, client *catalog.Client, args []string) error {
	config, _, err := client.RestishConfig(ctx)
	if err != nil {
		return err
	}
	runtime, err := a.newRestishRuntime(service, config)
	if err != nil {
		return err
	}
	argvArgs := append([]string(nil), args...)
	if !hasRuntimeFlag(argvArgs, "--rsh-print") {
		argvArgs = append(argvArgs, "--rsh-print", "b")
	}
	if a.json {
		argvArgs = append(argvArgs, "--rsh-output-format", "json")
	}
	argv := append([]string{"realmroot toolbox"}, argvArgs...)
	if err := runtime.Run(argv); err != nil {
		return toolboxRuntimeError{cause: err}
	}
	return nil
}

func hasRuntimeFlag(args []string, name string) bool {
	for _, argument := range args {
		if argument == name || strings.HasPrefix(argument, name+"=") {
			return true
		}
	}
	return false
}

type toolboxRuntimeError struct{ cause error }

func (e toolboxRuntimeError) Error() string {
	replacer := strings.NewReplacer(
		"--rsh-output-format", "--output", "--rsh-print", "--print", "--rsh-header", "--header",
		"--rsh-query", "--query", "--rsh-filter", "--filter", "--rsh-content-type", "--content-type",
		"--rsh-timeout", "--timeout", "--rsh-profile", "--profile", "--rsh-auth", "--auth",
		"--rsh-no-browser", "--no-browser", "--rsh-no-paginate", "--no-paginate",
		"--rsh-no-cache", "--no-cache", "--rsh-max-pages", "--max-pages", "--rsh-max-items", "--max-items",
		"--rsh-retry", "--retry", "--rsh-validate", "--validate", "--rsh-generate-body", "--generate-body",
		"Restish", "Toolbox", "restish", "toolbox",
	)
	return replacer.Replace(e.cause.Error())
}

func (e toolboxRuntimeError) Unwrap() error { return e.cause }

func (a *App) newRestishRuntime(service *agent.Service, config *restish.Config) (*restish.CLI, error) {
	if err := configureRestishPaths(); err != nil {
		return nil, err
	}
	runtime := restish.New()
	runtime.SetCommandName("realmroot toolbox")
	runtime.SetCommandDescription("Operate Realmroot Resource Servers", "OpenAPI-generated and generic HTTP operations for discovered Resource Servers.")
	runtime.SetDefaultConfig(config)
	runtime.SetCommandSurface(restish.CommandSurface{
		HTTPMethods: []string{"get", "head", "post", "put", "patch", "delete"}, RegisteredAPIs: true, HideSupportCommands: true,
		MetadataRefreshTimeout: 30 * time.Second, IgnoreUserConfig: true, DisablePlugins: true, HideInternalFlags: true,
	})
	runtime.AddAuthHandler("dpop", restish.NewDPoPAuthHandler(service.CredentialSource()))
	runtime.AddResponseMiddleware(agent.NewInteractiveResponseMiddleware(runtime, service.OpenApproval, a.stderr, a.noBrowser, a.profile))
	runtime.Stdout, runtime.Stderr = a.stdout, a.stderr
	runtime.SetSignalHandling(false)
	return runtime, nil
}

func operationScopeSummary(operation restish.OperationInspection) string {
	alternatives := make([]string, 0, len(operation.CredentialAlternatives))
	seenAlternatives := make(map[string]bool)
	for _, alternative := range operation.CredentialAlternatives {
		var scopes []string
		seenScopes := make(map[string]bool)
		for _, requirement := range alternative {
			for _, scope := range requirement.Needs {
				if !seenScopes[scope] {
					scopes = append(scopes, scope)
					seenScopes[scope] = true
				}
			}
		}
		if len(scopes) == 0 {
			continue
		}
		expression := strings.Join(scopes, "+")
		if !seenAlternatives[expression] {
			alternatives = append(alternatives, expression)
			seenAlternatives[expression] = true
		}
	}
	return strings.Join(alternatives, " OR ")
}

func (a *App) services() (*agent.Service, *catalog.Client, *http.Client, error) {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	service, err := agent.NewService(a.origin, httpClient)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := catalog.New(service, httpClient)
	if err != nil {
		return nil, nil, nil, err
	}
	return service, client, httpClient, nil
}

func (a *App) printJSON(value any) error {
	encoder := json.NewEncoder(a.stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func parseAuthorizationDetails(values []string) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		var detail map[string]any
		if err := json.Unmarshal([]byte(value), &detail); err != nil {
			return nil, fmt.Errorf("decode --authorization-detail: %w", err)
		}
		result = append(result, detail)
	}
	return result, nil
}

func genericHTTPMethod(value string) bool {
	switch value {
	case "get", "head", "post", "put", "patch", "delete":
		return true
	default:
		return false
	}
}

func configureRestishPaths() error {
	if os.Getenv("RSH_CONFIG_DIR") != "" {
		if os.Getenv("RSH_CACHE_DIR") != "" {
			return nil
		}
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("resolve configuration directory: %w", err)
	}
	if os.Getenv("RSH_CONFIG_DIR") == "" {
		if err := os.Setenv("RSH_CONFIG_DIR", filepath.Join(directory, "realmroot", "restish")); err != nil {
			return err
		}
	}
	if os.Getenv("RSH_CACHE_DIR") == "" {
		cacheDirectory, err := os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("resolve cache directory: %w", err)
		}
		return os.Setenv("RSH_CACHE_DIR", filepath.Join(cacheDirectory, "realmroot", "restish"))
	}
	return nil
}

func environment(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
