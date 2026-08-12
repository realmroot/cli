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
	"github.com/realmroot/toolbox/internal/buildinfo"
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
	search    string
	scope     string
	all       bool
	context   string
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
	root.AddCommand(app.agentCommand(), app.toolboxCommand(), app.execCommand(), app.versionCommand())
	return root
}

func (a *App) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the installed Toolbox version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := buildinfo.Current()
			if a.json {
				return a.printJSON(info)
			}
			fmt.Fprintf(a.stdout, "realmroot %s\n", info.Version)
			if info.Commit != "" {
				fmt.Fprintf(a.stdout, "commit: %s\n", info.Commit)
			}
			if info.BuildTime != "" {
				fmt.Fprintf(a.stdout, "built: %s\n", info.BuildTime)
			}
			return nil
		},
	}
}

func (a *App) execCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "exec [resource-server [-- native-command [args...]]]",
		Short: "Run a native tool with approved Agent authority",
		Long:  "Discover native commands advertised by Resource Servers, or run one with approved Agent authority. Run without arguments to list every available native command. Use --context to override the Resource Server's selected Context for one command.",
		Example: strings.Join([]string{
			"realmroot exec",
			"realmroot exec github",
			"realmroot exec github -- git fetch origin",
			"realmroot exec github -- gh pr list",
			"realmroot exec github --context realmroot -- gh pr merge 42",
			"realmroot exec cloudflare -- wrangler deployments list",
		}, "\n"),
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, args []string) error {
			args, options, err := a.parseExecFlags(args)
			if err != nil {
				return err
			}
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				return command.Help()
			}
			service, catalogClient, httpClient, err := a.services()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if options.active() {
					return errors.New("--context requires a Resource Server and native command")
				}
				return a.listNativeTools(command.Context(), catalogClient)
			}
			resourceServer := args[0]
			server, err := catalogClient.Find(command.Context(), resourceServer)
			if err != nil {
				return err
			}
			integrations, err := catalogClient.ToolIntegrations(command.Context(), server)
			if err != nil {
				if len(args) == 1 && errors.Is(err, catalog.ErrNoToolIntegrations) {
					return a.printNativeToolSummary(nativeToolSummary{ResourceServer: server.CommandName})
				}
				return err
			}
			if len(args) == 1 || (len(args) == 2 && (args[1] == "--help" || args[1] == "-h")) {
				if options.active() {
					return errors.New("--context requires a native command")
				}
				return a.printNativeToolSummary(nativeToolSummary{
					ResourceServer: server.CommandName,
					Commands:       execution.NativeCommands(integrations),
				})
			}
			args = args[1:]
			if args[0] == "--" {
				args = args[1:]
			}
			if len(args) == 0 {
				return errors.New("native command is required after --")
			}
			details, err := catalogClient.AuthorizationDetails(command.Context(), server)
			if err != nil {
				return err
			}
			selected, err := a.resolveContext(service, server, details, options.context)
			if err != nil {
				return err
			}
			runner := execution.NewRunner(service, httpClient, command.InOrStdin(), a.stdout, a.stderr)
			return runner.Run(command.Context(), server, integrations, args, execution.RunOptions{
				AuthorizationDetails: selected,
			})
		},
	}
	command.Flags().String("context", "", "Resource Server Context name for this command")
	return command
}

type execOptions struct {
	context string
}

func (o execOptions) active() bool { return o.context != "" }

func (a *App) parseExecFlags(args []string) ([]string, execOptions, error) {
	result := make([]string, 0, len(args))
	var options execOptions
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--":
			return append(result, args[index:]...), options, nil
		case argument == "--json":
			a.json = true
		case argument == "--realmroot-origin":
			if index+1 >= len(args) {
				return nil, execOptions{}, errors.New("--realmroot-origin requires a value")
			}
			index++
			a.origin = args[index]
		case strings.HasPrefix(argument, "--realmroot-origin="):
			a.origin = strings.TrimPrefix(argument, "--realmroot-origin=")
		case argument == "--context":
			if index+1 >= len(args) {
				return nil, execOptions{}, errors.New("--context requires a value")
			}
			index++
			options.context = args[index]
		case strings.HasPrefix(argument, "--context="):
			options.context = strings.TrimPrefix(argument, "--context=")
		default:
			result = append(result, argument)
		}
	}
	return result, options, nil
}

func (a *App) agentCommand() *cobra.Command {
	command := &cobra.Command{Use: "agent", Short: "Manage this stable Agent identity and its Resource access"}
	var username string
	var nickname string
	enroll := &cobra.Command{
		Use:   "enroll --username <username>",
		Short: "Enroll this Agent with controller approval",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if strings.TrimSpace(username) == "" {
				return errors.New("--username is required")
			}
			return a.enroll(command, username, nickname)
		},
	}
	enroll.Flags().StringVar(&username, "username", "", "immutable Agent username")
	enroll.Flags().StringVar(&nickname, "nickname", "", "Agent nickname (defaults to the detected runtime)")
	command.AddCommand(
		enroll,
		&cobra.Command{Use: "whoami", Short: "Print the current stable Agent identity", Args: cobra.NoArgs, RunE: a.whoami},
		a.requestCommand(),
	)
	return command
}

func (a *App) requestCommand() *cobra.Command {
	var resourceServer string
	var scopes []string
	var contextName string
	var reason string
	var noWait bool
	command := &cobra.Command{
		Use:   "request",
		Short: "Request exact task-scoped authority from a Resource Server",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if resourceServer == "" {
				return errors.New("--resource-server is required")
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
			contexts, err := catalogClient.AuthorizationDetails(ctx, server)
			if err != nil {
				return err
			}
			details, err := a.resolveContext(agentService, server, contexts, contextName)
			if err != nil {
				return err
			}
			accessService, err := access.New(agentService, httpClient)
			if err != nil {
				return err
			}
			receipt, err := accessService.Request(ctx, server, scopes, details, reason, access.RequestOptions{Wait: !noWait})
			if err != nil {
				return err
			}
			return a.printJSON(receipt)
		},
	}
	command.Flags().StringVar(&resourceServer, "resource-server", "", "Toolbox Resource Server name, such as github or platform")
	command.Flags().StringArrayVar(&scopes, "scope", nil, "exact published scope to request (repeatable)")
	command.Flags().StringVar(&contextName, "context", "", "Resource Server Context name for this request")
	command.Flags().StringVar(&reason, "reason", "", "controller-facing reason for the request")
	command.Flags().BoolVar(&noWait, "no-wait", false, "return the approval URL without opening a browser or polling")
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
			if len(args) >= 2 && args[1] == "context" {
				return a.contextCommand(ctx, agentService, catalogClient, args[0], args[2:])
			}
			if a.discoveryOptions().active() {
				return errors.New("--search, --scope, and --all apply only to a Resource Server overview")
			}
			return a.runRestish(ctx, agentService, catalogClient, args)
		},
	}
	command.Flags().String("output", "auto", "response format: auto, json, yaml, table, or raw")
	command.Flags().StringArray("header", nil, `request header in "Name: Value" format (repeatable)`)
	command.Flags().StringArray("query", nil, `query parameter in "key=value" format (repeatable)`)
	command.Flags().String("filter", "", "filter or project the response")
	command.Flags().String("content-type", "", "request body content type")
	command.Flags().String("timeout", "", "request timeout, such as 30s")
	command.Flags().Bool("include", false, "include response headers")
	command.Flags().String("search", "", "find operations by command, summary, method, path, or operation ID")
	command.Flags().String("scope", "", "find operations requiring an exact scope")
	command.Flags().String("context", "", "Resource Server Context name for this operation")
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
		"--output": "--rsh-output-format", "--header": "--rsh-header",
		"--query": "--rsh-query", "--filter": "--rsh-filter", "--timeout": "--rsh-timeout",
		"--content-type": "--rsh-content-type",
		"--max-pages":    "--rsh-max-pages", "--max-items": "--rsh-max-items", "--retry": "--rsh-retry",
	}
	booleanFlags := map[string]string{
		"--no-browser": "--rsh-no-browser", "--no-paginate": "--rsh-no-paginate", "--no-cache": "--rsh-no-cache",
		"--validate": "--rsh-validate", "--generate-body": "--rsh-generate-body",
	}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if strings.HasPrefix(argument, "--rsh-") {
			return nil, fmt.Errorf("unsupported internal option %q", argument)
		}
		switch argument {
		case "--":
			return append(result, args[index:]...), nil
		case "--json":
			a.json = true
		case "--context":
			if index+1 >= len(args) {
				return nil, errors.New("--context requires a value")
			}
			index++
			a.context = args[index]
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
		case "--profile", "-p", "--auth", "--print":
			if positionals <= 1 {
				return nil, fmt.Errorf("unsupported Toolbox option %q", argument)
			}
			result = append(result, argument)
		case "--verbose", "-v":
			result = append(result, "--rsh-verbose")
		case "--include":
			result = append(result, "--rsh-print", "hb")
		default:
			if positionals <= 1 && removedToolboxOption(argument) {
				return nil, fmt.Errorf("unsupported Toolbox option %q", strings.SplitN(argument, "=", 2)[0])
			}
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
			if strings.HasPrefix(argument, "--context=") {
				a.context = strings.TrimPrefix(argument, "--context=")
				if strings.TrimSpace(a.context) == "" {
					return nil, errors.New("--context requires a non-empty value")
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
				result = append(result, internal, args[index])
				continue
			}
			translated := false
			for public, internal := range valueFlags {
				if strings.HasPrefix(argument, public+"=") {
					value := strings.TrimPrefix(argument, public+"=")
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

func removedToolboxOption(argument string) bool {
	for _, option := range []string{"--profile", "--auth", "--print"} {
		if strings.HasPrefix(argument, option+"=") {
			return true
		}
	}
	return false
}

func (a *App) enroll(command *cobra.Command, username, nickname string) error {
	service, _, _, err := a.services()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(command.Context(), 15*time.Minute)
	defer cancel()
	identity, err := service.Enroll(ctx, username, nickname)
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
	selected, selectedErr := service.SelectedContext(server.ResourceURL)
	if selectedErr != nil && !errors.Is(selectedErr, os.ErrNotExist) {
		return selectedErr
	}
	for index := range overview.Contexts {
		for _, detail := range details {
			if detail.Name == overview.Contexts[index].Name && sameDetails(detail.AuthorizationDetail, selected) {
				overview.Contexts[index].Current = true
			}
		}
	}
	integrations, integrationsErr := client.ToolIntegrations(ctx, server)
	if integrationsErr == nil {
		overview.NativeCommands = execution.NativeCommands(integrations)
	} else if !errors.Is(integrationsErr, catalog.ErrNoToolIntegrations) {
		return integrationsErr
	}
	var binding agent.CredentialBinding
	var bindErr error
	if len(selected) > 0 {
		binding, bindErr = service.BindingForAuthorizationContextAllAuthority(server.ResourceURL, selected)
	} else if len(details) == 1 {
		binding, bindErr = service.BindingForAuthorizationContextAllAuthority(server.ResourceURL, []map[string]any{details[0].AuthorizationDetail})
	} else {
		binding, bindErr = service.BindingForResource(server.ResourceURL)
	}
	if bindErr == nil {
		overview.ResourceServer.AgentAuthorityScopes = append([]string(nil), binding.Scopes...)
	} else if !errors.Is(bindErr, os.ErrNotExist) {
		return fmt.Errorf("load Agent authority for %s: %w", server.CommandName, bindErr)
	}
	if a.json {
		return a.printJSON(overview)
	}
	return a.printResourceServerOverview(overview)
}

func (a *App) printResourceServerOverview(overview resourceServerOverview) error {
	server := overview.ResourceServer
	serverLabel := server.CommandName
	if server.CommandName != server.Identifier {
		serverLabel += " (" + server.Identifier + ")"
	}
	fmt.Fprintf(a.stdout, "Resource Server: %s\nName: %s\nResource: %s\nConnection: %s\n", serverLabel, server.Name, server.ResourceURL, server.ConnectionStatus)
	if len(server.ConnectedAccountScopes) > 0 {
		fmt.Fprintf(a.stdout, "Connected account scopes: %s\n", scopeList(server.ConnectedAccountScopes, overview.Mode == overviewModeExpanded))
	}
	if len(server.AgentAuthorityScopes) > 0 {
		fmt.Fprintf(a.stdout, "Agent authority scopes: %s\n", strings.Join(server.AgentAuthorityScopes, ", "))
	} else {
		fmt.Fprintln(a.stdout, "Agent authority: not requested")
	}
	a.printNativeCommands(server.CommandName, overview.NativeCommands)
	if overview.Mode == overviewModeCompact {
		fmt.Fprintf(a.stdout, "\nCapabilities:\n  Operations: %d\n  Published scopes: %d\n  Contexts: %d\n", overview.OperationCount, overview.ScopeCount, overview.ContextCount)
		a.printContextSummary(overview)
		fmt.Fprintf(a.stdout, "\nDiscover operations:\n  realmroot toolbox %s --search \"<keywords>\"\n  realmroot toolbox %s --scope <scope>\n  realmroot toolbox %s --all\n", server.CommandName, server.CommandName, server.CommandName)
		return nil
	}
	if overview.Mode == overviewModeExpanded {
		if len(overview.Scopes) > 0 {
			fmt.Fprintln(a.stdout, "\nScopes:")
			for _, scope := range overview.Scopes {
				fmt.Fprintf(a.stdout, "  %-28s %s\n", scope.Value, scope.Description)
			}
		}
		a.printContextSummary(overview)
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

func (a *App) listNativeTools(ctx context.Context, client *catalog.Client) error {
	servers, err := client.List(ctx)
	if err != nil {
		return err
	}
	summaries := make([]nativeToolSummary, 0)
	for _, server := range servers {
		integrations, integrationsErr := client.ToolIntegrations(ctx, server)
		if errors.Is(integrationsErr, catalog.ErrNoToolIntegrations) {
			continue
		}
		if integrationsErr != nil {
			return integrationsErr
		}
		summaries = append(summaries, nativeToolSummary{
			ResourceServer: server.CommandName,
			Commands:       execution.NativeCommands(integrations),
		})
	}
	if a.json {
		return a.printJSON(summaries)
	}
	if len(summaries) == 0 {
		fmt.Fprintln(a.stdout, "No Resource Servers advertise native commands.")
		return nil
	}
	w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "RESOURCE SERVER\tCOMMANDS")
	for _, summary := range summaries {
		fmt.Fprintf(w, "%s\t%s\n", summary.ResourceServer, strings.Join(summary.Commands, ", "))
	}
	return w.Flush()
}

func (a *App) printNativeToolSummary(summary nativeToolSummary) error {
	if a.json {
		return a.printJSON(summary)
	}
	if len(summary.Commands) == 0 {
		fmt.Fprintf(a.stdout, "Resource Server %q does not advertise native commands.\n", summary.ResourceServer)
		return nil
	}
	fmt.Fprintf(a.stdout, "Native commands for %s:\n", summary.ResourceServer)
	for _, nativeCommand := range summary.Commands {
		fmt.Fprintf(a.stdout, "  realmroot exec %s -- %s <arguments>\n", summary.ResourceServer, nativeCommand)
	}
	return nil
}

func (a *App) printNativeCommands(resourceServer string, commands []string) {
	if len(commands) == 0 {
		return
	}
	fmt.Fprintln(a.stdout, "\nNative commands:")
	for _, nativeCommand := range commands {
		fmt.Fprintf(a.stdout, "  realmroot exec %s -- %s <arguments>\n", resourceServer, nativeCommand)
	}
}

func (a *App) discoveryOptions() discoveryOptions {
	return discoveryOptions{Search: strings.TrimSpace(a.search), Scope: strings.TrimSpace(a.scope), All: a.all}
}

func (a *App) printContextSummary(overview resourceServerOverview) {
	if len(overview.Contexts) == 0 {
		return
	}
	fmt.Fprintln(a.stdout, "\nContexts:")
	for _, item := range overview.Contexts {
		current := ""
		if item.Current {
			current = " (current)"
		}
		fmt.Fprintf(a.stdout, "  %s%s — %s\n", item.Name, current, item.AccountAuthorizationStatus)
	}
	if overview.ContextTruncated {
		fmt.Fprintf(a.stdout, "  Showing %d of %d Contexts. Run `realmroot toolbox %s context` to show every Context.\n", len(overview.Contexts), overview.ContextCount, overview.ResourceServer.CommandName)
	}
	fmt.Fprintf(a.stdout, "  Manage: realmroot toolbox %s context\n", overview.ResourceServer.CommandName)
}

func scopeList(scopes []string, expanded bool) string {
	if expanded || len(scopes) <= 12 {
		return strings.Join(scopes, ", ")
	}
	return fmt.Sprintf("%d available (add --all to list them)", len(scopes))
}

func (a *App) runRestish(ctx context.Context, service *agent.Service, client *catalog.Client, args []string) error {
	config, servers, err := client.RestishConfig(ctx)
	if err != nil {
		return err
	}
	runtime, err := a.newRestishRuntime(service, config)
	if err != nil {
		return err
	}
	if server, ok := selectedResourceServer(servers, args); ok {
		profile := "default"
		inspection, inspectErr := runtime.InspectAPI(ctx, server.CommandName, profile)
		if inspectErr != nil {
			return inspectErr
		}
		var selected []map[string]any
		operation, operationSelected := selectedOperation(inspection.Operations, args[1:])
		if operationSelected && invocationRequiresAuthority(args[1:]) && operationRequiresAuthority(operation) {
			details, detailsErr := client.AuthorizationDetails(ctx, server)
			if detailsErr != nil {
				return detailsErr
			}
			selected, err = a.resolveContext(service, server, details, a.context)
			if err != nil {
				return err
			}
		}
		binding, bindingErr := resolveOperationCredentialBinding(service, server, inspection, args[1:], selected)
		if bindingErr != nil {
			return bindingErr
		}
		if err := prepareOperationCredentials(config, server, inspection, args[1:], profile, binding); err != nil {
			return err
		}
		runtime, err = a.newRestishRuntime(service, config)
		if err != nil {
			return err
		}
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
		"--rsh-output-format", "--output", "--rsh-print", "--include", "--rsh-header", "--header",
		"--rsh-query", "--query", "--rsh-filter", "--filter", "--rsh-content-type", "--content-type",
		"--rsh-timeout", "--timeout",
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
		CompactOperationHelp: true,
	})
	runtime.AddAuthHandler("dpop", restish.NewDPoPAuthHandler(service.CredentialSource()))
	runtime.AddResponseMiddleware(agent.NewInteractiveResponseMiddleware(runtime, service.OpenApproval, a.stderr, a.noBrowser, "default"))
	runtime.Stdout, runtime.Stderr = a.stdout, a.stderr
	runtime.SetSignalHandling(false)
	return runtime, nil
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
		return os.Setenv("RSH_CACHE_DIR", filepath.Join(cacheDirectory, "realmroot", "restish", "v2"))
	}
	return nil
}

func environment(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
