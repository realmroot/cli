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
	restish "github.com/rest-sh/restish/v2"
	"github.com/spf13/cobra"
)

type App struct {
	stdout io.Writer
	stderr io.Writer
	origin string
	json   bool
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
	root.AddCommand(app.agentCommand(), app.toolboxCommand())
	return root
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
			agentService, catalogClient, err := a.services()
			if err != nil {
				return err
			}
			server, err := catalogClient.Find(ctx, resourceServer)
			if err != nil {
				return err
			}
			accessService, err := access.New(agentService)
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
	return &cobra.Command{
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
			ctx, cancel := context.WithTimeout(command.Context(), 2*time.Minute)
			defer cancel()
			agentService, catalogClient, err := a.services()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return a.listResourceServers(ctx, catalogClient)
			}
			if len(args) == 1 && !genericHTTPMethod(args[0]) {
				return a.showResourceServer(ctx, catalogClient, args[0])
			}
			return a.runRestish(ctx, agentService, catalogClient, args)
		},
	}
}

func (a *App) parseToolboxFlags(args []string) ([]string, error) {
	result := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--json":
			a.json = true
		case "--realmroot-origin":
			if index+1 >= len(args) {
				return nil, errors.New("--realmroot-origin requires a value")
			}
			index++
			a.origin = args[index]
		default:
			result = append(result, args[index])
		}
	}
	return result, nil
}

func (a *App) enroll(command *cobra.Command, _ []string) error {
	service, _, err := a.services()
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
	service, _, err := a.services()
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
		return a.printJSON(servers)
	}
	w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tRESOURCE SERVER\tCONNECTION\tDESCRIPTION")
	for _, server := range servers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", server.CommandName, server.Identifier, server.ConnectionStatus, server.Name)
	}
	return w.Flush()
}

func (a *App) showResourceServer(ctx context.Context, client *catalog.Client, name string) error {
	server, err := client.Find(ctx, name)
	if err != nil {
		return err
	}
	details, err := client.AuthorizationDetails(ctx, server)
	if err != nil {
		return err
	}
	if a.json {
		return a.printJSON(struct {
			Server               catalog.ResourceServer        `json:"resourceServer"`
			AuthorizationDetails []catalog.AuthorizationDetail `json:"authorizationDetails"`
		}{server, details})
	}
	fmt.Fprintf(a.stdout, "Resource Server: %s (%s)\nName: %s\nResource: %s\nConnection: %s\n\nScopes:\n", server.CommandName, server.Identifier, server.Name, server.ResourceURL, server.ConnectionStatus)
	for _, scope := range server.Scopes {
		fmt.Fprintf(a.stdout, "  %-28s %s\n", scope.Value, scope.Description)
	}
	fmt.Fprintln(a.stdout, "\nAuthorization details:")
	for _, detail := range details {
		fmt.Fprintf(a.stdout, "  %s\n    account: %s\n    authorized: %s\n    requestable: %s\n", detail.Name, detail.AccountAuthorizationStatus, strings.Join(detail.AuthorizedScopes, ", "), strings.Join(detail.RequestableScopes, ", "))
	}
	fmt.Fprintf(a.stdout, "\nOperations: realmroot toolbox %s --help\n", server.CommandName)
	return nil
}

func (a *App) runRestish(ctx context.Context, service *agent.Service, client *catalog.Client, args []string) error {
	config, _, err := client.RestishConfig(ctx)
	if err != nil {
		return err
	}
	if err := configureRestishPaths(); err != nil {
		return err
	}
	runtime := restish.New()
	runtime.SetCommandName("realmroot toolbox")
	runtime.SetCommandDescription("Operate Realmroot Resource Servers", "OpenAPI-generated and generic HTTP operations for discovered Resource Servers.")
	runtime.SetDefaultConfig(config)
	runtime.SetCommandSurface(restish.CommandSurface{
		HTTPMethods: []string{"get", "head", "post", "put", "patch", "delete"}, RegisteredAPIs: true, HideSupportCommands: true,
		MetadataRefreshTimeout: 30 * time.Second, IgnoreUserConfig: true, DisablePlugins: true,
	})
	runtime.AddAuthHandler("dpop", restish.NewDPoPAuthHandler(service.CredentialSource()))
	runtime.Stdout, runtime.Stderr = a.stdout, a.stderr
	runtime.SetSignalHandling(false)
	argv := append([]string{"realmroot toolbox"}, args...)
	return runtime.Run(argv)
}

func (a *App) services() (*agent.Service, *catalog.Client, error) {
	service, err := agent.NewService(a.origin, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	client, err := catalog.New(service)
	if err != nil {
		return nil, nil, err
	}
	return service, client, nil
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
