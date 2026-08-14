package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/realmroot/toolbox/internal/agent"
	"github.com/realmroot/toolbox/internal/catalog"
	"github.com/realmroot/toolbox/internal/observability"
)

type Runner struct {
	service *agent.Service
	client  *http.Client
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	logger  *slog.Logger
}

type RunOptions struct {
	AuthorizationDetails      []map[string]any
	ExactAuthorizationContext bool
	EffectiveScopes           []string
	RequestAuthority          func(context.Context, []string) error
}

func NewRunner(service *agent.Service, client *http.Client, stdin io.Reader, stdout, stderr io.Writer, loggers ...*slog.Logger) *Runner {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if len(loggers) == 1 {
		logger = loggers[0]
	}
	return &Runner{service: service, client: client, stdin: stdin, stdout: stdout, stderr: stderr, logger: logger}
}

func (r *Runner) Run(ctx context.Context, server catalog.ResourceServer, integrations []catalog.ToolIntegration, command []string, options RunOptions) error {
	startedAt := time.Now()
	if len(command) == 0 {
		return errors.New("native command is required after --")
	}
	integration, executable, err := selectIntegration(integrations, command)
	if err != nil {
		return err
	}
	observability.LogDuration(r.logger, observability.LevelTrace, "native_command.resolve", startedAt, "integration", integration.ID, "executable", filepath.Base(executable))
	phaseStartedAt := time.Now()
	var binding agent.CredentialBinding
	if options.ExactAuthorizationContext {
		binding, err = r.service.BindingForAuthorizationContextEffectiveScopes(
			server.ResourceURL,
			options.AuthorizationDetails,
			options.EffectiveScopes,
		)
	} else {
		binding, err = r.service.ExecutionBinding(server.ResourceURL, options.AuthorizationDetails)
	}
	if err != nil {
		return fmt.Errorf("load selected %s Context authority: %w; inspect Contexts with `realmroot toolbox %s context` or request access with `realmroot agent request`", server.CommandName, err, server.CommandName)
	}
	observability.LogDuration(r.logger, observability.LevelTrace, "authority.resolve", phaseStartedAt, "scope_count", len(binding.Scopes))
	binding.Scopes = intersectScopes(binding.Scopes, options.EffectiveScopes)
	broker, err := NewBroker(
		server.ResourceURL,
		binding.Reference,
		binding.Scopes,
		r.service.CredentialSource(),
		func(reference string, alternatives [][]string) ([]string, error) {
			resolved, err := r.service.BindingForReferenceScopeAlternatives(server.ResourceURL, reference, alternatives)
			if err == nil {
				return intersectScopes(resolved.Scopes, options.EffectiveScopes), nil
			}
			if !errors.Is(err, os.ErrNotExist) || options.RequestAuthority == nil {
				return nil, err
			}
			required, err := permittedScopeAlternative(alternatives, options.EffectiveScopes)
			if err != nil {
				return nil, err
			}
			if err := options.RequestAuthority(ctx, required); err != nil {
				return nil, err
			}
			resolved, err = r.service.BindingForReferenceScopeAlternatives(server.ResourceURL, reference, alternatives)
			return intersectScopes(resolved.Scopes, options.EffectiveScopes), err
		},
		r.client,
	)
	if err != nil {
		return err
	}
	defer broker.Close()
	phaseStartedAt = time.Now()
	environment := cleanEnvironment(os.Environ(), providerCredentialNames(integration.ID))
	switch integration.Protocol {
	case "cloudflare-api-base":
		base, err := broker.StartCloudflareAPIBase("https://api.cloudflare.com/client/v4")
		if err != nil {
			return err
		}
		environment = setEnvironment(environment, "CLOUDFLARE_API_BASE_URL", base+"/client/v4", "CLOUDFLARE_API_TOKEN", broker.SessionToken())
	case "github-http":
		socket, err := broker.StartGitHubSocket()
		if err != nil {
			return err
		}
		configDirectory := filepath.Dir(socket)
		hosts := "github.com:\n  user: realmroot-agent\n  oauth_token: " + broker.SessionToken() + "\n  git_protocol: https\n"
		if err := os.WriteFile(filepath.Join(configDirectory, "hosts.yml"), []byte(hosts), 0o600); err != nil {
			return err
		}
		configuration := "http_unix_socket: " + socket + "\nprompt: disabled\n"
		if err := os.WriteFile(filepath.Join(configDirectory, "config.yml"), []byte(configuration), 0o600); err != nil {
			return err
		}
		environment = setEnvironment(environment, "GH_CONFIG_DIR", configDirectory, "GH_TOKEN", broker.SessionToken())
	case "git-smart-http":
		base, err := broker.StartTCP(func(request *http.Request) (string, error) {
			prefix := "/" + broker.SessionToken()
			if !strings.HasPrefix(request.URL.Path, prefix+"/") {
				return "", errors.New("invalid Git broker session")
			}
			return "/git" + strings.TrimPrefix(request.URL.RequestURI(), prefix), nil
		}, func(request *http.Request) bool { return true })
		if err != nil {
			return err
		}
		identity, err := r.service.ExecutionIdentity(ctx)
		if err != nil {
			return err
		}
		local := base + "/" + broker.SessionToken() + "/"
		environment = appendGitConfig(environment, [][2]string{
			{"url." + local + ".insteadOf", "https://github.com/"},
			{"url." + local + ".insteadOf", "http://github.com/"},
			{"url." + local + ".insteadOf", "git@github.com:"},
			{"url." + local + ".insteadOf", "ssh://git@github.com/"},
			{"user.name", identity.Name}, {"user.email", identity.Email},
		})
	default:
		return fmt.Errorf("Resource Server integration %q uses unsupported protocol %q", integration.ID, integration.Protocol)
	}
	observability.LogDuration(r.logger, observability.LevelTrace, "broker.start", phaseStartedAt, "protocol", integration.Protocol)
	child := exec.CommandContext(ctx, executable, command[1:]...)
	child.Stdin, child.Stdout, child.Stderr, child.Env = r.stdin, r.stdout, r.stderr, environment
	phaseStartedAt = time.Now()
	err = child.Run()
	result := "ok"
	if err != nil {
		result = "error"
	}
	observability.LogDuration(r.logger, slog.LevelDebug, "child.execute", phaseStartedAt, "executable", filepath.Base(executable), "result", result)
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return &ExitError{
			Code: exit.ExitCode(), ResourceServer: server.CommandName,
			RequiredScopeAlternatives: broker.UnresolvedScopeAlternatives(),
		}
	}
	return err
}

func permittedScopeAlternative(alternatives [][]string, allowed []string) ([]string, error) {
	allowedSet := make(map[string]bool, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = true
	}
	for _, alternative := range alternatives {
		permitted := true
		for _, scope := range alternative {
			if !allowedSet[scope] {
				permitted = false
				break
			}
		}
		if permitted && len(alternative) > 0 {
			return append([]string(nil), alternative...), nil
		}
	}
	return nil, errors.New("native command requested scopes outside the selected Resource Context")
}

func intersectScopes(scopes, allowed []string) []string {
	available := make(map[string]bool, len(allowed))
	for _, scope := range allowed {
		available[scope] = true
	}
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if available[scope] {
			result = append(result, scope)
		}
	}
	return result
}

type ExitError struct {
	Code                      int
	ResourceServer            string
	RequiredScopeAlternatives [][]string
}

func (e *ExitError) Error() string {
	message := fmt.Sprintf("native command exited with status %d", e.Code)
	if len(e.RequiredScopeAlternatives) == 0 {
		return message
	}
	commands := make([]string, 0, len(e.RequiredScopeAlternatives))
	for _, scopes := range e.RequiredScopeAlternatives {
		arguments := []string{"realmroot agent request", "--resource-server", e.ResourceServer}
		for _, scope := range scopes {
			arguments = append(arguments, "--scope", scope)
		}
		commands = append(commands, "`"+strings.Join(arguments, " ")+"`")
	}
	return message + "; request additional authority with " + strings.Join(commands, " or ")
}
func (e *ExitError) ExitCode() int { return e.Code }

func selectIntegration(integrations []catalog.ToolIntegration, command []string) (catalog.ToolIntegration, string, error) {
	executable := filepath.Base(command[0])
	for _, integration := range integrations {
		for _, candidate := range integration.Executables {
			commandPrefix := nativeCommandPrefix(integration, candidate)
			if executable != commandPrefix[0] {
				continue
			}
			if len(commandPrefix) == 2 && (len(command) < 2 || filepath.Base(command[1]) != commandPrefix[1]) {
				continue
			}
			path, err := exec.LookPath(command[0])
			if err != nil {
				return catalog.ToolIntegration{}, "", fmt.Errorf("native executable %q was not found", command[0])
			}
			return integration, path, nil
		}
	}
	return catalog.ToolIntegration{}, "", fmt.Errorf("Resource Server does not advertise support for native command %q", executable)
}

func NativeCommands(integrations []catalog.ToolIntegration) []string {
	commands := make([]string, 0)
	for _, integration := range integrations {
		for _, executable := range integration.Executables {
			commands = append(commands, strings.Join(nativeCommandPrefix(integration, executable), " "))
		}
	}
	return commands
}

func nativeCommandPrefix(integration catalog.ToolIntegration, executable string) []string {
	if (executable == "npx" || executable == "pnpm") && integration.ID == "wrangler" {
		return []string{executable, "wrangler"}
	}
	return []string{executable}
}

func cleanEnvironment(values []string, removed []string) []string {
	blocked := make(map[string]bool, len(removed))
	for _, name := range removed {
		blocked[name] = true
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		name, _, _ := strings.Cut(value, "=")
		if !blocked[name] {
			result = append(result, value)
		}
	}
	return result
}

func setEnvironment(values []string, pairs ...string) []string {
	for index := 0; index < len(pairs); index += 2 {
		values = cleanEnvironment(values, []string{pairs[index]})
		values = append(values, pairs[index]+"="+pairs[index+1])
	}
	return values
}

func providerCredentialNames(id string) []string {
	switch id {
	case "wrangler":
		return []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL", "CF_API_TOKEN", "CF_API_KEY", "CF_EMAIL"}
	case "gh":
		return []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST", "GH_CONFIG_DIR", "SSL_CERT_FILE"}
	case "git":
		return []string{"GIT_ASKPASS", "SSH_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND"}
	default:
		return nil
	}
}

func appendGitConfig(environment []string, entries [][2]string) []string {
	environment = cleanEnvironment(environment, []string{"GIT_CONFIG_COUNT"})
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "GIT_CONFIG_KEY_") || strings.HasPrefix(value, "GIT_CONFIG_VALUE_") {
			name, _, _ := strings.Cut(value, "=")
			environment = cleanEnvironment(environment, []string{name})
		}
	}
	environment = append(environment, "GIT_CONFIG_COUNT="+strconv.Itoa(len(entries)))
	for index, entry := range entries {
		environment = append(environment, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", index, entry[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", index, entry[1]))
	}
	return environment
}
