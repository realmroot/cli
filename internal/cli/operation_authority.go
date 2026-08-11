package cli

import (
	"fmt"
	"strings"

	"github.com/realmroot/toolbox/internal/agent"
	"github.com/realmroot/toolbox/internal/catalog"
	restish "github.com/saltbo/restish/v2"
	restishconfig "github.com/saltbo/restish/v2/config"
)

func selectedResourceServer(servers []catalog.ResourceServer, args []string) (catalog.ResourceServer, bool) {
	if len(args) == 0 || genericHTTPMethod(args[0]) {
		return catalog.ResourceServer{}, false
	}
	for _, server := range servers {
		if server.CommandName == args[0] {
			return server, true
		}
	}
	return catalog.ResourceServer{}, false
}

func prepareOperationCredentials(
	config *restish.Config,
	server catalog.ResourceServer,
	inspection restish.APIInspection,
	args []string,
	profileName string,
	binding *agent.CredentialBinding,
) error {
	operation, selected := selectedOperation(inspection.Operations, args)
	if selected && invocationRequiresAuthority(args) && operationRequiresAuthority(operation) {
		if binding == nil {
			return operationAuthorityError(server.CommandName, operation, nil)
		}
		if !operationCoveredByScopes(operation, binding.Scopes) {
			return operationAuthorityError(server.CommandName, operation, binding.Scopes)
		}
	}
	if binding == nil {
		return nil
	}
	api := config.APIs[server.CommandName]
	if api == nil {
		return fmt.Errorf("Resource Server %q is not configured", server.CommandName)
	}
	profile := api.Profiles[profileName]
	if profile == nil {
		profile = &restish.ProfileConfig{}
		if api.Profiles == nil {
			api.Profiles = map[string]*restish.ProfileConfig{}
		}
		api.Profiles[profileName] = profile
	}
	auth := profile.Auth
	if auth == nil {
		auth = &restish.AuthConfig{Type: "dpop", Params: map[string]string{
			"source": "realmroot", "reference": binding.Reference,
		}}
	}
	profile.Auth = nil
	if profile.Credentials == nil {
		profile.Credentials = map[string]*restishconfig.CredentialConfig{}
	}
	for _, candidate := range inspection.Operations {
		for _, alternative := range candidate.CredentialAlternatives {
			for _, requirement := range alternative {
				if requirement.Kind != "oauth2-dpop" {
					continue
				}
				profile.Credentials[requirement.ID] = &restishconfig.CredentialConfig{
					Auth: auth, Satisfies: append([]string(nil), binding.Scopes...),
				}
			}
		}
	}
	return nil
}

func invocationRequiresAuthority(args []string) bool {
	for _, argument := range args {
		switch argument {
		case "--help", "-h", "--help-all", "--generate-body", "--rsh-generate-body":
			return false
		}
	}
	return true
}

func selectedOperation(operations []restish.OperationInspection, args []string) (restish.OperationInspection, bool) {
	var selected restish.OperationInspection
	for _, operation := range operations {
		if len(operation.Command) <= len(selected.Command) || len(operation.Command) > len(args) {
			continue
		}
		matches := true
		for index := range operation.Command {
			if args[index] != operation.Command[index] {
				matches = false
				break
			}
		}
		if matches {
			selected = operation
		}
	}
	return selected, len(selected.Command) > 0
}

func operationRequiresAuthority(operation restish.OperationInspection) bool {
	return !operation.NoAuth && !operation.OptionalAuth && len(operation.CredentialAlternatives) > 0
}

func operationCoveredByScopes(operation restish.OperationInspection, scopes []string) bool {
	have := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		have[scope] = true
	}
	for _, alternative := range operation.CredentialAlternatives {
		covered := len(alternative) > 0
		for _, requirement := range alternative {
			if requirement.Kind != "oauth2-dpop" {
				covered = false
				break
			}
			for _, need := range requirement.Needs {
				if !have[need] {
					covered = false
					break
				}
			}
		}
		if covered {
			return true
		}
	}
	return false
}

func operationAuthorityError(resourceServer string, operation restish.OperationInspection, activeScopes []string) error {
	required := operationScopeSummary(summarizeOperations([]restish.OperationInspection{operation}, "")[0])
	if required == "" {
		required = "authority declared by the operation"
	}
	command := strings.Join(operation.Command, " ")
	if len(activeScopes) == 0 {
		return fmt.Errorf("Resource Server %q has no approved Agent authority for operation %q; required scopes: %s; request the task-appropriate published scopes with `realmroot agent request --resource-server %s --scope <scope>`", resourceServer, command, required, resourceServer)
	}
	return fmt.Errorf("approved Agent authority for Resource Server %q does not cover operation %q; active scopes: %s; required scopes: %s; request the additional task-appropriate published scopes with `realmroot agent request --resource-server %s --scope <scope>`", resourceServer, command, strings.Join(activeScopes, ", "), required, resourceServer)
}
